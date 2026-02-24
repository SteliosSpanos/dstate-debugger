# dstate-debugger

A Linux tool for diagnosing processes stuck in **D-state** (uninterruptible sleep). Scans `/proc` to find blocked processes, reads kernel stack traces, identifies the blocking syscall and file descriptor, detects file lock conflicts, unwinds the user-space call stack, and can write a synthetic ELF core file for GDB.

Written in **C99** for x86-64 Linux. Dependencies: glibc and libunwind.

---

## Why D-state?

When a process enters D-state, the kernel has suspended it inside a system call waiting for something (usually I/O). It cannot respond to signals, not even `SIGKILL`.

Traditional debuggers attach via ptrace, which requires delivering `SIGSTOP`. A D-state process cannot receive signals, so ptrace fails entirely. This tool reads everything from `/proc`, no signals, no ptrace, no process cooperation required.

For **S-state** and **T-state** processes, ptrace works normally. The tool takes advantage of this: it supplements `/proc` reads with a live ptrace register snapshot, which fills the gap when `/proc/[pid]/syscall` returns no data (the process is not currently inside a syscall).

---

## Project Structure

```
dstate-debugger/
├── main.c                 Entry point, CLI argument handling
├── Makefile
├── include/
│   ├── dstate.h           Data structures and API declarations
│   └── proc_utils.h       Low-level /proc utility interface
├── src/
│   ├── proc_utils.c       /proc file I/O, symlinks, path building
│   ├── detector.c         D-state process scanning
│   ├── proc_reader.c      Per-PID diagnostics, user stack heuristic, x86-64 syscall table
│   ├── ptrace_reader.c    Full register capture via ptrace for S/T-state processes
│   ├── unwind_reader.c    User stack unwinding via libunwind
│   └── core_writer.c      Synthetic ELF core file generation
└── test/
    ├── unit_test.c        Unit tests for parsing and utility functions
    ├── monitor.c          Forks child into D-state, demonstrates signal immunity
    └── trap_fs.c          FUSE filesystem that blocks reads forever
```

---

## Dependencies

- **Build and runtime**: glibc and libunwind
- **Testing only**: libfuse-dev (for the FUSE test filesystem)

```bash
sudo apt-get install libunwind-dev libfuse-dev
```

---

## Build

| Target | Description | Requires sudo |
|---|---|---|
| `make` | Build `dstate` | No |
| `make unit-test` | Build and run unit tests | No |
| `make monitor` | Build test monitor | No |
| `make trap_fs` | Build FUSE test filesystem | No |
| `make test` | Full integration test: trap a process, run scanner | Yes |
| `make test-pid` | Same, but diagnoses by PID (`-p` flag) | Yes |
| `make test-monitor` | Demonstrates D-state and SIGTERM immunity | No |
| `make kill` | Kill trap_fs and unmount FUSE | No |
| `make clean` | Remove binaries and unmount FUSE | No |

---

## Usage

```bash
sudo ./dstate                  # scan all processes for D-state
sudo ./dstate -p PID           # diagnose a specific process
sudo ./dstate -p PID -o FILE   # diagnose and write an ELF core file
./dstate -h                    # show help
```

Root or `CAP_SYS_PTRACE` is required for: `/proc/[pid]/stack` (kernel stack), `/proc/[pid]/mem` (user stack unwinding and core generation), and ptrace register reads (S/T-state only). All other diagnostics work without elevated privileges.

---

## Architecture

| Module | Responsibility |
|---|---|
| `proc_utils.c` | Base layer: raw `/proc` I/O, symlink reads, path building. Every other module goes through this. |
| `detector.c` | Scans `/proc`, filters by state `D`, returns a capacity-doubling dynamic array. Entry point: `find_dstate_processes()`. |
| `proc_reader.c` | Per-PID diagnostics: stat, wchan, syscall, kernel stack, maps, user stack heuristic, x86-64 syscall name table. Entry point: `read_full_diagnostics()`. |
| `ptrace_reader.c` | Attaches ptrace, reads all 27 registers via `PTRACE_GETREGS`, detaches. Only called for S/T-state processes. |
| `unwind_reader.c` | User stack unwinding via libunwind. Reads `/proc/[pid]/mem` directly — no ptrace needed, works on D-state. |
| `core_writer.c` | Builds a synthetic ELF core file (two-pass design). Entry point: `write_core_file()`. |

---

## How It Works

### Detection and basic data collection

| Step | Reads from | Gives you |
|---|---|---|
| 1. Detection | `/proc/[pid]/stat` field 3 | Processes in state `D` |
| 2. Syscall ID | `/proc/[pid]/syscall` | Syscall nr + 6 args + RSP + RIP |
| 3. Registers | ptrace `PTRACE_GETREGS` | Full 27-register snapshot (S/T-state only) |
| 4. Blocking FD | `/proc/[pid]/fd/N` symlink | File/socket/device the process has open |
| 5. Kernel stack | `/proc/[pid]/stack` | Live kernel call chain (needs root) |
| 6. Wait channel | `/proc/[pid]/wchan` | Single kernel function name where process sleeps |
| 7. Memory map | `/proc/[pid]/maps` | All VMAs: address, permissions, file offset, backing file |

**Step 3 is skipped entirely for D-state.** Delivering `SIGSTOP` requires signal reception which is impossible in uninterruptible sleep. Calling `ptrace(PTRACE_ATTACH)` on a D-state process would block the tool indefinitely waiting for a stop that never arrives.

**Step 4 is only checked for D-state processes.** For syscalls that take a file descriptor as their first argument (`read`, `write`, `ioctl`, `pread64`, `pwrite64`, `readv`, `writev`, `connect`, `accept`, `accept4`, `sendto`, `recvfrom`, `fcntl`, `flock`), args[0] is resolved via the `/proc/[pid]/fd/N` symlink to get the actual path. Doing this for S-state processes would be misleading since they may be in the middle of any I/O without being genuinely stuck.

### File lock conflict detection

If the blocking syscall is `fcntl` (nr=72) or `flock` (nr=73), the process is waiting to acquire a file lock. The tool identifies the holder:

1. Resolves args[0] (the fd) via `/proc/[pid]/fd/N` to a path.
2. Calls `stat()` to get the file's device major:minor and inode.
3. Scans `/proc/locks` line by line for a matching `major:minor:inode` held by a different PID.
4. Stores `holder_pid`, `lock_type`, `access`, and `path` in `diag->lock_conflict`.

Device + inode uniquely identifies a file regardless of how it was opened (hard links, bind mounts, different paths). This is why `stat()` is used rather than comparing paths directly.

### User stack unwinding

Two methods run in sequence. libunwind runs first; if it fails or returns fewer than three frames, the heuristic scanner takes over.

**libunwind (`src/unwind_reader.c`)**

Reads DWARF CFI data from binaries and walks frames precisely, the same method GDB uses. Reads process memory from `/proc/[pid]/mem` directly without attaching, so it works on D-state processes.

Starting state for D-state: only RSP and RIP from `/proc/[pid]/syscall`. Starting state for S/T-state: all 27 registers from ptrace. The full register set matters because DWARF CFI rules frequently describe frame recovery in terms of callee-saved registers (RBP, RBX, R12–R15). Without them, libunwind stops early when it hits a frame whose recovery rule requires a register that was never captured.

**Heuristic scanner (`src/proc_reader.c`)**

Reads 2048 bytes from the stack pointer via `/proc/[pid]/mem`, then scans every 8-byte word. If a word falls inside an executable VMA, it is a candidate return address. Each candidate is validated by checking whether the bytes immediately before it match a `call` instruction encoding:

| Bytes before return address | Instruction | Example |
|---|---|---|
| `E8 xx xx xx xx` (5 bytes) | `call rel32` | Direct call |
| `FF /2` (2 bytes) | `call r/m64` | `call rax` |
| `FF /2 ModRM` (3 bytes) | `call [mem]` | `call [rbp-8]` |
| `REX FF /2` (3 bytes) | `call r/m64` | `call r8` |
| `FF 15 xx xx xx xx` (6 bytes) | `call [rip+rel32]` | PLT stub, glibc |
| `FF /2 disp32` (6 bytes, mod=10) | `call [reg+disp32]` | `call [rax+offset]` |
| `REX FF 15 xx xx xx xx` (7 bytes) | REX `call [rip+rel32]` | REX PLT stub |
| `REX FF /2 disp32` (7 bytes, mod=10) | REX `call [reg+disp32]` | REX indirect |

The `FF 15 rel32` form is critical since it covers every PLT stub and most glibc internal calls in position-independent code. Without it, any frame from a dynamically linked function would be silently dropped.

### Symbol resolution

For each frame pointing into a mapped binary, the tool calls `addr2line` with the file-relative offset: `(virtual_address - vma_start) + file_offset`. The `file_offset` comes from the maps table and correctly handles partially-mapped binaries. Requires the binary to be compiled with `-g`.

### ELF core file (`-o FILE`)

Writes a GDB-loadable ELF core from the live process using a two-pass design:

- **Pass 1 (`compute_layout`)**: probes every VMA with a one-byte `pread`, determines which are readable, and computes every file offset before writing begins.
- **Pass 2**: writes the entire file in a single sequential forward pass with no seeking. Unreadable VMAs (process exited mid-write) are zeroed.

**Core layout:**

```
ELF Header (ET_CORE, EM_X86_64)
  PT_NOTE  — note blob
  PT_LOAD  — one per readable VMA
Note blob:
  NT_PRSTATUS  — pid, ppid, registers
                 (full 27-reg ptrace snapshot for S/T-state;
                  RIP + RSP + syscall args for D-state)
  NT_PRPSINFO  — comm, cmdline
  NT_FILE      — maps each VMA to its backing file + page offset
PT_LOAD data   — raw memory from /proc/[pid]/mem
```

The NT_FILE note is what allows GDB to locate shared library debug information. Without it, GDB cannot match anonymous memory regions to `.so` files on disk and backtraces into libc show as `??`.

**Loading in GDB:**

```bash
gdb /path/to/binary output.core
(gdb) bt
(gdb) info registers
(gdb) x/40gx $rsp
```

---

## Sample Output

```
=== D-State Processes Found: 1 ===
PID      COMMAND              STATE    WAITING IN
---      -------              -----    ----------
1234     cat                  D        request_wait_answer

====================================================
   PROCESS DIAGNOSTICS: PID - 1234
====================================================

Basic Information:
   Command:      cat
   State:        D
   Parent PID:   1000
   Threads:      1

Executable & Working Directory:
   Exe: /usr/bin/cat
   CWD: /home/user

Command Line:
   cat /tmp/fuse_mount/trap.txt

Wait Channel (Kernel Function)
   request_wait_answer

System Call Information:
   Syscall:   read (nr = 0)
   Args:      0x3, 0x7f56a65c5000, 0x40000
   IP:        0x7f56a66f2687
   SP:        0x7ffe6acee8f0

Blocking File Descriptor:
   FD:        3
   Path:      /tmp/fuse_mount/trap.txt

Lock Conflict:
   Waiting for: WRITE lock on /var/lock/myapp.lock
   Held by PID: 5678 (myapp)

Memory Usage:
    Virtual:     5812 KB
    Resident:    1748 KB

Kernel Stack Trace:
   [<0>] folio_wait_bit_common+0x132/0x320
   [<0>] filemap_get_pages+0x6c6/0x6f0
   [<0>] filemap_read+0xf0/0x370
   [<0>] vfs_read+0x244/0x360
   [<0>] ksys_read+0x6d/0xf0
   [<0>] do_syscall_64+0x82/0x190
   [<0>] entry_SYSCALL_64_after_hwframe+0x76/0x7e

User Stack Trace (syscall SP):
   [0]  0x7f56a66f2687  /usr/lib/x86_64-linux-gnu/libc.so.6
         function: __GI___read
         source: ../sysdeps/unix/sysv/linux/read.c:26  (+0x22687)
   [1]  0x55a1b2c00a32  /usr/bin/cat
         function: main
         source: cat.c:140  (+0xa32)
```

Reading top to bottom: `cat` is in D-state, sleeping in `request_wait_answer` (a FUSE kernel function), stuck in a `read` syscall on fd 3 → `/tmp/fuse_mount/trap.txt`. The kernel stack confirms the path through the VFS layer. The user stack shows it entered the kernel via `__GI___read` in libc, called from `main`.

---

## Testing

### Unit tests

Cover pure logic: syscall name lookup, `/proc` path construction, PID directory validation. No root required.

```bash
make unit-test
```

### Integration tests

Uses `trap_fs`, a FUSE filesystem that accepts reads but never responds. Any process reading from it immediately enters D-state.

**Manual setup:**

```bash
# Terminal 1: start the blocking FUSE daemon
./trap_fs /tmp/fuse_mount

# Terminal 2: fork a child into D-state
./monitor

# Terminal 3: run the tool
sudo ./dstate
```

**Automated:**

```bash
make test           # trap a process, run scanner (requires sudo)
make test-pid       # same, diagnose by PID with -p flag (requires sudo)
make test-monitor   # SIGTERM immunity demonstration
```

> `make test` and `make test-monitor` must not run simultaneously. `trap_fs` runs single-threaded (`-s`): while handling the first blocked read it cannot process new requests, so the monitor's child behaves unpredictably.

---

## API Reference

All functions return `0` on success, `-1` on error. `read_full_diagnostics()` returns `DSTATE_PROC_GONE` (`1`) if the process exited between detection and the diagnostic read. See `include/dstate.h` for struct definitions.

### Detection

```c
int find_dstate_processes(dstate_process_t **results, int *count);
void free_dstate_list(dstate_process_t *list);
void print_dstate_summary(const dstate_process_t *procs, int count);
```

`find_dstate_processes` allocates the result array internally. Always free with `free_dstate_list`.

### Diagnostics

```c
int read_full_diagnostics(pid_t pid, process_diagnostics_t *diag);
int read_process_stat(pid_t pid, dstate_process_t *proc);
int read_process_syscall(pid_t pid, dstate_process_t *proc);
int read_process_wchan(pid_t pid, char *wchan, size_t len);
int read_process_stack(pid_t pid, char *stack, size_t len);
const char *syscall_name(long nr);
void print_diagnostics(const process_diagnostics_t *diag);
```

### Registers (ptrace)

```c
int read_registers_ptrace(pid_t pid, elf_gregset_t *regs_out);
```

Attaches via `PTRACE_ATTACH`, waits for stop, reads 27 registers via `PTRACE_GETREGS` into `regs_out` (indexed by `elfreg_index_t`), detaches. Only called for S/T-state. Returns `-1` if permission denied, process gone, or process transitioned to D-state before attach.

### User Stack Unwinding

```c
int read_user_stack_libunwind(pid_t pid, process_diagnostics_t *diag);
int read_user_stack(pid_t pid, process_diagnostics_t *diag);
void resolve_symbol(const char *binary_path, uint64_t offset,
                    char *func_out, size_t func_len,
                    char *src_out, size_t src_len);
```

`read_full_diagnostics` calls libunwind first; if it returns fewer than three frames, `read_user_stack` (heuristic) runs and overwrites the result.

| Failure code | Value | Meaning |
|---|---|---|
| `USER_STACK_ERR_PERM` | 1 | Permission denied on `/proc/[pid]/mem`. Needs root or `CAP_SYS_PTRACE`. |
| `USER_STACK_ERR_UNAVAIL` | 2 | Memory unreadable or process vanished. |
| `USER_STACK_ERR_NO_SP` | 3 | Stack pointer is zero, process was not in a syscall and ptrace also failed. |

### Lock Conflict

```c
int read_lock_conflict(pid_t pid, process_diagnostics_t *diag);
```

Only acts on `fcntl` (nr=72) and `flock` (nr=73). Resolves the fd, calls `stat()` for device+inode, scans `/proc/locks` for a matching entry held by another PID. Sets `diag->lock_conflict.found = 1` on match.

### ELF Core File

```c
int write_core_file(pid_t pid, process_diagnostics_t *diag, const char *outpath);
```

Requires `read_full_diagnostics` to have been called first. D-state cores contain only RIP, RSP, and syscall args. S/T-state cores contain the full 27-register snapshot.

---

## Known Limitations

| Limitation | Detail |
|---|---|
| x86-64 only | Syscall table is x86-64 specific. Compiles on other architectures but names will be wrong. |
| TOCTOU races | Processes can exit between detection and diagnostic read. Handled gracefully via `DSTATE_PROC_GONE`. |
| Privileges required | `/proc/[pid]/stack`, `/proc/[pid]/mem`, and ptrace all require root or `CAP_SYS_PTRACE`. |
| Symbol resolution requires `-g` | `addr2line` returns `??` / `??:0` for stripped binaries. |
| D-state unwinding is best-effort | Only RSP and RIP are available from `/proc/[pid]/syscall`. libunwind stops early when DWARF rules require callee-saved registers that were not captured. The heuristic scanner fills in but can include false positives. |
| Main thread only | `/proc/[pid]/syscall` targets the main thread. Multi-threaded programs may have other threads blocked, diagnosing them requires per-thread files under `/proc/[pid]/task/[tid]/`. |
| Advisory locks only | `flock` and `fcntl` locks appear in `/proc/locks`. Futex-based locks (pthreads mutexes, `std::mutex`, Go sync) do not. Holder identification is not possible for those. |
| Incomplete D-state core registers | NT_PRSTATUS contains only registers from `/proc/[pid]/syscall`. GDB can inspect memory but `bt` may be incomplete. |
| libunwind internal ABI | `src/unwind_reader.c` assumes `pid_t` is the first member of `struct UPT_info`. Not a public API guarantee. It has to be verified against libunwind 1.x. |

---

## License

This project is licensed under the [MIT LICENSE](LICENSE).
