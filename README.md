# dstate-debugger

A Linux tool for diagnosing processes stuck in **D-state** (uninterruptible sleep). It scans `/proc` to find blocked processes, reads kernel stack traces, identifies the blocking syscall and file descriptor, looks for file lock conflicts, unwinds the user-space call stack, and can write a synthetic ELF core file for GDB.

Written in **C99** for x86-64 Linux. Dependencies: glibc and libunwind.

See [Known Issues](#known-issues) for the remaining caveats.

---

## Why D-state?

When a process enters D-state, the kernel has suspended it inside the kernel waiting for something (usually I/O). It does not respond to ordinary signals. Some waits are killable (`TASK_KILLABLE`, used for example by FUSE requests) and still react to `SIGKILL`; others ignore every signal until the wait ends.

Traditional debuggers attach via ptrace, which requires the target to stop on a signal. A D-state process cannot do that, so ptrace is useless there. For D-state processes this tool reads everything from `/proc`: no signals, no ptrace, no cooperation from the process.

For **S-state** and **T-state** processes ptrace does work, and the tool uses it: it attaches, takes a register snapshot, and detaches. This fills the gap when `/proc/[pid]/syscall` has no register data. The attach uses `PTRACE_SEIZE` followed by `PTRACE_INTERRUPT`, so no `SIGSTOP` is injected, and a signal that arrives during the attach is handed back to the target on detach. Diagnosing a sleeping process still briefly stops it, and `PTRACE_INTERRUPT` wakes an interruptible sleep, so a syscall that is not automatically restarted (for example `epoll_wait`, or a sleep interrupted without `SA_RESTART` semantics) can return `EINTR` in the target.

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
    ├── unit_test.c        Unit tests for the /proc line parsers and helpers
    ├── monitor.c          Forks a child into D-state and sends it SIGTERM
    └── trap_fs.c          FUSE filesystem that blocks reads forever
```

---

## Dependencies

- **Build and runtime**: glibc and libunwind (`libunwind`, `libunwind-x86_64`, `libunwind-ptrace`)
- **Symbol resolution at runtime**: `addr2line` from binutils, invoked as `/usr/bin/addr2line`
- **Testing only**: libfuse (version 2) and `pkg-config`, for the FUSE test filesystem

```bash
sudo apt-get install libunwind-dev binutils libfuse-dev pkg-config
```

---

## Build

| Target | Description | Requires sudo |
|---|---|---|
| `make` | Build `dstate` | No |
| `make unit-test` | Build and run unit tests | No |
| `make monitor` | Build test monitor | No |
| `make trap_fs` | Build FUSE test filesystem | No |
| `make test` | Full integration test: trap a process, run the scanner | Yes |
| `make test-pid` | Same, but diagnoses by PID (`-p` flag) | Yes |
| `make test-monitor` | Demonstrates D-state and SIGTERM behavior | No |
| `make kill` | Kill trap_fs and unmount FUSE | No |
| `make clean` | Remove binaries and unmount FUSE | No |
| `make help` | Print a short target and usage summary | No |

The Makefile passes `-std=c99 -D_GNU_SOURCE -Wall -Wextra`. Every source file also guards its own `_GNU_SOURCE` definition. Headers under `include/` are tracked as dependencies of `dstate` and the unit tests. `make trap_fs` stops with a clear message if `pkg-config` cannot find `fuse`.

---

## Usage

```bash
sudo ./dstate                  # scan all processes for D-state
sudo ./dstate -p PID           # diagnose a specific process
sudo ./dstate -p PID -o FILE   # diagnose and write an ELF core file
./dstate -h                    # show help
```

| Option | Meaning |
|---|---|
| `-p PID` | Diagnose one process (any state). `PID` must be a positive decimal integer. |
| `-o FILE` | Write an ELF core file. Only valid together with `-p`. |
| `-h` | Print usage and exit. |

With `-p`, the exit status is non-zero if the process does not exist, the diagnostics cannot be read, or the core file cannot be written. In scan mode the exit status is non-zero if `/proc` cannot be scanned or if the diagnostic read failed for any D-state process (a process that exited in the meantime is not a failure). Extra positional arguments are rejected with the usage text.

Process names, command lines and paths come from the target and are printed with control characters (bytes below `0x20` and `0x7f`) replaced by `?`, so they cannot inject terminal escape sequences. Bytes `0x80` and above are left alone so UTF-8 text stays intact; C1 control code points encoded in UTF-8 are not filtered.

Root or `CAP_SYS_PTRACE` is required for `/proc/[pid]/stack` (kernel stack), `/proc/[pid]/mem` (user stack unwinding and core generation), and ptrace register reads (S/T-state only). The remaining diagnostics work without elevated privileges for processes you own.

---

## Architecture

| Module | Responsibility |
|---|---|
| `proc_utils.c` | Base layer: `read_proc_file`, `read_proc_line`, `read_proc_link`, `build_proc_path`. Every other module goes through this. |
| `detector.c` | Scans `/proc`, filters by state `D`, returns a capacity-doubling dynamic array. Entry point: `find_dstate_processes()`. |
| `proc_reader.c` | Per-PID diagnostics: stat, wchan, syscall, kernel stack, maps, user stack heuristic, lock conflicts, x86-64 syscall name table, printing. Entry point: `read_full_diagnostics()`. |
| `ptrace_reader.c` | Seizes the target (`PTRACE_SEIZE` + `PTRACE_INTERRUPT`), waits up to about 500 ms for the stop, reads all 27 registers via `PTRACE_GETREGS`, detaches (re-injecting any signal it stopped on). Only called for S/T-state processes. |
| `unwind_reader.c` | User stack unwinding via libunwind. Reads `/proc/[pid]/mem` directly (the `_UPT_*` helpers are used only for unwind-table lookup), so no ptrace is needed and it can run against D-state processes. |
| `core_writer.c` | Builds a synthetic ELF core file (two-pass design). Entry point: `write_core_file()`. |

### Data flow

```
main.c
  find_dstate_processes()          detector.c      scan /proc, return dstate_process_t[]
  read_full_diagnostics()          proc_reader.c   fill process_diagnostics_t for one PID
    1. read_process_stat()           /proc/[pid]/stat
    2. read_process_wchan()          /proc/[pid]/wchan
    3. read_process_syscall()        /proc/[pid]/syscall
    4. read_registers_ptrace()       ptrace GETREGS (S/T-state only)
    5. read_process_stack()          /proc/[pid]/stack
    6. exe, cwd, cmdline             /proc/[pid]/exe, cwd, cmdline
    7. blocking fd                   /proc/[pid]/fd/N (D-state only)
    8. read_process_maps()           /proc/[pid]/maps
    9. read_lock_conflict()          /proc/locks
   10. read_user_stack_libunwind()   libunwind over /proc/[pid]/mem
   11. read_user_stack()             heuristic scan, if step 10 failed or gave < 3 frames;
                                     the result with more frames is kept (libunwind on a tie)
  print_diagnostics()              proc_reader.c
  free_diagnostics()               proc_reader.c   releases the dynamic memory map
  write_core_file()                core_writer.c   only with -o
```

---

## How It Works

### Detection and basic data collection

| Step | Reads from | Gives you |
|---|---|---|
| Detection | `/proc/[pid]/stat` field 3 | Processes in state `D` |
| Syscall | `/proc/[pid]/syscall` | Syscall number, 6 arguments, RSP, RIP |
| Registers | ptrace `PTRACE_GETREGS` | Full 27-register snapshot (S/T-state only) |
| Blocking FD | `/proc/[pid]/fd/N` symlink | File, socket or device behind the fd (D-state only) |
| Kernel stack | `/proc/[pid]/stack` | Live kernel call chain (needs root) |
| Wait channel | `/proc/[pid]/wchan` | The kernel function where the process sleeps |
| Memory map | `/proc/[pid]/maps` | VMAs: address range, permissions, file offset, backing file |

**The ptrace step is skipped for D-state.** A D-state process cannot stop for the tracer. For S/T-state targets the wait for the stop is bounded (about 500 ms); on timeout the tool attempts `PTRACE_DETACH` and continues without registers. A target that never stopped cannot be detached (`ESRCH`); it stays seized until the tool exits.

**The blocking fd is only resolved for D-state processes**, and only for syscalls in this list, whose first argument is a file descriptor: `read`, `write`, `close`, `fstat`, `ioctl`, `pread64`, `pwrite64`, `readv`, `writev`, `connect`, `accept`, `accept4`, `sendto`, `recvfrom`, `fcntl`, `flock`, `fsync`, `fdatasync`, `ftruncate`, `getdents`, `getdents64`. An S-state process may be in the middle of any I/O without being stuck, so reporting an fd there would be misleading.

The comm field of `/proc/[pid]/stat` is parsed by searching for the last `)`, so process names containing spaces or parentheses are handled. The stat and syscall lines must parse completely; partial lines are rejected.

When a task is blocked outside a system call (for example in a page fault), `/proc/[pid]/syscall` holds `-1 SP PC`. The syscall number stays -1 but SP and PC are kept, so the user stack and the core file still get a starting point.

For a 32-bit target (ELF class of `/proc/[pid]/exe`) the syscall number is printed with a "32-bit process" note instead of a name from the x86-64 table, and the blocking-fd and lock-conflict lookups are skipped.

The memory map is a dynamic array, so processes with thousands of VMAs keep `[stack]`. Map lines of any length are read whole; paths are truncated to 255 characters.

### File lock conflict detection

If the blocking syscall is `fcntl` (nr 72) or `flock` (nr 73), the process may be waiting for a file lock. The tool tries to identify the holder:

1. Calls `stat()` on `/proc/[pid]/fd/N` itself (the magic link), which works for deleted files and other mount namespaces, to get the device major:minor and the inode. The link text is only used for display.
2. Scans `/proc/locks` line by line for a matching `major:minor:inode` held by a different process (compared against the target's thread group id from `/proc/[pid]/status`, so `-p <TID>` of a thread does not report its own process). The device is hexadecimal in `/proc/locks` and the inode is decimal. Waiting entries (`->`) are skipped.
3. Only lock types that can conflict count: `FLOCK` for `flock`, `POSIX` or `OFDLCK` for `fcntl`. For `flock` the requested operation (args[1]) is honoured: a `LOCK_SH` request is not blocked by a `READ` holder, and `LOCK_UN` never is.
4. Stores `holder_pid`, `lock_type`, `access`, `advisory` and `path` in `diag->lock_conflict`.

Device plus inode identifies a file regardless of how it was opened (hard links, bind mounts, different paths), which is why they are compared instead of paths.

The output names the holder: `PID n (comm)`, or "an open file description" for OFD locks, which have no owning PID. The first matching holder is reported; `fcntl` byte ranges are not compared. Verified with a `flock -x` holder and a blocked `flock -x` waiter (the waiter was in S-state, not D-state, but takes the same code path).

### User stack unwinding

Two methods run in sequence. libunwind runs first. If it fails or returns fewer than three frames, the heuristic scanner runs as well and the result with more frames is kept (libunwind wins a tie). The "User Stack Trace" header names the method that produced the frames and where the stack pointer came from, for example `(libunwind, from ptrace RSP)`.

**libunwind (`src/unwind_reader.c`)**

Uses DWARF CFI data from the binaries on disk to walk frames, the same method GDB uses. Process memory is read from `/proc/[pid]/mem` without attaching.

Starting state for D-state: only RSP and RIP from `/proc/[pid]/syscall`. Starting state for S/T-state: all 27 registers from ptrace. The full set matters because CFI rules often describe frame recovery in terms of callee-saved registers (RBP, RBX, R12 to R15).

With a ptrace snapshot it unwinds the whole stack (10 frames for a small test program blocked in `pause()`). With only RSP and RIP (the D-state case) frame recovery that depends on RBP stops early; in a `-O0` test it returned 4 of 10 frames. The D-state case itself could not be exercised here because it needs root and FUSE; the RSP/RIP-only start was simulated on a sleeping process.

**Heuristic scanner (`src/proc_reader.c`)**

Reads 2048 bytes from the stack pointer via `/proc/[pid]/mem` and scans every 8-byte word. A word that falls inside an executable VMA is a candidate return address. Each candidate is accepted only if the bytes immediately before it look like a `call` instruction:

| Bytes before return address | Instruction | Example |
|---|---|---|
| `E8 xx xx xx xx` (5 bytes) | `call rel32` | Direct call |
| `FF /2` (2 bytes) | `call r/m64` | `call rax` |
| `FF /2 xx` (3 bytes) | `call [reg+disp8]` | `call [rbp-8]` |
| `REX FF /2` (3 bytes) | `call r/m64` with REX | `call r8` |
| `FF 15 xx xx xx xx` (6 bytes) | `call [rip+rel32]` | PLT and GOT calls |
| `REX FF 15 xx xx xx xx` (7 bytes) | `call [rip+rel32]` with REX | |
| `FF /2 disp32` (6 bytes, mod=10) | `call [reg+disp32]` | `call [rbx+offset]` |
| `REX FF /2 disp32` (7 bytes, mod=10) | `call [reg+disp32]` with REX | `call [r12+offset]` |

The `FF 15` form matters most: it covers calls through the GOT, which is how position-independent code reaches most library functions.

Each form is accepted only when the ModRM byte (and SIB byte, if any) gives exactly the instruction length that ends at the candidate address; SIB forms such as `call [rsp]` are covered the same way. The scanner is a heuristic: it can still report stale return addresses left on the stack by earlier calls.

### Symbol resolution

For each frame inside a file-backed mapping, the tool computes the file offset `(address - vma_start) + file_offset`, converts it to an ELF virtual address using the binary's program headers (the `PT_LOAD` segment containing the offset: `offset - p_offset + p_vaddr`), and runs `/usr/bin/addr2line -f -e <binary>` on that. If the file is not a readable ELF64 the raw offset is used. This resolves both PIE and non-PIE (`-no-pie`) executables; both were checked with a `-g` test program. Function names and source lines need debug information (`-g`); without it `addr2line` prints `??`. Very long function names are cut at 255 characters without corrupting the source line.

The `(+0x...)` value printed next to each frame is `address - vma_start`; it is omitted when no mapping was found for the address.

### ELF core file (`-o FILE`)

Writes an ELF core from the live process using a two-pass design:

- **Pass 1 (`compute_layout`)**: skips VMAs without the `r` permission, probes the rest with a one-byte `pread`, reads `/proc/[pid]/auxv`, and computes every file offset before any writing begins. The first `PT_LOAD` data starts on a page boundary, so every segment's file offset is congruent with its virtual address modulo `0x1000`.
- **Size cap**: if the computed file would exceed `MAX_CORE_SIZE` (4 GiB), the tool prints the size and the limit on stderr and writes nothing.
- **Pass 2**: writes the whole file in one sequential forward pass with no seeking, looping over short writes and retrying `EINTR`. Memory that becomes unreadable during the write is zero-filled one page at a time, so readable pages around it are kept.
- **Output file**: the core is written to a temporary file next to the output path (`<FILE>.XXXXXX`, mode 0600, created with `mkstemp`) and `rename()`d onto the output path on success. A symlink at the output path is replaced, not followed, and an existing regular file there is replaced on success. An existing device node, FIFO, socket or directory at the output path is refused. On any failure (including `close` and `rename`) only the temporary file is removed, nothing is left behind and an existing file at the output path is not modified; the error message includes `strerror(errno)`. Paths too long for the temporary name are rejected.
- **Failure**: `SIGXFSZ` is ignored while writing (the previous disposition is restored afterwards) so that hitting `ulimit -f` is such a failure rather than a kill; checked with `ulimit -f 100`.

**Core layout:**

```
ELF Header (ET_CORE, EM_X86_64)
Program headers:
  PT_NOTE        the note blob
  PT_LOAD        one per readable VMA
Note blob:
  NT_PRSTATUS    pid, ppid, registers
                 (full 27-register ptrace snapshot for S/T-state;
                  RIP, RSP and syscall arguments for D-state)
  NT_PRPSINFO    comm, cmdline
  NT_AUXV        copy of /proc/[pid]/auxv (omitted if unreadable)
  NT_FILE        maps each file-backed VMA to its file and page offset
PT_LOAD data     raw memory from /proc/[pid]/mem
```

In the D-state register set the fourth syscall argument goes into **R10**, not RCX, because the `syscall` instruction overwrites RCX. The set also fills `cs=0x33`, `ss=0x2b`, `rcx=rip` and `rax=-ENOSYS` (the last two only when the task is inside a syscall); everything else is zero.

**Loading in GDB:**

```bash
gdb /path/to/binary output.core
(gdb) bt
(gdb) info registers
(gdb) x/40gx $rsp
```

With the `NT_AUXV` note GDB relocates a PIE executable and finds the shared library list. Checked on a core of a sleeping `sleep` process: `gdb -batch -ex bt /usr/bin/sleep output.core` printed a symbolised backtrace down to `main`, with libc and the dynamic loader loaded, for both the ptrace register set and the RSP/RIP-only set.

---

## Sample Output

Illustrative and abbreviated (the real output also lists every memory region). Addresses and offsets will differ on your system.

```
=== D-State Processes Found: 1 ===
PID      COMMAND              STATE    WAITING IN
---      -------              -----    ----------
1234     cat                  D        folio_wait_bit_common

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
   folio_wait_bit_common

System Call Information:
   Syscall:   read (nr = 0)
   Args:      0x3, 0x7f56a65c5000, 0x40000
   IP:        0x7f56a66f2687
   SP:        0x7ffe6acee8f0

Blocking File Descriptor:
   FD:        3
   Path:      /tmp/fuse_mount/trap.txt

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

User Stack Trace (libunwind, from syscall SP):
   [0]  0x7f56a66f2687  /usr/lib/x86_64-linux-gnu/libc.so.6
         function: __GI___read
         source: ../sysdeps/unix/sysv/linux/read.c:26  (+0x22687)
   [1]  0x55a1b2c00a32  /usr/bin/cat
         function: main
         source: cat.c:140  (+0xa32)
```

Reading top to bottom: `cat` is in D-state inside a `read` syscall on fd 3, which resolves to `/tmp/fuse_mount/trap.txt`. The kernel stack shows the path through the VFS layer down to `folio_wait_bit_common`: the process is waiting for a page that the FUSE daemon never delivers. The user stack shows it entered the kernel through `read` in libc, called from `main`.

---

## Testing

### Unit tests

Cover `syscall_name`, `build_proc_path`, `is_pid_dir`, the `bufsize 0` guards of the `/proc` helpers, the pure line parsers (`parse_stat_line` including comm with spaces and parentheses, `parse_syscall_line` including the `-1 SP PC` form, `parse_lock_line` including decimal inodes, OFD and waiting entries), `file_offset_to_vaddr`, `fprint_safe`, and `read_process_maps` on the test process itself. No root required.

```bash
make unit-test
```

### Integration tests

These use `trap_fs`, a FUSE filesystem that accepts reads but never answers them. Any process reading `trap.txt` from it enters D-state.

**Manual setup:**

```bash
# Terminal 1: start the blocking FUSE daemon in the foreground
mkdir -p /tmp/fuse_mount
./trap_fs /tmp/fuse_mount -s -f

# Terminal 2: fork a child into D-state
./monitor

# Terminal 3: run the tool
sudo ./dstate
```

**Automated:**

```bash
make test           # trap a process, run the scanner (requires sudo)
make test-pid       # same, diagnose by PID with the -p flag (requires sudo)
make test-monitor   # D-state and SIGTERM demonstration
```

Notes:

- `make test` and `make test-monitor` must not run at the same time. `trap_fs` runs single-threaded (`-s`): while it holds the first blocked read it cannot serve new requests.
- The test recipes run `trap_fs` with `-f` (foreground), so its `[Daemon]` messages appear in the output. They always run the cleanup step, even when `sudo ./dstate` fails, and fail with a clear message if the trapped process did not start.
- `make kill` runs `pkill -9 -x trap_fs`, which matches the exact process name only.
- The FUSE-based recipes were not run while preparing this README (they need sudo and a FUSE mount), so the D-state paths themselves are untested here.
- `monitor` sends SIGTERM, and if the child is still in D-state it then sends SIGKILL and says so if the child could not be reaped.

---

## API Reference

Most functions return `0` on success and `-1` on error, with output through pointer parameters. Exceptions:

- `read_full_diagnostics()` also returns `DSTATE_PROC_GONE` (`1`) if the process does not exist or exited before the read.
- `read_proc_file()`, `read_proc_line()` and `read_proc_link()` return the number of bytes read, or `-1`.
- `build_proc_path()` returns the buffer, or `NULL` if the path does not fit.
- `is_pid_dir()` returns `1` or `0`.

See `include/dstate.h` for struct definitions and size constants (`MAX_COMM_LEN`, `MAX_PATH_LEN`, `MAX_WCHAN_LEN`, `MAX_STACK_LEN`, `MAPS_INITIAL_CAPACITY`, `MAX_USER_FRAMES`, `MAX_AUXV_LEN`, `MAX_CORE_SIZE`).

### Detection

```c
int is_pid_dir(const char *name);
int find_dstate_processes(dstate_process_t **results, int *count);
void free_dstate_list(dstate_process_t *list);
void print_dstate_summary(const dstate_process_t *procs, int count);
```

`find_dstate_processes` allocates the result array. Always free it with `free_dstate_list`.

### Diagnostics

```c
int read_full_diagnostics(pid_t pid, process_diagnostics_t *diag);
int read_process_stat(pid_t pid, dstate_process_t *proc);
int read_process_syscall(pid_t pid, dstate_process_t *proc);
int read_process_wchan(pid_t pid, char *wchan, size_t len);
int read_process_stack(pid_t pid, char *stack, size_t len);
int read_process_maps(pid_t pid, process_maps_t *maps);
void free_process_maps(process_maps_t *maps);
void free_diagnostics(process_diagnostics_t *diag);
int parse_stat_line(const char *line, dstate_process_t *proc);
int parse_syscall_line(const char *line, dstate_process_t *proc);
int parse_lock_line(const char *line, lock_entry_t *out);
uint64_t file_offset_to_vaddr(const char *binary_path, uint64_t offset);
const char *syscall_name(long nr, char *buf, size_t buflen);
void print_diagnostics(const process_diagnostics_t *diag);
```

`syscall_name` returns a name from the built-in x86-64 table, or formats `syscall_<nr>` into `buf` for numbers the table does not contain. The table is partial.

`read_process_maps` allocates `maps->entries`, which must start zero-initialised. `read_full_diagnostics` zeroes the whole struct first, so a failed read is safe to free. Always call `free_diagnostics` (or `free_process_maps`) on every diagnostics struct, including after a failed read. The three `parse_*` functions are pure (they take a string) and are what the readers call. `file_offset_to_vaddr` returns the offset unchanged if the file is not a readable ELF64.

### Registers (ptrace)

```c
int read_registers_ptrace(pid_t pid, elf_gregset_t *regs_out);
```

Seizes the target with `PTRACE_SEIZE` and `PTRACE_INTERRUPT`, polls `waitpid(__WALL | WNOHANG)` for up to about 500 ms, reads 27 registers with `PTRACE_GETREGS` into `regs_out` (indexed by `elfreg_index_t`, `ELFREG_*`), and detaches, passing back the signal the target was stopped on if it stopped at a signal delivery. Returns `-1` if the seize, interrupt, wait (timeout) or `PTRACE_GETREGS` fails; `regs_out` is only written once `PTRACE_GETREGS` succeeded. After that it returns `0` even if the final detach fails (for example the target died). On timeout it attempts `PTRACE_DETACH`; if the target never stopped this fails with `ESRCH` and the target stays seized until the tool exits. Checked on a sleeping process (state `S`, `TracerPid` 0 afterwards), on a `SIGSTOP`ped one (still `T` afterwards) and on a target receiving 400 `SIGUSR1` signals while being diagnosed repeatedly (all 400 handler runs counted).

### User stack unwinding

```c
int read_user_stack_libunwind(pid_t pid, process_diagnostics_t *diag);
int read_user_stack(pid_t pid, process_diagnostics_t *diag);
void resolve_symbol(const char *binary_path, uint64_t offset,
                    char *func_out, size_t func_len,
                    char *src_out, size_t src_len);
```

On failure `diag->user_stack.reason` holds one of:

| Failure code | Value | Meaning |
|---|---|---|
| `USER_STACK_ERR_PERM` | 1 | Permission denied on `/proc/[pid]/mem`. Needs root or `CAP_SYS_PTRACE`. |
| `USER_STACK_ERR_UNAVAIL` | 2 | Memory unreadable or process vanished. |
| `USER_STACK_ERR_NO_SP` | 3 | Stack pointer is zero: no syscall data and no ptrace snapshot. |

### Lock conflict

```c
int read_lock_conflict(pid_t pid, process_diagnostics_t *diag);
```

Only acts on `fcntl` (nr 72) and `flock` (nr 73). Sets `diag->lock_conflict.found = 1` on a match.

### ELF core file

```c
int write_core_file(pid_t pid, process_diagnostics_t *diag, const char *outpath);
```

Requires `read_full_diagnostics` to have been called first. D-state cores contain RIP, RSP, the syscall arguments and a few fixed registers (see above). S/T-state cores contain the full 27-register snapshot. Returns `-1` without leaving a file behind if the layout exceeds `MAX_CORE_SIZE` or any write fails.

### Low-level /proc helpers (`include/proc_utils.h`)

`read_proc_file`, `read_proc_line`, `read_proc_link`, `build_proc_path`. All take a caller-supplied buffer and its size, truncate silently if the content does not fit, and return `-1` for a buffer size of 0.

```c
void fprint_safe(FILE *out, const char *s, int maxlen, int pad);
```

Prints at most `maxlen` characters (0 means all) with bytes below `0x20` and `0x7f` replaced by `?`, then pads with spaces up to `pad` columns. Used for every string that comes from the target.

---

## Known Issues

What is still wrong or unchecked after the fixes:

| Area | Issue |
|---|---|
| Lock conflict | `fcntl` byte ranges are not compared. A WRITE holder is preferred over a READ holder, otherwise the first match is reported. |
| Memory map | Paths longer than 255 characters are truncated (parsing is not corrupted, but the truncated path cannot be opened). |
| ptrace | If a target never reaches the interrupt stop within the timeout, the detach fails with `ESRCH` because the target is not stopped. It stays seized until the tool exits. |
| libunwind | libunwind opens the mapped image of each frame by name. The tool refuses to call it for a mapping whose path is deleted, missing or not a regular file (so a FIFO swapped in by the target no longer hangs `dstate -p`), but the target can still swap the name in the short window between that `stat()` and libunwind's `open`. Frames in such mappings (for example a library that was upgraded while the process runs) get no DWARF unwinding and show `??`. |
| 32-bit targets | Syscalls are not named, and the blocking-fd and lock lookups are skipped, but the user stack unwinding still assumes x86-64. |
| Not tested | The D-state-only paths (`/proc/[pid]/stack`, FUSE-based `make test`, `make test-pid`, `make test-monitor`) need root and a FUSE mount and were not run. |

---

## Known Limitations

Design limits, as opposed to defects.

| Limitation | Detail |
|---|---|
| x86-64 only | The syscall table, register layout and call-instruction decoding are x86-64 specific. |
| TOCTOU races | Processes can exit between detection and the diagnostic read. This is reported through `DSTATE_PROC_GONE`. |
| Privileges required | `/proc/[pid]/stack`, `/proc/[pid]/mem`, and ptrace need root or `CAP_SYS_PTRACE`. |
| Symbol resolution needs debug info | `addr2line` prints `??` and `??:0` for stripped binaries. |
| D-state unwinding is best-effort | Only RSP and RIP are available from `/proc/[pid]/syscall`. The heuristic scanner can include false positives. |
| Main thread only | `/proc/[pid]/syscall` describes the thread whose ID is given. Other threads of a multi-threaded program are not examined, and the core has a single `NT_PRSTATUS` note. |
| Advisory locks only | `flock` and `fcntl` locks appear in `/proc/locks`. Futex-based locks (pthread mutexes, `std::mutex`, Go `sync`) do not, so their holders cannot be identified. |
| S/T-state targets are ptrace-attached | Diagnosing a sleeping or stopped process briefly stops it. |

---

## License

This project is licensed under the [MIT LICENSE](LICENSE).
