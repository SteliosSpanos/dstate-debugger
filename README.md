# dstate-debugger

## Overview

A Linux debugging tool that detects and diagnoses processes stuck in D-state (uninterruptible sleep). It scans `/proc` to find blocked processes, reads their kernel stack traces, identifies what syscall they are waiting in, and reports the exact file path they are blocked on. For S-state and T-state processes it supplements `/proc` with live CPU register reads via ptrace. It detects file lock conflicts, identifying which other process holds the lock blocking the target. It unwinds the user-space call stack using libunwind with a heuristic fallback. It can also produce a synthetic ELF core file that GDB can load directly.

Written in C99 for x86-64 Linux. Runtime dependencies: glibc and libunwind.

---

## Why does D-state matter?

When a Linux process enters D-state, the kernel has suspended it inside a system call. The process is waiting for something (usually I/O) and it cannot respond to signals until that wait completes. Not even `SIGKILL` works.

This creates a diagnostic problem. Traditional debuggers like `gdb` attach to processes using `ptrace`. `ptrace` requires delivering `SIGSTOP` to the target process first. A D-state process cannot receive signals. So `ptrace` fails entirely.

This tool works around that limitation. It reads everything it needs from `/proc`, which is a virtual filesystem the kernel maintains for exactly this purpose. No signals, no ptrace, no process cooperation required.

For S-state (interruptible sleep) and T-state (stopped) processes, the situation is different. Those processes can receive signals, so ptrace works. The tool takes advantage of this: when a process is in S or T-state, it supplements the `/proc` reads with a live ptrace register snapshot. This is useful because `/proc/[pid]/syscall` only captures registers when the process is actually inside a syscall. If it is not, that file returns "running" or "-1" and there is no stack pointer to start unwinding from. The ptrace snapshot fills that gap.

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

## Architecture

The tool is built in three layers. Each layer depends only on the one below it.

**Layer 1: `src/proc_utils.c`**

All raw `/proc` file I/O lives here: opening files, reading their contents, following symlinks, and constructing paths like `/proc/1234/stat`. Every other module goes through this layer. Nothing else opens `/proc` files directly.

**Layer 2: `src/detector.c`**

Scans `/proc` to find processes in D-state. Opens the `/proc` directory, iterates every numeric entry (each one is a PID), reads its `stat` file, and checks the state field. Returns a dynamically-allocated array that doubles its capacity whenever it fills. Entry point: `find_dstate_processes()`.

**Layer 3: `src/proc_reader.c`**

Reads deep diagnostics for a single PID: stat, wchan, syscall, kernel stack, maps, and process memory. Contains the x86-64 syscall-number-to-name table. Entry point: `read_full_diagnostics()`.

Headers in `include/dstate.h` define all shared data structures and function declarations. `include/proc_utils.h` exposes the utility interface.

**Complementary: `src/ptrace_reader.c`**

Not a fourth layer in the `/proc` pipeline. A separate observation method that applies only when the process state allows it. The three-layer `/proc` pipeline handles everything for D-state processes. For S/T-state processes, `ptrace_reader.c` adds a full 27-register snapshot that `/proc` cannot provide when the process is not currently inside a syscall. The rest of the pipeline (maps, user stack unwinding, core file) consumes those registers the same way it would consume values read from `/proc/[pid]/syscall`.

**Complementary: `src/unwind_reader.c`**

Performs user-space stack unwinding using libunwind. Works on D-state processes by reading memory directly from `/proc/[pid]/mem` instead of using ptrace. When full registers are available (S/T-state), libunwind can walk every frame accurately using DWARF CFI data from the binaries. For D-state, only RSP and RIP are available from `/proc/[pid]/syscall`, so unwinding may stop early when DWARF rules require a callee-saved register that was never captured.

**Complementary: `src/core_writer.c`**

Builds a synthetic ELF core file from a live process. The core can be loaded into GDB with the original binary for post-mortem inspection even though the process is still running. Uses a two-pass design: the first pass probes every VMA and computes all file offsets before writing begins; the second pass writes the entire file in one sequential forward pass.

---

## Dependencies

- **Build and runtime**: glibc and libunwind.
- **Testing only**: `libfuse-dev` is required to build the FUSE test filesystem.

```bash
sudo apt-get install libunwind-dev libfuse-dev
```

---

## Build

```bash
make            # builds dstate (main tool)
make unit-test  # builds and runs unit tests
make monitor    # builds test monitor
make trap_fs    # builds FUSE test filesystem (requires libfuse-dev)
make test           # scan test: trap a process, run dstate scanner (requires sudo)
make test-monitor   # demonstrates D-state and SIGTERM immunity using monitor
make test-pid   # test the -p flag: trap a process, diagnose by PID
make kill       # kill trap_fs and unmount FUSE
make clean      # remove binaries and unmount FUSE
make help       # show all targets and usage
```

---

## Usage

```bash
sudo ./dstate                  # scan all processes for D-state
sudo ./dstate -p PID           # diagnose a specific process
sudo ./dstate -p PID -o FILE   # diagnose and write an ELF core file
./dstate -h                    # show help
```

Root or `CAP_SYS_PTRACE` is required for three things: reading `/proc/[pid]/stack` (kernel stack trace), reading `/proc/[pid]/mem` (user stack unwinding and core generation), and attaching via ptrace to read registers on S/T-state processes. All other diagnostics (syscall identification, fd resolution, wchan, memory map, basic stat) work without elevated privileges.

### Loading a core file in GDB

```bash
gdb /path/to/original/binary output.core
(gdb) bt
(gdb) x/40gx $rsp
```

GDB uses the NT_FILE note inside the core to find shared library locations on disk, so backtraces into libc and other libraries resolve correctly even in stripped builds.

---

## How It Works

Here is what happens at each step, and why each step is necessary.

### Step 1: Detection

The tool opens `/proc` and iterates every directory whose name is a number. Each one is a running process. It reads `/proc/[pid]/stat` and checks the state field (the third field, after PID and command name). A value of `D` means the process is in uninterruptible sleep.

### Step 2: Syscall identification

The tool reads `/proc/[pid]/syscall`. This file contains the current syscall number, six argument registers, the stack pointer, and the instruction pointer, all in one line.

The syscall number is mapped to a name using a static table specific to x86-64 (for example, nr=0 is `read`, nr=1 is `write`, nr=72 is `fcntl`, nr=73 is `flock`). If the number is not in the table, the tool falls back to `syscall_N` as a placeholder.

This tells you exactly what the kernel was doing when the process froze.

### Step 3: Register reading via ptrace (S/T-state only)

For a D-state process, this step is skipped entirely. The kernel will not deliver `SIGSTOP` to a process in uninterruptible sleep, so `ptrace(PTRACE_ATTACH)` would block the tool itself indefinitely waiting for a stop that never arrives. There is no safe way to ptrace a D-state process.

For S-state and T-state processes, ptrace is safe. The tool attaches, waits for the process to stop, reads all 27 CPU registers using `PTRACE_GETREGS`, and immediately detaches. The full register set is stored in `diag->ptrace_regs` as an `elf_gregset_t` array, indexed by the `elfreg_index_t` enum defined in `dstate.h` (`ELFREG_RIP`, `ELFREG_RSP`, `ELFREG_RBP`, etc.). The `ptrace_valid` flag records whether this step succeeded.

Having the full register set rather than just RSP and RIP makes a significant difference for stack unwinding. DWARF CFI rules in compiled binaries frequently describe frame recovery in terms of callee-saved registers (RBP, RBX, R12–R15). With the full snapshot, libunwind can follow those rules precisely for every frame.

### Step 4: Blocking file descriptor resolution

Some syscalls operate on a file descriptor: `read`, `write`, `ioctl`, `pread64`, `pwrite64`, `readv`, `writev`, `connect`, `accept`, `accept4`, `sendto`, `recvfrom`, `fcntl`, `flock`. For these, the first argument (args[0]) is the fd number. This check is performed only for D-state processes. S-state processes may be in the middle of any I/O operation without being genuinely stuck, so reporting a blocking FD for them would be misleading.

The tool resolves that fd by reading the symbolic link `/proc/[pid]/fd/N`. This symbolic link points to the actual file, socket, or device the process has open. This is how the tool can tell you "blocked on `/tmp/fuse_mount/trap.txt`" instead of just "fd 3".

### Step 5: Kernel stack trace

The tool reads `/proc/[pid]/stack`. This file contains the live kernel call stack for the process: the exact chain of kernel functions that led to the current wait. It is the most direct answer to "what is the kernel doing right now?"

Reading this file requires root or `CAP_SYS_PTRACE`. Without privileges, the tool prints a message explaining why this section is unavailable.

### Step 6: Wait channel

The tool reads `/proc/[pid]/wchan`. This is a single string: the name of the kernel function where the process is currently sleeping. It is a one-line summary of the kernel stack.

For example, `request_wait_answer` identifies FUSE request waiting. `nfs_wait_bit_killable` identifies NFS I/O waiting.

### Step 7: Memory map parsing

The tool reads `/proc/[pid]/maps`. This file lists every virtual memory region the process has: start address, end address, permissions (`rwxp`), file offset, and the backing file (or anonymous if there is none).

The tool parses this into a table of `map_entry_t` structs. The file offset field is important: when a binary is partially mapped (which is the normal case, the kernel maps only the needed segments), the offset tells the tool where in the file on disk a given virtual address corresponds to. This is used both for symbol resolution and for the NT_FILE note in the core file.

### Step 8: File lock conflict detection

If the current syscall is `fcntl` (nr=72) or `flock` (nr=73), the process is attempting to acquire a file lock and is blocked because someone else holds it. The tool can identify exactly who.

First it resolves the file descriptor (args[0]) to a path using `/proc/[pid]/fd/N`. Then it calls `stat()` on that path to get the file's device major:minor number and inode number. These three numbers together uniquely identify a file on the system. Two processes can have the same file open under completely different paths (hard links, bind mounts), but the inode and device numbers will always be identical.

The tool then reads `/proc/locks`. This is a kernel-maintained file listing every advisory and mandatory lock currently held anywhere on the system. Each line contains the lock type (FLOCK or POSIX), advisory or mandatory status, access mode (READ or WRITE), the PID of the lock holder, and the device major:minor and inode of the locked file.

The tool scans every line for a matching major:minor:inode triple where the holder PID is different from the waiting process. When a match is found, the holder PID, lock type, access mode, and file path are stored in `diag->lock_conflict`. At print time, the holder's command name is looked up by reading `/proc/[holder_pid]/comm`.

### Step 9: User stack unwinding

User stack unwinding uses two methods in sequence. libunwind runs first. If it fails completely or returns fewer than three frames, the heuristic scanner runs instead.

**libunwind (`src/unwind_reader.c`)**

libunwind reads DWARF CFI (Call Frame Information) data embedded in every compiled binary. DWARF CFI is a precise machine-readable description of how to recover the previous frame from any instruction: which register holds the return address, where callee-saved registers were spilled onto the stack, and so on. This is the same information GDB uses.

The unwinder reads process memory directly from `/proc/[pid]/mem` without attaching to the process. This works for D-state processes. For D-state, the starting point is RSP and RIP from `/proc/[pid]/syscall`. For S/T-state, all 27 registers from ptrace are available as the starting state.

The limitation for D-state is that DWARF rules sometimes say things like "to find the return address, look at what was in RBP when you entered this function". If RBP was never captured (because ptrace failed), libunwind reports the register as unavailable and stops. This is why the fallback exists.

**Heuristic scanner (`src/proc_reader.c`)**

Opens `/proc/[pid]/mem`, reads 2048 bytes from the stack pointer, and scans every 8-byte word. If a word's value falls inside an executable region from the maps table (a region with `x` in its permissions), it is a candidate return address.

Each candidate is validated by checking whether the bytes immediately before it look like a `call` instruction. The tool checks for the following x86-64 call encodings:

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

The `FF 15 rel32` form is particularly important — it is how every PLT stub and most glibc internal calls are encoded in position-independent code. Without it, frames from any dynamically linked function would be silently dropped.

### Step 10: Symbol resolution

For each frame that points into a mapped binary file (a path starting with `/`), the tool calls `addr2line` to translate the file-relative offset to a function name and source file:line.

The offset passed to `addr2line` is `(virtual_address - vma_start) + file_offset`, where `file_offset` comes from the maps table. This correctly handles the case where only part of a binary is mapped.

Symbol resolution requires the binary to have been compiled with debug information (`-g`). Without it, `addr2line` returns `??` and `??:0`.

### Step 11: ELF core file (optional, `-o FILE`)

When the `-o` flag is given, the tool writes a synthetic ELF core file to the specified path. The file can be loaded into GDB for interactive inspection.

**Layout of the generated core:**

```
ELF Header (ET_CORE, EM_X86_64)
Program Headers:
  PT_NOTE  — one entry pointing at the note blob
  PT_LOAD  — one entry per readable VMA from /proc/[pid]/maps
Note blob:
  NT_PRSTATUS  — pid, ppid, and registers
                 (full 27-register ptrace snapshot for S/T-state;
                  RIP + RSP + syscall args from /proc/[pid]/syscall for D-state)
  NT_PRPSINFO  — comm, cmdline
  NT_FILE      — maps each virtual address range to its backing file and page offset
PT_LOAD data   — raw memory dumps read from /proc/[pid]/mem
```

The NT_FILE note is what allows GDB to locate shared library debug information on disk. Without it, GDB would not know which `.so` file backs each anonymous-looking memory region, and backtraces into libc or other libraries would show as `??`.

The core is generated using a two-pass design. The first pass (`compute_layout`) probes every VMA with a one-byte `pread` to determine which are actually readable, and computes the exact file offset of every section before any writing begins. The second pass writes the file in a single sequential forward pass with no seeking. If a VMA becomes unreadable between the two passes (for example because the process exited), that region is written as zeros.

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
   (This is the kernel function where the process is stuck)

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

Memory Regions:
   0x55a1b2c00000-0x55a1b2c01000  /usr/bin/cat
   0x7f56a65c5000-0x7f56a65c6000  (anonymous)
   0x7f56a66d0000-0x7f56a66f3000  /usr/lib/x86_64-linux-gnu/libc.so.6
   0x7ffe6acce000-0x7ffe6acef000  [stack]

User Stack Trace (syscall SP):
   [0]  0x7f56a66f2687  /usr/lib/x86_64-linux-gnu/libc.so.6
         function: __GI___read
         source: ../sysdeps/unix/sysv/linux/read.c:26  (+0x22687)
   [1]  0x55a1b2c00a32  /usr/bin/cat
         function: main
         source: cat.c:140  (+0xa32)
```

The "User Stack Trace" header shows the source of the starting address. When ptrace succeeded (S/T-state), it says `ptrace RSP`. When the tool used the syscall file (D-state), it says `syscall SP`.

Reading this output top to bottom tells a complete story. The process `cat` is in D-state, sleeping in `request_wait_answer` (a FUSE kernel function). It is stuck in a `read` syscall on fd 3, which resolves to `/tmp/fuse_mount/trap.txt`. The kernel stack confirms the path from the FUSE page fault handler through the VFS layer. The user stack shows it entered the kernel via `__GI___read` in libc, called from `main`.

---

## Testing

### Unit Tests

These tests cover pure logic: syscall name lookup, `/proc` path construction, PID directory name validation. No root required, no `/proc` access.

```bash
make unit-test
```

### Integration Tests

The integration test uses `trap_fs`, a FUSE filesystem that accepts reads but never responds to them. Any process that tries to read from it immediately enters D-state.

**Manual setup (three terminals):**

```bash
# Terminal 1: start the FUSE daemon that blocks reads forever
./trap_fs /tmp/fuse_mount

# Terminal 2: fork a child that reads from the mount, watch it enter D-state
./monitor

# Terminal 3: run the tool
sudo ./dstate

# To release: kill the FUSE daemon
# (SIGTERM and SIGKILL have no effect on D-state processes themselves)
```

**Automated:**

```bash
make test           # traps a process, runs dstate scanner — verifies full diagnostics output (requires sudo)
make test-pid       # same, but diagnoses by specific PID using the -p flag (requires sudo)
make test-monitor   # runs monitor standalone — demonstrates that SIGTERM is ignored in D-state
```

Note: `make test` and `make test-monitor` are intentionally separate. Running monitor alongside dstate in the same session causes interference because trap_fs runs single-threaded (-s): the FUSE daemon is busy handling the first blocked read and cannot process the monitor's child request, which causes the monitor's child to behave unpredictably.

---

## API Reference

All functions return `0` on success and `-1` on error. Output is written through pointer parameters. `read_full_diagnostics()` returns `DSTATE_PROC_GONE` (`1`) if the process exited between the initial detection scan and the diagnostic read. This is a normal condition — the caller should skip the process. See `include/dstate.h` for all struct definitions.

### Detection

```c
int find_dstate_processes(dstate_process_t **results, int *count);
void free_dstate_list(dstate_process_t *list);
void print_dstate_summary(const dstate_process_t *procs, int count);
```

`find_dstate_processes` allocates the result array internally and writes the pointer to `*results`. Always free it with `free_dstate_list` when done.

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

Attaches to the process with `PTRACE_ATTACH`, waits for it to stop with `waitpid`, reads the full 27-register set with `PTRACE_GETREGS`, stores them into `regs_out` indexed by `elfreg_index_t`, and immediately detaches. Only called from `read_full_diagnostics()` when the process state is `S` or `T`. Returns `-1` if permission is denied, the process no longer exists, or the process transitioned into D-state between the state check and the attach attempt.

The results are stored in `diag->ptrace_regs`. The `diag->ptrace_valid` flag is set to `1` only on success.

### User Stack Unwinding

```c
int read_user_stack_libunwind(pid_t pid, process_diagnostics_t *diag);
int read_user_stack(pid_t pid, process_diagnostics_t *diag);
void resolve_symbol(const char *binary_path, uint64_t offset,
                    char *func_out, size_t func_len,
                    char *src_out, size_t src_len);
```

`read_full_diagnostics` calls `read_user_stack_libunwind` first. If it returns an error or produces fewer than three frames, `read_user_stack` (the heuristic scanner) runs instead and overwrites the result.

On failure, `diag->user_stack.reason` is set to one of:

| Constant | Value | Meaning |
|---|---|---|
| `USER_STACK_ERR_PERM` | 1 | Permission denied opening `/proc/[pid]/mem`. Run as root or with `CAP_SYS_PTRACE`. |
| `USER_STACK_ERR_UNAVAIL` | 2 | Memory unreadable or the process vanished between steps. |
| `USER_STACK_ERR_NO_SP` | 3 | Stack pointer is zero. The process was not in a syscall when sampled and ptrace also failed, so there is no starting point for unwinding. |

### Lock Conflict Detection

```c
int read_lock_conflict(pid_t pid, process_diagnostics_t *diag);
```

Checks whether the current syscall is `fcntl` (nr=72) or `flock` (nr=73) and if not it returns immediately. If so, it resolves the file descriptor from args[0] via `/proc/[pid]/fd/N`, calls `stat()` to obtain the file's device major:minor and inode, then scans `/proc/locks` line by line looking for an entry with a matching major:minor:inode triple held by a different PID. On finding a conflict, sets `diag->lock_conflict.found = 1` and fills in `holder_pid`, `lock_type`, `access`, and `path`.

### ELF Core File

```c
int write_core_file(pid_t pid, process_diagnostics_t *diag, const char *outpath);
```

Writes a GDB-loadable ELF core file to `outpath`. Requires that `read_full_diagnostics` has already been called for the same PID. For D-state processes the register snapshot in the core contains only RIP, RSP, and the syscall arguments. For S/T-state processes it contains the full 27-register ptrace snapshot.

---

## Known Limitations

**x86-64 only.** The syscall number table in `proc_reader.c` is specific to x86-64. On ARM64 or RISC-V, syscall numbers are different. The tool compiles on other architectures but syscall names will be wrong.

**TOCTOU races.** Between the detection scan and the diagnostic read, a process can exit. This is unavoidable with `/proc`. The tool handles it gracefully: `read_full_diagnostics` returns `DSTATE_PROC_GONE` and the process is skipped.

**Privileges required for kernel stack, user stack, and ptrace.** Reading `/proc/[pid]/stack` and `/proc/[pid]/mem` both require root or `CAP_SYS_PTRACE`. Attaching via ptrace for register reads on S/T-state processes requires the same. The kernel enforces this.

**Symbol resolution requires debug info.** `resolve_symbol` calls `addr2line` for each frame. Function names and source lines only appear for binaries compiled with `-g`. Without debug information, every frame shows as `??` / `??:0`.

**D-state user stack is best-effort.** For D-state processes, only RSP and RIP are available from `/proc/[pid]/syscall`. libunwind may stop early if DWARF CFI rules for a frame require a callee-saved register (RBP, RBX, R12–R15) that was not captured. When this happens, the heuristic scanner takes over and scans raw stack memory for values that look like return addresses. The heuristic can include false positives and miss frames the compiler kept in registers rather than spilling to the stack.

**Only the main thread's stack is read.** `/proc/[pid]/syscall` and `/proc/[pid]/mem` target the process's main thread. For multi-threaded programs, other threads may have their own stacks and their own blocking syscalls. Diagnosing individual threads requires reading `/proc/[pid]/task/[tid]/syscall` per thread, which this tool does not do.

**ptrace cannot attach to D-state processes.** `SIGSTOP` cannot be delivered to a process in uninterruptible sleep, so `ptrace(PTRACE_ATTACH, ...)` blocks indefinitely. This is why the full register snapshot is unavailable for D-state, and why libunwind's DWARF unwinding is limited to RSP and RIP in that case.

**Lock conflict detection covers only advisory file locks.** The `flock` and `fcntl` locking mechanisms appear in `/proc/locks`. Futex-based locks (pthreads mutexes, C++ `std::mutex`, Go sync primitives) operate through a different kernel mechanism and do not appear there. If a process is deadlocked on a mutex rather than a file lock, this tool will not identify the holder.

**ELF core registers are incomplete for D-state.** Because ptrace cannot attach to a D-state process, the NT_PRSTATUS note in the core file contains only the registers available from `/proc/[pid]/syscall`: RIP, RSP, and the six syscall argument registers. GDB can still load and inspect memory, but register-dependent commands like `bt` may produce incomplete results compared to a core from a process that was cleanly stopped.

**libunwind UPT struct ABI dependency.** `src/unwind_reader.c` uses an internal layout assumption: that `struct UPT_info` in libunwind has `pid_t` as its first member. This is not part of libunwind's public API. The code is verified against libunwind 1.x. A future libunwind release that changes this layout would break unwinding silently with no compile-time warning.

---

## License

This project is licensed under the [MIT LICENSE](LICENSE).
