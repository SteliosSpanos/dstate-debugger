# dstate-debugger

## Overview

A Linux debugging tool that detects and diagnoses processes stuck in D-state (uninterruptible sleep). It scans `/proc` to find blocked processes, reads their kernel stack traces, identifies what syscall they are waiting in, and reports the exact file path they are blocked on. It also unwinds the user-space call stack by reading raw process memory.

Written in C99 for x86-64 Linux. No runtime dependencies beyond glibc.

---

## Why does D-state matter?

When a Linux process enters D-state, the kernel has suspended it inside a system call. The process is waiting for something (usually I/O) and it cannot respond to signals until that wait completes. Not even `SIGKILL` works.

This creates a diagnostic problem. Traditional debuggers like `gdb` attach to processes using `ptrace`. `ptrace` requires delivering `SIGSTOP` to the target process first. A D-state process cannot receive signals. So `ptrace` fails entirely.

This tool works around that limitation. It reads everything it needs from `/proc`, which is a virtual filesystem the kernel maintains for exactly this purpose. No signals, no ptrace, no process cooperation required.

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
│   └── proc_reader.c      Per-PID diagnostics, x86-64 syscall table
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

---

## Dependencies

- **Build and runtime**: glibc only. Nothing else.
- **Testing only**: `libfuse-dev` is required to build the FUSE test filesystem.

```bash
sudo apt-get install libfuse-dev
```

---

## Build

```bash
make            # builds dstate (main tool)
make unit-test  # builds and runs unit tests
make monitor    # builds test monitor
make trap_fs    # builds FUSE test filesystem (requires libfuse-dev)
make test       # full test: trap_fs + monitor + dstate (requires sudo)
make test-pid   # test the -p flag: trap a process, diagnose by PID
make kill       # kill trap_fs and unmount FUSE
make clean      # remove binaries and unmount FUSE
make help       # show all targets and usage
```

---

## Usage

```bash
sudo ./dstate            # scan all processes for D-state
sudo ./dstate -p PID     # diagnose a specific process
./dstate -h              # show help
```

Root or `CAP_SYS_PTRACE` is required for two things: reading `/proc/[pid]/stack` (kernel stack trace) and reading `/proc/[pid]/mem` (user stack unwinding). All other diagnostics, syscall identification, fd resolution, wchan, memory map, basic stat, work without elevated privileges.

---

## How It Works

Here is what happens at each step, and why each step is necessary.

### Step 1: Detection

The tool opens `/proc` and iterates every directory whose name is a number. Each one is a running process. It reads `/proc/[pid]/stat` and checks the state field (the third field, after PID and command name). A value of `D` means the process is in uninterruptible sleep.

### Step 2: Syscall identification

The tool reads `/proc/[pid]/syscall`. This file contains the current syscall number, six argument registers, the stack pointer, and the instruction pointer, all in one line.

The syscall number is mapped to a name using a static table specific to x86-64 (for example, nr=0 is `read`, nr=1 is `write`). If the number is not in the table, the tool falls back to `syscall_N` as a placeholder.

This tells you exactly what the kernel was doing when the process froze.

### Step 3: Blocking file descriptor resolution

Some syscalls operate on a file descriptor: `read`, `write`, `ioctl`, `pread64`, `pwrite64`, `readv`, `writev`, `connect`, `accept`, `accept4`, `sendto`, `recvfrom`. For these, the first argument (args[0]) is the fd number.

The tool resolves that fd by reading the symbolic link `/proc/[pid]/fd/N`. This symbolic link points to the actual file, socket, or device the process has open. This is how the tool can tell you "blocked on `/tmp/fuse_mount/trap.txt`" instead of just "fd 3".

### Step 4: Kernel stack trace

The tool reads `/proc/[pid]/stack`. This file contains the live kernel call stack for the process: the exact chain of kernel functions that led to the current wait. It is the most direct answer to "what is the kernel doing right now?"

Reading this file requires root or `CAP_SYS_PTRACE`. Without privileges, the tool prints a message explaining why this section is unavailable.

### Step 5: Wait channel

The tool reads `/proc/[pid]/wchan`. This is a single string: the name of the kernel function where the process is currently sleeping. It is a one-line summary of the kernel stack.

For example, `request_wait_answer` identifies FUSE request waiting. `nfs_wait_bit_killable` identifies NFS I/O waiting.

### Step 6: Memory map parsing

The tool reads `/proc/[pid]/maps`. This file lists every virtual memory region the process has: start address, end address, permissions (`rwxp`), and the backing file (or anonymous if there is none).

The tool parses this into a table of `map_entry_t` structs. This table is used in the next step to identify which memory addresses belong to executable code.

### Step 7: User stack unwinding

The tool opens `/proc/[pid]/mem` and reads 2048 bytes starting from the stack pointer captured in step 2. It then scans every 8-byte word in that buffer. If a word's value falls inside an executable region from the maps table (a region with `x` in its permissions), it is treated as a candidate return address.

This is a heuristic. The stack is a contiguous region of memory, and return addresses are pushed onto it by the CPU's `call` instruction. Scanning for values that land in executable regions is a reasonable approximation of stack unwinding, but it is not perfect. It can include false positives (values that happen to look like code pointers) and miss frames stored in registers.

### Step 8: Symbol resolution

For each candidate return address that points to a mapped binary file (a path starting with `/`), the tool calls `addr2line` to translate the file offset to a function name and source file:line.

This requires the binary to have been compiled with debug information (`-g`). Without it, `addr2line` returns `??` and `??:0`, which the tool displays as is. Paths containing single quotes are skipped to avoid shell injection in the `popen` call.

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

User Stack Trace:
   [0]  0x7f56a66f2687  /usr/lib/x86_64-linux-gnu/libc.so.6
         function: __GI___read
         source: ../sysdeps/unix/sysv/linux/read.c:26  (+0x22687)
   [1]  0x55a1b2c00a32  /usr/bin/cat
         function: main
         source: cat.c:140  (+0xa32)
```

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
make test       # runs trap_fs + monitor + dstate together (requires sudo)
make test-pid   # same, but uses -p to diagnose by a specific PID
```

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

### Memory Maps and User Stack

```c
int read_process_maps(pid_t pid, process_maps_t *maps);
const char *maps_find_region(const process_maps_t *maps, uint64_t addr);
int read_user_stack(pid_t pid, process_diagnostics_t *diag);
void resolve_symbol(const char *binary_path, uint64_t offset,
                    char *func_out, size_t func_len,
                    char *src_out, size_t src_len);
```

On failure, `diag->user_stack.reason` is set to one of:

| Constant                 | Value | Meaning                                                                                                           |
| ------------------------ | ----- | ----------------------------------------------------------------------------------------------------------------- |
| `USER_STACK_ERR_PERM`    | 1     | Permission denied opening `/proc/[pid]/mem`. Run as root or with `CAP_SYS_PTRACE`.                                |
| `USER_STACK_ERR_UNAVAIL` | 2     | Memory unreadable or the process vanished between steps.                                                          |
| `USER_STACK_ERR_NO_SP`   | 3     | Stack pointer is zero. The process was not in a syscall when sampled, so there is no starting point for the scan. |

---

## Known Limitations

**x86-64 only.** The syscall number table in `proc_reader.c` is specific to x86-64. On ARM64 or RISC-V, syscall numbers are different. The tool compiles on other architectures but syscall names will be wrong.

**TOCTOU races.** Between the detection scan and the diagnostic read, a process can exit. This is unavoidable with `/proc`. The tool handles it gracefully: `read_full_diagnostics` returns `DSTATE_PROC_GONE` and the process is skipped.

**Privileges required for kernel stack and user stack.** Reading `/proc/[pid]/stack` and `/proc/[pid]/mem` both require root or `CAP_SYS_PTRACE`. The kernel enforces this. All other diagnostics are available without elevated privileges.

**Symbol resolution requires debug info.** `resolve_symbol` calls `addr2line` for each frame. Function names and source lines only appear for binaries compiled with `-g`. Without debug information, every frame shows as `??` / `??:0`. Paths containing a single quote character are skipped entirely to avoid shell injection.

**User stack is a heuristic.** Scanning raw stack memory for values that fall in executable regions is an approximation, not proper stack unwinding. It can include false positives (arbitrary values that happen to point into code) and miss frames that the compiler stored in registers rather than on the stack.

**ptrace cannot attach to D-state processes.** This is why the tool reads `/proc` instead of using a debugger-style approach. `SIGSTOP` cannot be delivered to a process in uninterruptible sleep, so `ptrace(PTRACE_ATTACH, ...)` blocks indefinitely.

---

## License

This project is licensed under the [MIT LICENSE](LICENSE).
