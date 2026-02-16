# dstate-debugger

Linux debugging tool that detects and diagnoses processes stuck in D-state (uninterruptible sleep). Scans `/proc` to identify blocked processes, reads kernel stack traces, maps syscalls to names, and reports which file descriptor they're blocked on.

Written in C99 for x86-64 Linux. No runtime dependencies beyond glibc.

## Why D-state matters

When a Linux process enters D-state (uninterruptible sleep), it cannot be killed (not even by `SIGKILL`). This commonly happens with FUSE filesystems when the userspace daemon deadlocks or hangs. Traditional debuggers like `gdb` rely on `PTRACE`, which also fails on D-state processes. This tool bypasses that limitation by reading directly from `/proc`.

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

## Architecture

Three layers, all reading from `/proc`:

| Layer       | File                | Purpose                                                                                                                          |
| ----------- | ------------------- | -------------------------------------------------------------------------------------------------------------------------------- |
| Utilities   | `src/proc_utils.c`  | Low-level `/proc` I/O: reading files, symlinks, building `/proc/[pid]/...` paths                                                 |
| Detection   | `src/detector.c`    | Scans `/proc` for D-state processes, returns dynamically-allocated arrays                                                        |
| Diagnostics | `src/proc_reader.c` | Per-PID analysis: stat, wchan, syscall, kernel stack traces, blocking fd detection. Contains x86-64 syscall number-to-name table |

Headers: `include/dstate.h` (structs + API), `include/proc_utils.h` (utility interface).

## Dependencies

- **Build/runtime**: None beyond glibc
- **Testing only**: `libfuse-dev` (for the FUSE test filesystem)

```bash
sudo apt-get install libfuse-dev
```

## Build

```bash
make            # builds dstate
make unit-test  # builds and runs unit tests
make monitor    # builds test monitor
make trap_fs    # builds FUSE test filesystem (requires libfuse-dev)
make help       # show all targets and usage
make clean      # removes binaries, unmounts FUSE
```

## Usage

```bash
sudo ./dstate            # scan all processes for D-state
sudo ./dstate -p PID     # diagnose a specific process
./dstate -h              # show help
```

Requires root or `CAP_SYS_PTRACE` to read `/proc/[pid]/stack`. Without privileges, all other diagnostics still work but kernel stack traces will be unavailable.

### Sample output

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

## Testing

### Unit tests

Tests for pure logic functions that don't require `/proc` or root privileges: syscall name lookup, `/proc` path construction, PID directory validation.

```bash
make unit-test    # builds and runs unit tests
```

### Integration tests

Manual testing uses a FUSE filesystem (`trap_fs`) that blocks reads forever, putting any process that touches it into D-state.

```bash
# Terminal 1: start FUSE daemon that blocks reads forever
./trap_fs /tmp/fuse_mount

# Terminal 2: fork a child that reads from FUSE mount, monitor state
./monitor

# Terminal 3: run dstate as root
sudo ./dstate

# Kill FUSE daemon to release blocked processes
# (SIGTERM/SIGKILL on D-state processes has no effect)
```

Or run everything at once:

```bash
make test       # full test: trap_fs + monitor + dstate (requires sudo)
make test-pid   # test the -p flag: trap a process, diagnose by PID
```

## How it works

1. **Detection**: Iterates `/proc/[pid]/stat` for every process, checking for state `D`
2. **Syscall identification**: Reads `/proc/[pid]/syscall` to get the active syscall number and arguments, maps it to a name via an x86-64 lookup table
3. **Blocking fd resolution**: For fd-based syscalls (read, write, ioctl, etc.), extracts the first argument as a file descriptor and resolves it through `/proc/[pid]/fd/N`
4. **Kernel stack**: Reads `/proc/[pid]/stack` to show the exact kernel code path where the process is stuck
5. **Wait channel**: Reads `/proc/[pid]/wchan` to identify the kernel function the process is sleeping in
6. **Memory map parsing**: Reads `/proc/[pid]/maps` to build a table of virtual address ranges, their permissions, and backing files
7. **User stack unwinding**: Opens `/proc/[pid]/mem` to read raw stack memory, then scans each 8-byte word against the maps table to identify candidate return addresses in executable regions
8. **Symbol resolution**: For each return address pointing to a mapped binary, invokes `addr2line` to resolve the file offset to a demangled function name and source location

## API

All functions return `0` on success, `-1` on error. Output via pointer parameters. `read_full_diagnostics()` returns `DSTATE_PROC_GONE` (1) if the process exited between detection and diagnostics. See `include/dstate.h` for struct definitions.

### Detection

```c
int find_dstate_processes(dstate_process_t **results, int *count);
void free_dstate_list(dstate_process_t *list);
void print_dstate_summary(const dstate_process_t *procs, int count);
```

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

### Memory Maps & User Stack

```c
int read_process_maps(pid_t pid, process_maps_t *maps);
const char *maps_find_region(const process_maps_t *maps, uint64_t addr);
int read_user_stack(pid_t pid, process_diagnostics_t *diag);
void resolve_symbol(const char *binary_path, uint64_t offset,
                    char *func_out, size_t func_len,
                    char *src_out, size_t src_len);
```

`read_user_stack` sets `diag->user_stack.valid` on success. On failure, `diag->user_stack.reason` is set to `USER_STACK_ERR_PERM` (no permission to open `/proc/[pid]/mem`) or `USER_STACK_ERR_UNAVAIL` (stack pointer unavailable or memory unreadable). `resolve_symbol` falls back to `"??"` / `"??:0"` if `addr2line` is not available or the binary has no debug info.

## Known Limitations

- **x86-64 only**: The syscall number-to-name table in `proc_reader.c` is x86-64 specific. Other architectures use different syscall numbers.
- **TOCTOU races**: Processes can exit between detection and diagnostics. This is inherent to `/proc` and handled gracefully. Vanished processes are skipped silently.
- **Privileges**: Kernel stack traces and user stack unwinding require root or `CAP_SYS_PTRACE`. All other diagnostics work without elevated privileges.
- **Symbol resolution**: `resolve_symbol` shells out to `addr2line`. Function names and source locations are only available for binaries compiled with debug info (`-g`). Without `addr2line` or debug info, frames are shown as `??` / `??:0`.
- **User stack heuristic**: The user stack unwinding scans raw stack memory for values that fall in executable regions. This can produce false positives (non-return-address values that happen to point into code) and false negatives (frames stored in registers rather than on the stack).

## License

This project is licensed under the [MIT License](LICENSE).
