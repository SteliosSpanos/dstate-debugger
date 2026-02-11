# Dstate-Debugger

Linux debugging tool that detects and diagnoses processes stuck in D-state (uninterruptible sleep). Scans `/proc` to identify blocked processes, reads kernel stack traces, maps syscalls to names, and reports what they're blocked on.

Written in C99 for x86-64 Linux.

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
    ├── monitor.c          Forks child into D-state, demonstrates signal immunity
    └── trap_fs.c          FUSE filesystem that blocks reads forever
```

## Architecture

Three layers, all reading from `/proc`:

| Layer | File | Purpose |
|-------|------|---------|
| Utilities | `src/proc_utils.c` | Low-level `/proc` I/O: reading files, symlinks, building `/proc/[pid]/...` paths |
| Detection | `src/detector.c` | Scans `/proc` for D-state processes, returns dynamic arrays |
| Diagnostics | `src/proc_reader.c` | Per-PID analysis: stat, wchan, syscall, stack traces, blocking fd detection. Contains x86-64 syscall table |

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
make monitor    # builds test monitor
make trap_fs    # builds FUSE test filesystem
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
```

## Testing

No automated tests. Manual testing uses a FUSE filesystem that blocks processes in D-state.

```bash
# Terminal 1: start FUSE daemon that blocks reads forever
./trap_fs /tmp/fuse_mount

# Terminal 2: fork a child that reads from FUSE mount
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

## API

All functions return `0` on success, `-1` on error. Output via pointer parameters. `read_full_diagnostics()` returns `DSTATE_PROC_GONE` (1) if the process exited between detection and diagnostics. See `include/dstate.h` for struct definitions.

### Detection

```c
int find_dstate_processes(dstate_process_t **results, int *count);
int is_process_dstate(pid_t pid);
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

## Known Limitations

- **x86-64 only**: The syscall number-to-name table in `proc_reader.c` is x86-64 specific. Other architectures use different syscall numbers.
- **TOCTOU races**: Processes can exit between detection and diagnostics. This is inherent to `/proc` and handled gracefully — vanished processes are skipped silently.
- **Privileges**: Kernel stack traces require root or `CAP_SYS_PTRACE`. All other diagnostics work without elevated privileges.

## License

This project is intended for educational purposes.