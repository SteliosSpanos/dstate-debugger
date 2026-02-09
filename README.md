# Dstate-Debugger

Linux debugging tool that detects and diagnoses processes stuck in D-state (uninterruptible sleep). Scans `/proc` to identify blocked processes, reads kernel stack traces, maps syscalls to names, and reports what they're blocked on.

Written in C99 for x86-64 Linux.

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
make test       # full manual test (requires sudo)
make clean      # removes binaries, unmounts FUSE
```

## Usage

Requires root or `CAP_SYS_PTRACE` to read `/proc/[pid]/stack`.

```bash
sudo ./dstate
```

```
=== D-State Processes Found: 1 ===
PID      COMMAND              STATE    WAITING IN
---      -------              -----    ----------
1234     cat                  D        request_wait_answer
```

Each D-state process gets full diagnostics: command line, wait channel, syscall info with arguments, memory usage, kernel stack trace, and blocking file path.

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
make test
```

## API

All functions return `0` on success, `-1` on error. Output via pointer parameters. See `include/dstate.h` for struct definitions.

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
