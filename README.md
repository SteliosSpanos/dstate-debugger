# dstate-debugger

Linux tool for detecting and diagnosing processes stuck in D-state (uninterruptible sleep). Written in C99 for x86-64.

D-state processes are blocked in the kernel waiting for I/O and cannot be interrupted, even by SIGKILL. This tool scans `/proc`, identifies them, reads kernel stack traces, maps syscalls to names, and reports what they're blocked on.

## Architecture

Three layers, all reading from `/proc`:

| Layer | File | Role |
|-------|------|------|
| Utilities | `src/proc_utils.c` | Low-level `/proc` I/O (read files, symlinks, parse status lines) |
| Detection | `src/detector.c` | Scan `/proc` for D-state processes |
| Diagnostics | `src/proc_reader.c` | Deep per-PID diagnostics (syscall mapping, stack traces, blocking fd) |

Headers: `include/dstate.h` (all structs and API), `include/proc_utils.h` (utility interface).

## Dependencies

```bash
sudo apt-get install libcap-dev libfuse-dev
```

`libcap-dev` is required. `libfuse-dev` is only needed for the test FUSE filesystem.

## Build

```bash
# Main tool
gcc -std=c99 -D_GNU_SOURCE -Wall -o dstate \
    src/detector.c src/proc_reader.c src/proc_utils.c -lcap

# Test: FUSE filesystem that traps processes in D-state
gcc -D_GNU_SOURCE -Wall -o trap_fs test/trap_fs.c \
    $(pkg-config --cflags --libs fuse)

# Test: monitor that demonstrates D-state behavior
gcc -std=c99 -D_GNU_SOURCE -Wall -o monitor test/monitor.c -lcap
```

## Usage

```bash
sudo ./dstate
```

```
=== D-State Processes Found: 2 ===
PID      COMMAND              STATE    WAITING IN
---      -------              -----    ----------
1234     blocked_reader       D        vfs_read
5678     hung_process         D        wait_on_page_bit
```

Some operations (reading `/proc/[pid]/stack`) require root or `CAP_SYS_PTRACE`.

## Testing with the FUSE Trap

`trap_fs` mounts a FUSE filesystem where reading `/trap.txt` blocks forever, putting the reader into D-state.

```bash
# Terminal 1: mount the trap
mkdir -p /tmp/fuse_mount
./trap_fs /tmp/fuse_mount

# Terminal 2: run the monitor (forks a child that reads /tmp/fuse_mount/trap.txt)
./monitor

# Terminal 3: observe the D-state
sudo ./dstate
```

The monitor demonstrates that SIGKILL has no effect on D-state processes. Kill the FUSE daemon to release them.

## API

### Detection
```c
int find_dstate_processes(dstate_process_t **results, int *count);
int is_process_dstate(pid_t pid);
void free_dstate_list(dstate_process_t *list);
```

### Diagnostics
```c
int read_full_diagnostics(pid_t pid, process_diagnostics_t *diag);
int read_process_stat(pid_t pid, dstate_process_t *proc);
int read_process_status(pid_t pid, dstate_process_t *proc);
int read_process_syscall(pid_t pid, dstate_process_t *proc);
int read_process_stack(pid_t pid, char *stack, size_t len);
const char *syscall_name(long nr);
```

All functions return `0` on success, `-1` on error. See `include/dstate.h` for full struct definitions.
