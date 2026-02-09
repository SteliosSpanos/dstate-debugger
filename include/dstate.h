#ifndef DSTATE_H
#define DSTATE_H

#include <sys/types.h>
#include <stdint.h>

#define MAX_COMM_LEN 256
#define MAX_PATH_LEN 512
#define MAX_WCHAN_LEN 64
#define MAX_STACK_LEN 8192
#define MAX_PROCS 256
#define MAX_ERROR_LEN 256

typedef enum
{
    STATE_RUNNING = 'R',
    STATE_SLEEPING = 'S',
    STATE_DISK_SLEEP = 'D',
    STATE_ZOMBIE = 'Z',
    STATE_STOPPED = 'T',
    STATE_TRACING_STOP = 't',
    STATE_DEAD = 'X',
    STATE_IDLE = 'I',

} process_state_t;

typedef struct
{
    pid_t pid;
    pid_t ppid;
    pid_t tgid;

    char comm[MAX_COMM_LEN];
    char state;
    char wchan[MAX_WCHAN_LEN];

    long syscall_nr;
    uint64_t syscall_args[6];
    uint64_t instruction_ptr;
    uint64_t stack_ptr;

    unsigned long utime;
    unsigned long stime;
    unsigned long long start_time;

    unsigned long vm_size;
    unsigned long vm_rss;

    int num_threads;

} dstate_process_t;

typedef struct
{
    dstate_process_t basic;

    char kernel_stack[MAX_STACK_LEN];
    int kernel_stack_valid;

    int blocking_fd;
    char blocking_path[MAX_PATH_LEN];
    int mount_id;

    char cmdline[MAX_PATH_LEN];

    char cwd[MAX_PATH_LEN];

    char exe[MAX_PATH_LEN];

} process_diagnostics_t;

typedef struct
{
    int mount_id;
    int parent_id;
    char mount_point[MAX_PATH_LEN];
    char fs_type[64];
    char mount_source[MAX_PATH_LEN];

    pid_t fuse_daemon_pid;
    char fuse_daemon_comm[MAX_COMM_LEN];
    char fuse_daemon_state;
} fuse_mount_t;

typedef enum
{
    METHOD_PTRACE_ATTACH,
    METHOD_SIGABRT,
    METHOD_GCORE,
    METHOD_PROC_MEM,
    METHOD_PERF,
    METHOD_SYSRQ,
} coredump_method_t;

typedef struct
{
    coredump_method_t method;
    int success;
    int error_code;
    char error_msg[MAX_ERROR_LEN];
    char output_path[MAX_PATH_LEN];
    char notes[MAX_ERROR_LEN];
} coredump_result_t;

int find_dstate_processes(dstate_process_t **results, int *count);
int is_process_dstate(pid_t pid);
void free_dstate_list(dstate_process_t *list);

int read_process_stat(pid_t pid, dstate_process_t *proc);
int read_process_status(pid_t pid, dstate_process_t *proc);
int read_process_syscall(pid_t pid, dstate_process_t *proc);
int read_process_wchan(pid_t pid, char *wchan, size_t len);
int read_process_stack(pid_t pid, char *stack, size_t len);
int read_full_diagnostics(pid_t pid, process_diagnostics_t *diag);
const char *syscall_name(long nr);
void print_diagnostics(const process_diagnostics_t *diag);

int try_all_coredump_methods(pid_t pid, coredump_result_t *results, int *count);
int try_ptrace_coredump(pid_t pid, coredump_result_t *result);
int try_gcore(pid_t pid, coredump_result_t *result);
int try_proc_mem_dump(pid_t pid, const char *output_path, coredump_result_t *result);
const char *method_name(coredump_method_t method);

int get_kernel_stack(pid_t pid, char *buffer, size_t len);
int get_userspace_stack(pid_t pid, char *buffer, size_t len);
int parse_stack_frame(const char *line, uint64_t *addr, char *symbol, size_t sym_len);

int find_fuse_mount_for_process(pid_t pid, fuse_mount_t *mount);
int find_fuse_daemon(const char *mount_point, pid_t *daemon_pid);
int analyze_fuse_daemon(pid_t daemon_pid, process_diagnostics_t *diag);
int list_all_fuse_mounts(fuse_mount_t **mounts, int *count);

#endif
