#ifndef DSTATE_H
#define DSTATE_H

#include <sys/types.h>
#include <stdint.h>

#define DSTATE_PROC_GONE 1
#define USER_STACK_ERR_PERM 1
#define USER_STACK_ERR_UNAVAIL 2
#define USER_STACK_ERR_NO_SP 3

#define MAX_COMM_LEN 256
#define MAX_PATH_LEN 512
#define MAX_WCHAN_LEN 64
#define MAX_STACK_LEN 8192
#define MAX_MAPS 256
#define MAX_USER_FRAMES 32
typedef struct
{
    uint64_t start;
    uint64_t end;
    char perms[5];
    char path[256];
} map_entry_t;

typedef struct
{
    map_entry_t entries[MAX_MAPS];
    int count;
} process_maps_t;

typedef struct
{
    uint64_t addr;
    char region[256];
    uint64_t region_start;
    char function[256];
    char source[256];
} user_frame_t;

typedef struct
{
    user_frame_t frames[MAX_USER_FRAMES];
    int count;
    int valid;
    int reason;
} user_stack_t;

typedef struct
{
    int found;
    pid_t holder_pid;
    char lock_type[16];
    char access[16];
    char path[MAX_PATH_LEN];
} lock_conflict_t;

typedef struct
{
    pid_t pid;
    pid_t ppid;

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

    char cmdline[MAX_PATH_LEN];

    char cwd[MAX_PATH_LEN];

    char exe[MAX_PATH_LEN];

    process_maps_t maps;

    user_stack_t user_stack;

    int ptrace_valid;
    uint64_t ptrace_rip;
    uint64_t ptrace_rsp;
    uint64_t ptrace_rbp;

    lock_conflict_t lock_conflict;
} process_diagnostics_t;

int is_pid_dir(const char *name);
int find_dstate_processes(dstate_process_t **results, int *count);
void free_dstate_list(dstate_process_t *list);
void print_dstate_summary(const dstate_process_t *procs, int count);

int read_process_stat(pid_t pid, dstate_process_t *proc);
int read_process_syscall(pid_t pid, dstate_process_t *proc);
int read_process_wchan(pid_t pid, char *wchan, size_t len);
int read_process_stack(pid_t pid, char *stack, size_t len);
int read_full_diagnostics(pid_t pid, process_diagnostics_t *diag);
const char *syscall_name(long nr);
void print_diagnostics(const process_diagnostics_t *diag);

int read_process_maps(pid_t pid, process_maps_t *maps);
int read_user_stack(pid_t pid, process_diagnostics_t *diag);
void resolve_symbol(const char *binary_path, uint64_t offset,
                    char *func_out, size_t func_len,
                    char *src_out, size_t src_len);

int read_registers_ptrace(pid_t pid, uint64_t *rip, uint64_t *rsp, uint64_t *rbp);

int read_lock_conflict(pid_t pid, process_diagnostics_t *diag);

int write_core_file(pid_t pid, process_diagnostics_t *diag, const char *outpath);

#endif
