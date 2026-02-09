#ifndef DSTATE_H
#define DSTATE_H

#include <sys/types.h>
#include <stdint.h>

#define MAX_COMM_LEN 256
#define MAX_PATH_LEN 512
#define MAX_WCHAN_LEN 64
#define MAX_STACK_LEN 8192

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

} process_diagnostics_t;

int find_dstate_processes(dstate_process_t **results, int *count);
int is_process_dstate(pid_t pid);
void free_dstate_list(dstate_process_t *list);
void print_dstate_summary(const dstate_process_t *procs, int count);

int read_process_stat(pid_t pid, dstate_process_t *proc);
int read_process_syscall(pid_t pid, dstate_process_t *proc);
int read_process_wchan(pid_t pid, char *wchan, size_t len);
int read_process_stack(pid_t pid, char *stack, size_t len);
int read_full_diagnostics(pid_t pid, process_diagnostics_t *diag);
const char *syscall_name(long nr);
void print_diagnostics(const process_diagnostics_t *diag);

#endif
