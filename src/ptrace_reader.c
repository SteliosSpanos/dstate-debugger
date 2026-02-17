#include <sys/user.h>
#include <sys/wait.h>
#include <errno.h>
#include <sys/ptrace.h>

#include "../include/dstate.h"

int read_registers_ptrace(pid_t pid, uint64_t *rip, uint64_t *rsp, uint64_t *rbp)
{
    struct user_regs_struct regs;
    int status;

    if (ptrace(PTRACE_ATTACH, pid, NULL, NULL) < 0)
        return -1;

    if (waitpid(pid, &status, 0) < 0 || !WIFSTOPPED(status))
    {
        ptrace(PTRACE_DETACH, pid, NULL, NULL);
        return -1;
    }

    if (ptrace(PTRACE_GETREGS, pid, NULL, &regs) < 0)
    {
        ptrace(PTRACE_DETACH, pid, NULL, NULL);
        return -1;
    }

    *rip = (uint64_t)regs.rip;
    *rsp = (uint64_t)regs.rsp;
    *rbp = (uint64_t)regs.rbp;

    ptrace(PTRACE_DETACH, pid, NULL, NULL);
    return 0;
}