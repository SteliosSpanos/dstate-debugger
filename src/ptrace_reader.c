#ifndef _GNU_SOURCE
#define _GNU_SOURCE
#endif

#include <sys/user.h>
#include <sys/wait.h>
#include <errno.h>
#include <signal.h>
#include <stdio.h>
#include <string.h>
#include <time.h>
#include <sys/ptrace.h>

#include "../include/dstate.h"

#define PTRACE_STOP_TIMEOUT_MS 500
#define PTRACE_POLL_STEP_NS 1000000L

/* Returns the signal to hand back on detach, or -1 if no stop arrived. */
static int wait_for_stop(pid_t pid)
{
    struct timespec step = {0, PTRACE_POLL_STEP_NS};

    for (int waited_ms = 0; waited_ms < PTRACE_STOP_TIMEOUT_MS; ++waited_ms)
    {
        int status;
        pid_t ret = waitpid(pid, &status, __WALL | WNOHANG);

        if (ret < 0)
        {
            if (errno == EINTR)
                continue;
            return -1;
        }

        if (ret == pid)
        {
            if (!WIFSTOPPED(status))
                return -1;

            if ((status >> 16) == PTRACE_EVENT_STOP)
                return 0;

            return WSTOPSIG(status);
        }

        nanosleep(&step, NULL);
    }

    return -1;
}

int read_registers_ptrace(pid_t pid, elf_gregset_t *regs_out)
{
    struct user_regs_struct regs;

    if (ptrace(PTRACE_SEIZE, pid, NULL, NULL) < 0)
        return -1;

    if (ptrace(PTRACE_INTERRUPT, pid, NULL, NULL) < 0)
    {
        ptrace(PTRACE_DETACH, pid, NULL, NULL);
        return -1;
    }

    int sig = wait_for_stop(pid);
    if (sig < 0)
    {
        /* Fails with ESRCH if the target never stopped; it stays seized until this tool exits. */
        ptrace(PTRACE_DETACH, pid, NULL, NULL);
        return -1;
    }

    if (ptrace(PTRACE_GETREGS, pid, NULL, &regs) < 0)
    {
        ptrace(PTRACE_DETACH, pid, NULL, NULL);
        return -1;
    }

    (*regs_out)[ELFREG_R15] = regs.r15;
    (*regs_out)[ELFREG_R14] = regs.r14;
    (*regs_out)[ELFREG_R13] = regs.r13;
    (*regs_out)[ELFREG_R12] = regs.r12;
    (*regs_out)[ELFREG_RBP] = regs.rbp;
    (*regs_out)[ELFREG_RBX] = regs.rbx;
    (*regs_out)[ELFREG_R11] = regs.r11;
    (*regs_out)[ELFREG_R10] = regs.r10;
    (*regs_out)[ELFREG_R9] = regs.r9;
    (*regs_out)[ELFREG_R8] = regs.r8;
    (*regs_out)[ELFREG_RAX] = regs.rax;
    (*regs_out)[ELFREG_RCX] = regs.rcx;
    (*regs_out)[ELFREG_RDX] = regs.rdx;
    (*regs_out)[ELFREG_RSI] = regs.rsi;
    (*regs_out)[ELFREG_RDI] = regs.rdi;
    (*regs_out)[ELFREG_ORIG_RAX] = regs.orig_rax;
    (*regs_out)[ELFREG_RIP] = regs.rip;
    (*regs_out)[ELFREG_CS] = regs.cs;
    (*regs_out)[ELFREG_EFLAGS] = regs.eflags;
    (*regs_out)[ELFREG_RSP] = regs.rsp;
    (*regs_out)[ELFREG_SS] = regs.ss;
    (*regs_out)[ELFREG_FS_BASE] = regs.fs_base;
    (*regs_out)[ELFREG_GS_BASE] = regs.gs_base;
    (*regs_out)[ELFREG_DS] = regs.ds;
    (*regs_out)[ELFREG_ES] = regs.es;
    (*regs_out)[ELFREG_FS] = regs.fs;
    (*regs_out)[ELFREG_GS] = regs.gs;

    if (ptrace(PTRACE_DETACH, pid, NULL, (void *)(long)sig) < 0 && errno != ESRCH)
    {
        fprintf(stderr, "ptrace: detach from %d failed: %s\n", pid, strerror(errno));
    }

    return 0;
}
