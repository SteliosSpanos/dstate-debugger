#ifndef _GNU_SOURCE
#define _GNU_SOURCE
#endif

#include <errno.h>
#include <fcntl.h>
#include <unistd.h>
#include <string.h>
#include <stdint.h>
#include <stdio.h>
#include <libunwind.h>
#include <libunwind-ptrace.h>

#include "../include/dstate.h"

/*
 * unwind_ctx_t is deliberately laid out so its first field is pid_t pid.
 * _UPT_find_proc_info passes its void *arg to internal libunwind functions
 * (e.g. _Ux86_64_get_elf_image) which cast it to struct UPT_info * and read
 * only the first field: pid.  Because we share the same pointer for both
 * unw_init_remote and _UPT_find_proc_info, every access_mem callback below
 * receives &ctx (not an alien UPT_info pointer) and can read mem_fd correctly.
 *
 * FRAGILE: relies on struct UPT_info having pid_t as its first member —
 * an internal libunwind detail, not part of the public API.  Verified against
 * libunwind 1.x.  If a future release adds a field before pid, this breaks
 * silently with no compile-time warning.
 */
typedef struct
{
    pid_t pid;
    int mem_fd;
    uint64_t rsp;
    uint64_t rip;
    int have_full_regs;
    elf_gregset_t regs;
} unwind_ctx_t;

static const int elfreg_map[17] = {
    ELFREG_RAX, ELFREG_RDX, ELFREG_RCX, ELFREG_RBX,
    ELFREG_RSI, ELFREG_RDI, ELFREG_RBP, ELFREG_RSP,
    ELFREG_R8, ELFREG_R9, ELFREG_R10, ELFREG_R11,
    ELFREG_R12, ELFREG_R13, ELFREG_R14, ELFREG_R15,
    ELFREG_RIP};

static int acc_find_proc_info(unw_addr_space_t as, unw_word_t ip,
                              unw_proc_info_t *pip, int need_unwind_info,
                              void *arg)
{
    return _UPT_find_proc_info(as, ip, pip, need_unwind_info, arg);
}

static void acc_put_unwind_info(unw_addr_space_t as, unw_proc_info_t *pip,
                                void *arg)
{
    _UPT_put_unwind_info(as, pip, arg);
}

static int acc_get_dyn_info_list_addr(unw_addr_space_t as, unw_word_t *dil,
                                      void *arg)
{
    return _UPT_get_dyn_info_list_addr(as, dil, arg);
}

static int acc_access_mem(unw_addr_space_t as, unw_word_t addr, unw_word_t *val,
                          int write, void *arg)
{
    (void)as;

    if (write)
        return -UNW_EINVAL;

    unwind_ctx_t *ctx = arg;
    ssize_t n = pread(ctx->mem_fd, val, sizeof(*val), (off_t)addr);

    if (n != (ssize_t)sizeof(*val))
        return -UNW_EINVAL;

    return 0;
}

static int acc_access_reg(unw_addr_space_t as, unw_regnum_t reg, unw_word_t *val,
                          int write, void *arg)
{
    (void)as;

    if (write)
        return -UNW_EINVAL;

    unwind_ctx_t *ctx = arg;

    if (reg >= 0 && reg < 17 && ctx->have_full_regs)
    {
        *val = (unw_word_t)ctx->regs[elfreg_map[reg]];
        return 0;
    }

    if (reg == UNW_X86_64_RSP)
    {
        *val = ctx->rsp;
        return 0;
    }

    if (reg == UNW_X86_64_RIP)
    {
        *val = ctx->rip;
        return 0;
    }

    return -UNW_ENOINFO;
}

static int acc_access_fpreg(unw_addr_space_t as, unw_regnum_t reg, unw_fpreg_t *val,
                            int write, void *arg)
{
    (void)as;
    (void)reg;
    (void)val;
    (void)write;
    (void)arg;

    return -UNW_ENOINFO;
}

static int acc_resume(unw_addr_space_t as, unw_cursor_t *cur, void *arg)
{
    (void)as;
    (void)cur;
    (void)arg;

    return -UNW_ENOINFO;
}

static int acc_get_proc_name(unw_addr_space_t as, unw_word_t addr, char *buf,
                             size_t bufsize, unw_word_t *off, void *arg)
{
    (void)as;
    (void)addr;
    (void)buf;
    (void)bufsize;
    (void)off;
    (void)arg;

    return -UNW_ENOINFO;
}

static unw_accessors_t proc_accessors = {
    .find_proc_info = acc_find_proc_info,
    .put_unwind_info = acc_put_unwind_info,
    .get_dyn_info_list_addr = acc_get_dyn_info_list_addr,
    .access_mem = acc_access_mem,
    .access_reg = acc_access_reg,
    .access_fpreg = acc_access_fpreg,
    .resume = acc_resume,
    .get_proc_name = acc_get_proc_name,
};

int read_user_stack_libunwind(pid_t pid, process_diagnostics_t *diag)
{
    char path[64];

    diag->user_stack.count = 0;
    diag->user_stack.valid = 0;
    diag->user_stack.reason = 0;

    uint64_t rsp, rip;

    if (diag->ptrace_valid)
    {
        rsp = (uint64_t)diag->ptrace_regs[ELFREG_RSP];
        rip = (uint64_t)diag->ptrace_regs[ELFREG_RIP];
    }
    else
    {
        rsp = diag->basic.stack_ptr;
        rip = diag->basic.instruction_ptr;
    }

    if (rsp == 0 || rip == 0)
    {
        diag->user_stack.reason = USER_STACK_ERR_NO_SP;
        return -1;
    }

    snprintf(path, sizeof(path), "/proc/%d/mem", pid);

    int mem_fd = open(path, O_RDONLY);
    if (mem_fd < 0)
    {
        diag->user_stack.reason = (errno == EACCES || errno == EPERM)
                                      ? USER_STACK_ERR_PERM
                                      : USER_STACK_ERR_UNAVAIL;
        return -1;
    }

    unwind_ctx_t ctx = {
        .pid = pid,
        .mem_fd = mem_fd,
        .rsp = rsp,
        .rip = rip,
        .have_full_regs = diag->ptrace_valid,
    };

    if (diag->ptrace_valid)
        memcpy(ctx.regs, diag->ptrace_regs, sizeof(ctx.regs));

    unw_addr_space_t as = unw_create_addr_space(&proc_accessors, 0);
    if (!as)
    {
        close(mem_fd);
        return -1;
    }

    unw_set_caching_policy(as, UNW_CACHE_NONE);

    unw_cursor_t cursor;
    if (unw_init_remote(&cursor, as, &ctx) < 0)
    {
        unw_destroy_addr_space(as);
        close(mem_fd);
        return -1;
    }

    diag->user_stack.valid = 1;

    do
    {
        unw_word_t ip = 0;
        unw_get_reg(&cursor, UNW_REG_IP, &ip);

        if (ip == 0)
            break;

        user_frame_t *f = &diag->user_stack.frames[diag->user_stack.count];
        f->addr = (uint64_t)ip;
        f->region_start = 0;
        f->region[0] = '\0';
        f->function[0] = '\0';
        f->source[0] = '\0';

        for (int i = 0; i < diag->maps.count; ++i)
        {
            map_entry_t *e = &diag->maps.entries[i];
            if (ip >= e->start && ip < e->end)
            {
                f->region_start = e->start;
                strncpy(f->region, e->path[0] ? e->path : "(anonymous)",
                        sizeof(f->region) - 1);
                f->region[sizeof(f->region) - 1] = '\0';

                if (e->path[0] == '/')
                    resolve_symbol(e->path, ip - e->start + e->file_offset,
                                   f->function, sizeof(f->function),
                                   f->source, sizeof(f->source));

                break;
            }
        }

        if (f->region[0] == '\0')
            strncpy(f->region, "??", sizeof(f->region) - 1);
        if (f->function[0] == '\0')
            strncpy(f->function, "??", sizeof(f->function) - 1);
        if (f->source[0] == '\0')
            strncpy(f->source, "??:0", sizeof(f->source) - 1);

        diag->user_stack.count++;
    } while (unw_step(&cursor) > 0 && diag->user_stack.count < MAX_USER_FRAMES);

    unw_destroy_addr_space(as);
    close(mem_fd);
    return 0;
}
