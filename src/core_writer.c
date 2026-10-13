#ifndef _GNU_SOURCE
#define _GNU_SOURCE
#endif

#define CORE_PAGE_SIZE 0x1000
#define BUFSIZE (16 * CORE_PAGE_SIZE)
#define CORE_MAX_PHDRS 0xFFFF

#include <elf.h>
#include <sys/procfs.h>
#include <sys/user.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <unistd.h>
#include <string.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <errno.h>
#include <signal.h>

#include "../include/dstate.h"
#include "../include/proc_utils.h"

typedef struct
{
    uint32_t namesz;
    uint32_t descsz;
    uint32_t type;
} note_hdr_t;

typedef struct
{
    int *readable;
    uint64_t *load_offset;
    int readable_count;
    uint64_t note_offset;
    size_t note_total_size;
    uint64_t pad_size;
    uint64_t total_size;
    unsigned char auxv[MAX_AUXV_LEN];
    size_t auxv_len;
} core_layout_t;

static int write_all(int fd, const void *buf, size_t n)
{
    const char *p = buf;

    while (n > 0)
    {
        ssize_t w = write(fd, p, n);

        if (w < 0)
        {
            if (errno == EINTR)
                continue;
            return -1;
        }

        if (w == 0)
        {
            errno = EIO;
            return -1;
        }

        p += w;
        n -= (size_t)w;
    }

    return 0;
}

static size_t align4(size_t n)
{
    return (n + 3) & ~(size_t)3;
}

static size_t calc_note_size(const char *name, size_t descsz)
{
    return sizeof(note_hdr_t) + align4(strlen(name) + 1) + align4(descsz);
}

static size_t calc_nt_file_descsz(const process_maps_t *maps)
{
    int file_count = 0;
    size_t name_sz = 0;

    for (int i = 0; i < maps->count; ++i)
    {
        if (maps->entries[i].path[0] != '/')
            continue;

        file_count++;
        name_sz += strlen(maps->entries[i].path) + 1;
    }

    size_t result = 2 * sizeof(uint64_t) + (size_t)file_count * 3 * sizeof(uint64_t) + name_sz;

    return result;
}

static int write_nt_file(int fd, const process_maps_t *maps)
{
    uint64_t count = 0;
    for (int i = 0; i < maps->count; ++i)
    {
        if (maps->entries[i].path[0] == '/')
            count++;
    }

    uint64_t page_size = (uint64_t)sysconf(_SC_PAGESIZE);

    if (write_all(fd, &count, sizeof(count)) < 0)
        return -1;

    if (write_all(fd, &page_size, sizeof(page_size)) < 0)
        return -1;

    for (int i = 0; i < maps->count; ++i)
    {
        const map_entry_t *e = &maps->entries[i];
        if (e->path[0] != '/')
            continue;

        uint64_t file_off_pages = e->file_offset / page_size;

        if (write_all(fd, &e->start, sizeof(uint64_t)) < 0)
            return -1;

        if (write_all(fd, &e->end, sizeof(uint64_t)) < 0)
            return -1;

        if (write_all(fd, &file_off_pages, sizeof(uint64_t)) < 0)
            return -1;
    }

    for (int i = 0; i < maps->count; ++i)
    {
        const map_entry_t *e = &maps->entries[i];
        if (e->path[0] != '/')
            continue;

        if (write_all(fd, e->path, strlen(e->path) + 1) < 0)
            return -1;
    }

    return 0;
}

static int compute_layout(pid_t pid, const process_maps_t *maps, core_layout_t *layout)
{
    char mem_path[64];
    char auxv_path[64];

    snprintf(mem_path, sizeof(mem_path), "/proc/%d/mem", pid);

    int mem_fd = open(mem_path, O_RDONLY | O_CLOEXEC);
    if (mem_fd < 0)
        return -1;

    size_t slots = maps->count > 0 ? (size_t)maps->count : 1;
    layout->readable = calloc(slots, sizeof(*layout->readable));
    layout->load_offset = calloc(slots, sizeof(*layout->load_offset));
    if (!layout->readable || !layout->load_offset)
    {
        close(mem_fd);
        return -1;
    }

    layout->readable_count = 0;

    for (int i = 0; i < maps->count; ++i)
    {
        char probe;

        if (maps->entries[i].perms[0] != 'r')
            continue;

        ssize_t n = pread(mem_fd, &probe, 1, (off_t)maps->entries[i].start);
        layout->readable[i] = (n == 1) ? 1 : 0;

        if (layout->readable[i])
            layout->readable_count++;
    }

    close(mem_fd);

    layout->auxv_len = 0;
    if (build_proc_path(auxv_path, sizeof(auxv_path), pid, "auxv"))
    {
        unsigned char raw[MAX_AUXV_LEN + 1];
        ssize_t n = read_proc_file(auxv_path, (char *)raw, sizeof(raw));

        if (n > 0 && n <= (ssize_t)MAX_AUXV_LEN)
        {
            memcpy(layout->auxv, raw, (size_t)n);
            layout->auxv_len = (size_t)n;
        }
    }

    layout->note_total_size = calc_note_size("CORE", sizeof(struct elf_prstatus)) + calc_note_size("CORE", sizeof(struct elf_prpsinfo)) + calc_note_size("CORE", calc_nt_file_descsz(maps));

    if (layout->auxv_len > 0)
        layout->note_total_size += calc_note_size("CORE", layout->auxv_len);

    int phdr_count = 1 + layout->readable_count;
    uint64_t phdr_table_size = (uint64_t)phdr_count * sizeof(Elf64_Phdr);

    layout->note_offset = sizeof(Elf64_Ehdr) + phdr_table_size;

    uint64_t current_offset = layout->note_offset + layout->note_total_size;

    layout->pad_size = (CORE_PAGE_SIZE - (current_offset % CORE_PAGE_SIZE)) % CORE_PAGE_SIZE;
    current_offset += layout->pad_size;

    for (int i = 0; i < maps->count; ++i)
    {
        if (!layout->readable[i])
            continue;

        layout->load_offset[i] = current_offset;
        current_offset += maps->entries[i].end - maps->entries[i].start;
    }

    layout->total_size = current_offset;
    return 0;
}

static int write_elf_header(int fd, int phdr_count)
{
    Elf64_Ehdr ehdr;
    memset(&ehdr, 0, sizeof(ehdr));

    ehdr.e_ident[EI_MAG0] = ELFMAG0;
    ehdr.e_ident[EI_MAG1] = ELFMAG1;
    ehdr.e_ident[EI_MAG2] = ELFMAG2;
    ehdr.e_ident[EI_MAG3] = ELFMAG3;
    ehdr.e_ident[EI_CLASS] = ELFCLASS64;
    ehdr.e_ident[EI_DATA] = ELFDATA2LSB;
    ehdr.e_ident[EI_VERSION] = EV_CURRENT;
    ehdr.e_ident[EI_OSABI] = ELFOSABI_NONE;

    ehdr.e_type = ET_CORE;
    ehdr.e_machine = EM_X86_64;
    ehdr.e_version = EV_CURRENT;
    ehdr.e_phoff = sizeof(Elf64_Ehdr);
    ehdr.e_ehsize = sizeof(Elf64_Ehdr);
    ehdr.e_phentsize = sizeof(Elf64_Phdr);
    ehdr.e_phnum = (uint16_t)phdr_count;

    return write_all(fd, &ehdr, sizeof(ehdr));
}

static uint32_t perms_to_flags(const char *perms)
{
    uint32_t flags = 0;
    if (perms[0] == 'r')
        flags |= PF_R;
    if (perms[1] == 'w')
        flags |= PF_W;
    if (perms[2] == 'x')
        flags |= PF_X;

    return flags;
}

static int write_program_headers(int fd, const process_maps_t *maps, const core_layout_t *layout)
{
    Elf64_Phdr note_phdr;
    memset(&note_phdr, 0, sizeof(note_phdr));

    note_phdr.p_type = PT_NOTE;
    note_phdr.p_offset = layout->note_offset;
    note_phdr.p_filesz = (Elf64_Xword)layout->note_total_size;
    note_phdr.p_align = 4;

    if (write_all(fd, &note_phdr, sizeof(note_phdr)) < 0)
        return -1;

    for (int i = 0; i < maps->count; ++i)
    {
        if (!layout->readable[i])
            continue;

        uint64_t size = maps->entries[i].end - maps->entries[i].start;

        Elf64_Phdr load_phdr;
        memset(&load_phdr, 0, sizeof(load_phdr));

        load_phdr.p_type = PT_LOAD;
        load_phdr.p_offset = layout->load_offset[i];
        load_phdr.p_vaddr = maps->entries[i].start;
        load_phdr.p_paddr = maps->entries[i].start;
        load_phdr.p_filesz = size;
        load_phdr.p_memsz = size;
        load_phdr.p_flags = perms_to_flags(maps->entries[i].perms);
        load_phdr.p_align = CORE_PAGE_SIZE;

        if (write_all(fd, &load_phdr, sizeof(load_phdr)) < 0)
            return -1;
    }

    return 0;
}

static int write_note(int fd, const char *name, uint32_t type, const void *data, uint32_t descsz)
{
    static const char zeros[8] = {0};

    uint32_t namesz = (uint32_t)strlen(name) + 1;
    uint32_t name_pad = (uint32_t)(align4(namesz) - namesz);
    uint32_t data_pad = (uint32_t)(align4(descsz) - descsz);

    note_hdr_t hdr = {namesz, descsz, type};

    if (write_all(fd, &hdr, sizeof(hdr)) < 0)
        return -1;

    if (write_all(fd, name, namesz) < 0)
        return -1;

    if (write_all(fd, zeros, name_pad) < 0)
        return -1;

    if (write_all(fd, data, descsz) < 0)
        return -1;

    if (write_all(fd, zeros, data_pad) < 0)
        return -1;

    return 0;
}

static int write_note_blob(int fd, const process_diagnostics_t *diag, const core_layout_t *layout)
{
    struct elf_prstatus prstatus;
    memset(&prstatus, 0, sizeof(prstatus));

    prstatus.pr_pid = diag->basic.pid;
    prstatus.pr_ppid = diag->basic.ppid;

    if (diag->ptrace_valid)
    {
        memcpy(prstatus.pr_reg, diag->ptrace_regs, sizeof(prstatus.pr_reg));
    }
    else if (diag->basic.stack_ptr != 0)
    {
        prstatus.pr_reg[ELFREG_CS] = 0x33;
        prstatus.pr_reg[ELFREG_SS] = 0x2b;
        prstatus.pr_reg[ELFREG_RIP] = diag->basic.instruction_ptr;
        prstatus.pr_reg[ELFREG_RSP] = diag->basic.stack_ptr;
        prstatus.pr_reg[ELFREG_RDI] = diag->basic.syscall_args[0];
        prstatus.pr_reg[ELFREG_RSI] = diag->basic.syscall_args[1];
        prstatus.pr_reg[ELFREG_RDX] = diag->basic.syscall_args[2];
        prstatus.pr_reg[ELFREG_R10] = diag->basic.syscall_args[3];
        prstatus.pr_reg[ELFREG_R8] = diag->basic.syscall_args[4];
        prstatus.pr_reg[ELFREG_R9] = diag->basic.syscall_args[5];
        prstatus.pr_reg[ELFREG_ORIG_RAX] = (unsigned long)diag->basic.syscall_nr;

        if (diag->basic.syscall_nr >= 0)
        {
            prstatus.pr_reg[ELFREG_RCX] = diag->basic.instruction_ptr;
            prstatus.pr_reg[ELFREG_RAX] = (unsigned long)(-ENOSYS);
        }
    }

    if (write_note(fd, "CORE", NT_PRSTATUS, &prstatus, sizeof(prstatus)) < 0)
        return -1;

    struct elf_prpsinfo prpsinfo;
    memset(&prpsinfo, 0, sizeof(prpsinfo));

    prpsinfo.pr_pid = diag->basic.pid;
    prpsinfo.pr_ppid = diag->basic.ppid;
    strncpy(prpsinfo.pr_fname, diag->basic.comm, sizeof(prpsinfo.pr_fname) - 1);
    strncpy(prpsinfo.pr_psargs, diag->cmdline, sizeof(prpsinfo.pr_psargs) - 1);

    if (write_note(fd, "CORE", NT_PRPSINFO, &prpsinfo, sizeof(prpsinfo)) < 0)
        return -1;

    if (layout->auxv_len > 0 &&
        write_note(fd, "CORE", NT_AUXV, layout->auxv, (uint32_t)layout->auxv_len) < 0)
        return -1;

    size_t nt_file_descsz = calc_nt_file_descsz(&diag->maps);
    uint32_t namesz = 5;
    uint32_t name_pad = 3;
    uint32_t data_pad = (uint32_t)(align4(nt_file_descsz) - nt_file_descsz);

    note_hdr_t nt_file_hdr = {namesz, (uint32_t)nt_file_descsz, NT_FILE};
    static const char zeros[8] = {0};

    if (write_all(fd, &nt_file_hdr, sizeof(nt_file_hdr)) < 0)
        return -1;

    if (write_all(fd, "CORE", namesz) < 0)
        return -1;

    if (write_all(fd, zeros, name_pad) < 0)
        return -1;

    if (write_nt_file(fd, &diag->maps) < 0)
        return -1;

    if (write_all(fd, zeros, data_pad) < 0)
        return -1;

    return 0;
}

static int write_padding(int fd, uint64_t n)
{
    static const char zeros[CORE_PAGE_SIZE];

    if (n > sizeof(zeros))
        return -1;

    return write_all(fd, zeros, (size_t)n);
}

static int write_memory(pid_t pid, int fd_out, const process_maps_t *maps, const core_layout_t *layout)
{
    char mem_path[64];

    snprintf(mem_path, sizeof(mem_path), "/proc/%d/mem", pid);

    int mem_fd = open(mem_path, O_RDONLY | O_CLOEXEC);
    if (mem_fd < 0)
        return -1;

    static char buf[BUFSIZE];

    for (int i = 0; i < maps->count; ++i)
    {
        if (!layout->readable[i])
            continue;

        uint64_t pos = maps->entries[i].start;
        uint64_t end = maps->entries[i].end;

        while (pos < end)
        {
            size_t chunk = (end - pos) < sizeof(buf) ? (size_t)(end - pos) : sizeof(buf);

            ssize_t n = pread(mem_fd, buf, chunk, (off_t)pos);
            if (n <= 0)
            {
                for (size_t off = 0; off < chunk; off += CORE_PAGE_SIZE)
                {
                    size_t len = (chunk - off) < CORE_PAGE_SIZE ? (chunk - off) : CORE_PAGE_SIZE;
                    ssize_t got = pread(mem_fd, buf + off, len, (off_t)(pos + off));

                    if (got < 0)
                        got = 0;
                    if ((size_t)got < len)
                        memset(buf + off + got, 0, len - (size_t)got);
                }
                n = (ssize_t)chunk;
            }

            if (write_all(fd_out, buf, (size_t)n) < 0)
            {
                int saved = errno;
                close(mem_fd);
                errno = saved;
                return -1;
            }

            pos += (uint64_t)n;
        }
    }

    close(mem_fd);
    return 0;
}

int write_core_file(pid_t pid, process_diagnostics_t *diag, const char *outpath)
{
    core_layout_t layout;
    memset(&layout, 0, sizeof(layout));
    int ret = -1;
    char tmp_path[MAX_PATH_LEN + 16];
    struct sigaction ign, old_xfsz;
    int xfsz_changed = 0;

    if (compute_layout(pid, &diag->maps, &layout) < 0)
    {
        fprintf(stderr, "core: failed to probe /proc/%d/mem\n", pid);
        goto out;
    }

    int phdr_count = 1 + layout.readable_count;

    if (phdr_count > CORE_MAX_PHDRS)
    {
        fprintf(stderr, "core: %d segments exceed the ELF header limit of %d\n", phdr_count, CORE_MAX_PHDRS);
        goto out;
    }

    if (layout.total_size > MAX_CORE_SIZE)
    {
        fprintf(stderr, "core: layout needs %llu bytes (%llu MiB), above the limit of %llu bytes (%llu MiB); nothing written\n",
                (unsigned long long)layout.total_size, (unsigned long long)(layout.total_size >> 20),
                (unsigned long long)MAX_CORE_SIZE, (unsigned long long)(MAX_CORE_SIZE >> 20));
        goto out;
    }

    if (snprintf(tmp_path, sizeof(tmp_path), "%s.XXXXXX", outpath) >= (int)sizeof(tmp_path))
    {
        fprintf(stderr, "core: output path is too long (limit %d characters)\n", (int)sizeof(tmp_path) - 8);
        goto out;
    }

    /* rename() would replace a device node or FIFO with a regular file. */
    struct stat st;
    if (lstat(outpath, &st) == 0 && !S_ISREG(st.st_mode) && !S_ISLNK(st.st_mode))
    {
        fprintf(stderr, "core: %s exists and is not a regular file; refusing to replace it\n", outpath);
        goto out;
    }

    /* With SIGXFSZ at its default the process dies on RLIMIT_FSIZE and the temporary file cannot be removed. */
    memset(&ign, 0, sizeof(ign));
    ign.sa_handler = SIG_IGN;
    sigemptyset(&ign.sa_mask);
    xfsz_changed = sigaction(SIGXFSZ, &ign, &old_xfsz) == 0;

    int fd = mkstemp(tmp_path);
    if (fd < 0)
    {
        fprintf(stderr, "core: create temporary file for %s: %s\n", outpath, strerror(errno));
        goto out;
    }

    int ok = write_elf_header(fd, phdr_count) == 0 &&
             write_program_headers(fd, &diag->maps, &layout) == 0 &&
             write_note_blob(fd, diag, &layout) == 0 &&
             write_padding(fd, layout.pad_size) == 0 &&
             write_memory(pid, fd, &diag->maps, &layout) == 0;
    int saved = ok ? 0 : errno;

    if (close(fd) < 0 && ok)
    {
        ok = 0;
        saved = errno;
    }

    if (ok && rename(tmp_path, outpath) < 0)
    {
        ok = 0;
        saved = errno;
    }

    if (!ok)
    {
        unlink(tmp_path);
        fprintf(stderr, "core: write to %s failed: %s\n", outpath, strerror(saved));
        goto out;
    }

    printf("Core written  ->  %s\n", outpath);
    printf("Load with:     gdb ");
    fprint_safe(stdout, diag->exe, 0, 0);
    printf(" %s\n", outpath);
    ret = 0;

out:
    if (xfsz_changed)
        sigaction(SIGXFSZ, &old_xfsz, NULL);
    free(layout.readable);
    free(layout.load_offset);
    return ret;
}
