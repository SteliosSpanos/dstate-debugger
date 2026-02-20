#ifndef _GNU_SOURCE
#define _GNU_SOURCE
#endif

#define BUFSIZE 65535

#include <elf.h>
#include <sys/procfs.h>
#include <sys/user.h>
#include <fcntl.h>
#include <unistd.h>
#include <string.h>
#include <stdint.h>
#include <stdio.h>

#include "../include/dstate.h"
typedef struct
{
    uint32_t namesz;
    uint32_t descsz;
    uint32_t type;
} note_hdr_t;

typedef struct
{
    int readable[MAX_MAPS];
    int readable_count;
    uint64_t note_offset;
    size_t note_total_size;
    uint64_t load_offset[MAX_MAPS];
} core_layout_t;

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

    if (write(fd, &count, sizeof(count)) != (ssize_t)sizeof(count))
        return -1;

    if (write(fd, &page_size, sizeof(page_size)) != (ssize_t)sizeof(page_size))
        return -1;

    for (int i = 0; i < maps->count; ++i)
    {
        const map_entry_t *e = &maps->entries[i];
        if (e->path[0] != '/')
            continue;

        uint64_t file_off_pages = e->file_offset / page_size;

        if (write(fd, &e->start, sizeof(uint64_t)) != (ssize_t)sizeof(uint64_t))
            return -1;

        if (write(fd, &e->end, sizeof(uint64_t)) != (ssize_t)sizeof(uint64_t))
            return -1;

        if (write(fd, &file_off_pages, sizeof(uint64_t)) != (ssize_t)sizeof(uint64_t))
            return -1;
    }

    for (int i = 0; i < maps->count; ++i)
    {
        const map_entry_t *e = &maps->entries[i];
        if (e->path[0] != '/')
            continue;

        size_t len = strlen(e->path) + 1;
        if (write(fd, e->path, len) != (ssize_t)len)
            return -1;
    }

    return 0;
}

static int compute_layout(pid_t pid, const process_maps_t *maps, core_layout_t *layout)
{
    char mem_path[64];

    snprintf(mem_path, sizeof(mem_path), "/proc/%d/mem", pid);

    int mem_fd = open(mem_path, O_RDONLY);
    if (mem_fd < 0)
        return -1;

    layout->readable_count = 0;

    for (int i = 0; i < maps->count; ++i)
    {
        char probe;
        ssize_t n = pread(mem_fd, &probe, 1, (off_t)maps->entries[i].start);
        layout->readable[i] = (n == 1) ? 1 : 0;

        if (layout->readable[i])
            layout->readable_count++;
    }

    close(mem_fd);

    layout->note_total_size = calc_note_size("CORE", sizeof(struct elf_prstatus)) + calc_note_size("CORE", sizeof(struct elf_prpsinfo)) + calc_note_size("CORE", calc_nt_file_descsz(maps));

    int phdr_count = 1 + layout->readable_count;
    uint64_t phdr_table_size = (uint64_t)phdr_count * sizeof(Elf64_Phdr);

    layout->note_offset = sizeof(Elf64_Ehdr) + phdr_table_size;

    uint64_t current_offset = layout->note_offset + layout->note_total_size;

    for (int i = 0; i < maps->count; ++i)
    {
        if (!layout->readable[i])
        {
            layout->load_offset[i] = 0;
            continue;
        }
        layout->load_offset[i] = current_offset;
        current_offset += maps->entries[i].end - maps->entries[i].start;
    }

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

    ssize_t n = write(fd, &ehdr, sizeof(ehdr));

    if (n == (ssize_t)sizeof(ehdr))
    {
        return 0;
    }

    return -1;
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

    ssize_t note_n = write(fd, &note_phdr, sizeof(note_phdr));
    if (note_n != (ssize_t)sizeof(note_phdr))
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
        load_phdr.p_align = 0x1000;

        ssize_t load_n = write(fd, &load_phdr, sizeof(load_phdr));
        if (load_n != (ssize_t)sizeof(load_phdr))
        {
            return -1;
        }
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

    if (write(fd, &hdr, sizeof(hdr)) != (ssize_t)sizeof(hdr))
        return -1;

    if (write(fd, name, namesz) != (ssize_t)namesz)
        return -1;

    if (name_pad && write(fd, zeros, name_pad) != (ssize_t)name_pad)
        return -1;

    if (write(fd, data, descsz) != (ssize_t)descsz)
        return -1;

    if (data_pad && write(fd, zeros, data_pad) != (ssize_t)data_pad)
        return -1;

    return 0;
}

static int write_note_blob(int fd, const process_diagnostics_t *diag)
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
        prstatus.pr_reg[ELFREG_RIP] = diag->basic.instruction_ptr;
        prstatus.pr_reg[ELFREG_RSP] = diag->basic.stack_ptr;
        prstatus.pr_reg[ELFREG_RDI] = diag->basic.syscall_args[0];
        prstatus.pr_reg[ELFREG_RSI] = diag->basic.syscall_args[1];
        prstatus.pr_reg[ELFREG_RDX] = diag->basic.syscall_args[2];
        prstatus.pr_reg[ELFREG_R10] = diag->basic.syscall_args[3];
        prstatus.pr_reg[ELFREG_R8] = diag->basic.syscall_args[4];
        prstatus.pr_reg[ELFREG_R9] = diag->basic.syscall_args[5];
        prstatus.pr_reg[ELFREG_ORIG_RAX] = (unsigned long)diag->basic.syscall_nr;
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

    size_t nt_file_descsz = calc_nt_file_descsz(&diag->maps);
    uint32_t namesz = 5;
    uint32_t name_pad = 3;
    uint32_t data_pad = (uint32_t)(align4(nt_file_descsz) - nt_file_descsz);

    note_hdr_t nt_file_hdr = {namesz, (uint32_t)nt_file_descsz, NT_FILE};
    static const char zeros[8] = {0};

    if (write(fd, &nt_file_hdr, sizeof(nt_file_hdr)) != (ssize_t)sizeof(nt_file_hdr))
        return -1;

    if (write(fd, "CORE", namesz) != (ssize_t)namesz)
        return -1;

    if (write(fd, zeros, name_pad) != (ssize_t)name_pad)
        return -1;

    if (write_nt_file(fd, &diag->maps) < 0)
        return -1;

    if (data_pad && write(fd, zeros, data_pad) != (ssize_t)data_pad)
        return -1;

    return 0;
}

static int write_memory(pid_t pid, int fd_out, const process_maps_t *maps, const core_layout_t *layout)
{
    char mem_path[64];

    snprintf(mem_path, sizeof(mem_path), "/proc/%d/mem", pid);

    int mem_fd = open(mem_path, O_RDONLY);
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
                memset(buf, 0, chunk);
                n = (ssize_t)chunk;
            }

            if (write(fd_out, buf, (size_t)n) != n)
            {
                close(mem_fd);
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

    if (compute_layout(pid, &diag->maps, &layout) < 0)
    {
        fprintf(stderr, "core: failed to probe /proc/%d/mem\n", pid);
        return -1;
    }

    int phdr_count = 1 + layout.readable_count;

    int fd = open(outpath, O_WRONLY | O_CREAT | O_TRUNC, 0600);
    if (fd < 0)
    {
        perror("core: open output");
        return -1;
    }

    if (write_elf_header(fd, phdr_count) < 0 ||
        write_program_headers(fd, &diag->maps, &layout) < 0 ||
        write_note_blob(fd, diag) < 0 ||
        write_memory(pid, fd, &diag->maps, &layout) < 0)
    {
        fprintf(stderr, "core: write failed\n");
        close(fd);
        return -1;
    }

    close(fd);
    printf("Core written  ->  %s\n", outpath);
    printf("Load with:     gdb %s %s\n", diag->exe, outpath);
    return 0;
}