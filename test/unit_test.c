#ifndef _GNU_SOURCE
#define _GNU_SOURCE
#endif

#include <assert.h>
#include <elf.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/file.h>
#include <sys/mman.h>
#include <sys/stat.h>

#include "../include/dstate.h"
#include "../include/proc_utils.h"

void test_syscall_name_known(void)
{
    char buf[32];
    assert(strcmp(syscall_name(0, buf, sizeof(buf)), "read") == 0);
    assert(strcmp(syscall_name(1, buf, sizeof(buf)), "write") == 0);
    assert(strcmp(syscall_name(59, buf, sizeof(buf)), "execve") == 0);
    printf("  PASS: syscall_name known values\n");
}

void test_syscall_name_unknown(void)
{
    char buf[32];
    const char *name = syscall_name(999, buf, sizeof(buf));
    assert(strncmp(name, "syscall_", 8) == 0);
    printf("  PASS: syscall_name unknown value\n");
}

void test_syscall_name_negative(void)
{
    char buf[32];
    assert(strcmp(syscall_name(-1, buf, sizeof(buf)), "(not in syscall)") == 0);
    assert(strcmp(syscall_name(-100, buf, sizeof(buf)), "(not in syscall)") == 0);
    printf("  PASS: syscall_name_negative (not in syscall)\n");
}

void test_build_proc_path_normal(void)
{
    char buffer[64];
    char *result = build_proc_path(buffer, sizeof(buffer), 1234, "stat");
    assert(result != NULL);
    assert(strcmp(buffer, "/proc/1234/stat") == 0);
    printf("  PASS: build_proc_path normal\n");
}

void test_build_proc_path_buffer_too_small(void)
{
    char buffer[5];
    char *result = build_proc_path(buffer, sizeof(buffer), 1234, "stat");
    assert(result == NULL);
    printf("  PASS: build_proc_path buffer overflow returns NULL\n");
}

void test_build_proc_path_exact_fit(void)
{
    char buffer[16];
    char *result = build_proc_path(buffer, sizeof(buffer), 1234, "stat");
    assert(result != NULL);
    assert(strcmp(buffer, "/proc/1234/stat") == 0);
    printf("  PASS: build_proc_path exact fit\n");
}

void test_build_proc_path_one_byte_short(void)
{
    char buffer[15];
    char *result = build_proc_path(buffer, sizeof(buffer), 1234, "stat");
    assert(result == NULL);
    printf("  PASS: build_proc_path one byte short returns NULL\n");
}

void test_is_pid_dir_valid(void)
{
    assert(is_pid_dir("1") == 1);
    assert(is_pid_dir("1234") == 1);
    assert(is_pid_dir("999") == 1);
    printf("  PASS: is_pid_dir valid PIDs\n");
}

void test_is_pid_dir_invalid(void)
{
    assert(is_pid_dir("abcd") == 0);
    assert(is_pid_dir(".") == 0);
    assert(is_pid_dir("123abc") == 0);
    assert(is_pid_dir("") == 0);
    assert(is_pid_dir(NULL) == 0);
    printf("  PASS: is_pid_dir invalid names\n");
}

void test_syscall_name_new_entries(void)
{
    char buf[32];
    assert(strcmp(syscall_name(202, buf, sizeof(buf)), "futex") == 0);
    assert(strcmp(syscall_name(74, buf, sizeof(buf)), "fsync") == 0);
    assert(strcmp(syscall_name(230, buf, sizeof(buf)), "clock_nanosleep") == 0);
    assert(strcmp(syscall_name(426, buf, sizeof(buf)), "io_uring_enter") == 0);
    assert(strcmp(syscall_name(35, buf, sizeof(buf)), "nanosleep") == 0);
    printf("  PASS: syscall_name new entries\n");
}

void test_read_proc_file_zero_bufsize(void)
{
    char buf[4] = {'x', 'x', 'x', 'x'};
    assert(read_proc_file("/proc/self/stat", buf, 0) == -1);
    assert(read_proc_line("/proc/self/stat", buf, 0) == -1);
    assert(read_proc_link("/proc/self/exe", buf, 0) == -1);
    assert(buf[0] == 'x');
    printf("  PASS: proc helpers reject bufsize 0\n");
}

void test_parse_stat_line_basic(void)
{
    dstate_process_t p;
    memset(&p, 0, sizeof(p));
    const char *line = "1234 (cat) D 1000 1234 1000 34816 1234 4194304 100 0 0 0 5 6 0 0 20 0 3 0 99999 5951488 437 18446744073709551615 1 1 0";
    assert(parse_stat_line(line, &p) == 0);
    assert(strcmp(p.comm, "cat") == 0);
    assert(p.state == 'D');
    assert(p.ppid == 1000);
    assert(p.utime == 5 && p.stime == 6);
    assert(p.num_threads == 3);
    assert(p.start_time == 99999);
    assert(p.vm_size == 5951488 / 1024);
    printf("  PASS: parse_stat_line basic\n");
}

void test_parse_stat_line_odd_comm(void)
{
    dstate_process_t p;
    memset(&p, 0, sizeof(p));
    const char *line = "42 (a b) c) S 1 42 42 0 -1 4194560 10 0 0 0 1 2 0 0 20 0 1 0 500 4096 7 0";
    assert(parse_stat_line(line, &p) == 0);
    assert(strcmp(p.comm, "a b) c") == 0);
    assert(p.state == 'S');
    assert(p.ppid == 1);
    printf("  PASS: parse_stat_line comm with spaces and parentheses\n");
}

void test_parse_stat_line_malformed(void)
{
    dstate_process_t p;
    memset(&p, 0, sizeof(p));
    assert(parse_stat_line("42 (x)", &p) == -1);
    assert(parse_stat_line("42 (x) ", &p) == -1);
    assert(parse_stat_line("42 (x) S 1 2", &p) == -1);
    assert(parse_stat_line("no parens here", &p) == -1);
    assert(parse_stat_line("42 )x( S 1", &p) == -1);
    printf("  PASS: parse_stat_line malformed input\n");
}

void test_parse_syscall_line_in_syscall(void)
{
    dstate_process_t p;
    memset(&p, 0, sizeof(p));
    assert(parse_syscall_line("0 0x3 0x7f56a65c5000 0x40000 0x0 0x0 0x0 0x7ffe6acee8f0 0x7f56a66f2687", &p) == 0);
    assert(p.syscall_nr == 0);
    assert(p.syscall_args[0] == 3);
    assert(p.syscall_args[1] == 0x7f56a65c5000UL);
    assert(p.stack_ptr == 0x7ffe6acee8f0UL);
    assert(p.instruction_ptr == 0x7f56a66f2687UL);
    printf("  PASS: parse_syscall_line in-syscall form\n");
}

void test_parse_syscall_line_not_in_syscall(void)
{
    dstate_process_t p;
    memset(&p, 0, sizeof(p));
    assert(parse_syscall_line("-1 0x7ffe6acee8f0 0x55a1b2c00a32", &p) == 0);
    assert(p.syscall_nr == -1);
    assert(p.stack_ptr == 0x7ffe6acee8f0UL);
    assert(p.instruction_ptr == 0x55a1b2c00a32UL);

    memset(&p, 0, sizeof(p));
    assert(parse_syscall_line("running", &p) == 0);
    assert(p.syscall_nr == -1 && p.stack_ptr == 0);
    printf("  PASS: parse_syscall_line -1 SP PC form and running\n");
}

void test_parse_syscall_line_partial(void)
{
    dstate_process_t p;
    memset(&p, 0, sizeof(p));
    assert(parse_syscall_line("0 0x3 0x7f56a65c5000", &p) == -1);
    assert(p.syscall_nr == -1);
    assert(p.syscall_args[0] == 0);
    assert(parse_syscall_line("-1 0x7ffe", &p) == -1);
    assert(parse_syscall_line("", &p) == -1);
    printf("  PASS: parse_syscall_line rejects partial lines\n");
}

void test_parse_lock_line_flock(void)
{
    lock_entry_t l;
    assert(parse_lock_line("2: FLOCK  ADVISORY  WRITE 2345 00:2a:1234 0 EOF", &l) == 0);
    assert(!l.blocked);
    assert(strcmp(l.lock_type, "FLOCK") == 0);
    assert(strcmp(l.access, "WRITE") == 0);
    assert(l.pid == 2345);
    assert(l.dev_major == 0 && l.dev_minor == 0x2a);
    assert(l.inode == 1234);
    printf("  PASS: parse_lock_line inode is decimal, dev is hex\n");
}

void test_parse_lock_line_variants(void)
{
    lock_entry_t l;
    assert(parse_lock_line("3: OFDLCK ADVISORY  READ -1 08:01:131077 0 EOF", &l) == 0);
    assert(l.pid == -1);
    assert(strcmp(l.access, "READ") == 0);
    assert(l.dev_major == 8 && l.dev_minor == 1 && l.inode == 131077);

    assert(parse_lock_line("1: -> POSIX  ADVISORY  WRITE 77 fd:00:99 0 EOF", &l) == 0);
    assert(l.blocked);
    assert(l.pid == 77 && l.dev_major == 0xfd && l.inode == 99);

    assert(parse_lock_line("garbage", &l) == -1);
    assert(parse_lock_line("4: POSIX ADVISORY WRITE", &l) == -1);
    printf("  PASS: parse_lock_line OFD, waiter and malformed lines\n");
}

void test_file_offset_to_vaddr(void)
{
    char path[] = "/tmp/dstate_elf_XXXXXX";
    int fd = mkstemp(path);
    assert(fd >= 0);

    Elf64_Ehdr eh;
    memset(&eh, 0, sizeof(eh));
    memcpy(eh.e_ident, ELFMAG, SELFMAG);
    eh.e_ident[EI_CLASS] = ELFCLASS64;
    eh.e_ident[EI_DATA] = ELFDATA2LSB;
    eh.e_type = ET_EXEC;
    eh.e_phoff = sizeof(eh);
    eh.e_phentsize = sizeof(Elf64_Phdr);
    eh.e_phnum = 2;

    Elf64_Phdr ph[2];
    memset(ph, 0, sizeof(ph));
    ph[0].p_type = PT_LOAD;
    ph[0].p_offset = 0;
    ph[0].p_vaddr = 0x400000;
    ph[0].p_filesz = 0x1000;
    ph[1].p_type = PT_LOAD;
    ph[1].p_offset = 0x1000;
    ph[1].p_vaddr = 0x401000;
    ph[1].p_filesz = 0x2000;

    assert(write(fd, &eh, sizeof(eh)) == (ssize_t)sizeof(eh));
    assert(write(fd, ph, sizeof(ph)) == (ssize_t)sizeof(ph));
    close(fd);

    assert(file_offset_to_vaddr(path, 0x10) == 0x400010);
    assert(file_offset_to_vaddr(path, 0x1234) == 0x401234);
    assert(file_offset_to_vaddr(path, 0x9000) == 0x9000);
    unlink(path);

    assert(file_offset_to_vaddr(path, 0x1234) == 0x1234);
    assert(file_offset_to_vaddr("/proc/self/stat", 0x55) == 0x55);
    printf("  PASS: file_offset_to_vaddr maps PT_LOAD and falls back\n");
}

void test_fprint_safe(void)
{
    char *out = NULL;
    size_t len = 0;
    FILE *f = open_memstream(&out, &len);
    assert(f);

    fprint_safe(f, "a\033[31mb\n\x7f" "c", 0, 0);
    fputc('|', f);
    fprint_safe(f, "abcdef", 3, 5);
    fputc('|', f);
    fprint_safe(f, "xy", 0, 4);
    fputc('|', f);
    fprint_safe(f, "\xce\xb1\xc2\x9b" "1m\x9b\xc2\xa9\xe2\x82\xac\xff", 0, 0);
    fputc('|', f);
    /* overlong CSI, truncated sequence before ASCII, lone lead byte, surrogate */
    fprint_safe(f, "\xe0\x80\x9b\xf0\x80\x80\x9b\xe2\x9b[\xc2" "a\xed\xa0\x80\xc2", 0, 0);
    fputc('|', f);
    /* a multi-byte character is never cut in half by maxlen */
    fprint_safe(f, "ab\xe2\x82\xac", 4, 0);
    fclose(f);

    assert(strcmp(out, "a?[31mb??c|abc  |xy  |\xce\xb1??1m?\xc2\xa9\xe2\x82\xac?|?????????[?a????|ab") == 0);
    free(out);
    printf("  PASS: fprint_safe replaces control bytes and C1 controls, keeps UTF-8, truncates and pads\n");
}

void test_read_process_maps_self(void)
{
    process_maps_t maps;
    memset(&maps, 0, sizeof(maps));

    assert(read_process_maps(getpid(), &maps) == 0);
    assert(maps.count > 0 && maps.entries != NULL);

    int has_stack = 0;
    for (int i = 0; i < maps.count; ++i)
    {
        if (strcmp(maps.entries[i].path, "[stack]") == 0)
            has_stack = 1;
    }
    assert(has_stack);

    free_process_maps(&maps);
    assert(maps.entries == NULL && maps.count == 0);
    free_process_maps(&maps);
    printf("  PASS: read_process_maps self, free is idempotent\n");
}

void test_is_indirect_call(void)
{
#define YES(...) do { unsigned char b[] = {__VA_ARGS__}; assert(is_indirect_call(b, sizeof(b))); } while (0)
#define NO(...) do { unsigned char b[] = {__VA_ARGS__}; assert(!is_indirect_call(b, sizeof(b))); } while (0)
    YES(0xFF, 0xD0);
    YES(0xFF, 0x10);
    YES(0xFF, 0x50, 0x08);
    YES(0x41, 0xFF, 0xD0);
    YES(0xFF, 0x14, 0x24);
    YES(0xFF, 0x15, 1, 2, 3, 4);
    YES(0x41, 0xFF, 0x15, 1, 2, 3, 4);
    YES(0xFF, 0x90, 1, 2, 3, 4);
    YES(0x41, 0xFF, 0x90, 1, 2, 3, 4);
    YES(0x41, 0xFF, 0x94, 0x24, 1, 2, 3, 4);
    NO(0xFF, 0xD0, 0x90);
    NO(0xFF, 0x20);
    NO(0xFF, 0x50);
    NO(0xFF, 0x15, 1);
    NO(0xFF, 0x50, 0x08, 0, 0, 0);
#undef YES
#undef NO
    printf("  PASS: is_indirect_call encodings and lengths\n");
}

void test_lock_blocks_waiter(void)
{
    lock_entry_t l;
    memset(&l, 0, sizeof(l));
    strcpy(l.lock_type, "FLOCK");
    strcpy(l.access, "READ");

    assert(lock_blocks_waiter(&l, 73, LOCK_EX));
    assert(!lock_blocks_waiter(&l, 73, LOCK_SH));
    assert(!lock_blocks_waiter(&l, 73, LOCK_UN));
    strcpy(l.access, "WRITE");
    assert(lock_blocks_waiter(&l, 73, LOCK_SH));
    assert(!lock_blocks_waiter(&l, 72, 0));
    strcpy(l.lock_type, "POSIX");
    assert(lock_blocks_waiter(&l, 72, 0));
    assert(!lock_blocks_waiter(&l, 73, LOCK_EX));
    strcpy(l.lock_type, "OFDLCK");
    assert(lock_blocks_waiter(&l, 72, 0));
    printf("  PASS: lock_blocks_waiter flock and fcntl compatibility\n");
}

void test_lock_is_better(void)
{
    lock_entry_t r, w;
    memset(&r, 0, sizeof(r));
    memset(&w, 0, sizeof(w));
    strcpy(r.access, "READ");
    strcpy(w.access, "WRITE");

    assert(lock_is_better(NULL, &r));
    assert(lock_is_better(&r, &w));
    assert(!lock_is_better(&w, &r));
    assert(!lock_is_better(&w, &w));
    assert(!lock_is_better(&r, &r));
    printf("  PASS: lock_is_better prefers WRITE over READ\n");
}

void test_file_offset_to_vaddr_bad_files(void)
{
    char path[] = "/tmp/dstate_elf_XXXXXX";
    int fd = mkstemp(path);
    assert(fd >= 0);

    Elf64_Ehdr eh;
    memset(&eh, 0, sizeof(eh));
    memcpy(eh.e_ident, ELFMAG, SELFMAG);
    eh.e_ident[EI_CLASS] = ELFCLASS64;
    eh.e_ident[EI_DATA] = ELFDATA2LSB;
    eh.e_phoff = sizeof(eh);
    eh.e_phentsize = sizeof(Elf64_Phdr);
    eh.e_phnum = 2;
    assert(write(fd, &eh, sizeof(eh)) == (ssize_t)sizeof(eh));
    close(fd);
    assert(file_offset_to_vaddr(path, 0x42) == 0x42);

    fd = open(path, O_WRONLY | O_TRUNC);
    assert(fd >= 0);
    eh.e_phnum = 0xFFFF;
    assert(write(fd, &eh, sizeof(eh)) == (ssize_t)sizeof(eh));
    close(fd);
    assert(file_offset_to_vaddr(path, 0x42) == 0x42);

    fd = open(path, O_WRONLY | O_TRUNC);
    assert(fd >= 0);
    assert(write(fd, &eh, 20) == 20);
    close(fd);
    assert(file_offset_to_vaddr(path, 0x42) == 0x42);
    unlink(path);

    char fifo[] = "/tmp/dstate_fifo_XXXXXX";
    assert(mkdtemp(fifo) != NULL);
    char fifo_path[64];
    snprintf(fifo_path, sizeof(fifo_path), "%s/f", fifo);
    assert(mkfifo(fifo_path, 0600) == 0);
    assert(file_offset_to_vaddr(fifo_path, 0x42) == 0x42);
    char f[16], src[16];
    resolve_symbol(fifo_path, 0x42, f, sizeof(f), src, sizeof(src));
    assert(strcmp(f, "??") == 0);
    unlink(fifo_path);
    rmdir(fifo);
    printf("  PASS: file_offset_to_vaddr truncated, absurd e_phnum and FIFO\n");
}

void test_read_process_maps_growth(void)
{
    size_t page = 4096, pages = 800;
    char *base = mmap(NULL, pages * page, PROT_NONE, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    assert(base != MAP_FAILED);
    for (size_t i = 0; i < pages; i += 2)
        assert(mprotect(base + i * page, page, PROT_READ) == 0);

    process_maps_t maps;
    memset(&maps, 0, sizeof(maps));
    assert(read_process_maps(getpid(), &maps) == 0);
    assert(maps.count > MAPS_INITIAL_CAPACITY);

    int has_stack = 0;
    for (int i = 0; i < maps.count; ++i)
    {
        if (strcmp(maps.entries[i].path, "[stack]") == 0)
            has_stack = 1;
    }
    assert(has_stack);

    free_process_maps(&maps);
    munmap(base, pages * page);
    printf("  PASS: read_process_maps grows past the initial capacity\n");
}

int main(void)
{
    printf("Running unit tests...\n\n");

    printf("[syscall_name]\n");
    test_syscall_name_known();
    test_syscall_name_unknown();
    test_syscall_name_negative();
    test_syscall_name_new_entries();

    printf("\n[build_proc_path]\n");
    test_build_proc_path_normal();
    test_build_proc_path_buffer_too_small();
    test_build_proc_path_exact_fit();
    test_build_proc_path_one_byte_short();

    printf("\n[is_pid_dir]\n");
    test_is_pid_dir_valid();
    test_is_pid_dir_invalid();

    printf("\n[read_proc_*]\n");
    test_read_proc_file_zero_bufsize();

    printf("\n[parsers]\n");
    test_parse_stat_line_basic();
    test_parse_stat_line_odd_comm();
    test_parse_stat_line_malformed();
    test_parse_syscall_line_in_syscall();
    test_parse_syscall_line_not_in_syscall();
    test_parse_syscall_line_partial();
    test_parse_lock_line_flock();
    test_parse_lock_line_variants();

    printf("\n[helpers]\n");
    test_file_offset_to_vaddr();
    test_fprint_safe();
    test_read_process_maps_self();
    test_read_process_maps_growth();
    test_file_offset_to_vaddr_bad_files();
    test_is_indirect_call();
    test_lock_blocks_waiter();
    test_lock_is_better();

    printf("\nAll tests passed.\n");
    return 0;
}