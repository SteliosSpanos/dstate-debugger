#include <assert.h>
#include <stdio.h>
#include <string.h>

#include "../include/dstate.h"
#include "../include/proc_utils.h"

void test_syscall_name_known(void)
{
    assert(strcmp(syscall_name(0), "read") == 0);
    assert(strcmp(syscall_name(1), "write") == 0);
    assert(strcmp(syscall_name(59), "execve") == 0);
    printf("  PASS: syscall_name known values\n");
}

void test_syscall_name_unknown(void)
{
    const char *name = syscall_name(999);
    assert(strncmp(name, "syscall_", 8) == 0);
    printf("  PASS: syscall_name unknown value\n");
}

void test_syscall_name_negative(void)
{
    assert(strcmp(syscall_name(-1), "(not in syscall)") == 0);
    assert(strcmp(syscall_name(-100), "(not in syscall)") == 0);
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

int main(void)
{
    printf("Running unit tests...\n\n");

    printf("[syscall_name]\n");
    test_syscall_name_known();
    test_syscall_name_unknown();
    test_syscall_name_negative();

    printf("\n[build_proc_path]\n");
    test_build_proc_path_normal();
    test_build_proc_path_buffer_too_small();
    test_build_proc_path_exact_fit();
    test_build_proc_path_one_byte_short();

    printf("\n[is_pid_dir]\n");
    test_is_pid_dir_valid();
    test_is_pid_dir_invalid();

    printf("\nAll test passed.\n");
    return 0;
}