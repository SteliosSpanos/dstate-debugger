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