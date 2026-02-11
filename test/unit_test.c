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

test_build_proc_path_buffer_too_small(void)
{
    char buffer[5];
    char *result = build_proc_path(buffer, sizeof(buffer), 1234, "stat");
    assert(result == NULL);
    printf("  PASS: build_proc_path buffer overflow returns NULL\n");
}
