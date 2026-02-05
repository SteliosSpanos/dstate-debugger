#ifndef PROC_UTILS_H
#define PROC_UTILS_H

#include <sys/types.h>
#include <stddef.h>
#include <stdint.h>

ssize_t read_proc_file(const char *path, char *buffer, size_t bufsize);

ssize_t read_proc_line(const char *path, char *buffer, size_t bufsize);

ssize_t read_proc_link(const char *path, char *buffer, size_t bufsize);

char *build_proc_path(char *buffer, size_t bufsize, pid_t pid, const char *file);

int pid_exists(pid_t pid);

int parse_status_line(const char *line, char *key, size_t keylen, char *value, size_t vallen);

double ticks_to_seconds(unsigned long ticks);

void format_size(unsigned long bytes, char *buffer, size_t bufsize);

uint64_t get_timestamp();

int has_ptrace_capability();

#endif