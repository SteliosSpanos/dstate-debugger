#ifndef PROC_UTILS_H
#define PROC_UTILS_H

#include <sys/types.h>
#include <stddef.h>

ssize_t read_proc_file(const char *path, char *buffer, size_t bufsize);

ssize_t read_proc_line(const char *path, char *buffer, size_t bufsize);

ssize_t read_proc_link(const char *path, char *buffer, size_t bufsize);

char *build_proc_path(char *buffer, size_t bufsize, pid_t pid, const char *file);

#endif
