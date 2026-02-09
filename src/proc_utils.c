#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <fcntl.h>
#include <errno.h>
#include <time.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <sys/capability.h>

#include "../include/proc_utils.h"

ssize_t read_proc_file(const char *path, char *buffer, size_t bufsize)
{
    int fp;
    ssize_t total = 0;
    ssize_t n;

    fp = open(path, O_RDONLY);
    if (fp < 0)
        return -1;

    while (total < (ssize_t)bufsize - 1)
    {
        n = read(fp, buffer + total, bufsize - 1 - total);

        if (n < 0)
        {
            close(fp);
            return -1;
        }

        if (n == 0)
            break;

        total += n;
    }

    buffer[total] = '\0';
    close(fp);
    return total;
}

ssize_t read_proc_line(const char *path, char *buffer, size_t bufsize)
{

    FILE *fp;

    fp = fopen(path, "r");
    if (!fp)
        return -1;

    if (fgets(buffer, bufsize, fp) == NULL)
    {
        fclose(fp);
        return -1;
    }

    fclose(fp);

    ssize_t len = strlen(buffer);
    if (len > 0 && buffer[len - 1] == '\n')
    {
        buffer[len - 1] = '\0';
        len--;
    }

    return len;
}

ssize_t read_proc_link(const char *path, char *buffer, size_t bufsize)
{
    ssize_t len;

    if (bufsize == 0)
        return -1;

    len = readlink(path, buffer, bufsize - 1);

    if (len < 0)
    {
        buffer[0] = '\0';
        return -1;
    }

    buffer[len] = '\0';
    return len;
}

char *build_proc_path(char *buffer, size_t bufsize, pid_t pid, const char *file)
{
    int n;

    n = snprintf(buffer, bufsize, "/proc/%d/%s", pid, file);

    if (n < 0 || (size_t)n >= bufsize)
        return NULL;

    return buffer;
}

int pid_exists(pid_t pid)
{
    char path[32];
    struct stat st;

    snprintf(path, sizeof(path), "/proc/%d", pid);

    return (stat(path, &st) == 0);
}

int parse_status_line(const char *line, char *key, size_t keylen, char *value, size_t vallen)
{
    const char *colon;
    const char *val_start;
    size_t key_len;

    colon = strchr(line, ":");
    if (!colon)
        return 0;

    key_len = colon - line;
    if (key_len >= keylen)
        key_len = keylen - 1;

    strncpy(key, line, key_len);
    key[key_len] = '\0';

    val_start = colon + 1;
    while (*val_start == ' ' || *val_start == '\t')
        val_start++;

    strncpy(value, val_start, vallen - 1);
    value[vallen - 1] = '\0';

    size_t val_len = strlen(value);
    if (val_len > 0 && value[val_len - 1] == '\n')
        value[val_len - 1] = '\0';

    return 1;
}

double ticks_to_seconds(unsigned long ticks)
{
    static long ticks_per_sec = 0;

    if (ticks_per_sec == 0)
    {
        ticks_per_sec = sysconf(_SC_CLK_TCK);
        if (ticks_per_sec <= 0)
            ticks_per_sec = 100;
    }

    return (double)ticks / ticks_per_sec;
}

void format_size(unsigned long bytes, char *buffer, size_t bufsize)
{
    const char *units[] = {"B", "KB", "MB", "GB", "TB"};
    int unit_index = 0;
    double size = bytes;

    while (size >= 1024.0 && unit_index < 4)
    {
        size /= 1024.0;
        unit_index++;
    }

    snprintf(buffer, bufsize, "%.1f %s", size, units[unit_index]);
}

uint64_t get_timestamp()
{
    return (uint64_t)time(NULL);
}

int is_root()
{
    return (geteuid() == 0);
}

int has_ptrace_capability()
{
    cap_t caps;
    cap_flag_value_t value;
    int result = 0;

    caps = cap_get_proc();
    if (caps == NULL)
        return 0;

    if (cap_get_flag(caps, CAP_SYS_PTRACE, CAP_EFFECTIVE, &value) == 0)
        result = (value == CAP_SET);

    cap_free(caps);
    return result;
}
