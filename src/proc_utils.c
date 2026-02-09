#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <fcntl.h>

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
