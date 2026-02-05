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