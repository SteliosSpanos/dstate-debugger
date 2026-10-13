#ifndef _GNU_SOURCE
#define _GNU_SOURCE
#endif

#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <fcntl.h>
#include <limits.h>

#include "../include/proc_utils.h"

ssize_t read_proc_file(const char *path, char *buffer, size_t bufsize)
{
    int fp;
    ssize_t total = 0;
    ssize_t n;

    if (bufsize == 0)
        return -1;

    fp = open(path, O_RDONLY | O_CLOEXEC);
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

    if (bufsize == 0 || bufsize > INT_MAX)
        return -1;

    fp = fopen(path, "r");
    if (!fp)
        return -1;

    if (fgets(buffer, (int)bufsize, fp) == NULL)
    {
        fclose(fp);
        return -1;
    }

    fclose(fp);

    ssize_t len = (ssize_t)strlen(buffer);
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

/* Length of the well-formed UTF-8 sequence at s that encodes a printable
 * code point, or 0 if there is none (malformed, overlong, surrogate,
 * out of range, or a control character). */
static int printable_utf8_len(const unsigned char *s)
{
    unsigned char c = s[0];
    uint32_t cp, min;
    int len;

    if (c < 0x80)
        return (c >= 0x20 && c != 0x7f) ? 1 : 0;

    if (c >= 0xC2 && c <= 0xDF)
    {
        len = 2;
        cp = c & 0x1F;
        min = 0xA0; /* U+0080 to U+009F are C1 controls */
    }
    else if (c >= 0xE0 && c <= 0xEF)
    {
        len = 3;
        cp = c & 0x0F;
        min = 0x800;
    }
    else if (c >= 0xF0 && c <= 0xF4)
    {
        len = 4;
        cp = c & 0x07;
        min = 0x10000;
    }
    else
        return 0;

    for (int i = 1; i < len; ++i)
    {
        if ((s[i] & 0xC0) != 0x80) /* also stops at the terminating NUL */
            return 0;
        cp = (cp << 6) | (s[i] & 0x3F);
    }

    if (cp < min || cp > 0x10FFFF || (cp >= 0xD800 && cp <= 0xDFFF))
        return 0;

    return len;
}

void fprint_safe(FILE *out, const char *s, int maxlen, int pad)
{
    const unsigned char *p = (const unsigned char *)s;
    int printed = 0;

    while (*p && (maxlen <= 0 || printed < maxlen))
    {
        int len = printable_utf8_len(p);

        if (len == 0)
        {
            fputc('?', out);
            ++p;
            ++printed;
            continue;
        }

        if (maxlen > 0 && printed + len > maxlen)
            break;

        fwrite(p, 1, (size_t)len, out);
        p += len;
        printed += len;
    }

    for (; printed < pad; ++printed)
        fputc(' ', out);
}
