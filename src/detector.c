#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <dirent.h>
#include <ctype.h>

#include "../include/dstate.h"
#include "../include/proc_utils.h"

static int is_pid_dir(const char *name)
{
    if (!name || !*name)
        return 0;

    while (*name)
    {
        if (!isdigit((unsigned char)*name))
            return 0;
        name++;
    }

    return 1;
}

static char get_process_state(pid_t pid)
{
    char path[64];
    char buffer[512];
    char *state_ptr;

    snprintf(path, sizeof(path), "/proc/%d/stat", pid);

    if (read_proc_file(path, buffer, sizeof(buffer)) < 0)
        return '\0';

    state_ptr = strrchr(buffer, ')');
    if (!state_ptr || state_ptr[1] != ' ')
        return '\0';

    return state_ptr[2];
}

int is_process_dstate(pid_t pid)
{
    return (get_process_state(pid) == 'D');
}

int find_dstate_processes(dstate_process_t **results, int *count)
{
    DIR *proc_dir;
    struct dirent *entry;
    dstate_process_t *list;
    int capacity = 32;
    int num_found = 0;

    proc_dir = opendir("/proc");
    if (!proc_dir)
    {
        perror("opendir /proc");
        return -1;
    }

    list = malloc(sizeof(dstate_process_t) * capacity);
    if (!list)
    {
        closedir(proc_dir);
        return -1;
    }

    while ((entry = readdir(proc_dir)) != NULL)
    {
        pid_t pid;

        if (!is_pid_dir(entry->d_name))
            continue;

        pid = (pid_t)atoi(entry->d_name);

        dstate_process_t tmp;
        memset(&tmp, 0, sizeof(tmp));
        tmp.pid = pid;

        if (read_process_stat(pid, &tmp) < 0)
            continue;

        if (tmp.state != 'D')
            continue;

        if (num_found >= capacity)
        {
            capacity *= 2;
            dstate_process_t *new_list = realloc(list, sizeof(dstate_process_t) * capacity);
            if (!new_list)
            {
                free(list);
                closedir(proc_dir);
                return -1;
            }

            list = new_list;
        }

        list[num_found] = tmp;
        read_process_wchan(pid, list[num_found].wchan, sizeof(list[num_found].wchan));
        read_process_syscall(pid, &list[num_found]);

        num_found++;
    }

    closedir(proc_dir);

    if (num_found > 0)
    {
        dstate_process_t *final = realloc(list, sizeof(dstate_process_t) * num_found);
        if (final)
            list = final;
    }
    else
    {
        free(list);
        list = NULL;
    }

    *results = list;
    *count = num_found;

    return 0;
}

void free_dstate_list(dstate_process_t *list)
{
    free(list);
}

void print_dstate_summary(const dstate_process_t *procs, int count)
{
    printf("\n=== D-State Processes Found: %d ===\n", count);
    if (count == 0)
    {
        printf("No processes in D-State.\n");
        return;
    }

    printf("%-8s %-20s %-8s %-30s\n", "PID", "COMMAND", "STATE", "WAITING IN");
    printf("%-8s %-20s %-8s %-30s\n", "---", "-------", "-----", "----------");

    for (int i = 0; i < count; ++i)
    {
        const dstate_process_t *p = &procs[i];
        printf("%-8d %-20.20s %-8c %-30.30s\n",
               p->pid,
               p->comm[0] ? p->comm : "(unknown)",
               p->state,
               p->wchan[0] ? p->wchan : "(unknown)");
    }
    printf("\n");
}
