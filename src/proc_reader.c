#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <errno.h>

#include "../include/dstate.h"
#include "../include/proc_utils.h"

static const char *syscall_names[] = {
	[0] = "read",
	[1] = "write",
	[2] = "open",
	[3] = "close",
	[4] = "stat",
	[5] = "fstat",
	[6] = "lstat",
	[7] = "poll",
	[8] = "lseek",
	[9] = "mmap",
	[10] = "mprotect",
	[11] = "munmap",
	[16] = "ioctl",
	[17] = "pread64",
	[18] = "pwrite64",
	[19] = "readv",
	[20] = "writev",
	[21] = "access",
	[22] = "pipe",
	[23] = "select",
	[32] = "dup",
	[33] = "dup2",
	[35] = "nanosleep",
	[39] = "getpid",
	[41] = "socket",
	[42] = "connect",
	[43] = "accept",
	[44] = "sendto",
	[45] = "recvfrom",
	[56] = "clone",
	[57] = "fork",
	[59] = "execve",
	[60] = "exit",
	[61] = "wait4",
	[62] = "kill",
	[78] = "getdents",
	[79] = "getcwd",
	[80] = "chdir",
	[82] = "rename",
	[83] = "mkdir",
	[84] = "rmdir",
	[85] = "creat",
	[87] = "unlink",
	[89] = "readlink",
	[90] = "chmod",
	[217] = "getdents64",
	[257] = "openat",
	[262] = "newfstatat",
	[288] = "accept4",
};

#define SYSCALL_TABLE_SIZE (sizeof(syscall_names) / sizeof(syscall_names[0]))

const char *syscall_name(long nr)
{
	static char unknown[32];

	if (nr < 0)
		return "(not in syscall)";

	if ((size_t)nr < SYSCALL_TABLE_SIZE && syscall_names[nr])
		return syscall_names[nr];

	snprintf(unknown, sizeof(unknown), "syscall_%ld", nr);
	return unknown;
}

int read_process_stat(pid_t pid, dstate_process_t *proc)
{
	char path[64];
	char buffer[1024];
	char *ptr;
	char *comm_start, *comm_end;

	snprintf(path, sizeof(path), "/proc/%d/stat", pid);

	if (read_proc_file(path, buffer, sizeof(buffer)) < 0)
		return -1;

	comm_start = strchr(buffer, '(');
	comm_end = strrchr(buffer, ')');

	if (comm_start && comm_end && comm_end > comm_start)
	{
		size_t comm_len = comm_end - comm_start - 1;
		if (comm_len >= sizeof(proc->comm))
			comm_len = sizeof(proc->comm) - 1;

		strncpy(proc->comm, comm_start + 1, comm_len);
		proc->comm[comm_len] = '\0';

		ptr = comm_end + 2;
	}
	else
		return -1;

	int parsed = sscanf(ptr,
						"%c %d %*d %*d %*d %*d %*u "
						"%*u %*u %*u %*u "
						"%lu %lu %*d %*d "
						"%*d %*d %d "
						"%*d %llu "
						"%lu %lu",
						&proc->state,
						&proc->ppid,
						&proc->utime,
						&proc->stime,
						&proc->num_threads,
						&proc->start_time,
						&proc->vm_size,
						&proc->vm_rss);

	if (parsed < 2)
		return -1;

	long page_size = sysconf(_SC_PAGESIZE);
	if (page_size > 0)
		proc->vm_rss = (proc->vm_rss * page_size) / 1024;

	proc->vm_size /= 1024;

	return 0;
}

int read_process_status(pid_t pid, dstate_process_t *proc)
{
	char path[64];
	char line[256];
	FILE *fp;

	snprintf(path, sizeof(path), "/proc/%d/status", pid);

	fp = fopen(path, "r");
	if (!fp)
		return -1;

	while (fgets(line, sizeof(line), fp))
	{
		char key[32];
		char value[128];

		if (parse_status_line(line, key, sizeof(key), value, sizeof(value)))
		{
			if (strcmp(key, "Tgid") == 0)
				proc->tgid = atoi(value);
			else if (strcmp(key, "Ppid") == 0)
				proc->ppid = atoi(value);
			else if (strcmp(key, "Threads") == 0)
				proc->num_threads = atoi(value);
			else if (strcmp(key, "VmSize") == 0)
				proc->vm_size = strtol(value, NULL, 10);
			else if (strcmp(key, "VmRSS") == 0)
				proc->vm_rss = strtol(value, NULL, 10);
		}
	}

	fclose(fp);
	return 0;
}

int read_process_wchan(pid_t pid, char *wchan, size_t len)
{
	char path[64];

	snprintf(path, sizeof(path), "/proc/%d/wchan", pid);

	if (read_proc_line(path, wchan, len) < 0)
	{
		strncpy(wchan, "(unknown)", len - 1);
		wchan[len - 1] = '\0';
		return -1;
	}

	if (strcmp(wchan, "0") == 0)
	{
		strncpy(wchan, "(running)", len - 1);
		wchan[len - 1] = '\0';
		return -1;
	}

	return 0;
}

int read_process_syscall(pid_t pid, dstate_process_t *proc)
{
	char path[64];
	char buffer[256];

	snprintf(path, sizeof(path), "/proc/%d/syscall", pid);

	proc->syscall_nr = -1;

	if (read_proc_line(path, buffer, sizeof(buffer)) < 0)
		return -1;

	if (strncmp(buffer, "-1", 2) == 0)
		return 0;

	int parsed = sscanf(buffer,
						"%ld %lx %lx %lx %lx %lx %lx %lx %lx",
						&proc->syscall_nr,
						&proc->syscall_args[0],
						&proc->syscall_args[1],
						&proc->syscall_args[2],
						&proc->syscall_args[3],
						&proc->syscall_args[4],
						&proc->syscall_args[5],
						&proc->stack_ptr,
						&proc->instruction_ptr);

	if (parsed < 1)
	{
		proc->syscall_nr = -1;
		return -1;
	}

	return 0;
}

int read_process_stack(pid_t pid, char *stack, size_t len)
{
	char path[64];

	snprintf(path, sizeof(path), "/proc/%d/stack", pid);

	ssize_t bytes = read_proc_file(path, stack, len);

	if (bytes < 0)
	{
		snprintf(stack, len, "(Cannot read kernel stack - requires root or CAP_SYS_PTRACE)");
		return -1;
	}

	if (bytes == 0)
	{
		snprintf(stack, len, "(empty - process may not be in kernel)");
	}

	return 0;
}

int read_full_diagnostics(pid_t pid, process_diagnostics_t *diag)
{
	char path[128];
	ssize_t bytes_read;

	memset(diag, 0, sizeof(*diag));
	diag->blocking_fd = -1;
	diag->basic.pid = pid;

	if (read_process_stat(pid, &diag->basic) < 0)
		return -1;

	read_process_status(pid, &diag->basic);

	read_process_wchan(pid, diag->basic.wchan, sizeof(diag->basic.wchan));

	read_process_syscall(pid, &diag->basic);

	if (read_process_stack(pid, diag->kernel_stack, sizeof(diag->kernel_stack)) == 0)
		diag->kernel_stack_valid = 1;

	if (build_proc_path(path, sizeof(path), pid, "exe"))
		read_proc_link(path, diag->exe, sizeof(diag->exe));

	if (build_proc_path(path, sizeof(path), pid, "cwd"))
		read_proc_link(path, diag->cwd, sizeof(diag->cwd));

	if (build_proc_path(path, sizeof(path), pid, "cmdline"))
	{
		bytes_read = read_proc_file(path, diag->cmdline, sizeof(diag->cmdline));

		if (bytes_read > 0)
		{
			for (int i = 0; i < (int)bytes_read - 1; ++i)
			{
				if (diag->cmdline[i] == '\0')
					diag->cmdline[i] = ' ';
			}
		}
	}

	if (diag->basic.syscall_nr != -1 && (diag->basic.state == 'D' || diag->basic.state == 'S'))
	{
		int target_fd = -1;

		if (diag->basic.syscall_nr == 0 || diag->basic.syscall_nr == 1)
			target_fd = (int)diag->basic.syscall_args[0];

		if (target_fd >= 0)
		{
			diag->blocking_fd = target_fd;

			snprintf(path, sizeof(path), "/proc/%d/fd/%d", pid, target_fd);
			read_proc_link(path, diag->blocking_path, sizeof(diag->blocking_path));
		}
	}

	return 0;
}
