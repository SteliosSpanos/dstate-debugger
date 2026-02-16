#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <errno.h>
#include <signal.h>
#include <fcntl.h>

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
		return 0;
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

	if (strncmp(buffer, "running", 7) == 0)
		return 0;

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
	{
		if (kill(pid, 0) == -1 && errno == ESRCH)
			return DSTATE_PROC_GONE;
		return -1;
	}

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
		long nr = diag->basic.syscall_nr;

		if (nr == 0 || nr == 1 ||
			nr == 16 || nr == 17 ||
			nr == 18 || nr == 19 ||
			nr == 20 || nr == 44 ||
			nr == 45)
			target_fd = (int)diag->basic.syscall_args[0];

		if (target_fd >= 0)
		{
			diag->blocking_fd = target_fd;

			snprintf(path, sizeof(path), "/proc/%d/fd/%d", pid, target_fd);
			read_proc_link(path, diag->blocking_path, sizeof(diag->blocking_path));
		}
	}

	read_process_maps(pid, &diag->maps);

	read_user_stack(pid, diag);

	return 0;
}

void print_diagnostics(const process_diagnostics_t *diag)
{
	const dstate_process_t *p = &diag->basic;

	printf("\n");
	printf("====================================================\n");
	printf("   PROCESS DIAGNOSTICS: PID - %d\n", p->pid);
	printf("====================================================\n");

	printf("\nBasic Information:\n");
	printf("   Command:      %-48s\n", p->comm);
	printf("   State:        %c\n", p->state);
	printf("   Parent PID:   %-48d\n", p->ppid);
	printf("   Threads:      %-48d\n", p->num_threads);

	printf("\nExecutable & Working Directory:\n");
	printf("   Exe: %-55.55s\n", diag->exe[0] ? diag->exe : "(unknown)");
	printf("   CWD: %-55.55s\n", diag->cwd[0] ? diag->cwd : "(unknown)");

	printf("\nCommand Line:\n");
	printf("   %.60s\n", diag->cmdline[0] ? diag->cmdline : "(none)");

	printf("\nWait Channel (Kernel Function)\n");
	printf("   %s\n", p->wchan[0] ? p->wchan : "(unknown)");
	printf("   (This is the kernel function where the process is stuck)\n");

	printf("\nSystem Call Information:\n");
	if (p->syscall_nr >= 0)
	{
		printf("   Syscall:   %s (nr = %ld)\n", syscall_name(p->syscall_nr), p->syscall_nr);
		printf("   Args:      0x%lx, 0x%lx, 0x%lx\n", p->syscall_args[0], p->syscall_args[1], p->syscall_args[2]);
		printf("   IP:        0x%lx\n", p->instruction_ptr);
		printf("   SP:        0x%lx\n", p->stack_ptr);
	}
	else
		printf("   (Not currently in a system call)\n");

	if (diag->blocking_fd >= 0)
	{
		printf("\nBlocking File Descriptor:\n");
		printf("   FD:        %d\n", diag->blocking_fd);
		printf("   Path:      %s\n", diag->blocking_path[0] ? diag->blocking_path : "(unknown)");
	}

	printf("\nMemory Usage:\n");
	printf("    Virtual:     %lu KB\n", p->vm_size);
	printf("    Resident:    %lu KB\n", p->vm_rss);

	printf("\nKernel Stack Trace:\n");
	if (diag->kernel_stack_valid && diag->kernel_stack[0])
	{
		char stack_copy[MAX_STACK_LEN];
		strncpy(stack_copy, diag->kernel_stack, sizeof(stack_copy));
		stack_copy[sizeof(stack_copy) - 1] = '\0';

		char *line = strtok(stack_copy, "\n");
		while (line)
		{
			printf("   %s\n", line);
			line = strtok(NULL, "\n");
		}
	}
	else
	{
		printf("   (Cannot read - requires root or CAP_SYS_PTRACE)\n");
	}

	printf("\nMemory Regions:\n");
	for (int i = 0; i < diag->maps.count; ++i)
	{
		const map_entry_t *e = &diag->maps.entries[i];
		printf("   0x%lx-0x%lx  %s\n", e->start, e->end, e->path[0] ? e->path : "(anonymous)");
	}

	printf("\nUser Stack Trace:\n");
	if (diag->user_stack.valid && diag->user_stack.count > 0)
	{
		for (int i = 0; i < diag->user_stack.count; ++i)
		{
			const user_frame_t *f = &diag->user_stack.frames[i];
			printf("   [%d]  0x%lx  %s  (+0x%lx)\n", i, f->addr, f->region, f->addr - f->region_start);
		}
	}
	else if (diag->user_stack.valid)
		printf("  (no executable addresses found on stack)\n");
	else
		printf("   (requires root to read /proc/[pid]/mem)\n");
	printf("\n");
}

const char *maps_find_region(const process_maps_t *maps, uint64_t addr)
{
	for (int i = 0; i < maps->count; ++i)
	{
		if (addr >= maps->entries[i].start && addr < maps->entries[i].end)
			return maps->entries[i].path[0] ? maps->entries[i].path : "(anonymous)";
	}
	return "(unknown)";
}

int read_process_maps(pid_t pid, process_maps_t *maps)
{
	char path[64];
	FILE *fp;
	char line[512];

	snprintf(path, sizeof(path), "/proc/%d/maps", pid);

	fp = fopen(path, "r");
	if (!fp)
		return -1;

	while (fgets(line, sizeof(line), fp))
	{
		if (maps->count >= MAX_MAPS)
			break;

		map_entry_t *e = &maps->entries[maps->count];

		int parsed = sscanf(line, "%lx-%lx %4s %*x %*x:%*x %*d %255[^\n]", &e->start, &e->end, e->perms, e->path);

		if (parsed < 3)
			continue;

		if (parsed == 3)
			e->path[0] = '\0';

		maps->count++;
	}

	fclose(fp);
	return 0;
}

int read_user_stack(pid_t pid, process_diagnostics_t *diag)
{
	char path[64];
	int mem_fd;
	uint64_t sp;
	uint64_t buffer[256];
	ssize_t bytes_read;

	diag->user_stack.count = 0;
	diag->user_stack.valid = 0;

	sp = diag->basic.stack_ptr;
	if (sp == 0)
		return -1;

	snprintf(path, sizeof(path), "/proc/%d/mem", pid);

	mem_fd = open(path, O_RDONLY);
	if (mem_fd < 0)
		return -1;

	bytes_read = pread(mem_fd, buffer, sizeof(buffer), (off_t)sp);
	close(mem_fd);

	if (bytes_read <= 0)
		return -1;

	diag->user_stack.valid = 1;

	int num_values = bytes_read / 8;

	for (int i = 0; i < num_values; ++i)
	{
		uint64_t val = buffer[i];

		for (int j = 0; j < diag->maps.count; ++j)
		{
			map_entry_t *e = &diag->maps.entries[j];

			if (strchr(e->perms, 'x') == NULL)
				continue;

			if (val >= e->start && val < e->end)
			{
				if (diag->user_stack.count >= MAX_USER_FRAMES)
					break;

				user_frame_t *f = &diag->user_stack.frames[diag->user_stack.count];
				f->addr = val;
				f->region_start = e->start;

				strncpy(f->region, e->path[0] ? e->path : "(anonymous)", sizeof(f->region) - 1);

				f->region[sizeof(f->region) - 1] = '\0';

				diag->user_stack.count++;
				break;
			}
		}
	}

	return 0;
}