#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <errno.h>
#include <signal.h>
#include <fcntl.h>
#include <sys/stat.h>
#include <sys/sysmacros.h>

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
	[72] = "fcntl",
	[73] = "flock",
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
	char unknown[32];

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

	if (diag->basic.state == 'S' || diag->basic.state == 'T')
	{
		if (read_registers_ptrace(pid, &diag->ptrace_regs) == 0)
		{
			diag->ptrace_valid = 1;
		}
	}

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
			nr == 20 || nr == 42 ||
			nr == 43 || nr == 44 ||
			nr == 45 || nr == 288)
			target_fd = (int)diag->basic.syscall_args[0];

		if (target_fd >= 0)
		{
			diag->blocking_fd = target_fd;

			snprintf(path, sizeof(path), "/proc/%d/fd/%d", pid, target_fd);
			read_proc_link(path, diag->blocking_path, sizeof(diag->blocking_path));
		}
	}

	read_process_maps(pid, &diag->maps);

	read_lock_conflict(pid, diag);

	if (read_user_stack_libunwind(pid, diag) < 0 || diag->user_stack.count < 3)
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

	if (diag->ptrace_valid)
	{
		printf("\nRegisters (via ptrace):\n");
		printf("   RIP: 0x%016llx   RSP: 0x%016llx   RBP: 0x%016llx\n",
			   diag->ptrace_regs[ELFREG_RIP], diag->ptrace_regs[ELFREG_RSP], diag->ptrace_regs[ELFREG_RBP]);
		printf("   RAX: 0x%016llx   RBX: 0x%016llx   RCX: 0x%016llx\n",
			   diag->ptrace_regs[ELFREG_RAX], diag->ptrace_regs[ELFREG_RBX], diag->ptrace_regs[ELFREG_RCX]);
		printf("   RDX: 0x%016llx   RSI: 0x%016llx   RDI: 0x%016llx\n",
			   diag->ptrace_regs[ELFREG_RDX], diag->ptrace_regs[ELFREG_RSI], diag->ptrace_regs[ELFREG_RDI]);
		printf("   R8:  0x%016llx   R9:  0x%016llx   R10: 0x%016llx\n",
			   diag->ptrace_regs[ELFREG_R8], diag->ptrace_regs[ELFREG_R9], diag->ptrace_regs[ELFREG_R10]);
		printf("   R11: 0x%016llx   R12: 0x%016llx   R13: 0x%016llx\n",
			   diag->ptrace_regs[ELFREG_R11], diag->ptrace_regs[ELFREG_R12], diag->ptrace_regs[ELFREG_R13]);
		printf("   R14: 0x%016llx   R15: 0x%016llx   EFLAGS: 0x%08llx\n",
			   diag->ptrace_regs[ELFREG_R14], diag->ptrace_regs[ELFREG_R15], diag->ptrace_regs[ELFREG_EFLAGS]);
	}

	if (diag->blocking_fd >= 0)
	{
		printf("\nBlocking File Descriptor:\n");
		printf("   FD:        %d\n", diag->blocking_fd);
		printf("   Path:      %s\n", diag->blocking_path[0] ? diag->blocking_path : "(unknown)");
	}

	if (diag->lock_conflict.found)
	{
		char holder_comm[MAX_COMM_LEN] = "(unknown)";
		char holder_path[64];
		snprintf(holder_path, sizeof(holder_path), "/proc/%d/comm",
				 diag->lock_conflict.holder_pid);
		read_proc_line(holder_path, holder_comm, sizeof(holder_comm));

		printf("\nLock Conflict:\n");
		printf("   Waiting for: %s lock on %s\n",
			   diag->lock_conflict.access,
			   diag->lock_conflict.path[0] ? diag->lock_conflict.path : "(unknown)");
		printf("   Held by PID: %d (%s)\n", diag->lock_conflict.holder_pid, holder_comm);
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

	printf("\nUser Stack Trace (%s):\n", diag->ptrace_valid ? "ptrace RSP" : "syscall SP");
	if (diag->user_stack.valid && diag->user_stack.count > 0)
	{
		for (int i = 0; i < diag->user_stack.count; ++i)
		{
			const user_frame_t *f = &diag->user_stack.frames[i];
			printf("   [%d]  0x%lx  %s\n", i, f->addr, f->region);
			printf("         function: %s\n", f->function);
			printf("         source: %s  (+0x%lx)\n", f->source, f->addr - f->region_start);
		}
	}
	else if (diag->user_stack.valid)
		printf("   (no executable addresses found on stack)\n");
	else if (diag->user_stack.reason == USER_STACK_ERR_PERM)
		printf("   (requires root to read /proc/[pid]/mem)\n");
	else if (diag->user_stack.reason == USER_STACK_ERR_NO_SP)
		printf("   (no stack pointer - process was not in a syscall when sampled)\n");
	else
		printf("   (process memory unavailable)\n");
	printf("\n");
}

int read_process_maps(pid_t pid, process_maps_t *maps)
{
	char path[64];
	FILE *fp;
	char line[1024];

	maps->count = 0;

	snprintf(path, sizeof(path), "/proc/%d/maps", pid);

	fp = fopen(path, "r");
	if (!fp)
		return -1;

	while (fgets(line, sizeof(line), fp))
	{
		if (maps->count >= MAX_MAPS)
			break;

		map_entry_t *e = &maps->entries[maps->count];

		int parsed = sscanf(line, "%lx-%lx %4s %lx %*x:%*x %*d %255[^\n]", &e->start, &e->end, e->perms, &e->file_offset, e->path);

		if (parsed < 3)
			continue;

		if (parsed < 5)
			e->path[0] = '\0';

		maps->count++;
	}

	fclose(fp);
	return 0;
}

static int is_call_target(int mem_fd, uint64_t addr)
{
	unsigned char buf[7];
	ssize_t n;

	if (addr < 7)
		return 0;

	n = pread(mem_fd, buf, 5, (off_t)(addr - 5));
	if (n == 5 && buf[0] == 0xE8)
		return 1;

	n = pread(mem_fd, buf, 2, (off_t)(addr - 2));
	if (n == 2 && buf[0] == 0xFF && (buf[1] & 0x38) == 0x10)
		return 1;

	n = pread(mem_fd, buf, 3, (off_t)(addr - 3));
	if (n == 3 && buf[0] == 0xFF && (buf[1] & 0x38) == 0x10)
		return 1;
	if (n == 3 && (buf[0] & 0xF0) == 0x40 && buf[1] == 0xFF && (buf[2] & 0x38) == 0x10)
		return 1;

	n = pread(mem_fd, buf, 2, (off_t)(addr - 6));
	if (n == 2 && buf[0] == 0xFF && buf[1] == 0x15)
		return 1;

	if (n == 2 && buf[0] == 0xFF &&
		(buf[1] & 0x38) == 0x10 && (buf[1] & 0xC0) == 0x80)
		return 1;

	n = pread(mem_fd, buf, 3, (off_t)(addr - 7));
	if (n == 3 && (buf[0] & 0xF0) == 0x40 && buf[1] == 0xFF && buf[2] == 0x15)
		return 1;

	if (n == 3 && (buf[0] & 0xF0) == 0x40 && buf[1] == 0xFF &&
		(buf[2] & 0x38) == 0x10 && (buf[2] & 0xC0) == 0x80)
		return 1;

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
	diag->user_stack.reason = 0;

	sp = diag->ptrace_valid ? diag->ptrace_regs[ELFREG_RSP] : diag->basic.stack_ptr;
	if (sp == 0)
	{
		diag->user_stack.reason = USER_STACK_ERR_NO_SP;
		return -1;
	}

	snprintf(path, sizeof(path), "/proc/%d/mem", pid);

	mem_fd = open(path, O_RDONLY);
	if (mem_fd < 0)
	{
		diag->user_stack.reason = (errno == EACCES || errno == EPERM)
									  ? USER_STACK_ERR_PERM
									  : USER_STACK_ERR_UNAVAIL;
		return -1;
	}

	bytes_read = pread(mem_fd, buffer, sizeof(buffer), (off_t)sp);

	if (bytes_read <= 0)
	{
		close(mem_fd);
		diag->user_stack.reason = USER_STACK_ERR_UNAVAIL;
		return -1;
	}

	diag->user_stack.valid = 1;

	int num_values = bytes_read / 8;

	for (int i = 0; i < num_values && diag->user_stack.count < MAX_USER_FRAMES; ++i)
	{
		uint64_t val = buffer[i];

		for (int j = 0; j < diag->maps.count; ++j)
		{
			map_entry_t *e = &diag->maps.entries[j];

			if (strchr(e->perms, 'x') == NULL)
				continue;

			if (val >= e->start && val < e->end)
			{
				if (!is_call_target(mem_fd, val))
					break;

				user_frame_t *f = &diag->user_stack.frames[diag->user_stack.count];
				f->addr = val;
				f->region_start = e->start;

				strncpy(f->region, e->path[0] ? e->path : "(anonymous)", sizeof(f->region) - 1);

				f->region[sizeof(f->region) - 1] = '\0';

				if (e->path[0] == '/')
				{
					resolve_symbol(e->path, val - e->start + e->file_offset,
								   f->function, sizeof(f->function),
								   f->source, sizeof(f->source));
				}
				else
				{
					strncpy(f->function, "??", sizeof(f->function) - 1);
					strncpy(f->source, "??:0", sizeof(f->source) - 1);
					f->function[sizeof(f->function) - 1] = '\0';
					f->source[sizeof(f->source) - 1] = '\0';
				}

				diag->user_stack.count++;
				break;
			}
		}
	}

	close(mem_fd);
	return 0;
}

void resolve_symbol(const char *binary_path, uint64_t offset,
					char *func_out, size_t func_len,
					char *src_out, size_t src_len)
{
	char cmd[MAX_PATH_LEN + 64];
	FILE *fp;
	char line[256];

	strncpy(func_out, "??", func_len - 1);
	strncpy(src_out, "??:0", src_len - 1);
	func_out[func_len - 1] = '\0';
	src_out[src_len - 1] = '\0';

	if (strchr(binary_path, '\'') != NULL)
		return;

	snprintf(cmd, sizeof(cmd), "addr2line -e '%s' -f -C 0x%lx 2>/dev/null", binary_path, offset);

	fp = popen(cmd, "r");
	if (!fp)
		return;

	if (fgets(line, sizeof(line), fp))
	{
		line[strcspn(line, "\n")] = '\0';
		strncpy(func_out, line, func_len - 1);
		func_out[func_len - 1] = '\0';
	}

	if (fgets(line, sizeof(line), fp))
	{
		line[strcspn(line, "\n")] = '\0';
		strncpy(src_out, line, src_len - 1);
		src_out[src_len - 1] = '\0';
	}

	pclose(fp);
}

int read_lock_conflict(pid_t pid, process_diagnostics_t *diag)
{
	long nr = diag->basic.syscall_nr;

	if (nr != 72 && nr != 73)
		return -1;

	int fd = (int)diag->basic.syscall_args[0];
	char fd_link[64];
	char file_path[MAX_PATH_LEN];

	snprintf(fd_link, sizeof(fd_link), "/proc/%d/fd/%d", pid, fd);
	if (read_proc_link(fd_link, file_path, sizeof(file_path)) < 0)
		return -1;

	struct stat st;
	if (stat(file_path, &st) < 0)
		return -1;

	unsigned int target_major = major(st.st_dev);
	unsigned int target_minor = minor(st.st_dev);
	unsigned long target_inode = (unsigned long)st.st_ino;

	FILE *fp = fopen("/proc/locks", "r");
	if (!fp)
		return -1;

	char line[256];
	while (fgets(line, sizeof(line), fp))
	{
		int lock_num;
		char lock_type[16], advisory[16], access[16];
		pid_t holder_pid;
		unsigned int lmajor, lminor;
		unsigned long linode;

		if (sscanf(line, "%d: %15s %15s %15s %d %x:%x:%lx", &lock_num, lock_type,
				   advisory, access, &holder_pid, &lmajor, &lminor, &linode) < 8)
			continue;

		if (lmajor == target_major && lminor == target_minor && linode == target_inode && holder_pid != pid)
		{
			diag->lock_conflict.found = 1;
			diag->lock_conflict.holder_pid = holder_pid;
			strncpy(diag->lock_conflict.lock_type, lock_type, sizeof(diag->lock_conflict.lock_type) - 1);
			diag->lock_conflict.lock_type[sizeof(diag->lock_conflict.lock_type) - 1] = '\0';
			strncpy(diag->lock_conflict.access, access, sizeof(diag->lock_conflict.access) - 1);
			diag->lock_conflict.access[sizeof(diag->lock_conflict.access) - 1] = '\0';
			strncpy(diag->lock_conflict.path, file_path, sizeof(diag->lock_conflict.path) - 1);
			diag->lock_conflict.path[sizeof(diag->lock_conflict.path) - 1] = '\0';

			fclose(fp);
			return 0;
		}
	}
	fclose(fp);
	return -1;
}