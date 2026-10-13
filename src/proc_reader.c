#ifndef _GNU_SOURCE
#define _GNU_SOURCE
#endif

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <errno.h>
#include <signal.h>
#include <fcntl.h>
#include <sys/stat.h>
#include <sys/file.h>
#include <elf.h>
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
	[26] = "msync",
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
	[74] = "fsync",
	[75] = "fdatasync",
	[77] = "ftruncate",
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
	[162] = "sync",
	[202] = "futex",
	[217] = "getdents64",
	[230] = "clock_nanosleep",
	[232] = "epoll_wait",
	[247] = "waitid",
	[257] = "openat",
	[262] = "newfstatat",
	[270] = "pselect6",
	[271] = "ppoll",
	[281] = "epoll_pwait",
	[285] = "fallocate",
	[288] = "accept4",
	[306] = "syncfs",
	[426] = "io_uring_enter",
};

#define SYSCALL_TABLE_SIZE (sizeof(syscall_names) / sizeof(syscall_names[0]))

const char *syscall_name(long nr, char *buf, size_t buflen)
{
	if (nr < 0)
		return "(not in syscall)";

	if ((size_t)nr < SYSCALL_TABLE_SIZE && syscall_names[nr])
		return syscall_names[nr];

	snprintf(buf, buflen, "syscall_%ld", nr);
	return buf;
}

int parse_stat_line(const char *line, dstate_process_t *proc)
{
	const char *comm_start = strchr(line, '(');
	const char *comm_end = strrchr(line, ')');
	char state;
	int ppid, num_threads;
	unsigned long utime, stime, vm_size, vm_rss;
	unsigned long long start_time;

	if (!comm_start || !comm_end || comm_end <= comm_start)
		return -1;

	if (comm_end[1] != ' ' || comm_end[2] == '\0')
		return -1;

	int parsed = sscanf(comm_end + 2,
						"%c %d %*d %*d %*d %*d %*u "
						"%*u %*u %*u %*u "
						"%lu %lu %*d %*d "
						"%*d %*d %d "
						"%*d %llu "
						"%lu %lu",
						&state,
						&ppid,
						&utime,
						&stime,
						&num_threads,
						&start_time,
						&vm_size,
						&vm_rss);

	if (parsed != 8)
		return -1;

	size_t comm_len = comm_end - comm_start - 1;
	if (comm_len >= sizeof(proc->comm))
		comm_len = sizeof(proc->comm) - 1;

	memcpy(proc->comm, comm_start + 1, comm_len);
	proc->comm[comm_len] = '\0';

	proc->state = state;
	proc->ppid = ppid;
	proc->utime = utime;
	proc->stime = stime;
	proc->num_threads = num_threads;
	proc->start_time = start_time;

	long page_size = sysconf(_SC_PAGESIZE);
	if (page_size > 0)
		vm_rss = (vm_rss * page_size) / 1024;

	proc->vm_size = vm_size / 1024;
	proc->vm_rss = vm_rss;

	return 0;
}

int read_process_stat(pid_t pid, dstate_process_t *proc)
{
	char path[64];
	char buffer[1024];

	snprintf(path, sizeof(path), "/proc/%d/stat", pid);

	if (read_proc_file(path, buffer, sizeof(buffer)) < 0)
		return -1;

	return parse_stat_line(buffer, proc);
}

int read_process_wchan(pid_t pid, char *wchan, size_t len)
{
	char path[64];

	if (len == 0)
		return -1;

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

int parse_syscall_line(const char *line, dstate_process_t *proc)
{
	long nr;
	uint64_t args[6], sp, pc;

	proc->syscall_nr = -1;

	if (strncmp(line, "running", 7) == 0)
		return 0;

	if (strncmp(line, "-1 ", 3) == 0)
	{
		if (sscanf(line, "%*d %lx %lx", &sp, &pc) != 2)
			return -1;

		proc->stack_ptr = sp;
		proc->instruction_ptr = pc;
		return 0;
	}

	int parsed = sscanf(line,
						"%ld %lx %lx %lx %lx %lx %lx %lx %lx",
						&nr, &args[0], &args[1], &args[2],
						&args[3], &args[4], &args[5], &sp, &pc);

	if (parsed != 9)
		return -1;

	proc->syscall_nr = nr;
	memcpy(proc->syscall_args, args, sizeof(args));
	proc->stack_ptr = sp;
	proc->instruction_ptr = pc;
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

	return parse_syscall_line(buffer, proc);
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

/* A target can swap a mapped file's name for a FIFO; never block on it. */
static int open_regular(const char *path)
{
	struct stat st;
	int fd = open(path, O_RDONLY | O_NONBLOCK | O_CLOEXEC | O_NOCTTY);

	if (fd < 0)
		return -1;

	if (fstat(fd, &st) < 0 || !S_ISREG(st.st_mode))
	{
		close(fd);
		return -1;
	}

	return fd;
}

int mapping_image_is_safe(const char *path)
{
	struct stat st;
	size_t len = strlen(path);

	if (len == 0 || path[0] == '[')
		return 1;

	if (len >= 10 && strcmp(path + len - 10, " (deleted)") == 0)
		return 0;

	return stat(path, &st) == 0 && S_ISREG(st.st_mode);
}

static int exe_is_32bit(pid_t pid)
{
	char path[64];
	unsigned char ident[EI_NIDENT];
	int fd;
	ssize_t n;

	snprintf(path, sizeof(path), "/proc/%d/exe", pid);

	fd = open_regular(path);
	if (fd < 0)
		return 0;

	n = read(fd, ident, sizeof(ident));
	close(fd);

	return n == (ssize_t)sizeof(ident) && memcmp(ident, ELFMAG, SELFMAG) == 0 &&
		   ident[EI_CLASS] == ELFCLASS32;
}

static int syscall_has_fd_arg0(long nr)
{
	switch (nr)
	{
	case 0:	  /* read */
	case 1:	  /* write */
	case 3:	  /* close */
	case 5:	  /* fstat */
	case 16:  /* ioctl */
	case 17:  /* pread64 */
	case 18:  /* pwrite64 */
	case 19:  /* readv */
	case 20:  /* writev */
	case 42:  /* connect */
	case 43:  /* accept */
	case 44:  /* sendto */
	case 45:  /* recvfrom */
	case 72:  /* fcntl */
	case 73:  /* flock */
	case 74:  /* fsync */
	case 75:  /* fdatasync */
	case 77:  /* ftruncate */
	case 78:  /* getdents */
	case 217: /* getdents64 */
	case 288: /* accept4 */
		return 1;
	default:
		return 0;
	}
}

void free_process_maps(process_maps_t *maps)
{
	free(maps->entries);
	maps->entries = NULL;
	maps->count = 0;
	maps->capacity = 0;
}

void free_diagnostics(process_diagnostics_t *diag)
{
	free_process_maps(&diag->maps);
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

	diag->is_32bit = exe_is_32bit(pid);

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

	if (diag->basic.syscall_nr != -1 && diag->basic.state == 'D' && !diag->is_32bit &&
		syscall_has_fd_arg0(diag->basic.syscall_nr))
	{
		int target_fd = (int)diag->basic.syscall_args[0];

		if (target_fd >= 0)
		{
			diag->blocking_fd = target_fd;

			snprintf(path, sizeof(path), "/proc/%d/fd/%d", pid, target_fd);
			read_proc_link(path, diag->blocking_path, sizeof(diag->blocking_path));
		}
	}

	read_process_maps(pid, &diag->maps);

	if (!diag->is_32bit)
		read_lock_conflict(pid, diag);

	int unwind_ret = read_user_stack_libunwind(pid, diag);

	if (unwind_ret < 0 || diag->user_stack.count < 3)
	{
		user_stack_t unwound = diag->user_stack;

		read_user_stack(pid, diag);

		if (unwound.valid && unwound.count >= diag->user_stack.count)
			diag->user_stack = unwound;
	}

	return 0;
}

static const char *user_stack_method_name(int method)
{
	if (method == USER_STACK_METHOD_LIBUNWIND)
		return "libunwind";
	if (method == USER_STACK_METHOD_HEURISTIC)
		return "heuristic scan";
	return NULL;
}

void print_diagnostics(const process_diagnostics_t *diag)
{
	const dstate_process_t *p = &diag->basic;

	printf("\n");
	printf("====================================================\n");
	printf("   PROCESS DIAGNOSTICS: PID - %d\n", p->pid);
	printf("====================================================\n");

	printf("\nBasic Information:\n");
	printf("   Command:      ");
	fprint_safe(stdout, p->comm, 0, 48);
	printf("\n");
	printf("   State:        %c\n", p->state);
	printf("   Parent PID:   %-48d\n", p->ppid);
	printf("   Threads:      %-48d\n", p->num_threads);

	printf("\nExecutable & Working Directory:\n");
	printf("   Exe: ");
	fprint_safe(stdout, diag->exe[0] ? diag->exe : "(unknown)", 55, 55);
	printf("\n   CWD: ");
	fprint_safe(stdout, diag->cwd[0] ? diag->cwd : "(unknown)", 55, 55);
	printf("\n");

	printf("\nCommand Line:\n   ");
	fprint_safe(stdout, diag->cmdline[0] ? diag->cmdline : "(none)", 60, 0);
	printf("\n");

	printf("\nWait Channel (Kernel Function)\n");
	printf("   %s\n", p->wchan[0] ? p->wchan : "(unknown)");
	printf("   (This is the kernel function where the process is stuck)\n");

	printf("\nSystem Call Information:\n");
	if (p->syscall_nr >= 0)
	{
		char scbuf[32];
		if (diag->is_32bit)
			printf("   Syscall:   nr = %ld (32-bit process, name not resolved)\n", p->syscall_nr);
		else
			printf("   Syscall:   %s (nr = %ld)\n", syscall_name(p->syscall_nr, scbuf, sizeof(scbuf)), p->syscall_nr);
		printf("   Args:      0x%lx, 0x%lx, 0x%lx\n", p->syscall_args[0], p->syscall_args[1], p->syscall_args[2]);
		printf("   IP:        0x%lx\n", p->instruction_ptr);
		printf("   SP:        0x%lx\n", p->stack_ptr);
	}
	else if (p->stack_ptr != 0)
	{
		printf("   (Not in a system call; blocked in user-mode code, for example a page fault)\n");
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
		printf("   Path:      ");
		fprint_safe(stdout, diag->blocking_path[0] ? diag->blocking_path : "(unknown)", 0, 0);
		printf("\n");
	}

	if (diag->lock_conflict.found)
	{
		const lock_conflict_t *lc = &diag->lock_conflict;

		printf("\nLock Conflict:\n");
		printf("   Path:        ");
		fprint_safe(stdout, lc->path[0] ? lc->path : "(unknown)", 0, 0);
		printf("\n");

		if (lc->holder_pid > 0)
		{
			char holder_comm[MAX_COMM_LEN] = "(unknown)";
			char holder_path[64];
			snprintf(holder_path, sizeof(holder_path), "/proc/%d/comm", lc->holder_pid);
			read_proc_line(holder_path, holder_comm, sizeof(holder_comm));

			printf("   Held by:     PID %d (", lc->holder_pid);
			fprint_safe(stdout, holder_comm, 0, 0);
			printf(")\n");
		}
		else if (lc->holder_pid < 0)
			printf("   Held by:     an open file description (OFD lock, no owning PID)\n");
		else
			printf("   Held by:     a process outside this PID namespace\n");

		printf("   Lock:        %s %s (%s)\n", lc->lock_type, lc->access, lc->advisory);
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
		printf("   0x%lx-0x%lx  ", e->start, e->end);
		fprint_safe(stdout, e->path[0] ? e->path : "(anonymous)", 0, 0);
		printf("\n");
	}

	const char *method = user_stack_method_name(diag->user_stack.method);
	if (diag->user_stack.valid && method)
		printf("\nUser Stack Trace (%s, from %s):\n", method, diag->ptrace_valid ? "ptrace RSP" : "syscall SP");
	else
		printf("\nUser Stack Trace:\n");

	if (diag->user_stack.valid && diag->user_stack.count > 0)
	{
		for (int i = 0; i < diag->user_stack.count; ++i)
		{
			const user_frame_t *f = &diag->user_stack.frames[i];
			printf("   [%d]  0x%lx  ", i, f->addr);
			fprint_safe(stdout, f->region, 0, 0);
			printf("\n         function: ");
			fprint_safe(stdout, f->function, 0, 0);
			printf("\n         source: ");
			fprint_safe(stdout, f->source, 0, 0);
			if (f->region_start != 0)
				printf("  (+0x%lx)", f->addr - f->region_start);
			printf("\n");
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
	char *line = NULL;
	size_t line_cap = 0;

	maps->count = 0;

	snprintf(path, sizeof(path), "/proc/%d/maps", pid);

	fp = fopen(path, "r");
	if (!fp)
		return -1;

	while (getline(&line, &line_cap, fp) != -1)
	{
		if (maps->count >= maps->capacity)
		{
			int new_cap = maps->capacity ? maps->capacity * 2 : MAPS_INITIAL_CAPACITY;
			map_entry_t *grown = realloc(maps->entries, sizeof(map_entry_t) * new_cap);
			if (!grown)
			{
				free(line);
				fclose(fp);
				return -1;
			}

			maps->entries = grown;
			maps->capacity = new_cap;
		}

		map_entry_t *e = &maps->entries[maps->count];
		memset(e, 0, sizeof(*e));

		int parsed = sscanf(line, "%lx-%lx %4s %lx %*x:%*x %*d %255[^\n]", &e->start, &e->end, e->perms, &e->file_offset, e->path);

		if (parsed < 4)
			continue;

		if (parsed < 5)
			e->path[0] = '\0';

		maps->count++;
	}

	free(line);
	fclose(fp);
	return 0;
}

int is_indirect_call(const unsigned char *b, size_t len)
{
	size_t i = ((b[0] & 0xF0) == 0x40) ? 1 : 0;

	if (len < i + 2 || b[i] != 0xFF)
		return 0;

	unsigned char modrm = b[i + 1];
	if ((modrm & 0x38) != 0x10)
		return 0;

	unsigned char mod = modrm >> 6;
	unsigned char rm = modrm & 7;
	size_t modrm_len = 1;

	if (mod != 3 && rm == 4)
	{
		if (len < i + 3)
			return 0;
		modrm_len++;
		if (mod == 0 && (b[i + 2] & 7) == 5)
			modrm_len += 4;
	}
	else if (mod == 0 && rm == 5)
		modrm_len += 4;

	if (mod == 1)
		modrm_len += 1;
	else if (mod == 2)
		modrm_len += 4;

	return len == i + 1 + modrm_len;
}

static int is_call_target(int mem_fd, uint64_t addr)
{
	unsigned char buf[9];

	if (addr < sizeof(buf))
		return 0;

	if (pread(mem_fd, buf, sizeof(buf), (off_t)(addr - sizeof(buf))) != (ssize_t)sizeof(buf))
		return 0;

	if (buf[sizeof(buf) - 5] == 0xE8)
		return 1;

	for (size_t len = 2; len <= 8; ++len)
	{
		if (is_indirect_call(buf + sizeof(buf) - len, len))
			return 1;
	}

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
	diag->user_stack.method = USER_STACK_METHOD_NONE;

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
	diag->user_stack.method = USER_STACK_METHOD_HEURISTIC;

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

uint64_t file_offset_to_vaddr(const char *binary_path, uint64_t offset)
{
	Elf64_Ehdr eh;
	uint64_t result = offset;
	int fd = open_regular(binary_path);

	if (fd < 0)
		return offset;

	if (pread(fd, &eh, sizeof(eh), 0) != (ssize_t)sizeof(eh) ||
		memcmp(eh.e_ident, ELFMAG, SELFMAG) != 0 ||
		eh.e_ident[EI_CLASS] != ELFCLASS64 ||
		eh.e_ident[EI_DATA] != ELFDATA2LSB ||
		eh.e_phentsize != sizeof(Elf64_Phdr))
	{
		close(fd);
		return offset;
	}

	for (unsigned int i = 0; i < eh.e_phnum; ++i)
	{
		Elf64_Phdr ph;

		if (pread(fd, &ph, sizeof(ph), (off_t)(eh.e_phoff + (uint64_t)i * sizeof(ph))) != (ssize_t)sizeof(ph))
			break;

		if (ph.p_type == PT_LOAD && offset >= ph.p_offset && offset - ph.p_offset < ph.p_filesz)
		{
			result = offset - ph.p_offset + ph.p_vaddr;
			break;
		}
	}

	close(fd);
	return result;
}

static int read_line_truncated(FILE *fp, char *buf, size_t size)
{
	if (!fgets(buf, (int)size, fp))
		return -1;

	size_t len = strlen(buf);
	if (len > 0 && buf[len - 1] != '\n')
	{
		int c;
		while ((c = fgetc(fp)) != EOF && c != '\n')
			;
	}

	buf[strcspn(buf, "\n")] = '\0';
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

	size_t path_len = strlen(binary_path);
	if (path_len >= 10 && strcmp(binary_path + path_len - 10, " (deleted)") == 0)
		return;

	int probe_fd = open_regular(binary_path);
	if (probe_fd < 0)
		return;
	close(probe_fd);

	snprintf(cmd, sizeof(cmd), "/usr/bin/addr2line -e '%s' -f -C 0x%lx 2>/dev/null",
			 binary_path, (unsigned long)file_offset_to_vaddr(binary_path, offset));

	fp = popen(cmd, "r");
	if (!fp)
		return;

	if (read_line_truncated(fp, line, sizeof(line)) == 0)
	{
		strncpy(func_out, line, func_len - 1);
		func_out[func_len - 1] = '\0';
	}

	if (read_line_truncated(fp, line, sizeof(line)) == 0)
	{
		strncpy(src_out, line, src_len - 1);
		src_out[src_len - 1] = '\0';
	}

	pclose(fp);
}

int parse_lock_line(const char *line, lock_entry_t *out)
{
	int num, consumed = 0;
	long pid;
	const char *p;

	memset(out, 0, sizeof(*out));

	if (sscanf(line, "%d: %n", &num, &consumed) < 1 || consumed == 0)
		return -1;

	p = line + consumed;
	if (strncmp(p, "->", 2) == 0)
	{
		out->blocked = 1;
		p += 2;
	}

	if (sscanf(p, "%15s %15s %15s %ld %x:%x:%lu", out->lock_type, out->advisory,
			   out->access, &pid, &out->dev_major, &out->dev_minor, &out->inode) != 7)
		return -1;

	out->pid = (pid_t)pid;
	return 0;
}

int lock_blocks_waiter(const lock_entry_t *l, long nr, uint64_t arg1)
{
	if (nr == 73)
	{
		int op = (int)arg1;

		if (strcmp(l->lock_type, "FLOCK") != 0 || (op & LOCK_UN))
			return 0;

		if ((op & LOCK_SH) && strcmp(l->access, "READ") == 0)
			return 0;

		return 1;
	}

	return strcmp(l->lock_type, "POSIX") == 0 || strcmp(l->lock_type, "OFDLCK") == 0;
}

int lock_is_better(const lock_entry_t *best, const lock_entry_t *cand)
{
	return !best || (strcmp(best->access, "WRITE") != 0 && strcmp(cand->access, "WRITE") == 0);
}

static pid_t read_tgid(pid_t pid)
{
	char path[64];
	char line[128];
	pid_t tgid = pid;
	FILE *fp;

	snprintf(path, sizeof(path), "/proc/%d/status", pid);
	fp = fopen(path, "r");
	if (!fp)
		return pid;

	while (fgets(line, sizeof(line), fp))
	{
		int val;

		if (sscanf(line, "Tgid: %d", &val) == 1 && val > 0)
		{
			tgid = (pid_t)val;
			break;
		}
	}

	fclose(fp);
	return tgid;
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

	struct stat st;
	if (stat(fd_link, &st) < 0)
		return -1;

	if (read_proc_link(fd_link, file_path, sizeof(file_path)) < 0)
		file_path[0] = '\0';

	unsigned int target_major = major(st.st_dev);
	unsigned int target_minor = minor(st.st_dev);
	unsigned long target_inode = (unsigned long)st.st_ino;
	pid_t tgid = read_tgid(pid);

	FILE *fp = fopen("/proc/locks", "r");
	if (!fp)
		return -1;

	lock_entry_t best;
	int have_best = 0;
	char line[256];
	while (fgets(line, sizeof(line), fp))
	{
		lock_entry_t l;

		if (parse_lock_line(line, &l) < 0 || l.blocked)
			continue;

		if (l.dev_major != target_major || l.dev_minor != target_minor ||
			l.inode != target_inode || l.pid == tgid)
			continue;

		if (!lock_blocks_waiter(&l, nr, diag->basic.syscall_args[1]))
			continue;

		if (lock_is_better(have_best ? &best : NULL, &l))
		{
			best = l;
			have_best = 1;
		}
	}

	fclose(fp);

	if (!have_best)
		return -1;

	diag->lock_conflict.found = 1;
	diag->lock_conflict.holder_pid = best.pid;
	snprintf(diag->lock_conflict.lock_type, sizeof(diag->lock_conflict.lock_type), "%s", best.lock_type);
	snprintf(diag->lock_conflict.access, sizeof(diag->lock_conflict.access), "%s", best.access);
	snprintf(diag->lock_conflict.advisory, sizeof(diag->lock_conflict.advisory), "%s", best.advisory);
	snprintf(diag->lock_conflict.path, sizeof(diag->lock_conflict.path), "%s", file_path);
	return 0;
}
