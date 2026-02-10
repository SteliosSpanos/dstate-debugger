#define _GNU_SOURCE

#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>

#include "include/dstate.h"

static void print_usage(const char *prog)
{
	fprintf(stderr,
			"Usage: %s [options]\n"
			"\n"
			"Detect and diagnose processes in D-state.\n"
			"\n"
			"  -p PID    Diagnose a specific process\n"
			"  -h        Show this help\n"
			"\n"
			"Reading /proc/[pid]/stack requires root or CAP_SYS_PTRACE.\n",
			prog);
}

int main(int argc, char *argv[])
{
	int opt;
	pid_t target_pid = -1;

	while ((opt = getopt(argc, argv, "hp:")) != -1)
	{
		switch (opt)
		{
		case 'h':
			print_usage(argv[0]);
			return 0;
		case 'p':
			target_pid = (pid_t)atoi(optarg);
			if (target_pid <= 0)
			{
				fprintf(stderr, "Invalid PID: %s\n", optarg);
				return 1;
			}
			break;
		default:
			print_usage(argv[0]);
			return 1;
		}
	}

	if (target_pid > 0)
	{
		process_diagnostics_t diag;
		int ret = read_full_diagnostics(target_pid, &diag);

		if (ret == DSTATE_PROC_GONE)
		{
			fprintf(stderr, "Process %d does not exist\n", target_pid);
			return 1;
		}
		if (ret < 0)
		{
			fprintf(stderr, "Failed to read diagnostics for PID %d\n", target_pid);
			return 1;
		}

		print_diagnostics(&diag);
		return 0;
	}

	dstate_process_t *procs = NULL;
	int count = 0;

	if (find_dstate_processes(&procs, &count) < 0)
	{
		fprintf(stderr, "Failed to scan /proc\n");
		return 1;
	}

	print_dstate_summary(procs, count);

	for (int i = 0; i < count; i++)
	{
		process_diagnostics_t diag;

		int ret = read_full_diagnostics(procs[i].pid, &diag);
		if (ret == 0)
			print_diagnostics(&diag);
		else if (ret == DSTATE_PROC_GONE)
			continue;
		else
			fprintf(stderr, "Failed to read diagnostics for PID %d\n", procs[i].pid);
	}

	free_dstate_list(procs);
	return 0;
}
