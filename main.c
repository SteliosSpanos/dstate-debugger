#ifndef _GNU_SOURCE
#define _GNU_SOURCE
#endif

#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <errno.h>
#include <limits.h>

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
			"  -o FILE   Write ELF core file (use with -p)\n"
			"\n"
			"Reading /proc/[pid]/stack requires root or CAP_SYS_PTRACE.\n",
			prog);
}

int main(int argc, char *argv[])
{
	int opt;
	pid_t target_pid = -1;
	const char *outfile = NULL;

	while ((opt = getopt(argc, argv, "hp:o:")) != -1)
	{
		switch (opt)
		{
		case 'h':
			print_usage(argv[0]);
			return EXIT_SUCCESS;
		case 'p':
		{
			char *endptr;
			errno = 0;
			long val = strtol(optarg, &endptr, 10);
			if (optarg[0] < '0' || optarg[0] > '9' || errno != 0 || *endptr != '\0' || val <= 0 || val > INT_MAX)
			{
				fprintf(stderr, "Invalid PID: %s\n", optarg);
				return EXIT_FAILURE;
			}
			target_pid = (pid_t)val;
			break;
		}
		case 'o':
			outfile = optarg;
			break;
		default:
			print_usage(argv[0]);
			return EXIT_FAILURE;
		}
	}

	if (optind < argc)
	{
		fprintf(stderr, "Unexpected argument: %s\n", argv[optind]);
		print_usage(argv[0]);
		return EXIT_FAILURE;
	}

	if (outfile && target_pid <= 0)
	{
		fprintf(stderr, "Error: -o requires -p PID\n");
		return EXIT_FAILURE;
	}

	if (target_pid > 0)
	{
		process_diagnostics_t diag;
		int status = EXIT_SUCCESS;
		int ret = read_full_diagnostics(target_pid, &diag);

		if (ret == DSTATE_PROC_GONE)
		{
			fprintf(stderr, "Process %d does not exist\n", target_pid);
			status = EXIT_FAILURE;
		}
		else if (ret < 0)
		{
			fprintf(stderr, "Failed to read diagnostics for PID %d\n", target_pid);
			status = EXIT_FAILURE;
		}
		else
		{
			print_diagnostics(&diag);

			if (outfile && write_core_file(target_pid, &diag, outfile) < 0)
			{
				fprintf(stderr, "Failed to write core file: %s\n", outfile);
				status = EXIT_FAILURE;
			}
		}

		free_diagnostics(&diag);
		return status;
	}

	dstate_process_t *procs = NULL;
	int count = 0;
	int status = EXIT_SUCCESS;

	if (find_dstate_processes(&procs, &count) < 0)
	{
		fprintf(stderr, "Failed to scan /proc\n");
		return EXIT_FAILURE;
	}

	print_dstate_summary(procs, count);

	for (int i = 0; i < count; i++)
	{
		process_diagnostics_t diag;

		int ret = read_full_diagnostics(procs[i].pid, &diag);
		if (ret == 0)
			print_diagnostics(&diag);
		else if (ret != DSTATE_PROC_GONE)
		{
			fprintf(stderr, "Failed to read diagnostics for PID %d\n", procs[i].pid);
			status = EXIT_FAILURE;
		}

		free_diagnostics(&diag);
	}

	free_dstate_list(procs);
	return status;
}
