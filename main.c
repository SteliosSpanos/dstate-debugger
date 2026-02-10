#include <stdio.h>
#include <stdlib.h>

#include "include/dstate.h"

int main(void)
{
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
