#ifndef _GNU_SOURCE
#define _GNU_SOURCE
#endif

#include <stdio.h>
#include <unistd.h>
#include <stdlib.h>
#include <signal.h>
#include <string.h>
#include <sys/types.h>
#include <sys/wait.h>

char analyze_child(pid_t pid)
{
	char stat_path[64];
	char stack_path[64];
	char state = '\0';
	FILE *fp;
	char line[512];
	char *state_ptr;

	snprintf(stat_path, sizeof(stat_path), "/proc/%d/stat", pid);

	fp = fopen(stat_path, "r");
	if (fp)
	{
		if (fgets(line, sizeof(line), fp))
		{
			state_ptr = strrchr(line, ')');
			if (state_ptr && state_ptr[1] == ' ')
			{
				state = state_ptr[2];
				printf("\n[Monitor]: Process State: %c ", state);

				if (state == 'D')
					printf("(UNINTERRUPTIBLE SLEEP - D-STATE)\n");
				else if (state == 'Z')
					printf("(Zombie - Z-State)\n");
				else
					printf("(Other state)\n");
			}
		}
		fclose(fp);
	}
	else
	{
		perror("[Monitor]: Failed to open stat file");
		return '\0';
	}

	snprintf(stack_path, sizeof(stack_path), "/proc/%d/stack", pid);

	fp = fopen(stack_path, "r");
	if (fp)
	{
		printf("[Monitor]: Kernel Stack Trace:\n");
		while (fgets(line, sizeof(line), fp))
			printf("%s", line);

		fclose(fp);
	}
	else
	{
		perror("[Monitor]: Failed to open stack file");
	}

	return state;
}

int main(void)
{
	printf("[Monitor]: Starting Search (PID %d)\n", getpid());
	fflush(stdout);

	pid_t pid = fork();

	if (pid < 0)
	{
		perror("fork");
		exit(1);
	}

	if (pid == 0)
	{
		printf("[Child]: Trying to read trapped file...\n");
		char *args[] = {"cat", "/tmp/fuse_mount/trap.txt", NULL};
		execvp(args[0], args);

		perror("execvp failed");
		_exit(1);
	}
	else
	{
		sleep(2);

		analyze_child(pid);

		printf("\n[Monitor]: Trying SIGTERM on child (kill %d)...\n", pid);
		if (kill(pid, SIGTERM) < 0)
			perror("[Monitor]: kill SIGTERM");

		sleep(2);

		printf("[Monitor]: After SIGTERM:");
		char state = analyze_child(pid);

		if (state == 'D')
		{
			printf("\n[Monitor]: SIGTERM was ignored! Process is still in D-State.\n");
			printf("[Monitor]: On modern kernels, SIGKILL can wake FUSE D-state (TASK_KILLABLE).\n");
			printf("[Monitor]: But the real fix is to kill the FUSE daemon.\n");

			if (kill(pid, SIGKILL) < 0)
				perror("[Monitor]: kill SIGKILL");
			sleep(1);

			if (waitpid(pid, NULL, WNOHANG) == pid)
				printf("[Monitor]: SIGKILL ended the child.\n");
			else
				printf("[Monitor]: Child %d is still stuck and was left behind; run 'make kill' to stop the FUSE daemon.\n", pid);
		}
		else
		{
			if (state == '\0')
				printf("\n[Monitor]: Process has already exited.\n");
			else
				printf("\n[Monitor]: Process exited (state: %c)\n", state);
			waitpid(pid, NULL, 0);
		}
	}

	return 0;
}
