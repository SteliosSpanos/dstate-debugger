#define FUSE_USE_VERSION 26
#define _FILE_OFFSET_BITS 64

#include <fuse.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <sys/stat.h>
#include <time.h>
#include <errno.h>

static const char *trap_path = "/trap.txt";
static const char *trap_str = "You are now trapped";

static int do_getattr(const char *path, struct stat *st)
{
	memset(st, 0, sizeof(struct stat));

	st->st_uid = getuid();
	st->st_gid = getgid();
	st->st_atime = st->st_mtime = time(NULL);

	if (strcmp(path, "/") == 0)
	{
		st->st_mode = S_IFDIR | 0755;
		st->st_nlink = 2;
	}
	else if (strcmp(path, trap_path) == 0)
	{
		st->st_mode = S_IFREG | 0444;
		st->st_nlink = 1;
		st->st_size = (off_t)strlen(trap_str);
	}
	else
	{
		return -ENOENT;
	}

	return 0;
}

static int do_readdir(const char *path, void *buffer, fuse_fill_dir_t filler, off_t offset, struct fuse_file_info *fi)
{
	(void)offset;
	(void)fi;

	filler(buffer, ".", NULL, 0);
	filler(buffer, "..", NULL, 0);
	if (strcmp(path, "/") == 0)
		filler(buffer, "trap.txt", NULL, 0);

	return 0;
}

static int do_read(const char *path, char *buffer, size_t size, off_t offset, struct fuse_file_info *fi)
{
	(void)buffer;
	(void)size;
	(void)offset;
	(void)fi;

	if (strcmp(path, trap_path) == 0)
	{
		printf("[Daemon]: The process is trying to read 'trap.txt'...\n");
		printf("[Daemon]: Activating D-State\n");

		while (1)
			sleep(1000);

		/*size_t len = strlen(trap_str);
		  if (offset < len) {
			if (offset + size > len)
				size = len - offset;
			memcpy(buffer, trap_str + offset, size);
			return size;
		  }
		  else
			return 0;
		*/
	}

	return -ENOENT;
}

static struct fuse_operations operations = {
	.getattr = do_getattr,
	.readdir = do_readdir,
	.read = do_read,
};

int main(int argc, char *argv[])
{
	return fuse_main(argc, argv, &operations, NULL);
}
