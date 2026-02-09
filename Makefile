CC = gcc
CFLAGS = -std=c99 -D_GNU_SOURCE -Wall -Wextra

SRCS = src/detector.c src/proc_reader.c src/proc_utils.c

all: dstate

dstate: main.c $(SRCS)
	$(CC) $(CFLAGS) -o $@ $^

monitor: test/monitor.c $(SRCS)
	$(CC) $(CFLAGS) -o $@ $^

trap_fs: test/trap_fs.c
	$(CC) -D_GNU_SOURCE -Wall -o $@ $< $(shell pkg-config --cflags --libs fuse)

test: trap_fs monitor dstate
	@mkdir -p /tmp/fuse_mount
	@kill -9 $$(pgrep trap_fs) 2>/dev/null; fusermount -u /tmp/fuse_mount 2>/dev/null; sleep 1
	./trap_fs /tmp/fuse_mount -s &
	@sleep 1
	./monitor
	@echo ""
	sudo ./dstate
	@$(MAKE) --no-print-directory kill

kill:
	@kill -9 $$(pgrep trap_fs) 2>/dev/null; true
	@fusermount -u /tmp/fuse_mount 2>/dev/null; true
	@echo "Cleanup done."

clean: kill
	rm -f dstate monitor trap_fs

.PHONY: all clean test kill
