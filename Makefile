CC = gcc
CFLAGS = -std=c99 -D_GNU_SOURCE -Wall -Wextra

SRCS = src/detector.c src/proc_reader.c src/proc_utils.c src/ptrace_reader.c src/core_writer.c src/unwind_reader.c

all: dstate

dstate: main.c $(SRCS)
	$(CC) $(CFLAGS) -o $@ $^ -lunwind -lunwind-x86_64 -lunwind-ptrace

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

test-pid: trap_fs dstate
	@mkdir -p /tmp/fuse_mount
	@kill -9 $$(pgrep trap_fs) 2>/dev/null; fusermount -u /tmp/fuse_mount 2>/dev/null; sleep 1
	./trap_fs /tmp/fuse_mount -s &
	@sleep 1
	@echo "Trapping process..."
	@cat /tmp/fuse_mount/trap.txt &
	@sleep 1
	@echo "Running dstate on PID $$(pgrep -o -f 'cat /tmp/fuse_mount/trap.txt')..."
	sudo ./dstate -p $$(pgrep -o -f 'cat /tmp/fuse_mount/trap.txt')
	@$(MAKE) --no-print-directory kill

unit-test: test/unit_test.c src/proc_utils.c src/proc_reader.c src/detector.c src/ptrace_reader.c
	$(CC) $(CFLAGS) -o unit_test $^
	./unit_test

kill:
	@kill -9 $$(pgrep trap_fs) 2>/dev/null; true
	@fusermount -u /tmp/fuse_mount 2>/dev/null; true
	@echo "Cleanup done."

clean: kill
	rm -f dstate monitor trap_fs unit_test

help:
	@echo "Targets:"
	@echo "  make            Build dstate"
	@echo "  make monitor    Build test monitor"
	@echo "  make trap_fs    Build FUSE test filesystem (requires libfuse-dev)"
	@echo "  make test       Full test: trap_fs + monitor + dstate (requires sudo)"
	@echo "  make test-pid   Test the -p flag: trap a process, diagnose by PID"
	@echo "  make kill       Kill trap_fs and unmount FUSE"
	@echo "  make clean      Remove binaries and unmount FUSE"
	@echo ""
	@echo "Usage:"
	@echo "  sudo ./dstate          Scan all processes for D-state"
	@echo "  sudo ./dstate -p PID   Diagnose a specific process"
	@echo "  ./dstate -h            Show help"

.PHONY: all clean test kill test-pid unit-test help
