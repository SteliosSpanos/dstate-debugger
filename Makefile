CC = gcc
CFLAGS = -std=c99 -D_GNU_SOURCE -Wall -Wextra
LIBS = -lunwind-ptrace -lunwind-x86_64 -lunwind

MNT = /tmp/fuse_mount

SRCS = src/detector.c src/proc_reader.c src/proc_utils.c src/ptrace_reader.c src/core_writer.c src/unwind_reader.c
HDRS = include/dstate.h include/proc_utils.h

all: dstate

dstate: main.c $(SRCS) $(HDRS)
	$(CC) $(CFLAGS) -o $@ main.c $(SRCS) $(LIBS)

monitor: test/monitor.c
	$(CC) $(CFLAGS) -o $@ $<

trap_fs: test/trap_fs.c
	@pkg-config --exists fuse || { echo "error: pkg-config cannot find 'fuse' (install libfuse-dev and pkg-config)" >&2; exit 1; }
	$(CC) -D_GNU_SOURCE -Wall -o $@ $< $(shell pkg-config --cflags --libs fuse)

unit_test: test/unit_test.c $(SRCS) $(HDRS)
	$(CC) $(CFLAGS) -o $@ test/unit_test.c $(SRCS) $(LIBS)

unit-test: unit_test
	./unit_test

test: trap_fs dstate
	@mkdir -p $(MNT)
	@pkill -9 -x trap_fs 2>/dev/null; fusermount -u $(MNT) 2>/dev/null; sleep 1
	@rc=0; \
	./trap_fs $(MNT) -s -f & \
	sleep 1; \
	cat $(MNT)/trap.txt & \
	trapped=$$!; \
	sleep 1; \
	if kill -0 $$trapped 2>/dev/null; then sudo ./dstate || rc=$$?; \
	else echo "error: no trapped process found" >&2; rc=1; fi; \
	$(MAKE) --no-print-directory kill; \
	exit $$rc

test-monitor: trap_fs monitor
	@mkdir -p $(MNT)
	@pkill -9 -x trap_fs 2>/dev/null; fusermount -u $(MNT) 2>/dev/null; sleep 1
	@rc=0; \
	./trap_fs $(MNT) -s -f & \
	sleep 1; \
	./monitor || rc=$$?; \
	$(MAKE) --no-print-directory kill; \
	exit $$rc

test-pid: trap_fs dstate
	@mkdir -p $(MNT)
	@pkill -9 -x trap_fs 2>/dev/null; fusermount -u $(MNT) 2>/dev/null; sleep 1
	@rc=0; \
	echo "Trapping process..."; \
	./trap_fs $(MNT) -s -f & \
	sleep 1; \
	cat $(MNT)/trap.txt & \
	trapped=$$!; \
	sleep 1; \
	if kill -0 $$trapped 2>/dev/null; then \
		echo "Running dstate on PID $$trapped..."; \
		sudo ./dstate -p $$trapped || rc=$$?; \
	else echo "error: no trapped process found" >&2; rc=1; fi; \
	$(MAKE) --no-print-directory kill; \
	exit $$rc

kill:
	@pkill -9 -x trap_fs 2>/dev/null; true
	@fusermount -u $(MNT) 2>/dev/null; true
	@echo "Cleanup done."

clean: kill
	rm -f dstate monitor trap_fs unit_test

help:
	@echo "Targets:"
	@echo "  make              Build dstate"
	@echo "  make monitor      Build test monitor"
	@echo "  make trap_fs      Build FUSE test filesystem (requires libfuse-dev)"
	@echo "  make unit-test    Build and run unit tests"
	@echo "  make test         Full scan test: trap a process, run dstate (requires sudo)"
	@echo "  make test-pid     Test the -p flag: trap a process, diagnose by PID"
	@echo "  make test-monitor Test monitor: demonstrates D-state and SIGTERM behavior"
	@echo "  make kill         Kill trap_fs and unmount FUSE"
	@echo "  make clean        Remove binaries and unmount FUSE"
	@echo ""
	@echo "Usage:"
	@echo "  sudo ./dstate              Scan all processes for D-state"
	@echo "  sudo ./dstate -p PID       Diagnose a specific process"
	@echo "  sudo ./dstate -p PID -o F  Diagnose and write an ELF core file to F"
	@echo "  ./dstate -h                Show help"

.PHONY: all clean test test-monitor kill test-pid unit-test help
