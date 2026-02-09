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

clean:
	rm -f dstate monitor trap_fs

.PHONY: all clean
