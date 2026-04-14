CC = gcc
CFLAGS = -g -O0 -w
# CFLAGS = -g -O3 -Wall -Wextra

.phony: all clean

all: cache-time flush-reload spectre out-of-order

%: %.c
	$(CC) -o $@ $(CFLAGS) $^

clean:
	rm -f cache-time flush-reload spectre out-of-order
