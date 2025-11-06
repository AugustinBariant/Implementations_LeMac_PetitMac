CFLAGS= -Wall -Wextra -O3 -march=native -fno-lto

all: bench

bench: bench.c
	$(CC) $(CFLAGS) -o $@ $^

clean:
	rm -f bench *.o

.PHONY: all clean
