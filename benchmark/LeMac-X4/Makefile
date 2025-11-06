CFLAGS= -Wall -Wextra -O3 -fno-lto -mavx512f -mavx512vl -mvaes -maes

all: bench

bench: bench.c
	$(CC) $(CFLAGS) -o $@ $^

clean:
	rm -f bench *.o

.PHONY: all clean
