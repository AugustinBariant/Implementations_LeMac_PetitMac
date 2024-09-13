CFLAGS= -Wall -Wextra -O3 -g -march=native

all: lemac.so petitmac.so

lemac.so: lemac.c
	$(CC) $(CPPFLAGS) $(CFLAGS) -shared -fPIC -o $@ $<

petitmac.so: petitmac.c
	$(CC) $(CPPFLAGS) $(CFLAGS) -shared -fPIC -o $@ $<

clean:
	rm -f *.o *.so

.PHONY: all clean
