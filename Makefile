#
# Makefile for haproxy test programs
#

PROGS = test-math-1024 test-math-65536 test-haproxy-fdsets

all: $(PROGS)

test-math-1024: test-haproxy-math.c
	gcc -Wall -Werror -o $@ test-haproxy-math.c

test-math-65536: test-haproxy-math.c
	gcc -DFD_SETSIZE=65536 -Wall -Werror -o $@ test-haproxy-math.c

test-haproxy-fdsets: test-haproxy-fdsets.c
	gcc -DFD_SETSIZE=65536 -Wall -Werror -o $@ test-haproxy-fdsets.c

clean:
	-rm -f $(PROGS)
