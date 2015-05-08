/*
 * test-haproxy-fdsets.c: validates haproxy's usage of multiple adjacent
 * "fd_set" objects as a single giant fd_set.
 */

#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <sys/time.h>

static void fdset_print_present(fd_set *, int);

int
main(int argc, char *argv[])
{
	fd_set *set;
	int maxsock, nbytes;

	maxsock = 131091;
	nbytes = sizeof (fd_set) * ((maxsock + FD_SETSIZE - 1) / FD_SETSIZE);
	set = (fd_set *)calloc(1, nbytes);

	fdset_print_present(set, maxsock);

	return (0);
}

static void
fdset_print_present(fd_set *set, int maxsock)
{
	int i, count;

	count = 0;
	for (i = 0; i < maxsock; i++) {
		if (FD_ISSET(i, set)) {
			printf("    fd %6d present\n", i);
			count++;
		}
	}

	if (count == 0)
		printf("    empty set\n");
}
