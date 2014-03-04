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

	maxsock = 350000;
	nbytes = sizeof (fd_set) * ((maxsock + FD_SETSIZE - 1) / FD_SETSIZE);
	set = (fd_set *)calloc(1, nbytes);

	printf("FD_SETSIZE: %d\n", FD_SETSIZE);
	printf("maxsockets: %d\n", maxsock);
	printf("total size: %d\n", nbytes);
	printf("allowed sockets: %d\n", nbytes * 8);

	printf("initial set (should be empty)\n");
	fdset_print_present(set, maxsock);

	printf("adding fd 10 ... \n");
	FD_SET(10, set);
	fdset_print_present(set, maxsock);

	printf("adding fd 345000 ... \n");
	FD_SET(345000, set);
	fdset_print_present(set, maxsock);

	printf("clearing fd 10 ... \n");
	FD_CLR(10, set);
	fdset_print_present(set, maxsock);

	printf("adding fd 343123 ... \n");
	FD_SET(343123, set);
	fdset_print_present(set, maxsock);

	printf("clearing fd 345000 ... \n");
	FD_CLR(345000, set);
	fdset_print_present(set, maxsock);

	/* This is the only one that does not work. */
	printf("zero'ing set (DOES NOT WORK) ... \n");
	FD_ZERO(set);
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
