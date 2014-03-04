/*
 * test-haproxy-math.c: replicates the calculation used by haproxy to determine
 * how many bytes to allocate for its array of "fd_set" objects.
 */

#include <stdio.h>
#include <sys/time.h>

static void do_example(int);

int
main(int argc, char *argv[])
{
	printf("sizeof (fd_set) = %d\n", sizeof (fd_set));
	printf("FD_SETSIZE = %d\n", FD_SETSIZE);

	printf("%7s  %10s  %11s  %10s  %11s\n",
	    "MAXSOCK", "CALCNBYTES", "CALCMAXSOCK", "CORRNBYTES",
	    "CORRMAXSOCK");
	do_example(1000);
	do_example(1002);
	do_example(65000);
	do_example(65535);
	do_example(65536);
	do_example(65538);
	do_example(130000);

	printf("\nKey:\n");
	printf("MAXSOCK:     example value for \"maxsock\" config variable\n");
	printf("CALCNBYTES:  number of bytes haproxy allocates for this value "
	    "of MAXSOCK\n");
	printf("CALCMAXSOCK: number of sockets actually supported based on "
	    "CALCNBYTES\n");
	printf("CORRNBYTES:  number of bytes allocated based on a corrected "
	    "formula\n");
	printf("CORRMAXSOCK: number of sockets actually supported based on "
	    "CORRNBYTES\n");

	return (0);
}

static void
do_example(int maxsock)
{
	int fd_set_haproxy, fd_set_correct;

	/*
	 * "fd_set_haproxy" is the calculation that haproxy actually uses, and
	 * appears to be unintentionally conservative because of the order in
	 * which the operations are evaluated.  "fd_set_correct" is the the
	 * number of bytes based on how the formula appears to be intended.
	 */
	fd_set_haproxy =
	    sizeof (fd_set) * (maxsock + FD_SETSIZE - 1) / FD_SETSIZE;
	fd_set_correct =
	    sizeof (fd_set) * ((maxsock + FD_SETSIZE - 1) / FD_SETSIZE);
	printf("%7d  %10d  %11d  %10d  %11d\n", maxsock,
	    fd_set_haproxy, fd_set_haproxy * 8,
	    fd_set_correct, fd_set_correct * 8);
}
