# haproxy tests

This repo has a few test programs for testing some of the haproxy `fd_set`
logic.  Most of the haproxy "poller" backends use a bitmask to keep track of
which fds are associated for read and write events.  The "kqueue" poller and
the new event ports poller use an implied array of `fd_set` structures, but use
the existing `FD_SET`/`FD_CLEAR`/`FD_ISSET` macros to access them.  (The "epoll"
and "poll" backends use similar hand-rolled versions, with few or no macros to
help.)  This usage of `fd_set`s is a little shady, but seems to work.

The test programs here include:

- test-haproxy-math.c: tests the haproxy code for computing the size of the
  bitmask structure (applicable to the "kqueue" and "select" pollers).
- test-haproxy-fdsets.c: tests the use of the `FD_*` macros on an implied array
  of `fd_set` objects (applicable to the "kqueue" and "select" pollers).

You can `make all` (or just `make`) to build the corresponding programs.
"test-haproxy-math" generates two programs: one with the default value of
`FD_SETSIZE` (which is assumed to be 1024), and one with a value of 65536 (which
is how haproxy is actually built on SunOS systems).  Use `make clean` to clean
up.
