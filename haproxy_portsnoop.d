#!/usr/sbin/dtrace -Cqs

/*
 * haproxy_portsnoop -p PID: trace file descriptor event port activity for an
 * haproxy process.  This is an ugly, hacked-up version of portsnoop
 * (https://github.com/davepacheco/portsnoop) that combines that output with
 * information from the haproxy poller-level functions.
 */

#define	PORT_OPCODE_MASK	0xff
#define	OP_PORT_ASSOCIATE	1
#define	OP_PORT_DISSOCIATE	2
#define	OP_PORT_GET		5
#define	OP_PORT_GETN		6

#define PORT_OPCODE(x)	((x) & PORT_OPCODE_MASK)
#define	HI32(x)		(((uint64_t)(x) & 0xffffffff) >> 32)
#define	LO32(x)		((uint64_t)(x) & 0xffffffff)

#define _SYSCALL32
#include <sys/port.h>

#define PORT_SOURCE_TOSTR(x)	\
    (x) == PORT_SOURCE_AIO	? "PORT_SOURCE_AIO" :	\
    (x) == PORT_SOURCE_TIMER	? "PORT_SOURCE_TIMER" :	\
    (x) == PORT_SOURCE_USER	? "PORT_SOURCE_USER" :	\
    (x) == PORT_SOURCE_FD	? "PORT_SOURCE_FD" :	\
    (x) == PORT_SOURCE_ALERT	? "PORT_SOURCE_ALERT" :	\
    (x) == PORT_SOURCE_MQ	? "PORT_SOURCE_MQ" :	\
    (x) == PORT_SOURCE_FILE	? "PORT_SOURCE_FILE" : "UNKNOWN"

#define	TIMESTAMP_ARGS \
    (timestamp - start) / (1000 * 1000 * 1000), \
    ((timestamp - start) % (1000 * 1000 * 1000)) / 1000, \
    (self->inpoll ? "* " : "  ")

#define	PRINT_EVENT							\
	syscall::portfs:return						\
	/this->ev_source != 0/						\
	{								\
		printf("%3d.%06d  %s%22s fd %3d fdevents 0x%02x\n",	\
		    TIMESTAMP_ARGS, 					\
		    PORT_SOURCE_TOSTR(this->ev_source), this->ev_fd,    \
		    this->ev_events);					\
		self->pendings[this->ev_fd] = 1;			\
		this->ev_fd = 0;					\
		this->ev_events = 0;					\
		this->ev_source = 0;					\
	}

#define LOGENTRY \
	printf("%3d.%06d  %s%-15s:%-6s ", TIMESTAMP_ARGS, \
	    probefunc, probename);

BEGIN
{
	start = timestamp;
	printf("%-10s    %-22s  %5s %-25s  %-11s\n",
	    "TIME", "SYSCALL", "FD", "DETAILS", "ERROR");
}

pid$target::ev_do_poll:entry
{
	self->inpoll = 1;
	LOGENTRY;
	printf("\n");
}

pid$target::ev_do_poll:return
{
	LOGENTRY
	self->inpoll = 0;
	printf("\n");
}

/*
 * The event port system calls return an rval_t, a 64-bit union containing two
 * 32-bit ints.  See usr/src/lib/libc/port/gen/event_port.c for details.  The
 * logic here mirrors that implementation.
 *
 * In general, the call failed if the low int is -1, in which case errno is
 * already set.  For port_getn, if the low int is not -1, it denotes the number
 * of events returned.  In that case, the high value is either 0 or ETIME, but
 * both indicate that at least one event may have been returned.  See 6456558.
 */

/*
 * port_getn
 */
syscall::portfs:entry
/pid == $target && PORT_OPCODE(arg0) == OP_PORT_GETN/
{
	self->getn_list = arg2;
}

syscall::portfs:return
/self->getn_list && LO32(arg0) == (uint32_t)-1/
{
	printf("%3d.%06d  %s%-22s    %3s %-25s  errno = %3d\n",
	    TIMESTAMP_ARGS, "port_getn", "-", "FAILED", errno);
	self->getn_list = 0;
}

syscall::portfs:return
/self->getn_list && LO32(arg0) != (uint32_t)-1/
{
	printf("%3d.%06d  %s%-22s    %3s %d events\n",
	    TIMESTAMP_ARGS, "port_getn", "-", LO32(arg0));
	this->getn_count = LO32(arg0);
	this->getn_i = 0;
}

#define	ITER_EVENT							\
	syscall::portfs:return						\
	/self->getn_list && this->getn_count > 0 &&			\
	 this->getn_i < this->getn_count/				\
	{								\
		this->event = (port_event32_t *)copyin(		\
		    self->getn_list +					\
		    this->getn_i * sizeof (port_event32_t),		\
		    sizeof (port_event32_t));				\
		this->ev_fd = this->event->portev_object;		\
		this->ev_events = this->event->portev_events;		\
		this->ev_source = this->event->portev_source;		\
		this->event = 0;					\
		this->getn_i++;						\
	}								\
									\
	PRINT_EVENT

ITER_EVENT
ITER_EVENT
ITER_EVENT
ITER_EVENT
ITER_EVENT
ITER_EVENT
ITER_EVENT
ITER_EVENT
ITER_EVENT
ITER_EVENT
ITER_EVENT
ITER_EVENT
ITER_EVENT
ITER_EVENT
ITER_EVENT

syscall::portfs:return
/self->getn_list/
{
	self->getn_list = 0;
	this->getn_i = 0;
	this->getn_count = 0;
}

/*
 * read/write/accept
 */
syscall::read:entry,
syscall::write:entry,
syscall::accept:entry
/self->pendings[arg0]/
{
	self->fd = arg0;
}

syscall::read:return,
syscall::write:return,
syscall::accept:return,
syscall::close:return
/self->fd && arg1 == -1/
{
	printf("%3d.%06d      %s%-18s fd %3d = %-18d  (errno = %d)\n",
	    TIMESTAMP_ARGS, probefunc, self->fd, arg1, errno);
	self->fd = 0;
}

syscall::close:return
/self->fd/
{
	self->pendings[self->fd] = 0;
}

syscall::read:return,
syscall::write:return,
syscall::accept:return,
syscall::close:return
/self->fd/
{
	printf("%3d.%06d      %s%-18s fd %3d = %-23d\n",
	    TIMESTAMP_ARGS, probefunc, self->fd, arg1);
	self->fd = 0;
}


/*
 * port_get
 */
syscall::portfs:entry
/pid == $target && PORT_OPCODE(arg0) == OP_PORT_GET/
{
	self->get_event = arg2;
}

syscall::portfs:return
/self->get_event && LO32(arg0) == -1/
{
	printf("%3d.%06d  %s%-22s  %5s %-25s  errno = %3d\n",
	    TIMESTAMP_ARGS, "port_get", "-", "FAILED", errno);
	self->get_event = 0;
}

syscall::portfs:return
/self->get_event/
{
	printf("%3d.%06d  %s%-22s  %5s\n",
	    TIMESTAMP_ARGS, "port_get", "-");
	this->event = (port_event32_t *)copyin(
	    self->get_event, sizeof (port_event32_t));
	this->ev_fd = this->event->portev_object;
	this->ev_events = this->event->portev_events;
	this->ev_source = this->event->portev_source;
	this->event = 0;
	this->get_event = 0;
}

PRINT_EVENT

syscall::portfs:return
/self->get_event/
{
	this->ev_fd = 0;
	this->ev_events = 0;
	this->ev_source = 0;
}

/*
 * port_associate
 */
syscall::portfs:entry
/pid == $target && PORT_OPCODE(arg0) == OP_PORT_ASSOCIATE && arg2 == PORT_SOURCE_FD/
{
	self->assoc_follow = 1;
	self->assoc_fd = arg3;
	self->assoc_events = arg4;
	self->pendings[arg3] = 0;
}

syscall::portfs:return
/self->assoc_follow && LO32(arg0) == -1/
{
	printf("%3d.%06d  %s%-22s fd %3d %-25s  errno = %3d\n",
	    TIMESTAMP_ARGS, "port_associate", self->assoc_fd, "FAILED",
	    errno);
	self->assoc_follow = 0;
	self->assoc_fd = 0;
	self->assoc_events = 0;
}

syscall::portfs:return
/self->assoc_follow/
{
	printf("%3d.%06d  %s%-22s fd %3d 0x%02x\n",
	    TIMESTAMP_ARGS, "port_associate", self->assoc_fd,
	    self->assoc_events);
	self->assoc_follow = 0;
	self->assoc_fd = 0;
	self->assoc_events = 0;
}

/*
 * port_dissociate
 */
syscall::portfs:entry
/pid == $target && PORT_OPCODE(arg0) == OP_PORT_DISSOCIATE && arg2 == PORT_SOURCE_FD/
{
	self->dissoc_follow = 1;
	self->dissoc_fd = arg3;
	self->pendings[arg3] = 0;
}

syscall::portfs:return
/self->dissoc_follow && LO32(arg0) == -1/
{
	printf("%3d.%06d  %s%-22s fd %3d %-25s  errno = %3d\n",
	    TIMESTAMP_ARGS, "port_dissociate", self->dissoc_fd,
	    "FAILED", errno);
	self->dissoc_follow = 0;
	self->dissoc_fd = 0;
}

syscall::portfs:return
/self->dissoc_follow/
{
	printf("%3d.%06d  %s%-22s  fd %3d\n",
	    TIMESTAMP_ARGS, "port_dissociate", self->dissoc_fd);
	self->dissoc_follow = 0;
	self->dissoc_fd = 0;
}

pid$target::ev_fd_is_set:entry,
pid$target::ev_fd_set:entry,
pid$target::ev_fd_clr:entry
{
	LOGENTRY
	printf("fd %3d direction %s\n", arg0, arg1 ? "WRITE" : "READ");
}

pid$target::ev_fd_is_set:return,
pid$target::ev_fd_set:return,
pid$target::ev_fd_clr:return
{
	LOGENTRY
	printf("\n");
}

pid$target::ev_fd_rem:entry,
pid$target::ev_fd_clo:entry,
pid$target::ev_fd_update:entry
{
	LOGENTRY
	printf("fd %3d\n", arg0);
}

pid$target::ev_fd_events:entry
{
	self->fd = arg0;
}

pid$target::ev_fd_events:return
/self->fd/
{
	LOGENTRY
	printf("fd %3d events 0x%x\n", self->fd, arg1);
	self->fd = 0;
}
