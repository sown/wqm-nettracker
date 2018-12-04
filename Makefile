PROGS := nettracker
NETTRACKER_SRCS := main.c
NETTRACKER_OBJS := ${NETTRACKER_SRCS:.c=.o}

.PHONY: all

all: ${PROGS}

nettracker: ${NETTRACKER_OBJS}
	gcc ${NETTRACKER_OBJS} -lpcap -o nettracker


%.o: %.c Makefile
	gcc ${CFLAGS} -c $<
