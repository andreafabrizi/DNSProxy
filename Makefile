

CC=gcc
CFLAGS=-Wall
LIBS=-lcurl

dnsp: dnsp.c
	${CC} ${CFLAGS} ${LIBS} -o dnsp dnsp.c

clean:
	rm -fr *.o
	rm -fr dnsp
