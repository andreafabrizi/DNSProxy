CC=gcc
CFLAGS=-O2 -Wall
LIBS=-lcurl

dnsp: dnsp.c
	${CC} ${CFLAGS} -o dnsp dnsp.c ${LIBS}

clean:
	rm -fr *.o
	rm -fr dnsp
