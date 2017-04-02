CC=gcc
CFLAGS=-O2 -g -DTLS -rdynamic -lrt
LIBS+=-lcurl -lpthread 

dnsp: dnsp.c
	${CC} ${CFLAGS} -o dnsp dnsp.c ${LIBS}

clean:
	rm -fr *.o
	rm -fr dnsp
