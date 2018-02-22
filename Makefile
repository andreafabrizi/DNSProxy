CC=gcc
CFLAGS=-O2 -g -DTLS -rdynamic
LIBS+=-lcurl -lpthread -lrt

#mutex
#gcc dnsp.c -W -lcurl -g -lpthread -rdynamic -lrt -o dnsp
#semaphores
#gcc dnsp.c -W -lcurl -g -lpthread -rdynamic -lrt -o dnsp ......
#threads
#gcc dnsp.c -DTLS -W -lcurl -g -lpthread -rdynamic -lrt -o dnsp

dnsp: dnsp.c
	${CC} ${CFLAGS} ${LIBS} -o dnsp dnsp.c

clean:
	rm -fr *.o
	rm -fr dnsp
