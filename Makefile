CC=gcc
CFLAGS=-O2 -g -rdynamic
LIBS+=-lcurl -lpthread -lrt -DTLS

# mutex
# gcc dnsp.c -W -lcurl -g -lpthread -rdynamic -lrt -o dnsp
# semaphores
# gcc dnsp.c -W -lcurl -g -lpthread -rdynamic -lrt -o dnsp ......
# threads
# gcc dnsp.c -DTLS -W -lcurl -g -lpthread -rdynamic -lrt -o dnsp

all : dnsp

dnsp : dnsp.o
	${CC} dnsp.o ${CFLAGS} ${LIBS} -w -o dnsp

dnsp.o : dnsp.c
	${CC} -w -c dnsp.c

clean :
	rm -fr *.o
	rm -fr dnsp
