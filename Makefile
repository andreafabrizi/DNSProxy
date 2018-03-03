CC=gcc
CFLAGS=-O2 -g -rdynamic
LIBS+=-lcurl -lpthread -lrt -DTLS

# mutex
# gcc dnsp.c -W -lcurl -g -lpthread -rdynamic -lrt -o dnsp
# semaphores
# gcc dnsp.c -W -lcurl -g -lpthread -rdynamic -lrt -o dnsp ......
# threads
# gcc dnsp.c -DTLS -W -lcurl -g -lpthread -rdynamic -lrt -o dnsp

all : dnsp h2
dnsp : dnsp.o
	${CC} dnsp.o ${CFLAGS} ${LIBS} -w -o dnsp
h2 : dnsp-h2.c
	#${CC} dnsp-h2.o ${CFLAGS} -lcurl -lpthread -lrt -w -o dnsp-h2
	gcc dnsp-h2.c -O2 -g -DTLS -rdynamic -lcurl -lpthread -lrt -o dnsp-h2
	#gcc dnsp-h2.c -O2 -g -DTLS -rdynamic -lcurl -lpthread -lrt -o dnsp-h2
dnsp.o : dnsp.c
	${CC} -w -c dnsp.c
dnsp-h2.o : dnsp-h2.c
	${CC} -w -c dnsp-h2.c
clean :
	rm *.o dnsp dnsp-h2
