CC=gcc
CFLAGS=-O2 -g -rdynamic
LIBS+=-lcurl -lpthread -lrt -DTLS

# mutex
# gcc dnsp.c -W -lcurl -g -lpthread -rdynamic -lrt -o dnsp
# semaphores
# gcc dnsp.c -W -lcurl -g -lpthread -rdynamic -lrt -o dnsp ......
# threads
# gcc dnsp.c -DTLS -W -lcurl -g -lpthread -rdynamic -lrt -o dnsp

# asio, nghttp, ssl ...
# gcc dnsp-h2.c -O2 -g -rdynamic -lcurl -lnghttp2 -lpthread -lssl -lboost_system -lboost_system -lboost_thread -lcrypto -lrt -w -o dnsp-h2

all : dnsp

dnsp : dnsp.c
	${CC} dnsp.c ${CFLAGS} ${LIBS} -w -o dnsp
	${CC} dnsp-h2.c ${CFLAGS} ${LIBS} -w -o dnsp-h2

clean :
	rm dnsp dnsp-h2
