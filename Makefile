CC      = gcc
CFLAGS  = -O2 -Wall -W -pedantic -g -rdynamic
FLAG    = -DTLS
CFLAGS += $(FLAG)
LIBS    = -L/usr/local/lib -lcurl -lpthread -lrt

#LIBS   += -L/usr/local/lib -lcurl -lpthread -lrt -lssl -lboost_system -lboost_system -lboost_thread 
#LIBS   += -L/usr/local/lib -lcurl -lpthread -lrt -lnghttp2
#TARGET = testflag

# mutex
# gcc dnsp.c -W -lcurl -g -lpthread -rdynamic -lrt -o dnsp
# semaphores
# gcc dnsp.c -W -lcurl -g -lpthread -rdynamic -lrt -o dnsp ......
# threads
# gcc dnsp.c -DTLS -W -lcurl -g -lpthread -rdynamic -lrt -o dnsp

# asio, nghttp, ssl ...
# gcc dnsp-h2.c -O2 -g -rdynamic -lcurl -lnghttp2 -lpthread -lssl -lboost_system -lboost_system -lboost_thread -lcrypto -lrt -w -o dnsp-h2

all : dnsp dnsp-h2

dnsp : dnsp.o
	${CC} dnsp.o ${CFLAGS} ${LIBS} -w -o dnsp

dnsp.o : dnsp.c
	${CC} -w -c dnsp.c

dnsp-h2 : dnsp-h2.c
	${CC} dnsp-h2.c ${CFLAGS} ${LIBS} -w -o dnsp-h2

#dnsp-h2.o : dnsp-h2.c
#	${CC} -w -c dnsp-h2.c

clean :
	rm dnsp dnsp-h2 dnsp.o dnsp-h2.o

#$(TARGET): $(TARGET).c
#	@echo "In Makefile: FLAG = <$(FLAG)>"
#	$(CC) $(CFLAGS) $< -o $@
#
#clean:
#	rm -f $(TARGET)

