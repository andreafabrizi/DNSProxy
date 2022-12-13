CC      = gcc
CFLAGS  = -O2 -Wall -W -pedantic -rdynamic -g
FLAG    = -DTLS
CFLAGS += $(FLAG)
LIBS    = -lcurl -lrt -lnghttp2 -lssl -lbrotlidec -lz -lcrypto -lpthread -lnghttp2
#LIBS   += -L/usr/local/lib

#CFLAGS  = -std=c99 -O2 -Wall -W -pedantic -g -rdynamic
#LIBS   += -lssl -lboost_system -lboost_system -lboost_thread 
#LIBS   += -lnghttp2
#LIBS   += -lb64
#TARGET = testflag
#LIBS:            -lnghttp2 -lpsl -lssl -lcrypto -lssl -lcrypto -lbrotlidec -lz

# mutex
# gcc dnsp.c -W -lcurl -g -lpthread -rdynamic -lrt -lbrotlidec -o dnsp
# semaphore
# gcc dnsp.c -W -lcurl -g -lpthread -rdynamic -lrt -o dnsp
# threads
# gcc dnsp.c -DTLS -W -lcurl -g -lpthread -rdynamic -lrt -o dnsp
# asio, boost, nghttp, ssl
# gcc dnsp-h2.c -O2 -g -rdynamic -lcurl -lnghttp2 -lpthread -lssl -lboost_system -lboost_system -lboost_thread -lcrypto -lrt -lbrotlidec -w -o dnsp-h2

all : dnsp dnsp-h2

dnsp : dnsp.o
	${CC} dnsp.o ${CFLAGS} ${LIBS} -w -o dnsp

dnsp.o : dnsp.c
	${CC} -w -c dnsp.c

dnsp-h2 : dnsp-h2.o
	${CC} encode.o decode.o dnsp-h2.o ${CFLAGS} ${LIBS} -w -o dnsp-h2

dnsp-h2.o : dnsp-h2.c
	${CC} -w -c dnsp-h2.c

#${CC} encode.o decode.o dnsp-h2.c ${CFLAGS} ${LIBS} -w -o dnsp-h2

#${CC} librb64u.c encode.o decode.o base64.c dnsp-h2.c ${CFLAGS} ${LIBS} -w -o dnsp-h2
#dnsp-h2.o : dnsp-h2.c
#	${CC} -w -c dnsp-h2.c

clean :
	rm -v dnsp dnsp-h2 dnsp.o dnsp-h2.o

#$(TARGET): $(TARGET).c
#	@echo "In Makefile: FLAG = <$(FLAG)>"
#	$(CC) $(CFLAGS) $< -o $@
#
#clean:
#	rm -f $(TARGET)

