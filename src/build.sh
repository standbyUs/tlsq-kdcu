CC=/media/alex/ex-hard/oct/gcc-linaro-arm-linux-gnueabihf-4.7-2013.03-20130313_linux/bin/arm-linux-gnueabihf-gcc
LD=/media/alex/ex-hard/oct/gcc-linaro-arm-linux-gnueabihf-4.7-2013.03-20130313_linux/bin/arm-linux-gnueabihf-ld


INC = -I./ -I./include 
LIBS = -L./libs -lczmq -lzmq -lcurl -lssl -lcrypto -ljson-c -lpthread -lrt -lstdc++
CFLAGS = -Wall -lm $(INC)

ALL_EXE=iaaa-client
IAAA_CLIENT_OBJ=tlsq-dcu-logger.o tlsq-dcu-utils.o msg-queue.o

all	: ${ALL_EXE}

iaaa-client : udp-server.c $(IAAA_CLIENT_OBJ)
	$(CC) -o $@ udp-server.c $(IAAA_CLIENT_OBJ) $(CFLAGS) $(LIBS)

tlsq-dcu-logger.o : tlsq-dcu-logger.c
	$(CC) -c tlsq-dcu-logger.c $(CFLAGS)

tlsq-dcu-utils.o : tlsq-dcu-utils.c
	$(CC) -c tlsq-dcu-utils.c $(CFLAGS)

msg-queue.o : msg-queue.c
	$(CC) -c msg-queue.c $(CFLAGS)

clean:
	rm $(ALL_EXE) *.o

