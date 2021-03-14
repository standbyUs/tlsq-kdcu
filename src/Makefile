CC=/media/alex/ex-hard/oct/gcc-linaro-arm-linux-gnueabihf-4.7-2013.03-20130313_linux/bin/arm-linux-gnueabihf-gcc
LD=/media/alex/ex-hard/oct/gcc-linaro-arm-linux-gnueabihf-4.7-2013.03-20130313_linux/bin/arm-linux-gnueabihf-ld

CFLAGS = -I./include -L./libs -lczmq -lzmq -lcurl -lssl -lcrypto -ljson-c -lpthread -lrt -lstdc++ -Wall -lm

ALL_EXE=iaaa-client
IAAA_CLIENT_OBJ=tlsq-dcu-logger.o tlsq-dcu-utils.o

all	: ${ALL_EXE}

iaaa-client : udp-server.c $(IAAA_CLIENT_OBJ)
	$(CC) -o $@ udp-server.c $(IAAA_CLIENT_OBJ) $(CFLAGS)

tlsq-dcu-logger.o : tlsq-dcu-logger.c
	$(CC) -c tlsq-dcu-logger.c

tlsq-dcu-utils.o : tlsq-dcu-utils.c
	$(CC) -c tlsq-dcu-utils.c

clean:
	rm $(ALL_EXE) *.o

