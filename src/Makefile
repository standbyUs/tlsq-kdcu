CC=/media/alex/ex-hard/oct/gcc-linaro-arm-linux-gnueabihf-4.7-2013.03-20130313_linux/bin/arm-linux-gnueabihf-gcc
LD=/media/alex/ex-hard/oct/gcc-linaro-arm-linux-gnueabihf-4.7-2013.03-20130313_linux/bin/arm-linux-gnueabihf-ld

CFLAGS = -I./include -L./libs -lczmq -lzmq -lcurl -lssl -lcrypto -ljson-c -lpthread -lrt -lstdc++ -Wall -lm -L./ -lmsg-queue

ALL_EXE=iaaa-client
IAAA_CLIENT_OBJ=tlsq-dcu-logger.o tlsq-dcu-utils.o
MSGQUEUE_LIB_OUT=msg-queue
MSGQUEUE_LIB=msg-queue
MSGQUEUE_LIB_SO=libmsg-queue
all	: ${ALL_EXE}
msg : $(MSGQUEUE_LIB_OUT) 

iaaa-client : udp-server.c $(IAAA_CLIENT_OBJ) $(MSGQUEUE_LIB_OUT)
	$(CC) -o $@ udp-server.c $(IAAA_CLIENT_OBJ) $(CFLAGS)
	cp libmsg-queue.so libs/
	
tlsq-dcu-logger.o : tlsq-dcu-logger.c
	$(CC) -c tlsq-dcu-logger.c

tlsq-dcu-utils.o : tlsq-dcu-utils.c
	$(CC) -c tlsq-dcu-utils.c

$(MSGQUEUE_LIB_OUT) : $(MSGQUEUE_LIB).o
	$(CC) -c -fPIC -I./include $(MSGQUEUE_LIB).c
	$(CC) -shared -o $(MSGQUEUE_LIB_SO).so $(MSGQUEUE_LIB).o
	cp libmsg-queue.so libs/

clean:
	rm $(ALL_EXE) $(MSGQUEUE_LIB_SO).so *.o 

