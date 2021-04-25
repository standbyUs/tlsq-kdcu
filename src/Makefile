CC=/media/alex/ex-hard/oct/gcc-linaro-arm-linux-gnueabihf-4.7-2013.03-20130313_linux/bin/arm-linux-gnueabihf-gcc
LD=/media/alex/ex-hard/oct/gcc-linaro-arm-linux-gnueabihf-4.7-2013.03-20130313_linux/bin/arm-linux-gnueabihf-ld

CFLAGS = -I./include -L./ -lmsg-queue -L./libs -lczmq -lzmq -lcurl -lssl -lcrypto -ljson-c -lpthread -lrt -lstdc++ -Wall -lm -Wextra -Wno-unused-parameter
ALL_EXE=iaaa-client
IAAA_CLIENT_OBJ=tlsq-dcu-logger.o tlsq-dcu-utils.o
MSGQUEUE_LIB_OUT=msg-queue
MSGQUEUE_LIB=msg-queue
MSGQUEUE_LIB_SO=libmsg-queue
TEST_MSG_QUEUE=test-msg-queue
MSGQ_OBJ=./msgQ/msgQ.o


all	: ${ALL_EXE}
msg : $(MSGQUEUE_LIB_OUT) 

iaaa-client : udp-server.c $(IAAA_CLIENT_OBJ) $(MSGQUEUE_LIB_OUT) $(TEST_MSG_QUEUE) $(MSGQ_OBJ)
	$(CC) -o $@ udp-server.c $(IAAA_CLIENT_OBJ) $(MSGQ_OBJ) $(CFLAGS)
	cp libmsg-queue.so libs/
	rm -rf dist/*
	cp libs dist/ -a
	cp include dist/ -a
	cp conf/.curve/ dist/ -a
	cp $(ALL_EXE) $(TEST_MSG_QUEUE) dist/
	cp tlsq-dcu.conf dist/
	
tlsq-dcu-logger.o : tlsq-dcu-logger.c
	$(CC) -c -fPIC tlsq-dcu-logger.c

tlsq-dcu-utils.o : tlsq-dcu-utils.c
	$(CC) -c tlsq-dcu-utils.c

$(MSGQUEUE_LIB_OUT) : $(MSGQUEUE_LIB).o tlsq-dcu-logger.o base64-decode.o base64-encode.o buffer.o
	$(CC) -c -fPIC -I./include $(MSGQUEUE_LIB).c
	$(CC) -shared -o $(MSGQUEUE_LIB_SO).so $(MSGQUEUE_LIB).o tlsq-dcu-logger.o base64-decode.o base64-encode.o buffer.o
	cp libmsg-queue.so libs/

base64-decode.o : base64-decode.c
	$(CC) -c -fPIC base64-decode.c

base64-encode.o : base64-encode.c
	$(CC) -c -fPIC base64-encode.c

buffer.o : buffer.c
	$(CC) -c -fPIC buffer.c


$(MSGQ_OBJ): ./msgQ/msgQ.c
	$(CC) -c -fPIC ./msgQ/msgQ.c -o ./msgQ/msgQ.o

$(TEST_MSG_QUEUE) : $(TEST_MSG_QUEUE).c
	$(CC) -o $@ test-msg-queue.c $(CFLAGS)

clean:
	rm $(ALL_EXE) $(MSGQUEUE_LIB_SO).so *.o $(TEST_MSG_QUEUE)
	rm -f $(MSGQ_OBJ)

	
