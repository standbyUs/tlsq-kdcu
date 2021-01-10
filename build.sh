 rm *.o
 gcc -c tlsq-dcu-logger.c tlsq-dcu-utils.c -I./ -lpthread
 gcc -o udp-server udp-server.c tlsq-dcu-logger.o tlsq-dcu-utils.o -I./ -lpthread