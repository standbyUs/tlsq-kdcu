CC=gcc

CFLAGS=-Wall -Wextra -Wno-unused-parameter

OBJS1=./msgQ/msgQ.o snmpAuth.o
OBJS2=./msgQ/msgQ.o authSnmp.o

TARGETS1=snmp
TARGETS2=auth

# shared library flags (assumes gcc)
DLFLAGS=-fPIC -shared
LDFLAGS+=-lpthread -lrt

all: $(TARGETS1) $(TARGETS2)

$(TARGETS1): $(OBJS1) 
	$(CC) $(OBJS1) $(CFLAGS) -o $@

$(TARGETS2): $(OBJS2) 
	$(CC) $(OBJS2) $(CFLAGS) -o $@

clean:
	rm -f $(OBJS1) $(OBJS2)
	rm -f $(TARGETS1) $(TARGETS2)	

