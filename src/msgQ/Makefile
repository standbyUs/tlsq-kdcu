CC=gcc

CFLAGS=-Wall -Wextra 

OBJS1=msgQ.o msgQ_exam.o
OBJS2=msgQ.o msgQ_send_exam.o

TARGETS1=msg
TARGETS2=msgsend

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

