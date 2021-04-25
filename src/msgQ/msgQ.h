#ifndef _MSGQ_H_
#define _MSGQ_H_

#include <stdint.h>
#include <sys/types.h>
#include <sys/ipc.h>
#include <sys/msg.h>


#define MAX_MSGQ_DATA_SIZE 2048

typedef struct msgQ_data_context_s {
	size_t data_length;
	char data[MAX_MSGQ_DATA_SIZE];	
} msgQ_data_context;

typedef struct msgQ_context_s {
	long msg_type;
	msgQ_data_context msg_body;
} msgQ_context;

typedef struct msgQEvent_context_s {
	long msg_type;
	uint32_t msg;
} msgQEvent_context;



int create_msgQ(key_t msg_key);

int send_msgQ(int msgID, msgQ_context *msgq);

int recv_msgQ(int msgID, msgQ_context *msgq);

int remove_msgQ(int msgID);

int create_msgQEvent(key_t msg_key);

int send_msgQEvent(int msgID, msgQEvent_context *msgq);

int recv_msgQEvent(int msgID, msgQEvent_context *msgq);

int remove_msgQEvent(int msgID);


#endif /* _MSGQ_H_ */
