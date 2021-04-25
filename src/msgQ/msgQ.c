#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>

#include "msgQ.h"



int create_msgQ(key_t msg_key)
{
	int msgID;
	
	msgID = msgget(msg_key, 0666 | IPC_CREAT); 

	if (msgID == -1)  {
		perror("create_msgQ is failed !!");
		return -1;
	}

	return msgID;
}


int send_msgQ(int msgID, msgQ_context *msgq)
{
	int ret;
	size_t msg_size;

	if (msgq->msg_body.data_length == 0 || msgq->msg_body.data_length > MAX_MSGQ_DATA_SIZE)  {
		perror("send_msgQ data size is invalid !!");
		return -1;
	}

	msg_size = sizeof(msgq->msg_body.data_length) + msgq->msg_body.data_length;

	ret = msgsnd(msgID, (void *)msgq, msg_size, IPC_NOWAIT);

	if (ret == -1)  {
		perror("send_msgQ is failed !!");
		return -1;
	}

	return 0;
}


int recv_msgQ(int msgID, msgQ_context *msgq)
{
	ssize_t msg_size;
	
	msg_size = msgrcv(msgID, (void *)msgq, sizeof(msgQ_context), 0, IPC_NOWAIT | MSG_NOERROR);

	return msg_size;
}


int remove_msgQ(int msgID)
{
	if (msgctl(msgID, IPC_RMID, NULL) == -1)  {
		perror("remove_msgQ is failed !!");
		return -1;
	}

	return 0;
}


int create_msgQEvent(key_t msg_key)
{
	int msgID;
	
	msgID = msgget(msg_key, 0666 | IPC_CREAT); 

	if (msgID == -1)  {
		perror("create_msgQEvent is failed !!");
		return -1;
	}

	return msgID;
}


int send_msgQEvent(int msgID, msgQEvent_context *msgq)
{
	int ret;
	size_t msg_size;

	msg_size = sizeof(msgq->msg);

	ret = msgsnd(msgID, (void *)msgq, msg_size, IPC_NOWAIT);

	if (ret == -1)  {
		perror("send_msgQEvent is failed !!");
		return -1;
	}

	return 0;
}


int recv_msgQEvent(int msgID, msgQEvent_context *msgq)
{
	ssize_t msg_size;
	
	msg_size = msgrcv(msgID, (void *)msgq, sizeof(msgQEvent_context), 0, IPC_NOWAIT | MSG_NOERROR);

	return msg_size;
}


int remove_msgQEvent(int msgID)
{
	if (msgctl(msgID, IPC_RMID, NULL) == -1)  {
		perror("remove_msgQEvent is failed !!");
		return -1;
	}

	return 0;
}

