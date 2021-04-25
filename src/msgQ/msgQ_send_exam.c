#include <stdio.h>
#include <ctype.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <errno.h>
#include <string.h>
#include <stdlib.h>
#include <stdarg.h>
#include <unistd.h>

#include <sys/ipc.h>
#include <sys/msg.h>


#include "msgQ.h"
#include "msgQService.h"




void usage(void)
{
	fprintf(stdout, "Usage: msgsend [key] [type/cmd] [data]\n");
}


int main(int argc, char* argv[]) 
{
	int ret;
	int msgID;
	msgQ_context msgq;
	key_t msgKey;


	if (argc < 4 || argc > 4)  {
		usage();
		exit(1);
	}

	msgKey = (key_t)atol(argv[1]);

	msgID = create_msgQ(msgKey);
	fprintf(stdout, "Created Message Queue : msgKey = %d, msgID = %d\n", 
		(int)msgKey, msgID);

	if (msgID == -1) 
	{
		fprintf(stderr, "Message Queue Creation Error ..." );
		return -1;
	}

	msgq.msg_type = atol(argv[2]);
	msgq.msg_body.data_length = strlen(argv[3]);
	strncpy(msgq.msg_body.data, argv[3], msgq.msg_body.data_length);

	fprintf(stdout, "msg_type = 0x%04X\n", (unsigned int)msgq.msg_type);
	fprintf(stdout, "data_length = %lu\n", msgq.msg_body.data_length);
	fprintf(stdout, "data = %s\n", msgq.msg_body.data);

	fprintf(stdout, "Message Queue Data is sending ...\n");

	ret = send_msgQ(msgID, &msgq);
	
	if (ret != 0)  {
		fprintf(stdout, "Message Queue Data Sending is failed !!\n");
		return -1;
	}
	
	return 0;
}

