#include <stdio.h>
#include <ctype.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <errno.h>
#include <string.h>
#include <stdlib.h>
#include <stdarg.h>
#include <unistd.h>
#include <signal.h>

#include <sys/ipc.h>
#include <sys/msg.h>



#include "msgQ.h"
#include "msgQService.h"

char msgQ_data[MAX_MSGQ_DATA_SIZE];


int keep_running = 0;



void signal_handler(int signal)
{
	switch(signal)  {
		case SIGHUP:
			fprintf(stderr,"Hangup Signal Catched\n");
			break;
		case SIGTERM:
			fprintf(stderr,"Terminate Signal Catched\n");
			keep_running = 0;
			break;
		case SIGINT:
			fprintf(stderr,"Keyoard Interrupt Signal Catched\n");
			keep_running = 0;
			break;			
    }
}


int daemonize(void) 
{
	pid_t pid;
	pid_t sid;

    pid = fork();

	if (pid != 0)  {
		if (pid < 0)  {
			fprintf(stderr, "daemonize:first fork failed (errno %d)\n", errno);
			return -1;
		}
		fprintf(stderr, "daemonize:parent exiting, quit_immediately\n");
		fprintf(stderr, "child process id : [%d], parent process id : [%d] \n", pid, getpid());
		exit(0);
	}
	
	fprintf(stderr, "Daemonized process id : [%d]\n", getpid());
	
    sid = setsid();
	if(sid < 0)  exit(0);

    signal(SIGCHLD, SIG_IGN);
    signal(SIGTSTP, SIG_IGN);
    signal(SIGTTOU, SIG_IGN);
    signal(SIGTTIN, SIG_IGN);

    signal(SIGHUP, signal_handler);
    signal(SIGTERM, signal_handler);
	signal(SIGINT, signal_handler);

	return 0;
}


void usage(void)
{
	fprintf(stdout, "Usage: msg [key]\n");
}


int main(int argc, char* argv[]) 
{
	int dont_fork = 0;

	int msgID;
	msgQ_context msgq;
	int msgq_received;
	key_t msgKey;

	if (argc < 2 || argc > 2)  {
		usage();
		exit(1);
	}	

	fprintf(stdout, "Message Queue Servie is started\n");

	/* In case we recevie a request to stop (kill -TERM or kill -INT) */
	keep_running = 1;

	/* Daemonize */
	if (!dont_fork) {
		int ret = daemonize();
		if(ret != 0) {
			fprintf(stderr, "Daemonizing Exiting with code %d\n", ret);
			exit(1);
		}		
	}


	msgKey = (key_t)atol(argv[1]);

	memset(&msgq, 0x00, sizeof(msgq));

	msgID = create_msgQ(msgKey);
	fprintf(stdout, "Created Message Queue : msgKey = %d, msgID = %d\n", 
		(int)msgKey, msgID);

	if(msgID == -1) 
	{
		fprintf(stderr, "Message Queue Creation Error ..." );
		return -1;
	}	


	while (keep_running) {

		msgq_received = recv_msgQ(msgID, &msgq);
		if (msgq_received > 0) {
			fprintf(stdout, "Received Message Queue Data ...\n");
			
			fprintf(stdout, "msg_type = 0x%04X\n", (unsigned int)msgq.msg_type);
			fprintf(stdout, "data_length = %lu\n", msgq.msg_body.data_length);
			memset(msgQ_data, 0, MAX_MSGQ_DATA_SIZE);
			strncpy(msgQ_data, msgq.msg_body.data, msgq.msg_body.data_length);
			fprintf(stdout, "data = %s\n", msgQ_data);
			
			if(msgq.msg_type == MSGQ_TERMINATION_CMD)  {
				fprintf(stdout, "Received Message Queue Data : MSGQ_TERMINATION_CMD\n");
				keep_running = 0;
			}
		}

	}

	fprintf(stdout, "Message Queue Servie is shutdown\n");
	return 0;
}

