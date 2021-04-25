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



#include "msgQ/msgQ.h"
#include "msgQ/msgQService.h"

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



int main(int argc, char* argv[]) 
{
	int dont_fork = 0;

	int msgID;
	int msgID_req;
	msgQEvent_context msgQ;
	msgQEvent_context msgQ_req;
	int msgq_received;
	key_t msgKey;
	key_t msgKey_req;
	int ret;
	int exit_code = 0;


	fprintf(stdout, "SNMP Servie is started\n");

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


	msgKey = MSGQ_AUTH_SERVICE_KEY;
	msgKey_req = MSGQ_AUTH_SERVICE_REQ_KEY;

	memset(&msgQ, 0x00, sizeof(msgQ));
	memset(&msgQ_req, 0x00, sizeof(msgQ_req));

	msgID = create_msgQEvent(msgKey);
	fprintf(stdout, "Created Message Queue : msgKey = %d, msgID = %d\n", 
		(int)msgKey, msgID);

	if(msgID == -1) 
	{
		fprintf(stderr, "Message Queue Creation Error ..." );
		return -1;
	}	

	msgID_req = create_msgQEvent(msgKey_req);
	fprintf(stdout, "Created Requesting Message Queue : msgKey = %d, msgID = %d\n", 
		(int)msgKey_req, msgID_req);

	if(msgID_req == -1) 
	{
		fprintf(stderr, "Requesting Message Queue Creation Error ..." );
		return -1;
	}	


	msgQ_req.msg_type = MSGQ_AUTH_REQ_AGENT_STATUS_EVENT;
	msgQ_req.msg = 0;
	
	fprintf(stdout, "Requesting Message Queue Data is sending (MSGQ_AUTH_REQ_AGENT_STATUS_EVENT) ...\n");

	ret = send_msgQEvent(msgID_req, &msgQ_req);

	if (ret != 0)  {
		fprintf(stderr, "Message Queue Data Sending is failed !!\n");
		return -1;
	}

	while (keep_running) {

		msgq_received = recv_msgQEvent(msgID, &msgQ);
		if (msgq_received > 0) {
			fprintf(stdout, "Received Message Queue Data ...\n");
			
			fprintf(stdout, " msg_type = 0x%04X\n", (unsigned int)msgQ.msg_type);
			fprintf(stdout, " msg = %d\n", (int)msgQ.msg);

			if (msgQ.msg_type == MSGQ_AUTH_AGENT_STAUS_EVENT) {
				fprintf(stdout, "Received MSGQ_AUTH_REQ_AGENT_STATUS_EVENT\n");
				if (msgQ.msg == MSGQ_AUTH_AGENT_NORMAL)  fprintf(stdout, "Agent status is NORMAL\n");
				else if (msgQ.msg == MSGQ_AUTH_AGENT_ERROR)  fprintf(stdout, "Agent status is ERROR\n");
			}
			else if (msgQ.msg_type == MSGQ_AUTH_STATUS_EVENT) {
				fprintf(stdout, "Received MSGQ_AUTH_STATUS_EVENT\n");
				if (msgQ.msg == MSGQ_AUTH_DONE)  fprintf(stdout, "Authentication process is Done !!\n");
				else if (msgQ.msg == MSGQ_AUTH_FAIL)  fprintf(stdout, "Authentication process is Failed !!\n");
				else if (msgQ.msg == MSGQ_AUTH_DOING)  fprintf(stdout, "Authentication process is on Going !!\n");
				else if (msgQ.msg == MSGQ_AUTH_DOING)  fprintf(stdout, "Authentication process is Retrying !!\n");
			}			
			
			if(msgQ.msg_type == MSGQ_TERMINATION_CMD)  {
				fprintf(stdout, "Received Message Queue Data : MSGQ_TERMINATION_CMD\n");
				keep_running = 0;
			}
		}

	}


	fprintf(stdout, "SNMP Servie is shutdown\n");


	return exit_code;
}

