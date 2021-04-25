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


int keep_running = 0;


int authAgentStatus(void);

int get_authStatus(void);

void set_authStatus(int status);

int do_authProgress(void);



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
	int send_authStatus;


	fprintf(stdout, "Auth: Servie is started\n");

	/* In case we recevie a request to stop (kill -TERM or kill -INT) */
	keep_running = 1;

	/* Daemonize */
	if (!dont_fork) {
		int ret = daemonize();
		if(ret != 0) {
			fprintf(stderr, "Auth: Daemonizing Exiting with code %d\n", ret);
			exit(1);
		}		
	}


	msgKey = MSGQ_AUTH_SERVICE_KEY;
	msgKey_req = MSGQ_AUTH_SERVICE_REQ_KEY;

	memset(&msgQ, 0x00, sizeof(msgQ));
	memset(&msgQ_req, 0x00, sizeof(msgQ_req));

	msgID = create_msgQEvent(msgKey);
	fprintf(stdout, "Auth: Created Message Queue : msgKey = %d, msgID = %d\n", 
		(int)msgKey, msgID);

	if(msgID == -1) 
	{
		fprintf(stderr, "Auth: Message Queue Creation Error ..." );
		return -1;
	}	

	msgID_req = create_msgQEvent(msgKey_req);
	fprintf(stdout, "Auth: Created Requesting Message Queue : msgKey = %d, msgID = %d\n", 
		(int)msgKey_req, msgID_req);

	if(msgID_req == -1) 
	{
		fprintf(stderr, "Auth: Requesting Message Queue Creation Error ..." );
		return -1;
	}	

	send_authStatus = 0;

	while (keep_running) {

		msgq_received = recv_msgQEvent(msgID_req, &msgQ_req);
		if (msgq_received > 0) {
			fprintf(stdout, "Auth: Received Message Queue Data ...\n");
			
			fprintf(stdout, "Auth:  msg_type = 0x%04X\n", (unsigned int)msgQ_req.msg_type);
			fprintf(stdout, "Auth:  msg = %d\n", (int)msgQ_req.msg);

			if (msgQ_req.msg_type == MSGQ_AUTH_REQ_AGENT_STATUS_EVENT) {
				fprintf(stdout, "Auth: Received MSGQ_AUTH_REQ_AGENT_STATUS_EVENT\n");
				msgQ.msg = (uint32_t)authAgentStatus();
				msgQ.msg_type = MSGQ_AUTH_AGENT_STAUS_EVENT;
				fprintf(stdout, "Auth: Send MSGQ_AUTH_AGENT_STAUS_EVENT\n");
				fprintf(stdout, "Auth: Agent Status = %d\n", (int)msgQ.msg);
				ret = send_msgQEvent(msgID, &msgQ);
				if (ret != 0)  {
					fprintf(stderr, "Auth: Message Queue Data Sending is failed !!\n");
				}
			}	
			
			if(msgQ.msg_type == MSGQ_TERMINATION_CMD)  {
				fprintf(stdout, "Received Message Queue Data : MSGQ_TERMINATION_CMD\n");
				keep_running = 0;
			}
		}


		if (get_authStatus() != MSGQ_AUTH_DONE)  {
			fprintf(stdout, "Auth: Authentication Progressing ... \n");
			ret = do_authProgress();
			send_authStatus = 1;
		}

		if (send_authStatus) {
			msgQ.msg = (uint32_t)get_authStatus();
			msgQ.msg_type = MSGQ_AUTH_STATUS_EVENT;
			fprintf(stdout, "Auth: Send MSGQ_AUTH_STATUS_EVENT\n");
			fprintf(stdout, "Auth: Auth Status = %d\n", (int)msgQ.msg);
			ret = send_msgQEvent(msgID, &msgQ);
			if (ret != 0)  {
				fprintf(stderr, "Auth: Message Queue Data Sending is failed !!\n");
			}
			send_authStatus = 0;
		}
		

	}


	fprintf(stdout, "Auth: Auth Servie is shutdown\n");

	
	return exit_code;
}



int authAgentStatus(void)
{
	int status;
	
	// Agent Status Checking !!
	status = MSGQ_AUTH_AGENT_NORMAL;
	
	return status;
}


int authStatus = MSGQ_AUTH_NONE;

int get_authStatus(void)
{
	return authStatus;
}


void set_authStatus(int status)
{
	authStatus = status;
}


#define AUTH_SUCCESS	1
#define AUTH_FAIL		2


int do_authProgress(void)
{
	int status = 0;

	/*
		Athentication Progress
		
	*/
	sleep( 2 );

	
	status = AUTH_SUCCESS;

	if (status == AUTH_SUCCESS) {
		fprintf(stdout, "Auth: Authentication is Done !! \n");
		set_authStatus(MSGQ_AUTH_DONE);
	}
	else if (status == AUTH_FAIL) {
		fprintf(stdout, "Auth: Authentication is Failed !! \n");
		set_authStatus(MSGQ_AUTH_FAIL);
	}
	else {
	}

	return status;
}


