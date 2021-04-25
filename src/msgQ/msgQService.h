#ifndef _MSGQSERVICE_H_
#define _MSGQSERVICE_H_


#define MSGQ_TRAP_SERVICE_KEY		0x0001
#define MSGQ_AUTH_SERVICE_KEY		0x0002
#define MSGQ_AUTH_SERVICE_REQ_KEY	0x0003
#define MSGQ_KAMI_SERVICE_KEY		0x0004
#define MSGQ_HW_SERVICE_KEY			0x0005


#define MSGQ_TERMINATION_CMD  9999



typedef enum  msgQ_AuthEventType {
	MSGQ_AUTH_NONE_EVENT = 0,	
	MSGQ_AUTH_AGENT_STAUS_EVENT,		
	MSGQ_AUTH_STATUS_EVENT,
	MSGQ_AUTH_MAX_CMD	
} msgQ_AuthEvent;

typedef enum  msgQ_AuthAgentStatusType {
	MSGQ_AUTH_AGENT_NONE = 0,	
	MSGQ_AUTH_AGENT_NORMAL,		
	MSGQ_AUTH_AGENT_ERROR,
	MSGQ_AUTH_MAX_AGENT_STATUS	
} msgQ_AuthAgentStatus;

typedef enum  msgQ_AuthStatusType {
	MSGQ_AUTH_NONE = 0,	
	MSGQ_AUTH_DONE,		
	MSGQ_AUTH_FAIL,
	MSGQ_AUTH_DOING,
	MSGQ_AUTH_RETRY,
	MSGQ_AUTH_MAX_STATUS	
} msgQ_AuthStatus;


typedef enum  msgQ_AuthReqEventType {
	MSGQ_AUTH_REQ_NONE_EVENT = 0,	
	MSGQ_AUTH_REQ_AGENT_STATUS_EVENT,
	MSGQ_AUTH_REQ_MAX_EVENT	
} msgQ_AuthReqEvent;






#endif /* _MSGQSERVICE_H_ */
