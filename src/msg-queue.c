#include "czmq.h"
#include "json-c/json.h"
#include "tlsq-dcu-logger.h"
#include "msg-ququq.h"

getCertAndKeys_callback gpGetCertAndKeysCallback = NULL;

void regisger_getCertAndKeysCallback(getCertAndKeys_callback pCallback) {
	gpGetCertAndKeysCallback = pCallback;
}

zsock_t* gpZsockServer = NULL;
zactor_t *gpAuth = NULL;

bool gIsIaaaClient = false;
bool gProcessClose = false;

pthread_mutex_t gMutex_auth = PTHREAD_MUTEX_INITIALIZER;
pthread_mutex_t gMutexServerSend = PTHREAD_MUTEX_INITIALIZER;

int gIaaaClientMsgQueuePort = 9000;
int gPullMsgQueuePort = 9001;


void* msgQueueServerThread(void) 
void* msgQueueClientThread(void) 

char* msgQueueAliveEncoder() {
	LOG_DEBUG("msgQueueAliveEncoder:called");

	char* outStream = NULL;
	
	json_object *rootObj = json_object_new_object();
	json_object_get(rootObj);	// sta2002

	json_object *kdcuMessageObj = json_object_new_object();
	json_object_object_add(rootObj, "kdcu-message", kdcuMessageObj);
	json_object_get(kdcuMessageObj);

	json_object *commandObj = json_object_new_string("alive");
	json_object_object_add(kdcuMessageObj, "command", commandObj);

	outStream = (char*)json_object_to_json_string(rootObj);
	LOG_DEBUG("msgQueueAliveEncoder:outStream = %s",  outStream);

	json_object_put(rootObj);
	return outStream;
}

void msgQueueParser(char* recvData) {
	if(recvData == NULL) {
		LOG_ERROR("msgQueueParser:recvData is null")
		return;
	}

	json_object *rootObj, *kdcuMessageObj;
	json_object *commandVal, *commandType;
			
	/* JSON type의 데이터를 읽는다. */
	rootObj = json_tokener_parse(recvData);
	if(rootObj == NULL) {
		LOG_DEBUG("msgQueueParser:rootObj is null")
		return;
	}

  	kdcuMessageObj = json_object_object_get(rootObj, "kdcu-message");
 	if(kdcuMessageObj == NULL) {
		//LOG_ERROR("kdcuMessageObj is null");
		return -1;
	}

  	/* kdcu-message 영역 파싱 */
  	commandVal = json_object_object_get(kdcuMessageObj, "command");
	char* strCommand = (char*) json_object_get_string(commandVal);

	// to do : check if the dateTiem is valid or not.

	if(strcmp(strCommand, "getCert-Keys") == 0) {
		commandType = json_object_object_get(kdcuMessageObj, "commandType");
		char* pCommandType = (char*)json_object_get_string(commandType);
		LOG_DEBUG("msgQueueParser:pCommandType = %s",  pCommandType==NULL?"NULL":pCommandType);
		// to do : to handle 
		if(strcmp(pCommandType, "request") == 0) {
			char* sendBuffer = kdcuMessageEncoder("resp-off");
			if(gpZsockServer != NULL) {
				pthread_mutex_lock(&gMutexServerSend);
				zstr_send (gpZsockServer, sendBuffer);
				pthread_mutex_unlock(&gMutexServerSend);
			}
		} else if(strcmp(pCommandType, "response") == 0) {
			char* sendBuffer = kdcuMessageEncoder("resp-on");
			if(gpZsockServer != NULL) {
				pthread_mutex_lock(&gMutexServerSend);
				zstr_send (gpZsockServer, sendBuffer);
				pthread_mutex_unlock(&gMutexServerSend);
			}
			pthread_mutex_unlock(&gMutexServerSend);
		}
	} else if(strcmp(strCommand, "alive") == 0) {		
		//oppositeAlive();
	} else {
		LOG_DEBUG("- msgQueueParser:this command(%s) is not supported",  strCommand);
		return;
	}

	json_object_put(rootObj);
}


void zmqCommonInit(bool isIaaaClient, int iaaaClientPort, int pullPort) {
	LOG_DEBUG("void* zmqCommonInit is called");
	pthread_mutex_lock(&gMutex_auth);
	if(gpAuth == NULL) {
		gpAuth = zactor_new (zauth,NULL);
		//  Create and start authentication engine
		if(gpAuth == NULL) {
			LOG_ERROR("dataloggerClientThread:gpAuth is NULL");
			pthread_mutex_unlock(&gMutex_auth);
			return NULL;
		}
	}
	gIsIaaaClient = isIaaaClient;
	gIaaaClientMsgQueuePort = iaaaClientPort;
	gPullMsgQueuePort = pullPort;

	zstr_send(gpAuth,"VERBOSE");
	zsock_wait(gpAuth);
	zstr_sendx(gpAuth,"ALLOW","127.0.0.1",NULL);
	zsock_wait(gpAuth);
	//  Tell the authenticator to use the certificate store in .curve
	zstr_sendx (gpAuth,"CURVE",".curve",NULL);
	pthread_mutex_unlock(&gMutex_auth);


	createThreadMsgQueueServer();
	createThreadMsgQueueClinet();
}

void zmqCommonDeInit() {
	pthread_mutex_lock(&gMutex_auth);
	if(gpAuth != NULL) {
		zactor_destroy (&gpAuth);
		gpAuth = NULL;
	}
	pthread_mutex_unlock(&gMutex_auth);
}


void createThreadMsgQueueServer() {
	pthread_t threadT;
	pthread_attr_t thread_attr;
	int thr_id = 0;

	pthread_attr_init(&thread_attr);
	pthread_attr_setdetachstate(&thread_attr, PTHREAD_CREATE_DETACHED);
	thr_id = pthread_create(&threadT, &thread_attr, msgQueueServerThread, NULL);
	pthread_attr_destroy(&thread_attr);

	if (thr_id < 0) {

	}
}

void createThreadMsgQueueClinet() {
	pthread_t threadT;
	pthread_attr_t thread_attr;
	int thr_id = 0;

	pthread_attr_init(&thread_attr);
	pthread_attr_setdetachstate(&thread_attr, PTHREAD_CREATE_DETACHED);
	thr_id = pthread_create(&threadT, &thread_attr, msgQueueClientThread, NULL);
	pthread_attr_destroy(&thread_attr);

	if (thr_id < 0) {

	}
}

void* msgQueueServerThread(void) 
{
	LOG_DEBUG("[Server] - msgQueueServerThread:called");
	pthread_detach(pthread_self());

	//  Prepare the server certificate as we did in Stonehouse
	zcert_t *server_cert = zcert_load (".curve/cert.txt");
	if(server_cert == NULL) {
		LOG_ERROR("[Server] - msgQueueServerThread:server_cert is NULL");
		return NULL;
	}

	const char *server_key1 = zcert_public_txt (server_cert);
	if(server_key1 == NULL) {
		LOG_ERROR("[Server] - msgQueueServerThread:server_key1 is NULL");
		return NULL;
	}

	//  Create and bind server socket
	gpZsockServer = zsock_new (ZMQ_PUSH);
	zcert_apply (server_cert, gpZsockServer);
	zsock_set_curve_server (gpZsockServer, 1);
	zsock_bind (gpZsockServer, "tcp://*:9000");

	LOG_DEBUG("[Server] - msgQueueServerThread:Ironhouse test starts");

	int i = 0;
	char* pSendBuffer = NULL;
	unsigned int count = 0;
	unsigned int keepTime = 0;

	while(1) {
		if(gProcessClose == true) {
			LOG_DEBUG("[Server] - msgQueueServerThread:this client process will be terminated....");
			break; 
		}

		if(((count++) % 5) == 0) {	// 2 seconds
			pSendBuffer = msgQueueAliveEncoder();
			if(pSendBuffer != NULL) {
				pthread_mutex_lock(&gMutexServerSend);
				zstr_send (gpZsockServer, pSendBuffer);
				pthread_mutex_unlock(&gMutexServerSend);
				//FREE_CHAR(pSendBuffer);
			} else {
				LOG_DEBUG("[Server] - msgQueueServerThread:pSendBuffer is null.");
			}
		}
		usleep(500000);
	}

	zcert_destroy (&server_cert);
	zsock_destroy (&gpZsockServer);
  	
	LOG_DEBUG("[Server] - msgQueueServerThread:terminated...");
	return NULL;
}

void* msgQueueClientThread(void) 
{
	LOG_DEBUG("[Client] - msgQueueClientThread:called");
	pthread_detach(pthread_self());
	//  We'll generate a new client certificate and save the public part
	//  in the certificate store (in practice this would be done by hand
	//  or some out-of-band process).
	zcert_t *server_cert = zcert_load (".curve/cert.txt");
	if(server_cert == NULL) {
		LOG_ERROR("[Client] - msgQueueClientThread:server_cert is NULL");
		return NULL;
	}

	zcert_t *client_cert = zcert_load (".curve/cert.txt_secret");

	//  Create and connect client socket
	zsock_t *client = zsock_new (ZMQ_PULL);
	zcert_apply (client_cert, client);

	const char *server_key = zcert_public_txt (server_cert);
	if(server_key == NULL) {
		LOG_ERROR("[Client] - msgQueueClientThread:server_key is NULL");
	}
	zsock_set_curve_serverkey (client, server_key);
	char oppositServerURL[100] = {0,};
	if(gIsIaaaClient == false) {
		sprintf(oppositServerURL, "tcp://127.0.0.1:%d", gIaaaClientMsgQueuePort);
	} else {
		sprintf(oppositServerURL, "tcp://127.0.0.1:%d", gPullMsgQueuePort);
	}

	zsock_connect (client, oppositServerURL);
  
	LOG_DEBUG("[Client] - msgQueueClientThread:Ironhouse test starts");

	char *message = NULL;
	unsigned int count = 0;
	while(1) {		
		if(gProcessClose == true) {
			LOG_DEBUG("[Client] - msgQueueClientThread:this client process will be terminated....");
			break; 
		}

		message = zstr_recv (client);
		if(message != NULL && strlen(message) != 0) {
			LOG_DEBUG("[Client] - msgQueueClientThread:RECV = %s", message==NULL?"empty...":message);
			msgQueueParser(message);
		}
	
		FREE_CHAR(message);
		usleep(100000);
	}


	zcert_destroy (&server_cert);
	zcert_destroy (&client_cert);
	zsock_destroy (&client);

	LOG_DEBUG("[Client] - msgQueueClientThread:terminated...");
	return 0;
}
