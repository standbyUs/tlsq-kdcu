#include "czmq.h"
#include "json-c/json.h"
#include "tlsq-dcu-logger.h"
#include "msg-queue.h"
#include "b64.h"

#define	FREE_CHAR(x)	if(x != NULL) {free(x); x = NULL;}

getCertAndKeys_callback gpGetCertAndKeysCallback = NULL;
reAuth_callback gpReAuthCallback = NULL;
getAuthState_callback gpGetAuthStateCallback = NULL;

void register_getCertAndKeysCallback(getCertAndKeys_callback pCallback) {
	gpGetCertAndKeysCallback = pCallback;
}

void register_reAuthCallback(reAuth_callback pCallback) {
	gpReAuthCallback = pCallback;
}

void register_getAuthStateCallback(getAuthState_callback pCallback) {
	gpGetAuthStateCallback = pCallback;
}

zsock_t* gpZsockServer = NULL;
zactor_t *gpAuth = NULL;

bool gIsIaaaClient = false;
bool gProcessClose = false;

pthread_mutex_t gMutex_auth = PTHREAD_MUTEX_INITIALIZER;
pthread_mutex_t gMutexServerSend = PTHREAD_MUTEX_INITIALIZER;

int gIaaaClientMsgQueuePort = 9000;
int gPullMsgQueuePort = 9001;

typedef struct _CertKeyInfo {
	bool state;
	char* fepCert;
	int fepCertLen;
	char* emulatorCert;
	int emulatorCertLen;
	char* zKey1;
	int zKey1Len;
	char* zKey2;
	int zKey2Len;
} CertKeyInfo;

CertKeyInfo gCertKeyInfo;

void* msgQueueServerThread(void);
void* msgQueueClientThread(void);

void setCertAndKeys(IN bool authState, IN char* fepCert, IN int fepCertLen, IN char* emuCert, IN int emuCertLen, IN char* zKey1, IN int zKey1Len, IN char* zKey2, IN int zKey2Len) {
	LOG_DEBUG("setCertAndKeys:fepCertLen=%d, emulCertLen=%d, zKey1Len=%d, zKey2Len=%d", fepCertLen, emuCertLen, zKey1Len, zKey2Len);
	LOG_DEBUG("setCertAndKeys:message queue is not used. so it is not working!!! --> msgQ has been used. instead it.");
	return;

	if(authState == true) {
		if(gCertKeyInfo.fepCert != NULL) {
			free(gCertKeyInfo.fepCert);
		}
		gCertKeyInfo.fepCert = (char*)malloc(fepCertLen);
		memcpy(gCertKeyInfo.fepCert, fepCert, fepCertLen);
		gCertKeyInfo.fepCertLen = fepCertLen;

		if(gCertKeyInfo.emulatorCert != NULL) {
			free(gCertKeyInfo.emulatorCert);
		}
		gCertKeyInfo.emulatorCert = (char*)malloc(emuCertLen);
		memcpy(gCertKeyInfo.emulatorCert, emuCert, emuCertLen);
		gCertKeyInfo.emulatorCertLen = emuCertLen;

		if(gCertKeyInfo.zKey1 != NULL) {
			free(gCertKeyInfo.zKey1);
		}
		gCertKeyInfo.zKey1 = (char*)malloc(zKey1Len);	
		memcpy(gCertKeyInfo.zKey1, zKey1, zKey1Len);
		gCertKeyInfo.zKey1Len = zKey1Len;
		
		if(gCertKeyInfo.zKey2 != NULL) {
			free(gCertKeyInfo.zKey2);
		}
		gCertKeyInfo.zKey2 = (char*)malloc(zKey2Len);	
		memcpy(gCertKeyInfo.zKey2, zKey2, zKey2Len);
		gCertKeyInfo.zKey2Len = zKey2Len;
	} else {
		if(gCertKeyInfo.fepCert != NULL) {
			free(gCertKeyInfo.fepCert);
			gCertKeyInfo.fepCert = NULL;
		}
		gCertKeyInfo.fepCertLen = 0;

		if(gCertKeyInfo.emulatorCert != NULL) {
			free(gCertKeyInfo.emulatorCert);
			gCertKeyInfo.emulatorCert = NULL;
		}
		gCertKeyInfo.emulatorCertLen = 0;

		if(gCertKeyInfo.zKey1 != NULL) {
			free(gCertKeyInfo.zKey1);
			gCertKeyInfo.zKey1 = NULL;
		}
		gCertKeyInfo.zKey1Len = 0;

		if(gCertKeyInfo.zKey2 != NULL) {
			free(gCertKeyInfo.zKey2);
			gCertKeyInfo.zKey2 = NULL;
		}
		gCertKeyInfo.zKey2Len = 0;

		memset(&gCertKeyInfo, 0, sizeof(CertKeyInfo));
	}

	gCertKeyInfo.state = authState;

	char* outStream = NULL;
	
	json_object *rootObj = json_object_new_object();
	json_object_get(rootObj);	// sta2002

	json_object *kdcuMessageObj = json_object_new_object();
	json_object_object_add(rootObj, "kdcu-message", kdcuMessageObj);
	json_object_get(kdcuMessageObj);

	json_object *commandObj = json_object_new_string("getCert-Keys");
	json_object_object_add(kdcuMessageObj, "command", commandObj);

	json_object *pAuthState = json_object_new_boolean(gCertKeyInfo.state);
	json_object_object_add(kdcuMessageObj, "authState", pAuthState);

	char *encFepCert = NULL;
	char *encEmulatorCert = NULL;
	char *encZKey1 = NULL;
	char *enczKey2 = NULL;

	if(gCertKeyInfo.state) {
		encFepCert = b64_encode(gCertKeyInfo.fepCert, gCertKeyInfo.fepCertLen);
		encEmulatorCert = b64_encode(gCertKeyInfo.emulatorCert, gCertKeyInfo.emulatorCertLen);
		encZKey1 = b64_encode(gCertKeyInfo.zKey1, gCertKeyInfo.zKey1Len);
		enczKey2 = b64_encode(gCertKeyInfo.zKey2, gCertKeyInfo.zKey2Len);

		json_object *fepCert = json_object_new_string(encFepCert);
		json_object_object_add(kdcuMessageObj, "fepCert", fepCert);
		json_object *fepCertLen = json_object_new_int(gCertKeyInfo.fepCertLen);
		json_object_object_add(kdcuMessageObj, "fepCertLen", fepCertLen);

		json_object *emulatorCert = json_object_new_string(encEmulatorCert);
		json_object_object_add(kdcuMessageObj, "emulatorCert", emulatorCert);
		json_object *emulatorCertLen = json_object_new_int(gCertKeyInfo.emulatorCertLen);
		json_object_object_add(kdcuMessageObj, "emulatorCertLen", emulatorCertLen);

		json_object *zKey1 = json_object_new_string(encZKey1);
		json_object_object_add(kdcuMessageObj, "zKey1", zKey1);
		json_object *zKey1Len = json_object_new_int(gCertKeyInfo.zKey1Len);
		json_object_object_add(kdcuMessageObj, "zKey1Len", zKey1Len);

		json_object *zKey2 = json_object_new_string(enczKey2);
		json_object_object_add(kdcuMessageObj, "zKey2", zKey2);
		json_object *zKey2Len = json_object_new_int(gCertKeyInfo.zKey2Len);
		json_object_object_add(kdcuMessageObj, "zKey2Len", zKey2Len);
	}

	outStream = (char*)json_object_to_json_string(rootObj);
	LOG_DEBUG("setCertAndKeys:outStream = %s",  outStream);

	zstr_send (gpZsockServer, outStream);

	if(encFepCert) free(encFepCert);
	if(encEmulatorCert) free(encEmulatorCert);
	if(encZKey1) free(encZKey1);
	if(enczKey2) free(enczKey2);

	json_object_put(rootObj);
}

void reAuth() {
	LOG_DEBUG("reAuth:message queue is not used. so it is not working!!! --> msgQ has been used. instead it.");
	return;
#if 0
{
   "kdcu-message":{
      "command":"reAuth"
   }
}
#endif
	char* outStream = NULL;
	
	json_object *rootObj = json_object_new_object();
	json_object_get(rootObj);	// sta2002

	json_object *kdcuMessageObj = json_object_new_object();
	json_object_object_add(rootObj, "kdcu-message", kdcuMessageObj);
	json_object_get(kdcuMessageObj);

	json_object *commandObj = json_object_new_string("reAuth");
	json_object_object_add(kdcuMessageObj, "command", commandObj);

	outStream = (char*)json_object_to_json_string(rootObj);
	LOG_DEBUG("reAuth:outStream = %s",  outStream);

	zstr_send (gpZsockServer, outStream);

	json_object_put(rootObj);
}

void getAuthState() {
	LOG_DEBUG("getAuthState:message queue is not used. so it is not working!!! --> msgQ has been used. instead it.");
	return;
#if 0
{
   "kdcu-message":{
      "command":"getAuthState"
   }
}
#endif
	char* outStream = NULL;
	
	json_object *rootObj = json_object_new_object();
	json_object_get(rootObj);	// sta2002

	json_object *kdcuMessageObj = json_object_new_object();
	json_object_object_add(rootObj, "kdcu-message", kdcuMessageObj);
	json_object_get(kdcuMessageObj);

	json_object *commandObj = json_object_new_string("getAuthState");
	json_object_object_add(kdcuMessageObj, "command", commandObj);

	outStream = (char*)json_object_to_json_string(rootObj);
	LOG_DEBUG("getAuthState:outStream = %s",  outStream);

	zstr_send (gpZsockServer, outStream);

	json_object_put(rootObj);
	return outStream;
}

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

int msgQueueParser(char* recvData) {
	if(recvData == NULL) {
		LOG_ERROR("msgQueueParser:recvData is null");
		return -1;
	}

	json_object *rootObj, *kdcuMessageObj;
	json_object *commandVal;
	json_object *authState, *strVal, *intVal;
	char* pStrValue = NULL;
			
	/* JSON type의 데이터를 읽는다. */
	rootObj = json_tokener_parse(recvData);
	if(rootObj == NULL) {
		LOG_DEBUG("msgQueueParser:rootObj is null");
		return -1;
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
		authState = json_object_object_get(kdcuMessageObj, "authState");
		bool bAuthState = json_object_get_boolean(authState);
		LOG_DEBUG("msgQueueParser:authState = %s",  bAuthState==true?"true":"false");
		if(bAuthState == true) {
			strVal = json_object_object_get(kdcuMessageObj, "fepCert");
			char* pFepCert = (char*)json_object_get_string(strVal);
			LOG_DEBUG("msgQueueParser:fepCert = %s",  pFepCert==NULL?"NULL":pFepCert);
			intVal = json_object_object_get(kdcuMessageObj, "fepCertLen");
			int fepCertLen = json_object_get_int(intVal);
			LOG_DEBUG("msgQueueParser:fepCertLen = %d",  fepCertLen);

			strVal = json_object_object_get(kdcuMessageObj, "emulatorCert");
			char* pEmulatorCert = (char*)json_object_get_string(strVal);
			LOG_DEBUG("msgQueueParser:emulatorCert = %s",  pEmulatorCert==NULL?"NULL":pEmulatorCert);
			intVal = json_object_object_get(kdcuMessageObj, "emulatorCertLen");
			int emulCertLen = json_object_get_int(intVal);
			LOG_DEBUG("msgQueueParser:emulCertLen = %d",  emulCertLen);

			strVal = json_object_object_get(kdcuMessageObj, "zKey1");
			char* pZKey1 = (char*)json_object_get_string(strVal);
			LOG_DEBUG("msgQueueParser:zKey1 = %s",  pZKey1==NULL?"NULL":pZKey1);
			intVal = json_object_object_get(kdcuMessageObj, "zKey1Len");
			int zKey1Len = json_object_get_int(intVal);
			LOG_DEBUG("msgQueueParser:zKey1Len = %d",  zKey1Len);

			strVal = json_object_object_get(kdcuMessageObj, "zKey2");
			char* pZKey2 = (char*)json_object_get_string(strVal);
			LOG_DEBUG("msgQueueParser:zKey2 = %s",  pZKey2==NULL?"NULL":pZKey2);
			intVal = json_object_object_get(kdcuMessageObj, "zKey1Len");
			int zKey2Len = json_object_get_int(intVal);
			LOG_DEBUG("msgQueueParser:zKey2Len = %d",  zKey2Len);

			char *decFepCert = b64_decode(pFepCert, strlen(pFepCert));
			char *decEmulCert = b64_decode(pEmulatorCert, strlen(pEmulatorCert));
			char *decZKey1 = b64_decode(pZKey1, strlen(pZKey1));
			char *decZKey2 = b64_decode(pZKey2, strlen(pZKey2));

			if(gpGetCertAndKeysCallback) {
				gpGetCertAndKeysCallback(bAuthState, decFepCert, fepCertLen, decEmulCert, emulCertLen, decZKey1, zKey1Len, decZKey2, zKey2Len);
			} else {
				LOG_ERROR("gpGetCertAndKeysCallback is null, please check if calling register_getCertAndKeysCallback(...)");
			}
			if(decFepCert) free(decFepCert);
			if(decEmulCert) free(decEmulCert);
			if(decZKey1) free(decZKey1);
			if(decZKey2) free(decZKey2);
		} else {
			if(gpGetCertAndKeysCallback) {
				gpGetCertAndKeysCallback(bAuthState, NULL, 0, NULL, 0, NULL, 0, NULL, 0);
			} else {
				LOG_ERROR("gpGetCertAndKeysCallback is null, please check if calling register_getCertAndKeysCallback(...)");
			}
		}
	} else if(strcmp(strCommand, "reAuth") == 0) {		
		if(gpReAuthCallback != NULL) {
			gpReAuthCallback();
		} else {
			LOG_ERROR("gpReAuthCallback is null, please check if calling register_reAuthCallback()");
		}
	} else if(strcmp(strCommand, "getAuthState") == 0) {	
		if(gpGetAuthStateCallback != NULL) {
			gpGetAuthStateCallback();
		} else {
			LOG_ERROR("gpReAuthCallback is null, please check if calling register_getAuthStateCallback()");
		}
	} else if(strcmp(strCommand, "alive") == 0) {		


	} else {
		LOG_DEBUG("- msgQueueParser:this command(%s) is not supported",  strCommand);
		return -1;
	}

	json_object_put(rootObj);
	return 0;
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
	memset(&gCertKeyInfo, 0, sizeof(CertKeyInfo));

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
	char bindUrl[100] = {0,};

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
	LOG_DEBUG("[Server] - msgQueueServerThread:server_key1=%s", server_key1);
	//  Create and bind server socket
	gpZsockServer = zsock_new (ZMQ_PUSH);
	zcert_apply (server_cert, gpZsockServer);
	zsock_set_curve_server (gpZsockServer, 1);
	
	if(gIsIaaaClient == true) {
		sprintf(bindUrl, "tcp://*:%d", gIaaaClientMsgQueuePort);
	} else {
		sprintf(bindUrl, "tcp://*:%d", gPullMsgQueuePort);
	}
	LOG_DEBUG("[Server] - msgQueueServerThread:bindUrl=%s", bindUrl);


	int ret = zsock_bind (gpZsockServer, bindUrl);
	LOG_DEBUG("[Server] - msgQueueServerThread:zsock_bind() return value=%d", ret);

	LOG_DEBUG("[Server] - msgQueueServerThread:Ironhouse test starts");

	int i = 0;
	char* pSendBuffer = NULL;
	unsigned int count = 0;
	unsigned int keepTime = 0;
	return NULL;

	while(1) {
		if(gProcessClose == true) {
			LOG_DEBUG("[Server] - msgQueueServerThread:this client process will be terminated....");
			break; 
		}

#if 0
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
#endif

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
	if(client_cert == NULL) {
		LOG_ERROR("[Client] - msgQueueClientThread:client_cert is NULL");
		return NULL;
	}
	//  Create and connect client socket
	zsock_t *client = zsock_new (ZMQ_PULL);
	zcert_apply (client_cert, client);

	const char *server_key = zcert_public_txt (server_cert);
	if(server_key == NULL) {
		LOG_ERROR("[Client] - msgQueueClientThread:server_key is NULL");
	}

	LOG_DEBUG("[Client] - msgQueueClientThread:server_key=%s", server_key);

	zsock_set_curve_serverkey (client, server_key);
	char oppositServerURL[100] = {0,};
	if(gIsIaaaClient == true) {
		sprintf(oppositServerURL, "tcp://127.0.0.1:%d", gPullMsgQueuePort);
	} else {
		sprintf(oppositServerURL, "tcp://127.0.0.1:%d", gIaaaClientMsgQueuePort);
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
