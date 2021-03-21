#ifndef	__MSG_QUEUE_H__
#define __MSG_QUEUE_H__
#include <stdbool.h>  // error: unknown type name ‘bool’

#define	IN
#define OUT
typedef int (*getCertAndKeys_callback)(IN bool authState, IN char* fepCert, IN int fepCertLen, IN char* emuCert, IN int emuCertLen, IN char* zKey1, IN int zKey1Len, IN char* zKey2, IN int zKey2Len);
typedef void (*reAuth_callback)();
typedef void(*getAuthState_callback)();

void register_getCertAndKeysCallback(getCertAndKeys_callback pCallback);
void register_reAuthCallback(reAuth_callback pCallback);
void register_getAuthStateCallback(getAuthState_callback pCallback);

void setCertAndKeys(IN bool authState, IN char* fepCert, IN int fepCertLen, IN char* emuCert, IN int emuCertLen, IN char* zKey1, IN int zKey1Len, IN char* zKey2, IN int zKey2Len);
void reAuth();
void getAuthState();

void zmqCommonInit(bool isIaaaClient, int iaaaClientPort, int pullPort);
void zmqCommonDeInit();

#endif	//__MSG_QUEUE_H__