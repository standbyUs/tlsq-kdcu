#ifndef	__MSG_QUEUE_H__
#define __MSG_QUEUE_H__

#define	IN
#define OUT
typedef int (*getCertAndKeys_callback)(OUT char* fepCert, OUT int fepCertLen, OUT char* emuCert, OUT int emuCertLen, OUT char* zKey1, OUT int zKey1Len, OUT char* zKey2, OUT int zKey2Len);

void regisger_getCertAndKeysCallback(getCertAndKeys_callback pCallback);
void setCertAndKeys(IN char* fepCert, IN int fepCertLen, IN char* emuCert, IN int emuCertLen, IN char* zKey1, IN int zKey1Len, IN char* zKey2, IN int zKey2Len);

void zmqCommonInit(bool isIaaaClient, int iaaaClientPort, int pullPort);
void zmqCommonDeInit();

#endif	//__MSG_QUEUE_H__