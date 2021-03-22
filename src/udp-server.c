//--------------------------------------------------------------
// file Name : udp_echoserv.c
// command : cc -o udp_echoserv  udp_echoserv.c
// server 시작 : udp_echoserv  9999
// client에서 전송되는 메시지를 buf.txt 에 저장하고, 다시 client로 전송 후 유효성 체크
//--------------------------------------------------------------
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <pthread.h>
#include <stdbool.h>  // error: unknown type name ‘bool’


#include "tlsq-dcu-logger.h"
#include "tlsq-dcu-utils.h"
#include "msg-queue.h"


#define MAXLINE    1024*10
#define BLOCK      255

typedef union VersionMsgLen {
  unsigned char version;
  unsigned int messageLength;
} VERSION_MSGLEN;

typedef struct SecurityAgentHeader {
  //VERSION_MSGLEN verMsgLen;
  unsigned int verMsgLen;
  unsigned int commandCode;
  unsigned int transactionId;
} SECURITY_AGENT_HEADER;

typedef struct MessageProtocol {
  SECURITY_AGENT_HEADER header;
  unsigned char* body;
} MESSAGE_PROTO;

typedef struct HeaderFormat {
  int startPos;
  char headerName[100];
} HEADDER_FORMAT;

typedef struct RequestMsgAthentication {
  unsigned char sysT[8];
  char dcuId[10];
  unsigned char aaaIP[16];
  unsigned char aaaPort[4]; // 4bytes
  unsigned char authReqType;
  char callingStationId[23];
} REQ_MSG_AUTHENTICATION, *REQ_MSG_AUTHENTICATION_PTR;

typedef struct ResponseMsgAuthentication {
    unsigned char sysT[8];
    unsigned int resultCode;  // 4bytes
} RESP_MSG_AUTHENTICATION;

typedef struct _ResponseMsgAuthResultZKeyPacket {
  unsigned char sysT[8];
  unsigned int resultCode;
  unsigned short aaaType;
  unsigned char zKey1[32];
  unsigned char zKey2[32];
  unsigned short fepCertLen;
  unsigned char* pFepCert;
  unsigned short emulCertLen;
  unsigned char* pEmulCert;
} RESP_MSG_AUTH_RESULT_ZKEY_PACKET;

typedef struct config_info {
  char *key;
  char value[50];
} CONFIG_INFO;

enum CONFIG_INFO_KEY {
  SYSTEM_TITLE,
  DCU_ID,
  IAAA_SERVER_IPADDR,
  DCU_MAC_ADDR
};

CONFIG_INFO gConfigInfo[] = {
  {"system-title", ""},
  {"dcu-id", ""},
  {"iaaa-server-ip", ""},
  {"dcu-mac-addr", ""},
  {NULL, ""}
}; 

#define SECURITY_AGENT_UDP_PORT   13868
#define SERVER_UDP_PORT_FOR_TRAP  10000
#define CONFDIG_INFO_KEY_COUNT    4
#define SYSTEM_TITLE_LEN          13
#define DCU_ID_LEN                10
#define CALLING_STATTION_ID_LEN   23
#define REQ_AUTH_LEN              62

bool gIsSucessAuthResultTrap = false;
  unsigned int gTransactionId = 1;
  
SECURITY_AGENT_HEADER recvHeader;
RESP_MSG_AUTHENTICATION recvMsgAuthResp;
RESP_MSG_AUTH_RESULT_ZKEY_PACKET recvMsgAuthResultTrap;

int makeRequestMsgAuthentication(char* pSysT, char* pDcuId, char* pAaaIp, unsigned int aaaPort, char* pCallingStationId, unsigned char** ppOutMsg, int* outMsgLen) {
  int i = 0;
  LOG_DEBUG("makeRequestMsgAuthentication is called.");

  if(pSysT == NULL || strlen(pSysT) != SYSTEM_TITLE_LEN) {
    LOG_ERROR("pSysT is null or the length of pSysT is wrong.");
    return -1;
  }

  //LOG_DEBUG("makeRequestMsgAuthentication is called.");
  if(pAaaIp == NULL || strlen(pAaaIp) <= 0 ) {
    LOG_ERROR("pAaaIp is null or the length of pAaaIp is wrong.");
    return -1;
  }
  //LOG_DEBUG("makeRequestMsgAuthentication is called.");
  unsigned char* pMessage = (unsigned char*)malloc(sizeof(REQ_MSG_AUTHENTICATION));
  if(pMessage == NULL) {
    LOG_ERROR("pMessage is null");
    return -1;
  }
  *ppOutMsg = pMessage;
  *outMsgLen = sizeof(REQ_MSG_AUTHENTICATION);
  //LOG_DEBUG("makeRequestMsgAuthentication is called.");

  // SysT
  memset(pMessage, 0, sizeof(REQ_MSG_AUTHENTICATION));
  pMessage[0] = (char)pSysT[0];
  pMessage[1] = (char)pSysT[1];
  pMessage[2] = (char)pSysT[2];
  pMessage[3] = (asciiToHex((char)pSysT[3]) << 4) | asciiToHex((char)pSysT[4]);
  pMessage[4] = (asciiToHex((char)pSysT[5]) << 4) | asciiToHex((char)pSysT[6]);
  pMessage[5] = (asciiToHex((char)pSysT[7]) << 4) | asciiToHex((char)pSysT[8]);
  pMessage[6] = (asciiToHex((char)pSysT[9]) << 4) | asciiToHex((char)pSysT[10]);
  pMessage[7] = (asciiToHex((char)pSysT[11]) << 4) | asciiToHex((char)pSysT[12]);
  //LOG_DEBUG("makeRequestMsgAuthentication is called.");
  
  // DCU ID
  memcpy(&pMessage[8], pDcuId, DCU_ID_LEN);
  //LOG_DEBUG("makeRequestMsgAuthentication is called.");

  // AAA-IP
  struct in_addr addr;
  inet_aton(pAaaIp, &addr);
  LOG_DEBUG("addr=%x",  addr.s_addr);
  memcpy(&pMessage[18], &addr.s_addr, sizeof(unsigned int));
  // pMessage[18] = (unsigned char)((addr.s_addr >> 24) & 0x000000ff);
  // pMessage[19] = (unsigned char)((addr.s_addr >> 16) & 0x000000ff);
  // pMessage[20] = (unsigned char)((addr.s_addr >>  8) & 0x000000ff);
  // pMessage[21] = (unsigned char)((addr.s_addr) & 0x000000ff);

  //LOG_DEBUG("makeRequestMsgAuthentication is called.");

  // AAA-Port
  unsigned int serverPort = (unsigned int)htonl((unsigned long)aaaPort);
  memcpy(&pMessage[34], &serverPort, sizeof(unsigned int));
  //LOG_DEBUG("makeRequestMsgAuthentication is called.");
  // Auth-Request-Type
  pMessage[38] = 0x01;  // 인증 요청 (default)

  // Calling-Station-id

  memcpy(&pMessage[39], pCallingStationId, CALLING_STATTION_ID_LEN); 

  LOG_DEBUG("\nsending data >>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>");
  for(i=0; i < REQ_AUTH_LEN; i++) {
    printf("%02x ", pMessage[i]);
  }
  printf("\n");
  return 0;
}

HEADDER_FORMAT gHeaderFormat[] = {{1, "Version"}, 
                                  {1, "Message Length"},
                                  {0, ""}, 
                                  {0, ""}, 
                                  {1, "Command Code"},
                                  {0, ""}, 
                                  {0, ""}, 
                                  {0, ""}, 
                                  {1, "Transaction Id"},
                                  {0, ""}, 
                                  {0, ""}, 
                                  {0, ""},
                                  {-1, ""}, 
                                  };

int gServerSocket = -1;
void* threadRecv(void* obj) {
  pthread_detach(pthread_self());

  struct sockaddr_in servaddr, cliaddr;
  int nbyte, addrlen = sizeof(struct sockaddr);
  char buf[MAXLINE+1];
  int serverPort = 10000;
  int i = 0;
  int headEnd = 0;
  serverPort = (int)obj;

  unsigned int unTemp = 0;
  unsigned short usTemp = 0;
  unsigned int feildIndex = 0;
  //소켓 생성
  if((gServerSocket = socket(PF_INET, SOCK_DGRAM, 0)) < 0) {
      LOG_DEBUG("socket fail");
      exit(0);
  }
    
  // 서버 구조
  memset(&cliaddr, 0, addrlen); //bzero((char *)&cliaddr, addrlen);
  memset(&servaddr, 0, addrlen); //bzero((char *)&servaddr,addrlen);
  servaddr.sin_family = AF_INET;
  servaddr.sin_addr.s_addr = htonl(INADDR_ANY);
  LOG_DEBUG("UDP Server PORT = %d", serverPort);
  servaddr.sin_port = htons(serverPort); //argv[1]에서 port 번호 가지고 옴

  // 서버 로컬 주소로 bind()
  if(bind(gServerSocket, (struct sockaddr *)&servaddr, addrlen) < 0) {
      LOG_DEBUG("bind fail");
      exit(0);
  }

  while(1)
  {
    //LOG_DEBUG("Server : waiting request [gServerSocket=%d].", gServerSocket);
    //전송 받은 메시지 nbyte 저장
    nbyte = recvfrom(gServerSocket, buf, MAXLINE , 0, (struct sockaddr *)&cliaddr, &addrlen);
    LOG_DEBUG("Server : recvfrom:nbyte=%d", nbyte);
    if(nbyte < 0) {
      LOG_ERROR("recvfrom fail");
      exit(1);
    }
    buf[nbyte] = 0; //마지막 값에 0
    LOG_DEBUG("\nrecived data <<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<");
    for(i = 0; i < nbyte; i++) {
      #if 0
      if(headEnd != 1 && gHeaderFormat[i].startPos == 1 && gHeaderFormat[i].startPos != -1) {
        printf("%20s : ", gHeaderFormat[i].headerName);
      }
      if(headEnd != 1 && gHeaderFormat[i].startPos == -1) {
        LOG_DEBUG("\npayload +++++++++++++++++++++++\n");
        headEnd = 1;
      }
      #endif
      printf("%02x ", (unsigned char)buf[i]);
    }
    printf("\n\n");

    if(nbyte == 24) { // recvHeader + recvMsgAuthResp
      memcpy(&unTemp, sizeof(recvHeader.verMsgLen), &buf[0]);
      recvHeader.verMsgLen = ntohl(unTemp);
      feildIndex += sizeof(recvHeader.verMsgLen);

      memcpy(&unTemp, sizeof(recvHeader.commandCode), &buf[feildIndex]);
      recvHeader.commandCode = ntohl(unTemp);
      feildIndex += sizeof(recvHeader.commandCode);

      memcpy(&unTemp, sizeof(recvHeader.transactionId), &buf[feildIndex]);
      recvHeader.transactionId = ntohl(unTemp);
      feildIndex += sizeof(recvHeader.transactionId);

      memcpy(&recvMsgAuthResp.sysT, sizeof(recvMsgAuthResp.sysT), &buf[feildIndex]);
      feildIndex += sizeof(recvMsgAuthResp.sysT);

      memcpy(&unTemp, sizeof(recvMsgAuthResp.resultCode), &buf[feildIndex]);
      recvMsgAuthResp.resultCode = ntohl(unTemp);

      LOG_DEBUG("the reponse of request-auth:resultCode=%4x, %s", recvMsgAuthResp.resultCode, recvMsgAuthResp.resultCode==2001?"success":"fail");
    } else {  // recvHeader + recvMsgAuthResultTrap
      memcpy(&unTemp, sizeof(recvHeader.verMsgLen), &buf[0]);
      recvHeader.verMsgLen = ntohl(unTemp);
      feildIndex += sizeof(recvHeader.verMsgLen);

      memcpy(&unTemp, &buf[feildIndex], sizeof(recvHeader.commandCode));
      recvHeader.commandCode = ntohl(unTemp);
      feildIndex += sizeof(recvHeader.commandCode);

      memcpy(&unTemp, &buf[feildIndex], sizeof(recvHeader.transactionId));
      recvHeader.transactionId = ntohl(unTemp);
      feildIndex += sizeof(recvHeader.transactionId);

      memcpy(&recvMsgAuthResultTrap.sysT, &buf[feildIndex], sizeof(recvMsgAuthResultTrap.sysT));
      feildIndex += sizeof(recvMsgAuthResultTrap.sysT);

      memcpy(&unTemp, &buf[feildIndex], sizeof(recvMsgAuthResultTrap.resultCode));
      recvMsgAuthResultTrap.resultCode = ntohl(unTemp);
      feildIndex += sizeof(recvMsgAuthResultTrap.resultCode);
      LOG_DEBUG("the trap result of request-auth:resultCode=%04x, %s", recvMsgAuthResultTrap.resultCode, recvMsgAuthResultTrap.resultCode==2001?"success":"fail");
 
      gIsSucessAuthResultTrap = recvMsgAuthResultTrap.resultCode==2001?true:false;

      if(gIsSucessAuthResultTrap == true) {
        memcpy(&usTemp, &buf[feildIndex], sizeof(recvMsgAuthResultTrap.aaaType));
        recvMsgAuthResultTrap.aaaType = ntohs(usTemp);
        feildIndex += sizeof(recvMsgAuthResultTrap.aaaType);

        memcpy(&recvMsgAuthResultTrap.zKey1, &buf[feildIndex], sizeof(recvMsgAuthResultTrap.zKey1));
        feildIndex += sizeof(recvMsgAuthResultTrap.zKey1);

        memcpy(&recvMsgAuthResultTrap.zKey2, &buf[feildIndex], sizeof(recvMsgAuthResultTrap.zKey1));
        feildIndex += sizeof(recvMsgAuthResultTrap.zKey2);

        memcpy(&usTemp, &buf[feildIndex], sizeof(recvMsgAuthResultTrap.fepCertLen));
        recvMsgAuthResultTrap.fepCertLen = ntohs(usTemp);
        feildIndex += sizeof(recvMsgAuthResultTrap.fepCertLen);

        if(recvMsgAuthResultTrap.pFepCert == NULL) {
          recvMsgAuthResultTrap.pFepCert = (char*)malloc(recvMsgAuthResultTrap.fepCertLen);
        }
        memcpy(&recvMsgAuthResultTrap.pFepCert, &buf[feildIndex], recvMsgAuthResultTrap.fepCertLen);
        feildIndex += recvMsgAuthResultTrap.fepCertLen;

        memcpy(&usTemp, &buf[feildIndex], sizeof(recvMsgAuthResultTrap.emulCertLen));
        recvMsgAuthResultTrap.emulCertLen = ntohs(usTemp);
        feildIndex += sizeof(recvMsgAuthResultTrap.emulCertLen);

        if(recvMsgAuthResultTrap.pEmulCert == NULL) {
          recvMsgAuthResultTrap.pEmulCert = (char*)malloc(recvMsgAuthResultTrap.emulCertLen);
        }
        memcpy(&recvMsgAuthResultTrap.pEmulCert, &buf[feildIndex], recvMsgAuthResultTrap.emulCertLen);

        //void setCertAndKeys(IN bool authState, IN char* fepCert, IN int fepCertLen, IN char* emuCert, IN int emuCertLen, IN char* zKey1, IN int zKey1Len, IN char* zKey2, IN int zKey2Len);
        setCertAndKeys( gIsSucessAuthResultTrap, 
                        recvMsgAuthResultTrap.pFepCert, recvMsgAuthResultTrap.fepCertLen,
                        recvMsgAuthResultTrap.pEmulCert, recvMsgAuthResultTrap.emulCertLen,
                        recvMsgAuthResultTrap.zKey1, sizeof(recvMsgAuthResultTrap.zKey1),
                        recvMsgAuthResultTrap.zKey2, sizeof(recvMsgAuthResultTrap.zKey2));
      } else {
        //void setCertAndKeys(IN bool authState, IN char* fepCert, IN int fepCertLen, IN char* emuCert, IN int emuCertLen, IN char* zKey1, IN int zKey1Len, IN char* zKey2, IN int zKey2Len);
        setCertAndKeys( gIsSucessAuthResultTrap, 
                        NULL, 0,
                        NULL, 0,
                        NULL, 0,
                        NULL, 0);
      }
    }
  }
  
  return NULL;
}

void createThreadRecv(int port) {
  int thr_id = 0;
  pthread_t threadT;
  pthread_attr_t thread_attr;
  pthread_attr_init(&thread_attr);
  pthread_attr_setdetachstate(&thread_attr, PTHREAD_CREATE_DETACHED);

  thr_id = pthread_create(&threadT, &thread_attr, threadRecv, (void*)port);
  if (thr_id < 0) {
    LOG_ERROR("pthread_create(...,threadRecv,...) is error");
  }
  pthread_attr_destroy(&thread_attr);
}

int getCertAndKeysCallback(IN char* fepCert, IN int fepCertLen, IN char* emuCert, IN int emuCertLen, IN char* zKey1, IN int zKey1Len, IN char* zKey2, IN int zKey2Len) {
  LOG_DEBUG("getCertAndKeysCallback(...) is called, but not supported.");

  return 0;
}

#if 1
// simulation
char zKey1Buf[] = {0x82,0x99,0xa6,0x38,0x06,0x27,0x5f,0x56,0x9c,0xc1,0xe8,0x5b,0x26,0x9d,0x33,0x76,0x3d,0xea,0xbd,0x68,0x8b,0xb4,0x28,0x23,0xfb,0x50,0xec,0xe5,0x2d,0x42,0x53,0x8f};
char zKey2Buf[] = {0x00,0x01,0x02,0x03,0x04,0x05,0x06,0x07,0x08,0x09,0x0a,0x0b,0x0c,0x0d,0x0e,0x0f,0x3f,0x10,0x23,0x41,0x6e,0x64,0x9d,0x04,0x74,0x07,0x83,0x20,0x80,0x2e,0xac,0x5b};
char fepCertBuf[] = {0x30,0x82,0x01,0xd5,0x30,0x82,0x01,0x7a,0xa0,0x03,0x02,0x01,0x02,0x02,0x04,0x1d,0xce,0x17,0xcd,0x30,0x0c,0x06,0x08,0x2a,0x86,0x48,0xce,0x3d,0x04,0x03,0x02,0x05,
0x00,0x30,0x30,0x31,0x0b,0x30,0x09,0x06,0x03,0x55,0x04,0x06,0x13,0x02,0x6b,0x72,0x31,0x0e,0x30,0x0c,0x06,0x03,0x55,0x04,0x0a,0x0c,0x05,0x6b,0x65,0x70,0x63,0x6f,
0x31,0x11,0x30,0x0f,0x06,0x03,0x55,0x04,0x03,0x0c,0x08,0x41,0x4d,0x49,0x43,0x41,0x30,0x30,0x31,0x30,0x1e,0x17,0x0d,0x32,0x30,0x30,0x37,0x32,0x37,0x32,0x32,0x30,
0x30,0x30,0x30,0x5a,0x17,0x0d,0x32,0x35,0x30,0x37,0x32,0x37,0x32,0x31,0x35,0x39,0x35,0x39,0x5a,0x30,0x43,0x31,0x0b,0x30,0x09,0x06,0x03,0x55,0x04,0x06,0x13,0x02,
0x6b,0x72,0x31,0x0e,0x30,0x0c,0x06,0x03,0x55,0x04,0x0a,0x0c,0x05,0x6b,0x65,0x70,0x63,0x6f,0x31,0x0c,0x30,0x0a,0x06,0x03,0x55,0x04,0x0b,0x0c,0x03,0x41,0x4d,0x49,
0x31,0x16,0x30,0x14,0x06,0x03,0x55,0x04,0x03,0x0c,0x0d,0x4b,0x45,0x50,0x38,0x31,0x31,0x38,0x30,0x30,0x30,0x30,0x30,0x31,0x30,0x59,0x30,0x13,0x06,0x07,0x2a,0x86,
0x48,0xce,0x3d,0x02,0x01,0x06,0x08,0x2a,0x86,0x48,0xce,0x3d,0x03,0x01,0x07,0x03,0x42,0x00,0x04,0x99,0xb8,0x63,0x62,0xf9,0x94,0xf5,0xbe,0xed,0x01,0xca,0x17,0x0f,
0x36,0x2c,0xb1,0x75,0xe0,0x1b,0x24,0x7c,0xa9,0xdb,0x51,0x96,0x73,0x7b,0xac,0xae,0xd5,0x78,0x93,0xbe,0xd4,0x95,0x77,0xa6,0x49,0x4e,0xd7,0xa2,0x2b,0x51,0x1b,0x13,
0x94,0xbf,0x73,0xfa,0x5b,0x1b,0xab,0x2c,0xd3,0xef,0x06,0x1c,0x09,0x34,0xe5,0x80,0xa0,0x82,0x2f,0xa3,0x6d,0x30,0x6b,0x30,0x59,0x06,0x03,0x55,0x1d,0x23,0x04,0x52,
0x30,0x50,0x80,0x14,0x2f,0x3b,0xd6,0xed,0xf8,0xc2,0xce,0x39,0xcd,0xc1,0xe4,0xf3,0x79,0xea,0xbc,0xfd,0x49,0x3e,0x7f,0x78,0xa1,0x34,0xa4,0x32,0x30,0x30,0x31,0x0b,
0x30,0x09,0x06,0x03,0x55,0x04,0x06,0x13,0x02,0x6b,0x72,0x31,0x0e,0x30,0x0c,0x06,0x03,0x55,0x04,0x0a,0x0c,0x05,0x6b,0x65,0x70,0x63,0x6f,0x31,0x11,0x30,0x0f,0x06,
0x03,0x55,0x04,0x03,0x0c,0x08,0x52,0x4f,0x4f,0x54,0x43,0x41,0x30,0x31,0x82,0x02,0x00,0x85,0x30,0x0e,0x06,0x03,0x55,0x1d,0x0f,0x01,0x01,0xff,0x04,0x04,0x03,0x02,
0x06,0xc0,0x30,0x0c,0x06,0x08,0x2a,0x86,0x48,0xce,0x3d,0x04,0x03,0x02,0x05,0x00,0x03,0x47,0x00,0x30,0x44,0x02,0x20,0x56,0xf7,0x46,0xa5,0x96,0x89,0x55,0x8e,0x5d,
0x56,0x77,0x3c,0xc4,0xab,0x93,0xb2,0x3e,0x87,0x44,0x7c,0x44,0xb4,0xcf,0xc0,0xf1,0xc6,0xad,0x73,0x7c,0xf2,0x11,0x70,0x02,0x20,0x62,0x00,0x98,0xfd,0x10,0x8f,0x0f,
0x91,0xfd,0x1b,0x95,0x45,0x37,0x04,0x6a,0x8c,0x7f,0x8a,0xb8,0xbb,0x84,0x03,0x9d,0x7c,0x57,0x1a,0x8f,0x77,0x08,0xd6,0xec,0xca};
char emulCertBuf[] = {0x30,0x82,0x01,0xd7,0x30,0x82,0x01,0x7a,0xa0,0x03,0x02,0x01,0x02,0x02,0x04,0x1d,0xce,0x17,0xd1,0x30,0x0c,0x06,0x08,0x2a,0x86,0x48,0xce,0x3d,0x04,0x03,0x02,0x05,
0x00,0x30,0x30,0x31,0x0b,0x30,0x09,0x06,0x03,0x55,0x04,0x06,0x13,0x02,0x6b,0x72,0x31,0x0e,0x30,0x0c,0x06,0x03,0x55,0x04,0x0a,0x0c,0x05,0x6b,0x65,0x70,0x63,0x6f,
0x31,0x11,0x30,0x0f,0x06,0x03,0x55,0x04,0x03,0x0c,0x08,0x41,0x4d,0x49,0x43,0x41,0x30,0x30,0x31,0x30,0x1e,0x17,0x0d,0x32,0x30,0x30,0x37,0x32,0x37,0x32,0x32,0x30,
0x30,0x30,0x30,0x5a,0x17,0x0d,0x32,0x35,0x30,0x37,0x32,0x37,0x32,0x31,0x35,0x39,0x35,0x39,0x5a,0x30,0x43,0x31,0x0b,0x30,0x09,0x06,0x03,0x55,0x04,0x06,0x13,0x02,
0x6b,0x72,0x31,0x0e,0x30,0x0c,0x06,0x03,0x55,0x04,0x0a,0x0c,0x05,0x6b,0x65,0x70,0x63,0x6f,0x31,0x0c,0x30,0x0a,0x06,0x03,0x55,0x04,0x0b,0x0c,0x03,0x41,0x4d,0x49,
0x31,0x16,0x30,0x14,0x06,0x03,0x55,0x04,0x03,0x0c,0x0d,0x4b,0x45,0x50,0x38,0x32,0x31,0x38,0x30,0x30,0x30,0x30,0x30,0x31,0x30,0x59,0x30,0x13,0x06,0x07,0x2a,0x86,
0x48,0xce,0x3d,0x02,0x01,0x06,0x08,0x2a,0x86,0x48,0xce,0x3d,0x03,0x01,0x07,0x03,0x42,0x00,0x04,0x8f,0x47,0x04,0x15,0xc7,0x55,0x80,0x3f,0x9f,0x23,0xb6,0x0b,0xa7,
0x8a,0xbd,0x92,0x8c,0x8c,0xc4,0x33,0xb3,0x56,0x4d,0x8d,0xa0,0xd2,0x76,0xbe,0x09,0x23,0x38,0xd3,0x42,0xef,0xed,0xae,0xeb,0xc3,0x81,0x8a,0x1c,0xe5,0xf7,0xdd,0xdc,
0x69,0xee,0xfe,0xdb,0xdf,0x7e,0xe6,0x72,0x91,0x5d,0xb3,0x8f,0xed,0x95,0xb7,0xa0,0xe7,0xf9,0xe4,0xa3,0x6d,0x30,0x6b,0x30,0x59,0x06,0x03,0x55,0x1d,0x23,0x04,0x52,
0x30,0x50,0x80,0x14,0x2f,0x3b,0xd6,0xed,0xf8,0xc2,0xce,0x39,0xcd,0xc1,0xe4,0xf3,0x79,0xea,0xbc,0xfd,0x49,0x3e,0x7f,0x78,0xa1,0x34,0xa4,0x32,0x30,0x30,0x31,0x0b,
0x30,0x09,0x06,0x03,0x55,0x04,0x06,0x13,0x02,0x6b,0x72,0x31,0x0e,0x30,0x0c,0x06,0x03,0x55,0x04,0x0a,0x0c,0x05,0x6b,0x65,0x70,0x63,0x6f,0x31,0x11,0x30,0x0f,0x06,
0x03,0x55,0x04,0x03,0x0c,0x08,0x52,0x4f,0x4f,0x54,0x43,0x41,0x30,0x31,0x82,0x02,0x00,0x85,0x30,0x0e,0x06,0x03,0x55,0x1d,0x0f,0x01,0x01,0xff,0x04,0x04,0x03,0x02,
0x06,0xc0,0x30,0x0c,0x06,0x08,0x2a,0x86,0x48,0xce,0x3d,0x04,0x03,0x02,0x05,0x00,0x03,0x49,0x00,0x30,0x46,0x02,0x21,0x00,0xbb,0x8f,0x8f,0xed,0x9b,0xcb,0x67,0x32,
0x87,0x51,0x15,0x30,0x81,0x51,0x8f,0x02,0x3d,0x17,0x6d,0x7c,0x7a,0x61,0x4b,0x81,0x3c,0x53,0x03,0x4d,0xee,0x53,0x40,0x54,0x02,0x21,0x00,0xd0,0x69,0x79,0x3c,0xc8,
0x4b,0xdc,0x52,0xfd,0xe8,0x44,0xf1,0x1a,0xa9,0x17,0x43,0xcf,0x27,0xf3,0xcc,0x10,0x4a,0x87,0x28,0x8b,0xda,0x3f,0x50,0x2a,0xc8,0x1f,0xd5};
#endif
void reAuthCallback() {
  LOG_DEBUG("reAuthCallback() is called.");
  SECURITY_AGENT_HEADER reqAuthHeader;
  unsigned int verAndMesLength =  0x01 << 24;
  char* sendBufer = (char*)malloc(sizeof( SECURITY_AGENT_HEADER) + sizeof(REQ_MSG_AUTHENTICATION));
  struct sockaddr_in securityAgentServerAddr;
  int addrlen = sizeof(struct sockaddr);

  if(sendBufer) {
    verAndMesLength = verAndMesLength | (sizeof(SECURITY_AGENT_HEADER) + sizeof(REQ_MSG_AUTHENTICATION));
    reqAuthHeader.verMsgLen = (unsigned int)htonl(verAndMesLength);
    reqAuthHeader.commandCode = (unsigned int)htonl((uint32_t)0x000000f0);
    reqAuthHeader.transactionId = (unsigned int)htonl((uint32_t)gTransactionId++);

    char* pMsg = NULL;
    int msgLen = 0;
    //makeRequestMsgAuthentication("BMT3020000010", "0000000001", "192.168.0.137", 13868, "00-00-b8-27-eb-f0-09-48", &pMsg, &msgLen); // eth0
    //makeRequestMsgAuthentication("BMT3020000010", "0000000001", "192.168.0.11", 13868, "00-00-b8-27-eb-a5-5c-1d", &pMsg, &msgLen); // wlan0
                                  
    makeRequestMsgAuthentication( gConfigInfo[SYSTEM_TITLE].value, 
                                  gConfigInfo[DCU_ID].value, 
                                  gConfigInfo[IAAA_SERVER_IPADDR].value, 
                                  SECURITY_AGENT_UDP_PORT, 
                                  gConfigInfo[DCU_MAC_ADDR].value, &pMsg, &msgLen); // wlan0

    memcpy(sendBufer, &reqAuthHeader, sizeof(SECURITY_AGENT_HEADER));
    memcpy(sendBufer+sizeof(SECURITY_AGENT_HEADER), pMsg, sizeof(REQ_MSG_AUTHENTICATION));
    LOG_DEBUG("reAuthCallback:sending...");
    if(gServerSocket > 0) {
      memset(&securityAgentServerAddr, 0, addrlen); //bzero((char *)&servaddr, sizeof(servaddr));
      securityAgentServerAddr.sin_family = AF_INET; //인터넷 Addr Family
      securityAgentServerAddr.sin_addr.s_addr = inet_addr("127.0.0.1"); //argv[1]에서 주소를 가져옴

      //securityAgentPort = 10000;
      LOG_DEBUG("securityAgentPort=%d", SECURITY_AGENT_UDP_PORT);
      securityAgentServerAddr.sin_port = htons(SECURITY_AGENT_UDP_PORT); //argv[2]에서 port를 가져옴

      if((sendto(gServerSocket, sendBufer, sizeof(REQ_MSG_AUTHENTICATION) + sizeof(SECURITY_AGENT_HEADER), 0, (struct sockaddr *)&securityAgentServerAddr, addrlen)) < 0) {
        LOG_ERROR("reAuthCallback:sendto fail, so exit...");
      }
    } else {
      LOG_ERROR("reAuthCallback:gServerSocket(%d) is wrong.", gServerSocket);
    }

    free(sendBufer);
  } else {
    LOG_ERROR("reAuthCallback:sendBufer is null, memory allocation error.");
  }
}

void getAuthStateCallback() {
  LOG_DEBUG("getAuthStateCallback() is called.");
  if(gIsSucessAuthResultTrap == true) {
    setCertAndKeys( gIsSucessAuthResultTrap, 
                    recvMsgAuthResultTrap.pFepCert, recvMsgAuthResultTrap.fepCertLen,
                    recvMsgAuthResultTrap.pEmulCert, recvMsgAuthResultTrap.emulCertLen,
                    recvMsgAuthResultTrap.zKey1, sizeof(recvMsgAuthResultTrap.zKey1),
                    recvMsgAuthResultTrap.zKey2, sizeof(recvMsgAuthResultTrap.zKey2));
  } else{
#if 1    
      setCertAndKeys( gIsSucessAuthResultTrap, 
                      NULL, 0,
                      NULL, 0,
                      NULL, 0,
                      NULL, 0);
#else // simulation
      setCertAndKeys( 1, 
                      fepCertBuf, sizeof(fepCertBuf),
                      emulCertBuf, sizeof(emulCertBuf),
                      zKey1Buf, sizeof(zKey1Buf),
                      zKey2Buf, sizeof(zKey2Buf));
#endif
  }
}

int main(int argc, char *argv[]) {
  char buf[MAXLINE+1];
  struct sockaddr_in cliaddr;
  int nbyte, addrlen = sizeof(struct sockaddr);
  //int serverPort = 10000;

  struct sockaddr_in securityAgentServerAddr;
  //int securityAgentPort = 13868;
  char iaaaServerIPAddr[20] = {0,};
  int i = 0;
  char keyTemp[50], keyValueTemp[50];
  
  SECURITY_AGENT_HEADER reqAuthHeader;
  SetTlsqDcuDebugLevel(TLSQ_DCU_DEBUG_DEBUG);

  //void zmqCommonInit(bool isIaaaClient, int iaaaClientPort, int pullPort);
  //typedef int (*getCertAndKeys_callback)(IN char* fepCert, IN int fepCertLen, IN char* emuCert, IN int emuCertLen, IN char* zKey1, IN int zKey1Len, IN char* zKey2, IN int zKey2Len);
  zmqCommonInit(true, 9000, 9001);
  register_getCertAndKeysCallback(getCertAndKeysCallback);
  register_reAuthCallback(reAuthCallback);
  register_getAuthStateCallback(getAuthStateCallback);


  FILE *fp = NULL;
  fp = fopen("/tmp/tlsq-dcu.conf", "rt");
  if(fp == NULL) {
    LOG_DEBUG("Please create /tmp/tldq-dcu.conf like below.");
    LOG_DEBUG("system-title	BMT3020000010");
    LOG_DEBUG("dcu-id		BMT3020020");
    LOG_DEBUG("iaaa-server-ip	211.170.81.205");
    LOG_DEBUG("dcu-mac-addr	00-00-b8-27-eb-a5-5c-1d");
    exit(-1);
  }

  while(1) {
    if(fscanf(fp, "%s %s", keyTemp, keyValueTemp) == EOF) {
      //printf("there is empty in tlsq-dcu.conf\n");
      break;
    }

    //printf("tlsq-dcu.conf : key=%s, value=%s\n", keyTemp, keyValueTemp);
    i = 0;
    while(1) {
      if(gConfigInfo[i].key == NULL) {
        break;
      }
      if(strcmp(keyTemp, gConfigInfo[i].key) == 0) {
        //printf("found key=%s, value=%s\n\n", keyTemp, keyValueTemp);
        strcpy(gConfigInfo[i].value, keyValueTemp);
        break;
      }
      i++;
    }
  }

  i = 0;
  while(gConfigInfo[i].key != NULL) {

    if(strlen(gConfigInfo[i].value) == 0) {
      LOG_DEBUG("the value of key(%s) is empty. so this program has been terminated.");
      exit(-1);
    }

    LOG_DEBUG("%s:%s", gConfigInfo[i].key, gConfigInfo[i].value);
    i ++;
  }

  //serverPort = atoi(argv[1]);
  //securityAgentPort = atoi(argv[2]);
  //strcpy(iaaaServerIPAddr, argv[3]);

  createThreadRecv(SERVER_UDP_PORT_FOR_TRAP);

  LOG_DEBUG("\nselfUdpServerPort=%d, securityAgentUdpServerPort=%d, iaaaServerIPAddr=%s", \
    SERVER_UDP_PORT_FOR_TRAP, SECURITY_AGENT_UDP_PORT, gConfigInfo[IAAA_SERVER_IPADDR].value);

  //int makeRequestMsgAuthentication(char* pSysT, char* pDcuId, char* pAaaIp, unsigned int aaaPort, char* pCallingStationId, unsigned char** ppOutMsg, int* outMsgLen) {
  char* pMsg = NULL;
  int msgLen = 0;
  //makeRequestMsgAuthentication("BMT3020000010", "0000000001", "192.168.0.137", 13868, "00-00-b8-27-eb-f0-09-48", &pMsg, &msgLen); // eth0
  //makeRequestMsgAuthentication("BMT3020000010", "0000000001", "192.168.0.11", 13868, "00-00-b8-27-eb-a5-5c-1d", &pMsg, &msgLen); // wlan0
                                 
  makeRequestMsgAuthentication( gConfigInfo[SYSTEM_TITLE].value, 
                                gConfigInfo[DCU_ID].value, 
                                gConfigInfo[IAAA_SERVER_IPADDR].value, 
                                SECURITY_AGENT_UDP_PORT, 
                                gConfigInfo[DCU_MAC_ADDR].value, &pMsg, &msgLen); // wlan0
  if(pMsg == NULL) {
    LOG_ERROR("pMsg is null.");
  }
  LOG_DEBUG("sizeof(SECURITY_AGENT_HEADER)=%d, sizeof(REQ_MSG_AUTHENTICATION)=%d, msgLen=%d", sizeof(SECURITY_AGENT_HEADER), sizeof(REQ_MSG_AUTHENTICATION),  msgLen);

  //return 0;
  //서버 주소 구조
  memset(&securityAgentServerAddr, 0, addrlen); //bzero((char *)&servaddr, sizeof(servaddr));
  securityAgentServerAddr.sin_family = AF_INET; //인터넷 Addr Family
  securityAgentServerAddr.sin_addr.s_addr = inet_addr("127.0.0.1"); //argv[1]에서 주소를 가져옴

  //securityAgentPort = 10000;
  LOG_DEBUG("securityAgentPort=%d", SECURITY_AGENT_UDP_PORT);
  securityAgentServerAddr.sin_port = htons(SECURITY_AGENT_UDP_PORT); //argv[2]에서 port를 가져옴
  unsigned int verAndMesLength =  0x01 << 24;
  verAndMesLength = verAndMesLength | (sizeof(SECURITY_AGENT_HEADER) + sizeof(REQ_MSG_AUTHENTICATION));
  reqAuthHeader.verMsgLen = (unsigned int)htonl(verAndMesLength);

  reqAuthHeader.commandCode = (unsigned int)htonl((uint32_t)0x000000f0);
  reqAuthHeader.transactionId = (unsigned int)htonl((uint32_t)0x00000001);



  while(1) {
        //메시지 전송
    sleep(5);
    if(gTransactionId == 1) {
        char* sendBufer = (char*)malloc(sizeof( SECURITY_AGENT_HEADER) + sizeof(REQ_MSG_AUTHENTICATION));
        reqAuthHeader.transactionId = (unsigned int)htonl((uint32_t)gTransactionId++);
        memcpy(sendBufer, &reqAuthHeader, sizeof(SECURITY_AGENT_HEADER));
        memcpy(sendBufer+sizeof(SECURITY_AGENT_HEADER), pMsg, sizeof(REQ_MSG_AUTHENTICATION));
        LOG_DEBUG("sending...");
        if((sendto(gServerSocket, sendBufer, sizeof(REQ_MSG_AUTHENTICATION) + sizeof(SECURITY_AGENT_HEADER), 0, (struct sockaddr *)&securityAgentServerAddr, addrlen)) < 0) {
          LOG_ERROR("sendto fail, so exit...");
        }

        free(sendBufer);
      }
    //break;
  }

  close(gServerSocket);
  sleep(2);
  return 0;
}
