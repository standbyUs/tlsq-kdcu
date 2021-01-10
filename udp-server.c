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

#include "tlsq-dcu-logger.h"
#include "tlsq-dcu-utils.h"



#define MAXLINE    1024
#define BLOCK      255

#define LOOGER_E()
typedef union VersionMsgLen {
  unsigned char version;
  unsigned int messageLength;
} VERSION_MSGLEN;

typedef struct SecurityAgentHeader {
  VERSION_MSGLEN verMsgLen;
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
  unsigned int aaaPort; // 4bytes
  unsigned char authReqType;
  char callingStationId[23];
} REQ_MSG_AUTHENTICATION, *REQ_MSG_AUTHENTICATION_PTR;

typedef struct ResponseMsgAthentication {
    unsigned char sysT[8];
    unsigned int resultCode;  // 4bytes
} RESP_MSG_AUTHENTICATION;

#define SYSTEM_TITLE_LEN          13
#define DCU_ID_LEN                10
#define CALLING_STATTION_ID_LEN   23
#define REQ_AUTH_LEN              62

int makeRequestMsgAuthentication(char* pSysT, char* pDcuId, char* pAaaIp, unsigned int aaaPort, char* pCallingStationId, unsigned char** ppOutMsg, int* outMsgLen) {
  LOG_DEBUG("makeRequestMsgAuthentication is called.");
  if(pSysT == NULL || strlen(pSysT) != SYSTEM_TITLE_LEN) {
    LOG_ERROR("pSysT is null or the length of pSysT is wrong.");
    return -1;
  }
  LOG_DEBUG("makeRequestMsgAuthentication is called.");
  if(pAaaIp == NULL || strlen(pAaaIp) <= 0 ) {
    LOG_ERROR("pAaaIp is null or the length of pAaaIp is wrong.");
    return -1;
  }
  LOG_DEBUG("makeRequestMsgAuthentication is called.");
  unsigned char* pMessage = (unsigned char*)malloc(sizeof(REQ_MSG_AUTHENTICATION));
  if(pMessage == NULL) {
    LOG_ERROR("pMessage is null");
    return -1;
  }
  LOG_DEBUG("makeRequestMsgAuthentication is called.");

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
  LOG_DEBUG("makeRequestMsgAuthentication is called.");
  
  // DCU ID
  memcpy(&pMessage[8], pDcuId, DCU_ID_LEN);
  LOG_DEBUG("makeRequestMsgAuthentication is called.");

  // AAA-IP
  struct in_addr addr;
  inet_aton(pAaaIp, &addr);
  LOG_DEBUG("addr=%x",  addr.s_addr);
  memcpy(&pMessage[18], &addr.s_addr, sizeof(unsigned int));
  // pMessage[18] = (unsigned char)((addr.s_addr >> 24) & 0x000000ff);
  // pMessage[19] = (unsigned char)((addr.s_addr >> 16) & 0x000000ff);
  // pMessage[20] = (unsigned char)((addr.s_addr >>  8) & 0x000000ff);
  // pMessage[21] = (unsigned char)((addr.s_addr) & 0x000000ff);

  LOG_DEBUG("makeRequestMsgAuthentication is called.");

  // AAA-Port
  unsigned int serverPort = (unsigned int)htonl((unsigned long)aaaPort);
  memcpy(&pMessage[34], &serverPort, sizeof(unsigned int));
  LOG_DEBUG("makeRequestMsgAuthentication is called.");
  // Auth-Request-Type
  pMessage[38] = 0x01;  // 인증 요청 (default)

  // Calling-Station-id

  memcpy(&pMessage[39], pCallingStationId, CALLING_STATTION_ID_LEN); 

  for(int i=0; i < REQ_AUTH_LEN; i++) {
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

      //소켓 생성
  if((gServerSocket = socket(PF_INET, SOCK_DGRAM, 0)) < 0) {
      perror("socket fail");
      exit(0);
  }
    
  // 서버 구조
  memset(&cliaddr, 0, addrlen); //bzero((char *)&cliaddr, addrlen);
  memset(&servaddr, 0, addrlen); //bzero((char *)&servaddr,addrlen);
  servaddr.sin_family = AF_INET;
  servaddr.sin_addr.s_addr = htonl(INADDR_ANY);
  servaddr.sin_port = htons(serverPort); //argv[1]에서 port 번호 가지고 옴

  // 서버 로컬 주소로 bind()
  if(bind(gServerSocket, (struct sockaddr *)&servaddr, addrlen) < 0) {
      perror("bind fail");
      exit(0);
  }

  while(1)
  {
    LOG_DEBUG("Server : waiting request [gServerSocket=%d].", gServerSocket);
    //전송 받은 메시지 nbyte 저장
    nbyte = recvfrom(gServerSocket, buf, MAXLINE , 0, (struct sockaddr *)&cliaddr, &addrlen);
    LOG_DEBUG("Server : waiting request [gServerSocket2=%d].", gServerSocket);
    if(nbyte < 0) {
      perror("recvfrom fail");
      exit(1);
    }
    buf[nbyte] = 0; //마지막 값에 0
    printf("\nHeader ++++++++++++++++++++++++++++\n");
    for(i = 0; i < nbyte; i++) {
      if(headEnd != 1 && gHeaderFormat[i].startPos == 1 && gHeaderFormat[i].startPos != -1) {
        printf("\n20%s : ", gHeaderFormat[i].headerName);
      }
      if(headEnd != 1 && gHeaderFormat[i].startPos == -1) {
        printf("\npayload +++++++++++++++++++++++\n");
        headEnd = 1;
      }
      printf("02%x ", (unsigned char)buf[i]);
    }
  }
  
  return NULL;
}

void createThreadRecv(int* port) {
  int thr_id = 0;
  pthread_t threadT;
  pthread_attr_t thread_attr;
  pthread_attr_init(&thread_attr);
  pthread_attr_setdetachstate(&thread_attr, PTHREAD_CREATE_DETACHED);

  thr_id = pthread_create(&threadT, &thread_attr, threadRecv, (void*)port);
  if (thr_id < 0) {
    printf("pthread_create(...,threadCheckEasySetupTimeOut,...) is error");
  }
  pthread_attr_destroy(&thread_attr);
}

int main(int argc, char *argv[]) {
  char buf[MAXLINE+1];
  struct sockaddr_in cliaddr;
  int nbyte, addrlen = sizeof(struct sockaddr);
  int serverPort = 10000;

  struct sockaddr_in securityAgentServerAddr;
  int securityAgentPort = 13868;
  MESSAGE_PROTO sendReqMsg;

  SetTlsqDcuDebugLevel(TLSQ_DCU_DEBUG_DEBUG);

  //파일명 포트번호
  if(argc != 3) { 
      LOG_DEBUG("usage: %s udpServerPort securityAgentUdpPort", argv[0]);
      exit(0);
  }
    
  serverPort = atoi(argv[1]);
  securityAgentPort = atoi(argv[2]);

  createThreadRecv(&serverPort);

  printf("\nselfUdpServerPort=%d, securityAgentUdpServerPort=%d\n", serverPort, securityAgentPort);

  //int makeRequestMsgAuthentication(char* pSysT, char* pDcuId, char* pAaaIp, unsigned int aaaPort, char* pCallingStationId, unsigned char** ppOutMsg, int* outMsgLen) {
  char* pMsg = NULL;
  int msgLen = 0;
  makeRequestMsgAuthentication("BMT3020000010", "0000000001", "127.0.0.1", 13868, "00-00-b8-27-eb-a5-5c-1d", &pMsg, &msgLen);
  //return 0;
  //서버 주소 구조
  memset(&securityAgentServerAddr, 0, addrlen); //bzero((char *)&servaddr, sizeof(servaddr));
  securityAgentServerAddr.sin_family = AF_INET; //인터넷 Addr Family
  securityAgentServerAddr.sin_addr.s_addr = inet_addr("127.0.0.1"); //argv[1]에서 주소를 가져옴
  securityAgentServerAddr.sin_port = htons(securityAgentPort); //argv[2]에서 port를 가져옴

  sendReqMsg.header.commandCode;
  sendReqMsg.header.transactionId;
  sendReqMsg.header.verMsgLen.version = 0x01;
  sendReqMsg.header.verMsgLen.messageLength = (sendReqMsg.header.verMsgLen.messageLength & 0xff000000);
  while(1) {
        //메시지 전송
    sleep(5);
    if((sendto(gServerSocket, buf, strlen(buf), 0, (struct sockaddr *)&securityAgentServerAddr, addrlen)) < 0) {
      perror("sendto fail");
      exit(0);
    }
    break;
  }

  close(gServerSocket);
  sleep(2);
  return 0;
}