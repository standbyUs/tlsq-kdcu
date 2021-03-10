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



#define MAXLINE    1024*10
#define BLOCK      255

#define LOOGER_E()
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

typedef struct ResponseMsgAthentication {
    unsigned char sysT[8];
    unsigned int resultCode;  // 4bytes
} RESP_MSG_AUTHENTICATION;

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

int makeRequestMsgAuthentication(char* pSysT, char* pDcuId, char* pAaaIp, unsigned int aaaPort, char* pCallingStationId, unsigned char** ppOutMsg, int* outMsgLen) {
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
//printf("%s|%d, logging\n", __FILE__, __LINE__);
  SetTlsqDcuDebugLevel(TLSQ_DCU_DEBUG_DEBUG);

  //파일명 포트"번호
  // if(argc != 4) { 
  //     LOG_DEBUG("usage: %s udpServerPort securityAgentUdpPort iaaaServerIPAddress", argv[0]);
  //     exit(0);
  // }
  
//printf("%s|%d, logging\n", __FILE__, __LINE__);
  FILE *fp = NULL;
  fp = fopen("/tmp/tlsq-dcu.conf", "rt");
  // if(fp == NULL) {
  //   fp = fopen("./tldq-dcu.conf", "rt");
  // }
//printf("%s|%d, logging\n", __FILE__, __LINE__);
  if(fp == NULL) {
    LOG_DEBUG("Please create /tmp/tldq-dcu.conf like below.");
    LOG_DEBUG("system-title	BMT3020000010");
    LOG_DEBUG("dcu-id		BMT3020020");
    LOG_DEBUG("iaaa-server-ip	211.170.81.205");
    LOG_DEBUG("dcu-mac-addr	00-00-b8-27-eb-a5-5c-1d");
    exit(-1);
  }
//printf("%s|%d, logging\n", __FILE__, __LINE__);

  while(1) {
    if(fscanf(fp, "%s %s", keyTemp, keyValueTemp) == EOF) {
      //printf("there is empty in tlsq-dcu.conf\n");
      break;
    }
//printf("%s|%d, logging\n", __FILE__, __LINE__);

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

//printf("%s|%d, logging\n", __FILE__, __LINE__);

  i = 0;
  while(gConfigInfo[i].key != NULL) {
//printf("%s|%d, logging\n", __FILE__, __LINE__);

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

  unsigned int transactionId = 1;

  while(1) {
        //메시지 전송
    sleep(5);
    if(transactionId == 1) {
        char* sendBufer = (char*)malloc(sizeof( SECURITY_AGENT_HEADER) + sizeof(REQ_MSG_AUTHENTICATION));
        reqAuthHeader.transactionId = (unsigned int)htonl((uint32_t)transactionId++);
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
