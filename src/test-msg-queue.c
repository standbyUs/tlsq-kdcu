#include "msg-queue.h"
#include "tlsq-dcu-logger.h"
#include <stdbool.h>  // error: unknown type name ‘bool’
#include <unistd.h>

int getCertAndKeysCallback(IN bool authState, IN char* fepCert, IN int fepCertLen, IN char* emuCert, IN int emuCertLen, IN char* zKey1, IN int zKey1Len, IN char* zKey2, IN int zKey2Len) {
    printf("getCertAndKeysCallback(...) is called.\n");
    int i = 0;
    printf("getCertAndKeysCallback:authState=%s\n", authState==true?"true":"false");
    printf("getCertAndKeysCallback:fepCertLen=%d, emuCertLen=%d, zKey1Len=%d, zKey2Len=%d\n", fepCertLen, emuCertLen, zKey1Len, zKey2Len);

    printf("getCertAndKeysCallback:FEP Cert : ");
    for(i=0; i<fepCertLen; i ++) {

        printf("%02x ", (unsigned char)fepCert[i]);
    }
    printf("\n\n");

    printf("getCertAndKeysCallback:EMULATOR Cert : ");
    for(i=0; i<emuCertLen; i ++) {

        printf("%02x ", (unsigned char)emuCert[i]);
    }
    printf("\n\n");


    printf("getCertAndKeysCallback:zKey1 : ");
    for(i=0; i<zKey1Len; i ++) {

        printf("%02x ", (unsigned char)zKey1[i]);
    }
    printf("\n\n");

    printf("getCertAndKeysCallback:zKey2 : ");
    for(i=0; i<zKey2Len; i ++) {

        printf("%02x ", (unsigned char)zKey2[i]);
    }
    printf("\n\n");

    return 0;
}

#define SLEEP_TIME  1000*100

int main(void) {

    int nCount = 0;
    int nSelectNum = 0;
    SetTlsqDcuDebugLevel(TLSQ_DCU_DEBUG_DEBUG);
    zmqCommonInit(false, 9000, 9001);
    register_getCertAndKeysCallback(getCertAndKeysCallback);
    sleep(2);
    while(1) {
        printf("\n=============================================\n");
        printf("Select : 1(getAuthState), 2(reAuth), 0(exit)\n");
        printf("Enter : ");
        scanf("%d", &nSelectNum);
        if(nSelectNum == 1) {
            getAuthState();
        } else if(nSelectNum == 2) {
            reAuth();
        } else if(nSelectNum == 0) {
            break;
        } else {
            
        }

        usleep(SLEEP_TIME);
    }
    zmqCommonDeInit();
    printf("\ntest-msgQueue program is terminated.\n");
}
