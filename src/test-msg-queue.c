#include "msg-queue.h"
#include <stdbool.h>  // error: unknown type name ‘bool’
#include <unistd.h>

int getCertAndKeysCallback(OUT char* fepCert, OUT int fepCertLen, OUT char* emuCert, OUT int emuCertLen, OUT char* zKey1, OUT int zKey1Len, OUT char* zKey2, OUT int zKey2Len) {
    printf("getCertAndKeysCallback(...) is called.\n");
    int i = 0;

    printf("FEP Cert : ");
    for(i=0; i<fepCertLen; i ++) {

        printf("%02x ", (char)fepCert[i]);
    }
    printf("\n\n");

    printf("EMULATOR Cert : ");
    for(i=0; i<emuCertLen; i ++) {

        printf("%02x ", (char)emuCert[i]);
    }
    printf("\n\n");


    printf("zKey1 : ");
    for(i=0; i<zKey1Len; i ++) {

        printf("%02x ", (char)zKey1[i]);
    }
    printf("\n\n");

    printf("zKey2 : ");
    for(i=0; i<zKey2Len; i ++) {

        printf("%02x ", (char)zKey2[i]);
    }
    printf("\n\n");

    return 0;
}

#define SLEEP_TIME  1000*1000*2

int main(void) {

    int nCount = 0;
    int nSelectNum = 0;
    zmqCommonInit(false, 8800, 8801);
    register_getCertAndKeysCallback(getCertAndKeysCallback);

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
        }

        usleep(SLEEP_TIME);
    }
    printf("\ntest-msgQueue program is terminated.\n");
}