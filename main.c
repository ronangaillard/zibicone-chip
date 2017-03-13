#include <stdlib.h>
#include <stdio.h>
#include <pcap.h>
#include <stdint.h>
#include <string.h>
#include <time.h>

//gcc main.c -lpcap -I/usr/include/pcap -o main && ./main
// Sony Z4 	40:B8:37:0D:63:5D
// Chip 	CC:79:CF:20:6D:D1
//cc:79:cf:20:6d:d1
// Mac      0x78, 0x4f, 0x43, 0x4e, 0xcd, 0xfe
 // Xbox mac BC:83:85:71:90:23
// Coucou Ronan

uint8_t null_frame[] = { 0x48, 0x00, 0x00, 0x00, 
                /*4*/    0xbc, 0x83, 0x85, 0x71, 0x90, 0x23,
                /*10*/  0xcc, 0x79, 0xcf, 0x20, 0x6d, 0xd1,
                /*16*/  0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 
                /*22*/  0xc0, 0x6c, 
                /*24*/  0x83, 0x51, 0xf7, 0x8f, 0x0f, 0x00, 0x00, 0x00};  

void inject(char *iface, unsigned int cnt, uint8_t frame[], unsigned int len, unsigned long delay)
{
    char errbuf[PCAP_ERRBUF_SIZE];
    pcap_t *pcap;
    int result;
    unsigned int i;

    strcpy(errbuf, "");
    pcap = pcap_open_live(iface, 800, 1 ,20, errbuf);
    if(pcap == NULL){
        printf("FATAL : unable to open pcap device\n");
        exit(1);
    }

    for(i = 0; i < cnt; i++) {
        result = pcap_inject(pcap, frame, len);
        printf("result : %d\n", result);
        if(result == -1) {
            printf("Error : %s\n", pcap_geterr(pcap));
        }
        usleep(delay);
    }
 
    pcap_close(pcap);
}

int main(){
    srand(time(NULL));
    printf("Injecting packet\n");

    //Randomize source mac
    // Randomize SRC MAC
   
    /*null_frame[10] = null_frame[16] = rand() % 256;
    null_frame[11] = null_frame[17] = rand() % 256;
    null_frame[12] = null_frame[18] = rand() % 256;
    null_frame[13] = null_frame[19] = rand() % 256;
    null_frame[14] = null_frame[20] = rand() % 256;
    null_frame[15] = null_frame[21] = rand() % 256;*/

    inject("wlan0", 50, null_frame, sizeof(null_frame) / sizeof(null_frame[0]), 50);
    printf("Done\n");
    exit(0);
}