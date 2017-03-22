#include <stdlib.h>
#include <stdio.h>
#include <pcap.h>
#include <stdint.h>
#include <string.h>
#include <time.h>

#define WLAN_FC_TYPE_DATA	2
#define WLAN_FC_SUBTYPE_DATA	0

//gcc main.c -lpcap -I/usr/include/pcap -o main && ./main
// Sony Z4 	40:B8:37:0D:63:5D
// Chip 	CC:79:CF:20:6D:D1
//cc:79:cf:20:6d:d1
// Mac      0x78, 0x4f, 0x43, 0x4e, 0xcd, 0xfe
 // Xbox mac BC:83:85:71:90:23
// Coucou Ronan

const uint8_t mac_chip[6] = { 0xcc, 0x79, 0xcf, 0x20, 0x6d, 0xd1 };
const uint8_t mac_mac[6] = { 0x78, 0x4f, 0x43, 0x4e, 0xcd, 0xfe };

/* Defined in include/linux/ieee80211.h */
/* MAC Header */
struct ieee80211_hdr {
  uint16_t /*__le16*/ frame_control;
  uint16_t /*__le16*/ duration_id;
  uint8_t addr1[6];
  uint8_t addr2[6];
  uint8_t addr3[6];
  uint16_t /*__le16*/ seq_ctrl;
  //uint8_t addr4[6];
} __attribute__ ((packed));

static const uint8_t u8aRadiotapHeader[] = {

  0x00, 0x00, // <-- radiotap version (ignore this)
  0x18, 0x00, // <-- number of bytes in our header (count the number of "0x"s)

  /**
   * The next field is a bitmap of which options we are including.
   * The full list of which field is which option is in ieee80211_radiotap.h,
   * but I've chosen to include:
   *   0x00 0x01: timestamp
   *   0x00 0x02: flags
   *   0x00 0x03: rate
   *   0x00 0x04: channel
   *   0x80 0x00: tx flags (seems silly to have this AND flags, but oh well)
   */
  0x0f, 0x80, 0x00, 0x00,

  0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // <-- timestamp

  /**
   * This is the first set of flags, and we've set the bit corresponding to
   * IEEE80211_RADIOTAP_F_FCS, meaning we want the card to add a FCS at the end
   * of our buffer for us.
   */
  0x10,

  0x00, // <-- rate
  0x00, 0x00, 0x00, 0x00, // <-- channel

  /**
   * This is the second set of flags, specifically related to transmissions. The
   * bit we've set is IEEE80211_RADIOTAP_F_TX_NOACK, which means the card won't
   * wait for an ACK for this frame, and that it won't retry if it doesn't get
   * one.
   */
  /*0x08, 0x00,*/
  0x00, 0x00,
};

/**
 * After an 802.11 MAC-layer header, a logical link control (LLC) header should
 * be placed to tell the receiver what kind of data will follow (see IEEE 802.2
 * for more information).
 *
 * For political reasons, IP wasn't allocated a global so-called SAP number,
 * which means that a simple LLC header is not enough to indicate that an IP
 * frame was sent. 802.2 does, however, allow EtherType types (the same kind of
 * type numbers used in, you guessed it, Ethernet) through the use of the
 * "Subnetwork Access Protocol", or SNAP. To use SNAP, the three bytes in the
 * LLC have to be set to the magical numbers 0xAA 0xAA 0x03. The next five bytes
 * are then interpreted as a SNAP header. To specify an EtherType, we need to
 * set the first three of them to 0. The last two bytes can then finally be set
 * to 0x0800, which is the IP EtherType.
 */
const uint8_t ipllc[8] = { 0xaa, 0xaa, 0x03, 0x00, 0x00, 0x00, 0x08, 0x00 };

/**
 * A simple implementation of the internet checksum used by IP
 * Not very interesting, so it has been moved below main()
 */
uint16_t inet_csum(const void *buf, size_t hdr_len);

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
        pcap_sendpacket(pcap, frame, len);
        printf("result : %d\n", result);
        if(result == -1) {
            printf("Error : %s\n", pcap_geterr(pcap));
        }
        usleep(delay);
    }
 
    pcap_close(pcap);
}

int main(){
    size_t sz;
    uint8_t *rt; /* radiotap */
    uint8_t *buf;
    struct ieee80211_hdr *hdr;
    uint8_t fcchunk[2]; /* 802.11 header frame control */

    sz = sizeof(u8aRadiotapHeader) + sizeof(struct ieee80211_hdr) + 4; /* FCS*/
    buf = (uint8_t *) malloc(sz);

    /* Put our pointers in the right place */
    /* Strutcture
    ____________________________________________________________
     rt                       hdr          
    buf .                      |                         |
     |                         |                         |
     | .. u8aRadiotapHeader .. |   .. ieee80211_hdr   .. |
     ____________________________________________________________
    */
    rt = (uint8_t *) buf;
    memcpy(rt, u8aRadiotapHeader, sizeof(u8aRadiotapHeader));

    hdr = (struct ieee80211_hdr *) (rt+sizeof(u8aRadiotapHeader));
    /* Building the MAC header */
    fcchunk[0] = ((WLAN_FC_TYPE_DATA << 2) | (WLAN_FC_SUBTYPE_DATA << 4));
    fcchunk[1] = 0x02;
    memcpy(&hdr->frame_control, &fcchunk[0], 2*sizeof(uint8_t));

    hdr->duration_id = 0xffff;
    memcpy(&hdr->addr1[0], mac_mac, 6*sizeof(uint8_t));
    memcpy(&hdr->addr2[0], mac_mac, 6*sizeof(uint8_t));
    memcpy(&hdr->addr3[0], mac_chip, 6*sizeof(uint8_t));
    hdr->seq_ctrl = 0;

    inject("wlan0", 2, buf ,sz,  50);
    printf("Done\n");
    exit(0);
}