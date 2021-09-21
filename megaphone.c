#include <stdio.h>
#include <pcap.h>
#include <stdlib.h>
#include <time.h>
#include <string.h>
#include <unistd.h>

#define le_to_host16  le16toh
#define le_to_host32  le32toh

struct ieee80211_radiotap_hdr {
  uint8_t it_version;
  uint8_t it_pad;
  uint16_t it_len;
  uint32_t it_present;
} __attribute__ ((packed));

struct ieee80211_mgmt {
  uint16_t frame_control;
  uint16_t duration;
  uint8_t da[6];
  uint8_t sa[6];
  uint8_t bssid[6];
  uint16_t seq_ctrl;
  union {
    struct {
      uint16_t cap;
      uint16_t listen;
      uint8_t variable[0];
    } __attribute__ ((packed)) assoc_req;
    struct {
      uint8_t variable[0];
    } __attribute__ ((packed)) probe_req;
    struct {
      uint32_t timestamp1;
      uint32_t timestamp2;
      uint16_t beacon_interval;
      uint16_t capabilities;
      uint8_t variable[0];
    } __attribute__ ((packed)) probe_resp;
    struct {
      uint32_t timestamp1;
      uint32_t timestamp2;
      uint16_t beacon_interval;
      uint16_t capabilities;
      uint8_t variable[0];
    } __attribute__ ((packed)) beacon;
  } u;
} __attribute__ ((packed));


int check_seen(struct ieee80211_mgmt *hdr, unsigned char* packets[], uint8_t packet_len) {
    for (int i=0; i<packet_len; i++) {
        struct ieee80211_radiotap_hdr *rtap = (struct ieee80211_radiotap_hdr *)&packets[i][0];
        struct ieee80211_mgmt *mlme = (struct ieee80211_mgmt *)(&packets[i][0] + le_to_host16(rtap->it_len));
        if (hdr->bssid[0] == mlme->bssid[0] &&
            hdr->bssid[1] == mlme->bssid[1] &&
            hdr->bssid[2] == mlme->bssid[2] &&
            hdr->bssid[3] == mlme->bssid[3] &&
            hdr->bssid[4] == mlme->bssid[4] && 
            hdr->bssid[5] == mlme->bssid[5]) {
            return 0;
        }
    }
    return 1;
}

void update_filter(unsigned char* packets[], uint8_t packet_len, pcap_t *p) {
    char filter[16384];
    uint16_t offset = sprintf(filter, "type mgt subtype beacon");
    for (int i=0; i<packet_len; i++) {
        struct ieee80211_radiotap_hdr *rtap = (struct ieee80211_radiotap_hdr *)&packets[i][0];
        struct ieee80211_mgmt *mlme = (struct ieee80211_mgmt *)(&packets[i][0] + le_to_host16(rtap->it_len));
        offset += snprintf(filter+offset, 16384-offset, " and wlan addr3 not %02x:%02x:%02x:%02x:%02x:%02x",  mlme->bssid[0], mlme->bssid[1], mlme->bssid[2], mlme->bssid[3], mlme->bssid[4], mlme->bssid[5]);
    }
    printf("updating filter to: %s\n", filter);
    struct bpf_program fp;
    if (pcap_compile(p, &fp, filter, 1, PCAP_NETMASK_UNKNOWN) == -1) {
        pcap_perror(p, "error compiling ");
        exit(1);
    }
    if (pcap_setfilter(p, &fp) == -1) {
        fprintf(stderr,"Error setting filter\n"); 
        exit(1); 
    }
}

int main(void) {
    printf("OpenWRT MegaPhone v0.2\n");
    // TOOD check that /proc/sys/net/core/bpf_jit_enable is 0
    char errbuf[PCAP_ERRBUF_SIZE];
    pcap_t *iface = pcap_open_live("wlan1", 5000, 1, 20, errbuf);
    struct bpf_program fp;
    if (iface == NULL) {
        printf("pcap_open_live(): %s\n",errbuf);
        exit(1);
    }
    
    if (pcap_compile(iface, &fp, "type mgt subtype beacon", 1, PCAP_NETMASK_UNKNOWN) == -1) {
        fprintf(stderr,"Error calling pcap_compile\n");
        exit(1);
    }
    if (pcap_setfilter(iface, &fp) == -1) {
        fprintf(stderr,"Error setting filter\n"); 
        exit(1); 
    }
    if (pcap_setnonblock(iface, 1, errbuf) == -1) { 
        fprintf(stderr,"Error setting immediate\n"); 
        exit(1); 
    }
    
    /*if (pcap_set_buffer_size(iface, 8192) == -1) {
        fprintf(stderr,"Error setting buffer!\n"); 
        exit(1); 
    }*/
    if (pcap_datalink(iface) != DLT_IEEE802_11_RADIO) { 
        fprintf(stderr, "Not a RADIOTAP!\n");
        exit(1);
    }


    struct pcap_pkthdr hdr;
    uint16_t ctr = 0;
    uint8_t seen = 0;
    uint8_t *packets[256];
    uint16_t lens[256];
    time_t seconds = time(NULL);

    while (1) {
        struct ieee80211_radiotap_hdr *rtap;
        struct ieee80211_mgmt *mlme;
        uint16_t fc, type, subtype;


        const unsigned char *packet = pcap_next(iface, &hdr);
        if (packet != NULL) {
            rtap = (struct ieee80211_radiotap_hdr *)packet;
            mlme = (struct ieee80211_mgmt *)(packet + le_to_host16(rtap->it_len));

            fc = le_to_host16(mlme->frame_control);
            type = (fc >> 2) & 0x0003;
            subtype = (fc >> 4) & 0x000f;
            char mac[18];
            snprintf(mac, 18, "%02x:%02x:%02x:%02x:%02x:%02x", mlme->bssid[0], mlme->bssid[1], mlme->bssid[2], mlme->bssid[3], mlme->bssid[4], mlme->bssid[5]);
            printf("pkt from bssid:%s with type %d:%d\n", mac, type, subtype);


            if (type == 0 && subtype == 8) {
                if (check_seen(mlme, packets, seen) == 1 && seen < 256) {
                    printf("found a NEW beacon! from %02x:%02x:%02x:%02x:%02x:%02x seen: %d\n", mlme->bssid[0], mlme->bssid[1], mlme->bssid[2], mlme->bssid[3], mlme->bssid[4], mlme->bssid[5], seen);
                    packets[seen] = malloc(hdr.len);
                    lens[seen]= hdr.len;
                    memcpy(&packets[seen][0], packet, hdr.len);
                    packets[seen][25] = 22; // 11Mbps
                    seen++;
                    // update the filter
                    update_filter(packets, seen, iface);
                }
            }
        }

        // replay a bunch of our captured packets :D
        for (int i=0; i<seen; i++) {
            for (int j=0; j<1; j++) {
                if (pcap_sendpacket(iface, &packets[i][0], lens[i]) == 0) {
                        ctr++;
                }
            }
        }
        if ((seconds + 5) < time(NULL)) {
            seconds = time(NULL);
            printf("replayed %d beacons x %d/s\n", seen, ctr/5);
            ctr = 0;
        }
        usleep(100);
    }
}
