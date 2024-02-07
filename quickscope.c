#define _GNU_SOURCE
#include <netlink/netlink.h>
#include <netlink/genl/genl.h>
#include <netlink/genl/ctrl.h>
#include <net/if.h>
#include <linux/nl80211.h>
#include <stdio.h>
#include <stdio.h>
#include <pcap.h>
#include <stdlib.h>
#include <time.h>
#include <string.h>
#include <unistd.h>

#define le_to_host16  le16toh
#define le_to_host32  le32toh
#define TWO_START 2412
#define FIVE_START 5160

#define FILTER "wlan type mgt and subtype beacon"

struct ieee80211_radiotap_hdr {
  uint8_t it_version;
  uint8_t it_pad;
  uint16_t it_len;
  uint32_t it_present;
} __attribute__ ((packed));

struct ieee80211_mgmt {
  uint16_t frame_control;
  uint16_t duration;
  uint8_t ra[6];
  uint8_t ta[6];
  uint8_t bssid[6];
  uint16_t seq_ctrl;
  uint8_t junk[12];
};


static int error_handler(struct sockaddr_nl *nla, struct nlmsgerr *err, void *arg) {
  fprintf(stderr, "%s %d\n", strerror(-1 * err->error), -1 * err->error);
  return NL_STOP;
}

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

int set_channel(int channel, char* interface) {
    uint32_t freq = 0;
    if (channel >= 32) { 
        // wlan1 -> 5ghz
        freq = ((channel - 32) * 5) + FIVE_START;
    } else {
        freq = ((channel - 1) * 5) + TWO_START;
    }
    int err = 1;
    int rc;
    // socket + connect
    struct nl_sock* sk = nl_socket_alloc();
    genl_connect(sk);

    // message to set wifi
    struct nl_msg *mesg = nlmsg_alloc();
    enum nl80211_commands command = NL80211_CMD_SET_WIPHY;
    genlmsg_put(mesg, 0, 0, genl_ctrl_resolve(sk, "nl80211"), 0, 0, command, 0);

    
    int idx = if_nametoindex(interface);
    if (idx > 0) {
        fprintf(stderr, "Setting %s to channel %d (%d)\n", interface, channel, freq);
        struct nl_cb *cb = nl_cb_alloc(NL_CB_DEFAULT);
        NLA_PUT_U32(mesg, NL80211_ATTR_IFINDEX, idx);
        NLA_PUT_U32(mesg, NL80211_ATTR_WIPHY_FREQ, freq);
        NLA_PUT_U32(mesg, NL80211_ATTR_CHANNEL_WIDTH, NL80211_CHAN_WIDTH_20);
        nl_cb_err(cb, NL_CB_CUSTOM, error_handler, &err);
        rc = nl_send_auto_complete(sk, mesg);
        nl_recvmsgs(sk, cb);
        nl_cb_put(cb);
        nlmsg_free(mesg);
        nl_socket_free(sk);
        return (err >= 0);
    } else {
        fprintf(stderr, "Invalid wifi card %s\n", interface);
        return 2;
    }
    nla_put_failure:
        nlmsg_free(mesg);
        return 3;
}


int main(int argc, char** argv) {
    fprintf(stderr, "0x1a0 WiFi Scanner v0.1\n");
    if (argc != 2) {
        printf("Usage: %s <interface>\n", argv[0]);
        return 1;
    }
    int five_ghz = strncmp("wlan1", argv[1], 5);
    
    
    char errbuf[PCAP_ERRBUF_SIZE];
    pcap_t *iface = pcap_open_live(argv[1], 5000, 1, 20, errbuf);
    struct bpf_program fp;
    if (iface == NULL) {
        printf("pcap_open_live(): %s\n",errbuf);
        exit(1);
    }
    
    if (pcap_compile(iface, &fp, FILTER, 1, PCAP_NETMASK_UNKNOWN) == -1) {
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
    
    if (pcap_set_buffer_size(iface, 8192) == -1) {
        fprintf(stderr,"Error setting buffer!\n"); 
        exit(1); 
    }
    
    int fd = pcap_fileno(iface);
    int sndbuf = 0;
    socklen_t optlen;
    if (getsockopt(fd, SOL_SOCKET, SO_SNDBUF, &sndbuf, &optlen) == -1) {
        fprintf(stderr,"Error getting send buffer!\n"); 
        exit(1); 
    }
    fprintf(stderr, "modifying fd:%d, cbuf:%d\n", fd, sndbuf);
    sndbuf = 180224;
    if (setsockopt(fd, SOL_SOCKET, SO_SNDBUF, &sndbuf, sizeof(sndbuf)) == -1) {
        fprintf(stderr,"Error setting send buffer!\n"); 
        exit(1); 
    }
    
    if (getsockopt(fd, SOL_SOCKET, SO_SNDBUF, &sndbuf, &optlen) == -1) {
        fprintf(stderr,"Error getting send buffer!\n"); 
        exit(1); 
    }
    fprintf(stderr, "sendfd:%d, cbuf:%d\n", fd, sndbuf);
    
    if (pcap_datalink(iface) != DLT_IEEE802_11_RADIO) { 
        fprintf(stderr, "Not a RADIOTAP!\n");
        exit(1);
    }
    
    struct pcap_pkthdr hdr;
    uint16_t ctr = 0;
    uint8_t seen = 0;
    uint8_t macs[256][6] = {0};
    uint8_t channel = 0;
    uint8_t two_channel[] = {1, 6, 11, 2, 3, 4, 5, 7, 8, 9, 10, 12, 13};
    uint8_t five_channel[] = {36, 40, 44, 48, 52, 56, 60, 64, 100, 104, 
                             108, 112, 116, 132, 136, 140, 144, 149,
                             153, 157, 161, 165};
    time_t seconds = 0;
    while (1) {
        /** CHANNEL HOPPING **/
        if ((time(NULL) - seconds) > 1) {
            if (five_ghz == 0) {
                set_channel(five_channel[channel], argv[1]);
                channel++;
                if (channel >= (sizeof(five_channel) / sizeof(five_channel[0]))) {
                    break;
                }
            } else {
                set_channel(two_channel[channel], argv[1]);
                channel++;
                if (channel >= (sizeof(two_channel) / sizeof(two_channel[0]))) {
                    break;
                }
            }
            seconds = time(NULL);
        }
        /** SCANNING **/
        struct ieee80211_radiotap_hdr *rtap;
        struct ieee80211_mgmt *mlme;
        uint16_t fc, type, subtype;

        const unsigned char *packet = pcap_next(iface, &hdr);
        if (packet != NULL) {
            rtap = (struct ieee80211_radiotap_hdr *)packet;
            mlme = (struct ieee80211_mgmt *)(packet + le_to_host16(rtap->it_len));

            uint16_t rt_freq = (uint16_t) packet[26] | (uint16_t) packet[27]<<8;
            if (rt_freq >= FIVE_START) {
                rt_freq = 32 + ((rt_freq - FIVE_START) / 5);
            } else {
                rt_freq = 1 + ((rt_freq - TWO_START) / 5);
            }

            fc = le_to_host16(mlme->frame_control);
            type = (fc >> 2) & 0x0003;
            subtype = (fc >> 4) & 0x000f;
            if (type == 0 && subtype == 8) {
                int seen_bssid = 0;
                char mac[18];
                snprintf(mac, 18, "%02x:%02x:%02x:%02x:%02x:%02x", mlme->bssid[0], mlme->bssid[1], mlme->bssid[2], mlme->bssid[3], mlme->bssid[4], mlme->bssid[5]);
                for (uint8_t i=0; i<seen; i++) {
                    if (mlme->bssid[0] == macs[i][0] &&
                        mlme->bssid[1] == macs[i][1] &&
                        mlme->bssid[2] == macs[i][2] &&
                        mlme->bssid[3] == macs[i][3] &&
                        mlme->bssid[4] == macs[i][4] &&
                        mlme->bssid[5] == macs[i][5]) {
                            seen_bssid = 1;
                        }
                }
                if (seen_bssid == 0) {
                    // start of tags
                    uint16_t offset = le_to_host16(rtap->it_len) + sizeof(struct ieee80211_mgmt);

                    // packet bigger than our caplen
                    if (offset > hdr.caplen) {
                        continue;
                    }

                    char ssid[64];
                    memset(ssid, 0, 64);
                    while (offset < hdr.caplen) { 
                        uint8_t tag_id = *(packet + offset++);
                        uint8_t tag_len = *(packet + offset++);
                        if (tag_id == 0) { // ESSID
                            memcpy(ssid, packet + offset, tag_len);
                        }
                        if (tag_id == 3) { // Channel
                            rt_freq = *(packet + offset);
                        }
                        offset += tag_len;
                    }
                    printf("{\"essid\":\"%s\", \"bssid\":\"%s\", \"channel\":%d}\n", ssid, mac, rt_freq);
                    fflush(stdout);
                    // mark as seen
                    macs[seen][0] = mlme->bssid[0];
                    macs[seen][1] = mlme->bssid[1];
                    macs[seen][2] = mlme->bssid[2];
                    macs[seen][3] = mlme->bssid[3];
                    macs[seen][4] = mlme->bssid[4];
                    macs[seen][5] = mlme->bssid[5];
                    seen++;
                }
            }
        }
        usleep(100);
    }
    return 0;
}
