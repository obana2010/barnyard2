#ifndef __SPO_ALERT_CU_H__
#define __SPO_ALERT_CU_H__

#ifdef __cplusplus
extern "C" {
#endif

#include <pcap.h>
#include "unified2.h"
#include "util.h"

#define KYOTOTYCOON_DEFAULT_PORT "1978"
#define CONF_KTPORT              "ktport"
#define CONF_YAMLCONFFILE        "conffile"

#define IP_ADDRESS_STRING_MAX    20
#define PORT_STRING_MAX          6

typedef struct _SpoAlertCuData
{
    FILE *file;
    uint8_t flags;

    int architecture; // アーキテクチャ 今は2固定
    int timeSlotSize; // タイムスロットの秒数
    int localAlertTimeSlotSize; // ローカル閾値チェックの頻度 タイムスロット数
    int localAlertThreshold; // ローカルアラートでの閾値
    int globalAlertTimeSlotSize; // localAlertTimeSlotSizeと同じとする
    int globalAlertThreshold; // ローカルアラートでの閾値
    int globalAlertGenerationSlot; // グローバルアラート

    int blacklistLastTimeSlotSize; // ブラックリストの有効期限

    int fakeData; // Snortを使うか／unified2のデータをツールで作るか

    int icktport; // CU KyotoTycoonの待受ポート

    char cktip[IP_ADDRESS_STRING_MAX]; // CU KyotoTycoonのIP
    char cktport[PORT_STRING_MAX]; // CU KyotoTycoonの待受ポート

    void *conf; // いろんな設定？
    void *confcpp; // Cでコンパイルできない設定

    int isBatchMode; // バッチモードかどうか
    unsigned long current_timeslot; // 現在のtimeslot

} SpoAlertCuData;

#define IP_OPTMAX               40
#define IP6_EXTMAX              40
#define TCP_OPTLENMAX           40 /* (((2^4) - 1) * 4  - TCP_HEADER_LEN) */

// CPPでコンパイルできる構造体
// コンパイルできないものを削除している。必要な項目を詰め替える必要がある。
typedef struct _PacketCpp
{
    struct pcap_pkthdr *pkth;   /* BPF data */
    const uint8_t *pkt;         /* base pointer to the raw packet data */
#if 0
    EtherARP *ah;
    const EtherHdr *eh;         /* standard TCP/IP/Ethernet/ARP headers */
    const VlanTagHdr *vh;
    EthLlc *ehllc;
    EthLlcOther *ehllcother;
    const GREHdr *greh;
    uint32_t *mpls;

    const IPHdr *iph, *orig_iph;/* and orig. headers for ICMP_*_UNREACH family */
    const IPHdr *inner_iph;     /* if IP-in-IP, this will be the inner IP header */
    const IPHdr *outer_iph;     /* if IP-in-IP, this will be the outer IP header */
    const TCPHdr *tcph, *orig_tcph;
    const UDPHdr *udph, *orig_udph;
    const ICMPHdr *icmph, *orig_icmph;
#endif
    const uint8_t *data;        /* packet payload pointer */
    const uint8_t *ip_data;     /* IP payload pointer */
    const uint8_t *outer_ip_data;  /* Outer IP payload pointer */
    const uint8_t *ip_frag_start;
    const uint8_t *ip_options_data;
    const uint8_t *tcp_options_data;

    void *ssnptr;               /* for tcp session tracking info... */
    void *fragtracker;          /* for ip fragmentation tracking info... */
    void *flow;                 /* for flow info */
    void *streamptr;            /* for tcp pkt dump */
#if 0
    IP4Hdr *ip4h, *orig_ip4h;   /* SUP_IP6 members */
    IP6Hdr *ip6h, *orig_ip6h;
    ICMP6Hdr *icmp6h, *orig_icmp6h;

    IPH_API* iph_api;
    IPH_API* orig_iph_api;
    IPH_API* outer_iph_api;
    IPH_API* outer_orig_iph_api;

    IP4Hdr inner_ip4h, inner_orig_ip4h;
    IP6Hdr inner_ip6h, inner_orig_ip6h;
    IP4Hdr outer_ip4h, outer_orig_ip4h;
    IP6Hdr outer_ip6h, outer_orig_ip6h;

    MplsHdr   mplsHdr;
#endif
    int family;
    int orig_family;
    int outer_family;
    int bytes_to_inspect;       /* Number of bytes to check against rules */
                                /* this is not set - always 0 (inspect all) */

    uint32_t preprocessor_bits; /* flags for preprocessors to check */
    uint32_t preproc_reassembly_pkt_bits;

    /* int ip_payload_len; */   /* Replacement for IP_LEN(p->iph->ip_len) << 2 */
    /* int ip_payload_off; */   /* IP_LEN(p->iph->ip_len) << 2 + p->data */

    uint32_t caplen;
    uint32_t http_pipeline_count; /* Counter for HTTP pipelined requests */
    uint32_t packet_flags;      /* special flags for the packet */
    uint32_t proto_bits;

    uint16_t dsize;             /* packet payload size */
    uint16_t ip_dsize;          /* IP payload size */
    uint16_t alt_dsize;         /* the dsize of a packet before munging (used for log)*/
    uint16_t actual_ip_len;     /* for logging truncated pkts (usually by small snaplen)*/
    uint16_t outer_ip_dsize;    /* Outer IP payload size */

    uint16_t frag_offset;       /* fragment offset number */
    uint16_t ip_frag_len;
    uint16_t ip_options_len;
    uint16_t tcp_options_len;

    uint16_t sp;                /* source port (TCP/UDP) */
    uint16_t dp;                /* dest port (TCP/UDP) */
    uint16_t orig_sp;           /* source port (TCP/UDP) of original datagram */
    uint16_t orig_dp;           /* dest port (TCP/UDP) of original datagram */

    int16_t application_protocol_ordinal;

    uint8_t frag_flag;          /* flag to indicate a fragmented packet */
    uint8_t mf;                 /* more fragments flag */
    uint8_t df;                 /* don't fragment flag */
    uint8_t rf;                 /* IP reserved bit */

    uint8_t uri_count;          /* number of URIs in this packet */
    uint8_t csum_flags;         /* checksum flags */
    uint8_t encapsulated;

    uint8_t ip_option_count;    /* number of options in this packet */
    uint8_t tcp_option_count;
    uint8_t ip6_extension_count;
    uint8_t ip6_frag_index;

    uint8_t ip_lastopt_bad;     /* flag to indicate that option decoding was
                                   halted due to a bad option */
    uint8_t tcp_lastopt_bad;    /* flag to indicate that option decoding was
                                   halted due to a bad option */
#if 0
#ifndef NO_NON_ETHER_DECODER
    const Fddi_hdr *fddihdr;    /* FDDI support headers */
    Fddi_llc_saps *fddisaps;
    Fddi_llc_sna *fddisna;
    Fddi_llc_iparp *fddiiparp;
    Fddi_llc_other *fddiother;

    const Trh_hdr *trh;         /* Token Ring support headers */
    Trh_llc *trhllc;
    Trh_mr *trhmr;

    Pflog1Hdr *pf1h;            /* OpenBSD pflog interface header - version 1 */
    Pflog2Hdr *pf2h;            /* OpenBSD pflog interface header - version 2 */
    Pflog3Hdr *pf3h;            /* OpenBSD pflog interface header - version 3 */

    const SLLHdr *sllh;         /* Linux cooked sockets header */
    const WifiHdr *wifih;       /* wireless LAN header */
    const PPPoEHdr *pppoeh;     /* Encapsulated PPP of Ether header */

    const EtherEapol *eplh;     /* 802.1x EAPOL header */
    const EAPHdr *eaph;
    const uint8_t *eaptype;
    EapolKey *eapolk;
#endif

    // nothing after this point is zeroed ...
    Options ip_options[IP_OPTMAX];         /* ip options decode structure */
    Options tcp_options[TCP_OPTLENMAX];    /* tcp options decode struct */
    IP6Option ip6_extensions[IP6_EXTMAX];  /* IPv6 Extension References */
#endif
    /**policyId provided in configuration file. Used for correlating configuration
     * with event output
     */
    uint16_t configPolicyId;

    int         linktype;       /* packet specific linktype */
} PacketCpp;

/* YAMLを読み込む */
void getConfFile(const char *conffile, SpoAlertCuData *ctx);

// functions called by C
void AlertCuSetup(void);
void AlertCuInitCpp(SpoAlertCuData *data);
void AlertCuProcess(PacketCpp *p, Unified2EventCommon *event, char *ip_src_str, int port_src, char *ip_dst_str, int port_dst, SpoAlertCuData *ctx);
void AlertCuCleanExitFunc(int signal, void *arg);
void AlertCuCleanExitFuncCpp(int signal, SpoAlertCuData *ctx);

#ifdef __cplusplus
}
#endif

#endif  /* __SPO_ALERT_CU_H__ */

