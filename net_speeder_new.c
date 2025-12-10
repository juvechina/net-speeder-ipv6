#include <pcap.h>
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <ctype.h>
#include <errno.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <libnet.h>
#include <netinet/ip6.h>
#include <unistd.h>

/* default snap length (maximum bytes per packet to capture) */
#define SNAP_LEN 65535

#ifdef COOKED
    #define ETHERNET_H_LEN 16
#else
    #define ETHERNET_H_LEN 14
#endif

#define SPECIAL_TTL 88
#define SPECIAL_HOP_LIMIT 88
#define DEFAULT_MULTIPLIER 1

/* IPV6_HDRINCL 在某些旧系统上可能未定义 */
#ifndef IPV6_HDRINCL
#define IPV6_HDRINCL 36
#endif

/* 确保 TCP 标志位定义存在 */
#ifndef TH_FIN
#define TH_FIN    0x01
#endif
#ifndef TH_SYN
#define TH_SYN    0x02
#endif
#ifndef TH_RST
#define TH_RST    0x04
#endif
#ifndef TH_PUSH
#define TH_PUSH   0x08
#endif
#ifndef TH_ACK
#define TH_ACK    0x10
#endif
#ifndef TH_URG
#define TH_URG    0x20
#endif

typedef struct {
    libnet_t *libnet_handler;
    int raw_sock_v6;
    int multiplier;  /* 发包倍数 */
} handler_context;

void got_packet(u_char *args, const struct pcap_pkthdr *header, const u_char *packet);
void print_usage(void);

pcap_t *net_speeder_pcap_open_live(const char *device, int snaplen, int promisc, int to_ms, char *errbuf)
{
    pcap_t *p;
    int status;

    p = pcap_create(device, errbuf);
    if (p == NULL)
        return (NULL);
    status = pcap_set_snaplen(p, snaplen);
    if (status < 0)
        goto fail;
    status = pcap_set_promisc(p, promisc);
    if (status < 0)
        goto fail;
    status = pcap_set_timeout(p, to_ms);
    if (status < 0)
        goto fail;
    status = pcap_set_immediate_mode(p, 1);
    if (status < 0)
        goto fail;
    
    status = pcap_activate(p);
    if (status < 0)
        goto fail;
    return (p);
fail:
    if (status == PCAP_ERROR)
        snprintf(errbuf, PCAP_ERRBUF_SIZE, "%s: %.*s", device,
            PCAP_ERRBUF_SIZE - 3, pcap_geterr(p));
    else if (status == PCAP_ERROR_NO_SUCH_DEVICE ||
        status == PCAP_ERROR_PERM_DENIED ||
        status == PCAP_ERROR_PROMISC_PERM_DENIED)
        snprintf(errbuf, PCAP_ERRBUF_SIZE, "%s: %s (%.*s)", device,
            pcap_statustostr(status), PCAP_ERRBUF_SIZE - 6, pcap_geterr(p));
    else
        snprintf(errbuf, PCAP_ERRBUF_SIZE, "%s: %s", device,
            pcap_statustostr(status));
    pcap_close(p);
    return (NULL);
}

/*
 * print help text
 */
void print_usage(void) {
    printf("Usage: %s [interface] [\"filter rule\"] [multiplier]\n", "net_speeder");
    printf("\n");
    printf("Options:\n");
    printf("    interface    Listen on <interface> for packets.\n");
    printf("    filter       Rules to filter packets (e.g., \"ip\", \"tcp port 80\").\n");
    printf("    multiplier   Number of times to send each packet (default: 1).\n");
    printf("\n");
    printf("Examples:\n");
    printf("    ./net_speeder eth0 \"ip\" 2\n");
    printf("    ./net_speeder eth0 \"ip6\" 2\n");
    printf("    ./net_speeder eth0 \"tcp src port 80\" 2 (Best for CDN Outbound)\n");
    printf("\n");
}

/* Calculate IPv6 pseudo-header checksum */
uint16_t calculate_ipv6_checksum(struct ip6_hdr *ip6, uint8_t protocol, void *payload, uint16_t payload_len)
{
    uint32_t sum = 0;
    uint16_t *ptr;
    int i;

    /* IPv6 pseudo-header: source address (16 bytes) */
    ptr = (uint16_t *)&ip6->ip6_src;
    for (i = 0; i < 8; i++) {
        sum += ntohs(ptr[i]);
    }

    /* IPv6 pseudo-header: destination address (16 bytes) */
    ptr = (uint16_t *)&ip6->ip6_dst;
    for (i = 0; i < 8; i++) {
        sum += ntohs(ptr[i]);
    }

    /* IPv6 pseudo-header: upper-layer packet length */
    sum += payload_len;

    /* IPv6 pseudo-header: next header (protocol) */
    sum += protocol;

    /* Add payload data */
    ptr = (uint16_t *)payload;
    for (i = 0; i < payload_len / 2; i++) {
        sum += ntohs(ptr[i]);
    }

    /* Handle odd byte */
    if (payload_len & 1) {
        sum += (((uint8_t *)payload)[payload_len - 1]) << 8;
    }

    /* Fold 32-bit sum to 16 bits */
    while (sum >> 16) {
        sum = (sum & 0xFFFF) + (sum >> 16);
    }

    return (uint16_t)~sum;
}

void handle_ipv4_packet(handler_context *ctx, const struct pcap_pkthdr *header, const u_char *packet) {
    struct libnet_ipv4_hdr *ip;
    int i;
    int ip_hl_bytes;
    int tcp_hl_bytes;
    int payload_len;
    
    ip = (struct libnet_ipv4_hdr*)(packet + ETHERNET_H_LEN);

    /* 防止处理自己发出的特殊TTL包，避免死循环 */
    if(ip->ip_ttl == SPECIAL_TTL) return;

    ip_hl_bytes = ip->ip_hl * 4;

    if(ip->ip_p == IPPROTO_TCP) {
        struct libnet_tcp_hdr *tcp = (struct libnet_tcp_hdr *)((u_int8_t *)ip + ip_hl_bytes);
        tcp_hl_bytes = tcp->th_off * 4;
        payload_len = ntohs(ip->ip_len) - ip_hl_bytes - tcp_hl_bytes;

        /* * [优化修复] 
         * 1. 过滤 SYN/FIN/RST：防止破坏建联和断连状态，解决建联失败问题。
         * 2. 过滤 Payload <= 0：防止复制纯ACK包，解决带宽拥塞导致的 502/504。
         */
        if ((tcp->th_flags & (TH_SYN | TH_FIN | TH_RST)) || payload_len <= 0) {
            return;
        }

        ip->ip_ttl = SPECIAL_TTL;
        ip->ip_sum = 0;
        tcp->th_sum = 0;
        libnet_do_checksum(ctx->libnet_handler, (u_int8_t *)ip, IPPROTO_TCP, ntohs(ip->ip_len) - ip_hl_bytes);

    } else if(ip->ip_p == IPPROTO_UDP) {
        struct libnet_udp_hdr *udp = (struct libnet_udp_hdr *)((u_int8_t *)ip + ip_hl_bytes);
        
        /* 简单过滤 UDP 长度为 0 的包 */
        payload_len = ntohs(ip->ip_len) - ip_hl_bytes - 8; // 8 is UDP header len
        if (payload_len <= 0) return;

        ip->ip_ttl = SPECIAL_TTL;
        ip->ip_sum = 0;
        udp->uh_sum = 0;
        libnet_do_checksum(ctx->libnet_handler, (u_int8_t *)ip, IPPROTO_UDP, ntohs(ip->ip_len) - ip_hl_bytes);
    } else {
        return; 
    }
    
    /* 根据倍数发送多次 */
    for(i = 0; i < ctx->multiplier; i++) {
        int len_written = libnet_adv_write_raw_ipv4(ctx->libnet_handler, (u_int8_t *)ip, ntohs(ip->ip_len));
        if(len_written < 0) {
            // 在高并发下 printf 可能会严重拖慢速度，建议生产环境注释掉错误打印
            // printf("IPv4 write error: %s\n", libnet_geterror(ctx->libnet_handler));
            break; 
        }
    }
}

void handle_ipv6_packet(handler_context *ctx, const struct pcap_pkthdr *header, const u_char *packet) {
    struct ip6_hdr *ip6;
    struct sockaddr_in6 dst_addr;
    uint16_t total_payload_len; // IPv6 payload length (includes extension headers + L4 header + data)
    uint8_t next_header;
    void *payload;
    int total_len;
    int i;
    int tcp_data_len;
    
    ip6 = (struct ip6_hdr*)(packet + ETHERNET_H_LEN);

    if(ip6->ip6_hlim == SPECIAL_HOP_LIMIT) return;
    
    total_payload_len = ntohs(ip6->ip6_plen);
    next_header = ip6->ip6_nxt;
    payload = (u_int8_t *)ip6 + sizeof(struct ip6_hdr);
    
    if(next_header == IPPROTO_TCP) {
        struct libnet_tcp_hdr *tcp = (struct libnet_tcp_hdr *)payload;
        int tcp_hl_bytes = tcp->th_off * 4;

        /* 计算 TCP 实际数据长度 */
        tcp_data_len = total_payload_len - tcp_hl_bytes;

        /* [优化修复] 过滤 SYN/FIN/RST 和 纯ACK */
        if ((tcp->th_flags & (TH_SYN | TH_FIN | TH_RST)) || tcp_data_len <= 0) {
            return;
        }

        ip6->ip6_hlim = SPECIAL_HOP_LIMIT;
        tcp->th_sum = 0;
        tcp->th_sum = htons(calculate_ipv6_checksum(ip6, IPPROTO_TCP, payload, total_payload_len));

    } else if(next_header == IPPROTO_UDP) {
        struct libnet_udp_hdr *udp = (struct libnet_udp_hdr *)payload;
        int udp_data_len = total_payload_len - 8; // 8 bytes UDP header
        
        if (udp_data_len <= 0) return;

        ip6->ip6_hlim = SPECIAL_HOP_LIMIT;
        udp->uh_sum = 0;
        udp->uh_sum = htons(calculate_ipv6_checksum(ip6, IPPROTO_UDP, payload, total_payload_len));
    } else {
        return;
    }
    
    total_len = sizeof(struct ip6_hdr) + total_payload_len;
    
    /* Setup destination address */
    memset(&dst_addr, 0, sizeof(dst_addr));
    dst_addr.sin6_family = AF_INET6;
    memcpy(&dst_addr.sin6_addr, &ip6->ip6_dst, sizeof(struct in6_addr));
    
    /* 根据倍数发送多次 */
    for(i = 0; i < ctx->multiplier; i++) {
        int len_written = sendto(ctx->raw_sock_v6, ip6, total_len, 0,
                                 (struct sockaddr *)&dst_addr, sizeof(dst_addr));
        
        if(len_written < 0) {
            break; 
        }
    }
}

void got_packet(u_char *args, const struct pcap_pkthdr *header, const u_char *packet) {
    handler_context *ctx;
    const u_char *ip_packet;
    uint8_t version;
    
    ctx = (handler_context *)args;
    
    /* Determine IP version by examining the first nibble */
    ip_packet = packet + ETHERNET_H_LEN;
    version = (ip_packet[0] >> 4) & 0x0F;
    
    if(version == 4) {
        handle_ipv4_packet(ctx, header, packet);
    } else if(version == 6) {
        handle_ipv6_packet(ctx, header, packet);
    }
    
    return;
}

libnet_t* start_libnet(char *dev) {
    char errbuf[LIBNET_ERRBUF_SIZE];
    libnet_t *libnet_handler = libnet_init(LIBNET_RAW4_ADV, dev, errbuf);

    if(NULL == libnet_handler) {
        printf("libnet_init: error %s\n", errbuf);
    }
    return libnet_handler;
}

int create_raw_socket_v6() {
    int sock;
    int on = 1;
    
    sock = socket(AF_INET6, SOCK_RAW, IPPROTO_RAW);
    if(sock < 0) {
        printf("create raw socket v6 failed: %s\n", strerror(errno));
        return -1;
    }
    
    /* Enable manual header inclusion */
    if(setsockopt(sock, IPPROTO_IPV6, IPV6_HDRINCL, &on, sizeof(on)) < 0) {
        printf("setsockopt IPV6_HDRINCL failed: %s\n", strerror(errno));
        close(sock);
        return -1;
    }
    
    return sock;
}

int main(int argc, char **argv) {
    char *dev = NULL;
    char errbuf[PCAP_ERRBUF_SIZE];
    pcap_t *handle;

    char *filter_rule = NULL;
    struct bpf_program fp;
    bpf_u_int32 net, mask;
    
    handler_context ctx;
    ctx.multiplier = DEFAULT_MULTIPLIER;

    /* 支持 2 个或 3 个参数 */
    if (argc >= 3 && argc <= 4) {
        dev = argv[1];
        filter_rule = argv[2];
        
        /* 如果提供了第三个参数，解析为倍数 */
        if (argc == 4) {
            ctx.multiplier = atoi(argv[3]);
            if (ctx.multiplier < 1 || ctx.multiplier > 100) {
                printf("Error: multiplier must be between 1 and 100\n");
                print_usage();
                return -1;
            }
        }
        
        printf("Device: %s\n", dev);
        printf("Filter rule: %s\n", filter_rule);
        printf("Packet multiplier: %dx\n", ctx.multiplier);
        printf("Mode: Safe (SYN/FIN/RST/Pure-ACK filtered)\n");
    } else {
        print_usage();  
        return -1;
    }
    
    printf("ethernet header len:[%d](14:normal, 16:cooked)\n", ETHERNET_H_LEN);

    if (pcap_lookupnet(dev, &net, &mask, errbuf) == -1) {
        printf("Couldn't get netmask for device %s: %s\n", dev, errbuf);
        net = 0;
        mask = 0;
    }

    printf("init pcap\n");
    
    handle = net_speeder_pcap_open_live(dev, SNAP_LEN, 1, 0, errbuf);
    if(handle == NULL) {
        printf("net_speeder_pcap_open_live dev:[%s] err:[%s]\n", dev, errbuf);
        printf("init pcap failed\n");
        return -1;
    }

    printf("init libnet for IPv4\n");
    ctx.libnet_handler = start_libnet(dev);
    if(NULL == ctx.libnet_handler) {
        printf("init libnet failed\n");
        return -1;
    }
    
    printf("init raw socket for IPv6\n");
    ctx.raw_sock_v6 = create_raw_socket_v6();
    if(ctx.raw_sock_v6 < 0) {
        printf("init raw socket v6 failed\n");
        return -1;
    }

    if (pcap_compile(handle, &fp, filter_rule, 0, net) == -1) {
        printf("filter rule err:[%s][%s]\n", filter_rule, pcap_geterr(handle));
        return -1;
    }

    if (pcap_setfilter(handle, &fp) == -1) {
        printf("set filter failed:[%s][%s]\n", filter_rule, pcap_geterr(handle));
        return -1;
    }

    printf("Started capturing packets...\n");
    
    while(1) {
        pcap_loop(handle, 1, got_packet, (u_char *)&ctx);
    }

    /* cleanup */
    pcap_freecode(&fp);
    pcap_close(handle);
    libnet_destroy(ctx.libnet_handler);
    close(ctx.raw_sock_v6);
    return 0;
}
