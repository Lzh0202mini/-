#define _WINSOCK_DEPRECATED_NO_WARNINGS
#define _CRT_SECURE_NO_WARNINGS
#define WIN32
#include <winsock2.h>
#include <windows.h>
#include <pcap.h>
#include <stdio.h>
#pragma comment(lib, "wpcap.lib")
#pragma comment(lib, "Packet.lib")
#pragma comment(lib, "ws2_32.lib")

// 以太网头部 14字节
typedef struct ether_header
{
    u_char ether_dhost[6]; // 目标MAC
    u_char ether_shost[6]; // 源MAC
    u_short ether_type;    // 上层协议 0x0800=IPv4
}ether_header;

// IPv4头部
typedef struct ip_header
{
    u_char  ip_verlen;     // 版本+头长度
    u_char  ip_tos;        // 服务类型
    u_short ip_len;        // 总长度
    u_short ip_id;         // 标识
    u_short ip_off;        // 分片偏移
    u_char  ip_ttl;        // TTL
    u_char  ip_proto;      // 协议 6=TCP 17=UDP 1=ICMP
    u_short ip_sum;        // 校验和
    struct in_addr ip_src; // 源IP
    struct in_addr ip_dst; // 目的IP
}ip_header;

// TCP头部
typedef struct tcp_header
{
    u_short th_sport; // 源端口
    u_short th_dport; // 目的端口
    u_int th_seq;     // 序列号
    u_int th_ack;     // 确认号
    u_char th_offx2;  // 数据偏移
    u_char th_flags;  // 标志位 SYN/ACK/FIN/RST
    u_short th_win;   // 窗口大小
    u_short th_sum;   // 校验和
    u_short th_urp;   // 紧急指针
}tcp_header;

// MAC打印工具函数
void print_mac(u_char* mac)
{
    printf("%02x:%02x:%02x:%02x:%02x:%02x",
        mac[0], mac[1], mac[2], mac[3], mac[4], mac[5]);
}

// 数据包解析回调
void packet_handler(u_char* user, const struct pcap_pkthdr* hdr, const u_char* pkt)
{
    struct ether_header* eth = (struct ether_header*)pkt;
    printf("===== 捕获数据包 总长度:%d =====\n", hdr->len);

    // 1.打印以太网头部
    printf("【以太网帧】\n");
    printf("源MAC: "); print_mac(eth->ether_shost);
    printf(" | 目标MAC: "); print_mac(eth->ether_dhost);
    if (ntohs(eth->ether_type) == 0x0800)
        printf(" | 上层协议: IPv4\n");
    else
    {
        printf(" | 非IPv4报文，跳过解析\n\n");
        return;
    }

    // 2.解析IPv4头部
    struct ip_header* ip = (struct ip_header*)(pkt + 14);
    unsigned int ip_head_len = (ip->ip_verlen & 0x0f) * 4; // IP头长度
    printf("【IPv4报文】\n");
    printf("源IP:%s | 目的IP:%s | TTL:%d | 传输层协议:",
        inet_ntoa(ip->ip_src), inet_ntoa(ip->ip_dst), ip->ip_ttl);
    if (ip->ip_proto == 6) printf("TCP\n");
    else if (ip->ip_proto == 17) printf("UDP\n");
    else if (ip->ip_proto == 1) printf("ICMP\n");
    else printf("其他\n");

    // 3.解析TCP报文
    if (ip->ip_proto == 6)
    {
        struct tcp_header* tcp = (struct tcp_header*)(pkt + 14 + ip_head_len);
        printf("【TCP头部】源端口:%d 目的端口:%d\n",
            ntohs(tcp->th_sport), ntohs(tcp->th_dport));
        // 打印标志位
        printf("标志位: ");
        if (tcp->th_flags & 0x02) printf("SYN ");
        if (tcp->th_flags & 0x10) printf("ACK ");
        if (tcp->th_flags & 0x01) printf("FIN ");
        if (tcp->th_flags & 0x04) printf("RST ");
        printf("\n");
    }
    printf("\n");
}

int main()
{
    pcap_if_t* alldevs, * d;
    pcap_t* handle;
    char errbuf[PCAP_ERRBUF_SIZE];
    int i = 0, sel;

    // 枚举网卡
    if (pcap_findalldevs_ex(PCAP_SRC_IF_STRING, NULL, &alldevs, errbuf) == -1)
    {
        printf("网卡枚举失败：%s\n", errbuf);
        return -1;
    }
    // 打印网卡列表
    for (d = alldevs; d; d = d->next)
    {
        printf("%d. %s | %s\n", ++i, d->name, d->description ? d->description : "无描述");
    }
    printf("请输入网卡序号：");
    scanf("%d", &sel);
    // 选中网卡
    d = alldevs;
    for (i = 1; i < sel; i++) d = d->next;
    // 打开网卡
    handle = pcap_open(d->name, 65536, PCAP_OPENFLAG_PROMISCUOUS, 1000, NULL, errbuf);
    if (!handle)
    {
        printf("打开网卡失败：%s\n", errbuf);
        pcap_freealldevs(alldevs);
        return -1;
    }
    pcap_freealldevs(alldevs);
    // BPF过滤：只抓取IPv4 TCP流量
    struct bpf_program fp;
    pcap_compile(handle, &fp, "ip tcp", 0, PCAP_NETMASK_UNKNOWN);
    pcap_setfilter(handle, &fp);
    printf("开始抓包，访问网页即可看到解析结果，Ctrl+C停止\n");
    pcap_loop(handle, 0, packet_handler, NULL);
    pcap_close(handle);
    return 0;
}