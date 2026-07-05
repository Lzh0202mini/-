#define _WINSOCK_DEPRECATED_NO_WARNINGS
#define _CRT_SECURE_NO_WARNINGS
#define WIN32
#include <winsock2.h>
#include <windows.h>
#include <pcap.h>
#include <stdio.h>
#include <time.h>
#pragma comment(lib, "wpcap.lib")
#pragma comment(lib, "Packet.lib")
#pragma comment(lib, "ws2_32.lib")

// ===================== 全局增强流量统计结构体 =====================
typedef struct {
    unsigned long long total_pkts;    // 总捕获数据包数量
    unsigned long long total_bytes;   // 总字节
    unsigned long long tcp_cnt;      // TCP报文数
    unsigned long long udp_cnt;      // UDP报文数
    unsigned long long icmp_cnt;     // ICMP报文数
    time_t last_print_time;          // 上次打印统计时间
} TrafficStat;
TrafficStat g_stat = { 0, 0, 0, 0, 0, 0 };
int g_link_type = 0;
int g_ip_offset = 14;
pcap_dumper_t* g_dump = NULL;  // PCAP存储句柄

// ===================== 协议头部结构体 =====================
// 以太网头部 14字节
typedef struct ether_header
{
    u_char ether_dhost[6];
    u_char ether_shost[6];
    u_short ether_type;
} ether_header;

// IPv4头部
typedef struct ip_header
{
    u_char  ip_verlen;
    u_char  ip_tos;
    u_short ip_len;
    u_short ip_id;
    u_short ip_off;
    u_char  ip_ttl;
    u_char  ip_proto;
    u_short ip_sum;
    struct in_addr ip_src;
    struct in_addr ip_dst;
} ip_header;

// TCP头部
typedef struct tcp_header
{
    u_short th_sport;
    u_short th_dport;
    u_int th_seq;
    u_int th_ack;
    u_char th_offx2;
    u_char th_flags;
    u_short th_win;
    u_short th_sum;
    u_short th_urp;
} tcp_header;

// UDP头部
typedef struct udp_header
{
    u_short uh_sport;
    u_short uh_dport;
    u_short uh_len;
    u_short uh_sum;
} udp_header;

// ICMP头部
typedef struct icmp_header
{
    u_char icmp_type;   // ICMP类型
    u_char icmp_code;   // 代码
    u_short icmp_sum;   // 校验和
    union {
        struct {
            u_short id;
            u_short seq;
        } echo;
        u_int gateway;
    } un;
} icmp_header;

// ===================== 工具函数 =====================
void print_mac(u_char* mac)
{
    printf("%02x:%02x:%02x:%02x:%02x:%02x",
        mac[0], mac[1], mac[2], mac[3], mac[4], mac[5]);
}

// 打印ICMP类型说明
void print_icmp_type(u_char type, u_char code)
{
    switch (type)
    {
    case 0:
        printf("回显应答(Echo Reply)");
        break;
    case 3:
        printf("目标不可达, Code:%d", code);
        break;
    case 8:
        printf("回显请求(Echo Request)");
        break;
    case 11:
        printf("超时(Time Exceeded), Code:%d", code);
        break;
    default:
        printf("未知类型:%d Code:%d", type, code);
        break;
    }
}

// ===================== 增强版流量统计打印函数（核心完善功能） =====================
void print_traffic_stat()
{
    time_t now = time(NULL);
    // 控制1秒打印一次，防止刷屏
    if (now - g_stat.last_print_time < 1)
        return;
    g_stat.last_print_time = now;

    // 字节转MB，方便直观查看流量大小
    double total_mb = (double)g_stat.total_bytes / 1024 / 1024;
    unsigned long long other_pkt = g_stat.total_pkts - g_stat.tcp_cnt - g_stat.udp_cnt - g_stat.icmp_cnt;

    printf("\n==================== 实时流量统计面板 ====================\n");
    printf("总捕获数据包：%llu 个\n", g_stat.total_pkts);
    printf("总捕获流量：%llu 字节 (%.2f MB)\n", g_stat.total_bytes, total_mb);
    printf("----------------------------------------------------------\n");
    printf("TCP报文数量：%llu 个\n", g_stat.tcp_cnt);
    printf("UDP报文数量：%llu 个\n", g_stat.udp_cnt);
    printf("ICMP报文数量：%llu 个\n", g_stat.icmp_cnt);
    printf("其他IP报文：%llu 个\n", other_pkt);
    printf("==========================================================\n\n");
}

// ===================== 数据包回调函数 =====================
void packet_handler(u_char* user, const struct pcap_pkthdr* hdr, const u_char* pkt)
{
    // 1. PCAP写入文件
    if (g_dump != NULL)
    {
        pcap_dump((u_char*)g_dump, hdr, pkt);
    }
    // 2. 更新全局流量统计总计数
    g_stat.total_pkts++;
    g_stat.total_bytes += hdr->len;
    printf("===== 捕获数据包 总长度:%d =====\n", hdr->len);
    const u_char* ip_pkt = pkt + g_ip_offset;
    int proto_flag = -1;

    // 二层解析：以太网 / 环回DLT_NULL
    if (g_link_type == DLT_EN10MB)
    {
        struct ether_header* eth = (struct ether_header*)pkt;
        printf("【以太网帧】\n");
        printf("源MAC: "); print_mac(eth->ether_shost);
        printf(" | 目标MAC: "); print_mac(eth->ether_dhost);
        u_short eth_type = ntohs(eth->ether_type);
        if (eth_type != 0x0800)
        {
            printf(" | 非IPv4报文，跳过解析\n\n");
            print_traffic_stat();
            return;
        }
        printf(" | 上层协议: IPv4\n");
    }
    else if (g_link_type == DLT_NULL)
    {
        printf("【环回虚拟网卡】无以太网头部\n");
        ip_pkt = pkt + 4;
    }

    // 校验IPv4版本
    struct ip_header* ip = (struct ip_header*)ip_pkt;
    if ((ip->ip_verlen >> 4) != 4)
    {
        printf("非IPv4报文，跳过解析\n\n");
        print_traffic_stat();
        return;
    }
    unsigned int ip_head_len = (ip->ip_verlen & 0x0f) * 4;

    // IPv4信息打印
    printf("【IPv4报文】\n");
    printf("源IP:%s | 目的IP:%s | TTL:%d | 传输层协议:",
        inet_ntoa(ip->ip_src), inet_ntoa(ip->ip_dst), ip->ip_ttl);
    if (ip->ip_proto == 6)
    {
        printf("TCP\n");
        g_stat.tcp_cnt++;
        proto_flag = 6;
    }
    else if (ip->ip_proto == 17)
    {
        printf("UDP\n");
        g_stat.udp_cnt++;
        proto_flag = 17;
    }
    else if (ip->ip_proto == 1)
    {
        printf("ICMP\n");
        g_stat.icmp_cnt++;
        proto_flag = 1;
    }
    else
    {
        printf("其他\n");
    }

    // 传输层解析
    const u_char* trans_pkt = ip_pkt + ip_head_len;
    if (proto_flag == 6)
    {
        struct tcp_header* tcp = (struct tcp_header*)trans_pkt;
        printf("【TCP头部】源端口:%d 目的端口:%d\n",
            ntohs(tcp->th_sport), ntohs(tcp->th_dport));
        printf("标志位: ");
        if (tcp->th_flags & 0x02) printf("SYN ");
        if (tcp->th_flags & 0x10) printf("ACK ");
        if (tcp->th_flags & 0x01) printf("FIN ");
        if (tcp->th_flags & 0x04) printf("RST ");
        printf("\n");
    }
    else if (proto_flag == 17)
    {
        struct udp_header* udp = (struct udp_header*)trans_pkt;
        printf("【UDP头部】源端口:%d  目的端口:%d  报文总长度:%d字节  校验和:0x%04X\n",
            ntohs(udp->uh_sport),
            ntohs(udp->uh_dport),
            ntohs(udp->uh_len),
            ntohs(udp->uh_sum));
    }
    else if (proto_flag == 1)
    {
        // ICMP解析
        struct icmp_header* icmp = (struct icmp_header*)trans_pkt;
        printf("【ICMP头部】类型：");
        print_icmp_type(icmp->icmp_type, icmp->icmp_code);
        printf(" | 校验和:0x%04X\n", ntohs(icmp->icmp_sum));
        // 回显请求/应答打印ID、序列号
        if (icmp->icmp_type == 0 || icmp->icmp_type == 8)
        {
            printf("标识ID:%d 序列号:%d\n",
                ntohs(icmp->un.echo.id),
                ntohs(icmp->un.echo.seq));
        }
    }

    printf("\n");
    // 每次解析完一条报文自动调用流量统计函数
    print_traffic_stat();
}

int main()
{
    pcap_if_t* alldevs, * d;
    pcap_t* handle;
    char errbuf[PCAP_ERRBUF_SIZE];
    int i = 0, sel;
    struct bpf_program fp;
    const char* filter_rule = "ip and (tcp or udp or icmp)";
    printf("==== C语言数据包捕获解析工具（完善流量统计版）====\n");
    printf("功能：抓包解析 + 增强实时流量统计 + PCAP自动保存 capture.pcap\n");
    printf("支持：以太网、IPv4、TCP、UDP、ICMP完整解析\n");
    printf("流量统计：总报文、总流量MB、各协议报文计数\n");
    printf("停止方式：Ctrl + C\n\n");

    // 1. 枚举网卡
    if (pcap_findalldevs_ex(PCAP_SRC_IF_STRING, NULL, &alldevs, errbuf) == -1)
    {
        printf("网卡枚举失败：%s\n", errbuf);
        return -1;
    }
    for (d = alldevs; d; d = d->next)
    {
        printf("%d. %s | %s\n", ++i, d->name, d->description ? d->description : "无描述");
    }

    printf("\n请输入网卡序号：");
    scanf("%d", &sel);

    // 定位选中网卡
    d = alldevs;
    for (i = 1; i < sel; i++) d = d->next;

    // 2. 打开网卡 混杂模式
    handle = pcap_open(d->name, 65536, PCAP_OPENFLAG_PROMISCUOUS, 1000, NULL, errbuf);
    if (!handle)
    {
        printf("打开网卡失败：%s\n", errbuf);
        pcap_freealldevs(alldevs);
        return -1;
    }
    pcap_freealldevs(alldevs);

    // 3. 获取链路层类型
    g_link_type = pcap_datalink(handle);
    if (g_link_type == DLT_EN10MB)
    {
        g_ip_offset = 14;
        printf("\n【提示】当前设备：标准以太网网卡，IP头偏移14字节\n");
    }
    else if (g_link_type == DLT_NULL)
    {
        g_ip_offset = 4;
        printf("\n【提示】当前设备：环回虚拟网卡，IP头偏移4字节\n");
    }
    else
    {
        g_ip_offset = 14;
        printf("\n【警告】未知链路类型，默认按以太网解析\n");
    }

    // 4. 开启PCAP存储，保存到capture.pcap
    g_dump = pcap_dump_open(handle, "capture.pcap");
    if (g_dump == NULL)
    {
        printf("PCAP文件创建失败：%s\n", pcap_geterr(handle));
    }
    else
    {
        printf("【提示】抓包数据将自动保存至 capture.pcap（可用Wireshark打开）\n");
    }

    // 5. 编译并设置BPF过滤规则
    if (pcap_compile(handle, &fp, filter_rule, 0, PCAP_NETMASK_UNKNOWN) == -1)
    {
        printf("BPF过滤编译失败：%s\n", pcap_geterr(handle));
        pcap_close(handle);
        return -1;
    }
    pcap_setfilter(handle, &fp);
    pcap_freecode(&fp);

    printf("\n==================== 开始抓包 ====================\n\n");
    g_stat.last_print_time = time(NULL);

    // 6. 循环抓包（0代表无限捕获）
    pcap_loop(handle, 0, packet_handler, NULL);

    // 7. 程序退出资源释放
    if (g_dump != NULL)
    {
        pcap_dump_flush(g_dump);
        pcap_dump_close(g_dump);
        printf("\n【提示】PCAP文件已完整写入 capture.pcap\n");
    }
    pcap_close(handle);
    printf("程序正常退出\n");
    return 0;
}