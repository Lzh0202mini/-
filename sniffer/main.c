#define _WINSOCK_DEPRECATED_NO_WARNINGS
#define _CRT_SECURE_NO_WARNINGS
#define WIN32
#include <winsock2.h>
#include <windows.h>
#include <pcap.h>
#include <stdio.h>
#include <time.h>
#include <string.h>
#pragma comment(lib, "wpcap.lib")
#pragma comment(lib, "Packet.lib")
#pragma comment(lib, "ws2_32.lib")

// ===================== 全局增强流量统计结构体 =====================
typedef struct {
    unsigned long long total_pkts;    // 总捕获数据包数量
    unsigned long long total_bytes;   // 总字节
    unsigned long long tcp_cnt;      // TCP报文数
    unsigned long long udp_cnt;      // UDP报文数
    unsigned long long icmp_cnt;     // ICMPv4报文数
    unsigned long long icmpv6_cnt;   // ICMPv6报文数
    time_t last_print_time;          // 上次打印统计时间
} TrafficStat;
TrafficStat g_stat = { 0, 0, 0, 0, 0, 0, 0 };
int g_link_type = 0;
int g_ip_offset = 14;
pcap_dumper_t* g_dump = NULL;  // PCAP存储句柄
FILE* g_log_file = NULL;       // 流量日志文件句柄

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

// IPv6头部
typedef struct ipv6_header
{
    u_int vtf;
    u_short payload_len;
    u_char next_header;
    u_char hop_limit;
    u_char src_addr[16];
    u_char dst_addr[16];
} ipv6_header;

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

// ICMPv4头部
typedef struct icmp_header
{
    u_char icmp_type;
    u_char icmp_code;
    u_short icmp_sum;
    union {
        struct {
            u_short id;
            u_short seq;
        } echo;
        u_int gateway;
    } un;
} icmp_header;

// ========== DNS 相关结构体新增 ==========
// DNS头部
typedef struct dns_header {
    u_short id;         // 事务ID
    u_short flags;      // 标志位
    u_short qdcount;    // 查询段数量
    u_short ancount;   // 应答段数量
    u_short nscount;   // 授权记录数
    u_short arcount;   // 附加记录数
} dns_header;

// DNS资源记录RR头部（应答/授权/附加共用）
typedef struct dns_rr {
    u_short type;
    u_short cls;
    u_int ttl;
    u_short rdlength;
} dns_rr;

// DNS记录类型枚举
#define DNS_TYPE_A     1    // IPv4 A记录
#define DNS_TYPE_AAAA  28   // IPv6 AAAA记录
#define DNS_TYPE_CNAME 5
#define DNS_TYPE_NS    2

// ===================== 工具函数 =====================
void print_mac(u_char* mac)
{
    printf("%02x:%02x:%02x:%02x:%02x:%02x",
        mac[0], mac[1], mac[2], mac[3], mac[4], mac[5]);
}

// 打印IPv6地址
void print_ipv6(u_char* addr)
{
    printf("%02x%02x:%02x%02x:%02x%02x:%02x%02x:%02x%02x:%02x%02x:%02x%02x:%02x%02x",
        addr[0], addr[1], addr[2], addr[3],
        addr[4], addr[5], addr[6], addr[7],
        addr[8], addr[9], addr[10], addr[11],
        addr[12], addr[13], addr[14], addr[15]);
}

// 解析DNS域名（处理压缩指针）
const u_char* dns_parse_domain(const u_char* pkt, const u_char* start, char* out, int out_len)
{
    int pos = 0;
    const u_char* ptr = start;
    while (1)
    {
        u_char len = *ptr++;
        // 0 域名结束
        if (len == 0)
            break;
        // 最高两位11 = 压缩指针
        if ((len & 0xC0) == 0xC0)
        {
            u_short offset = ((len & 0x3F) << 8) | (*ptr++);
            ptr = pkt + offset;
            continue;
        }
        // 普通标签
        for (int i = 0; i < len; i++)
        {
            if (pos >= out_len - 1)
                goto end;
            out[pos++] = *ptr++;
        }
        if (pos < out_len - 1)
            out[pos++] = '.';
    }
end:
    if (pos > 0) pos--;
    out[pos] = '\0';
    return ptr;
}

// 打印DNS类型名称
void print_dns_type(u_short type)
{
    switch (type)
    {
    case DNS_TYPE_A: printf("A(IPv4)"); break;
    case DNS_TYPE_AAAA: printf("AAAA(IPv6)"); break;
    case DNS_TYPE_CNAME: printf("CNAME"); break;
    case DNS_TYPE_NS: printf("NS"); break;
    default: printf("TYPE%d", type); break;
    }
}

// 打印ICMPv4类型说明
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

// 打印IPv6下一层协议名称
void print_ipv6_proto(u_char proto)
{
    switch (proto)
    {
    case 6:
        printf("TCP");
        break;
    case 17:
        printf("UDP");
        break;
    case 58:
        printf("ICMPv6");
        break;
    default:
        printf("其他(%d)", proto);
        break;
    }
}

// ===================== 增强版流量统计打印 + 写入TXT日志 =====================
void print_traffic_stat()
{
    time_t now = time(NULL);
    if (now - g_stat.last_print_time < 1)
        return;
    g_stat.last_print_time = now;

    double total_mb = (double)g_stat.total_bytes / 1024 / 1024;
    unsigned long long other_pkt = g_stat.total_pkts - g_stat.tcp_cnt - g_stat.udp_cnt - g_stat.icmp_cnt - g_stat.icmpv6_cnt;

    char time_buf[64];
    struct tm* tm_now = localtime(&now);
    strftime(time_buf, sizeof(time_buf), "%Y-%m-%d %H:%M:%S", tm_now);

    printf("\n==================== 实时流量统计面板 ====================\n");
    printf("统计时间：%s\n", time_buf);
    printf("总捕获数据包：%llu 个\n", g_stat.total_pkts);
    printf("总捕获流量：%llu 字节 (%.2f MB)\n", g_stat.total_bytes, total_mb);
    printf("----------------------------------------------------------\n");
    printf("TCP报文数量：%llu 个\n", g_stat.tcp_cnt);
    printf("UDP报文数量：%llu 个\n", g_stat.udp_cnt);
    printf("ICMPv4报文：%llu 个\n", g_stat.icmp_cnt);
    printf("ICMPv6报文：%llu 个\n", g_stat.icmpv6_cnt);
    printf("其他IP报文：%llu 个\n", other_pkt);
    printf("==========================================================\n\n");

    if (g_log_file != NULL)
    {
        fprintf(g_log_file, "[%s] 流量统计记录\n", time_buf);
        fprintf(g_log_file, "总数据包：%llu | 总字节：%llu | 总MB：%.2f\n", g_stat.total_pkts, g_stat.total_bytes, total_mb);
        fprintf(g_log_file, "TCP：%llu | UDP：%llu | ICMPv4：%llu | ICMPv6：%llu | 其他：%llu\n",
            g_stat.tcp_cnt, g_stat.udp_cnt, g_stat.icmp_cnt, g_stat.icmpv6_cnt, other_pkt);
        fprintf(g_log_file, "--------------------------------------------------------\n");
        fflush(g_log_file);
    }
}

// ===================== 数据包回调函数 =====================
void packet_handler(u_char* user, const struct pcap_pkthdr* hdr, const u_char* pkt)
{
    g_stat.total_pkts++;
    g_stat.total_bytes += hdr->len;
    printf("===== 捕获数据包 总长度:%d =====\n", hdr->len);

    const u_char* net_layer = pkt + g_ip_offset;
    int ip_version = (net_layer[0] >> 4);
    int proto_flag = -1;
    int net_header_len = 0;

    // 二层解析：以太网 / 环回DLT_NULL
    if (g_link_type == DLT_EN10MB)
    {
        struct ether_header* eth = (struct ether_header*)pkt;
        printf("【以太网帧】\n");
        printf("源MAC: "); print_mac(eth->ether_shost);
        printf(" | 目标MAC: "); print_mac(eth->ether_dhost);
        u_short eth_type = ntohs(eth->ether_type);

        if (eth_type != 0x0800 && eth_type != 0x86DD)
        {
            printf(" | 非IPv4/IPv6报文，跳过解析\n\n");
            print_traffic_stat();
            return;
        }
        if (eth_type == 0x0800)
            printf(" | 上层协议: IPv4\n");
        else if (eth_type == 0x86DD)
            printf(" | 上层协议: IPv6\n");
    }
    else if (g_link_type == DLT_NULL)
    {
        printf("【环回虚拟网卡】无以太网头部\n");
        net_layer = pkt + 4;
        ip_version = (net_layer[0] >> 4);
    }

    // IPv4 解析分支
    if (ip_version == 4)
    {
        struct ip_header* ip = (struct ip_header*)net_layer;
        net_header_len = (ip->ip_verlen & 0x0f) * 4;

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
            printf("ICMPv4\n");
            g_stat.icmp_cnt++;
            proto_flag = 1;
        }
        else
        {
            printf("其他\n");
        }
    }
    // IPv6 解析分支
    else if (ip_version == 6)
    {
        struct ipv6_header* ipv6 = (struct ipv6_header*)net_layer;
        net_header_len = sizeof(ipv6_header);

        u_int flow_label = ntohl(ipv6->vtf) & 0x000FFFFF;
        u_short payload_len = ntohs(ipv6->payload_len);

        printf("【IPv6报文】\n");
        printf("源IPv6: "); print_ipv6(ipv6->src_addr);
        printf("\n目的IPv6: "); print_ipv6(ipv6->dst_addr);
        printf("\n流标签: 0x%05X | 跳数限制(Hop Limit): %d\n", flow_label, ipv6->hop_limit);
        printf("载荷长度: %d 字节 | 下一层协议: ", payload_len);
        print_ipv6_proto(ipv6->next_header);
        printf("\n");

        proto_flag = ipv6->next_header;
        if (proto_flag == 6)
            g_stat.tcp_cnt++;
        else if (proto_flag == 17)
            g_stat.udp_cnt++;
        else if (proto_flag == 58)
            g_stat.icmpv6_cnt++;
    }
    else
    {
        printf("未知IP版本(%d)，跳过解析\n\n", ip_version);
        print_traffic_stat();
        return;
    }

    // 传输层起始位置
    const u_char* trans_pkt = net_layer + net_header_len;

    // TCP 解析
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
    // UDP 解析 + DNS(53端口)解析
    else if (proto_flag == 17)
    {
        struct udp_header* udp = (struct udp_header*)trans_pkt;
        u_short sport = ntohs(udp->uh_sport);
        u_short dport = ntohs(udp->uh_dport);
        printf("【UDP头部】源端口:%d  目的端口:%d  报文总长度:%d字节  校验和:0x%04X\n",
            sport, dport,
            ntohs(udp->uh_len),
            ntohs(udp->uh_sum));

        // ========== UDP 53 端口 DNS解析逻辑 ==========
        if (sport == 53 || dport == 53)
        {
            printf("========== DNS报文解析 ==========\n");
            const u_char* dns_data = trans_pkt + sizeof(udp_header);
            dns_header* dns_hdr = (dns_header*)dns_data;

            u_short id = ntohs(dns_hdr->id);
            u_short flags = ntohs(dns_hdr->flags);
            u_short qd = ntohs(dns_hdr->qdcount);
            u_short an = ntohs(dns_hdr->ancount);

            printf("DNS事务ID: 0x%04X\n", id);
            printf("QR:%d OPCODE:%d AA:%d TC:%d RD:%d RA:%d\n",
                (flags >> 15) & 1,
                (flags >> 11) & 0xF,
                (flags >> 10) & 1,
                (flags >> 9) & 1,
                (flags >> 8) & 1,
                (flags >> 7) & 1);
            printf("查询段数量: %d | 应答段数量: %d\n", qd, an);

            const u_char* ptr = dns_data + sizeof(dns_header);
            char domain_buf[256];

            // 遍历所有查询段
            for (int i = 0; i < qd; i++)
            {
                ptr = dns_parse_domain(dns_data, ptr, domain_buf, sizeof(domain_buf));
                u_short qtype = ntohs(*(u_short*)(ptr));
                ptr += 2;
                u_short qcls = ntohs(*(u_short*)(ptr));
                ptr += 2;
                printf("【查询%d】域名:%s 类型:", i + 1, domain_buf);
                print_dns_type(qtype);
                printf("\n");
            }

            // 遍历所有应答段（A/AAAA记录打印IP）
            for (int i = 0; i < an; i++)
            {
                ptr = dns_parse_domain(dns_data, ptr, domain_buf, sizeof(domain_buf));
                dns_rr* rr = (dns_rr*)ptr;
                ptr += sizeof(dns_rr);
                u_short rtype = ntohs(rr->type);
                u_int ttl = ntohl(rr->ttl);
                u_short rdlen = ntohs(rr->rdlength);

                printf("【应答%d】域名:%s TTL:%d 类型:", i + 1, domain_buf, ttl);
                print_dns_type(rtype);
                printf(" 数据:");

                if (rtype == DNS_TYPE_A && rdlen == 4)
                {
                    u_char ip4[4];
                    memcpy(ip4, ptr, 4);
                    printf("%d.%d.%d.%d", ip4[0], ip4[1], ip4[2], ip4[3]);
                }
                else if (rtype == DNS_TYPE_AAAA && rdlen == 16)
                {
                    print_ipv6((u_char*)ptr);
                }
                else
                {
                    printf("二进制数据(%d字节)", rdlen);
                }
                printf("\n");
                ptr += rdlen;
            }
            printf("==================================\n");
        }
    }
    // ICMPv4
    else if (proto_flag == 1)
    {
        struct icmp_header* icmp = (struct icmp_header*)trans_pkt;
        printf("【ICMPv4头部】类型：");
        print_icmp_type(icmp->icmp_type, icmp->icmp_code);
        printf(" | 校验和:0x%04X\n", ntohs(icmp->icmp_sum));
        if (icmp->icmp_type == 0 || icmp->icmp_type == 8)
        {
            printf("标识ID:%d 序列号:%d\n",
                ntohs(icmp->un.echo.id),
                ntohs(icmp->un.echo.seq));
        }
    }
    // ICMPv6
    else if (proto_flag == 58)
    {
        printf("【ICMPv6报文】暂未细分类型解析\n");
    }

    printf("\n");
    print_traffic_stat();
}

int main()
{
    pcap_if_t* alldevs, * d;
    pcap_t* handle;
    char errbuf[PCAP_ERRBUF_SIZE];
    int i = 0, sel;
    struct bpf_program fp;
    const char* filter_rule = "ip or ip6 and (tcp or udp or icmp or icmp6)";

    g_log_file = fopen("traffic_log.txt", "a+");
    if (g_log_file == NULL)
    {
        printf("警告：无法创建流量日志文件 traffic_log.txt\n");
    }
    else
    {
        time_t now = time(NULL);
        char time_buf[64];
        struct tm* tm_now = localtime(&now);
        strftime(time_buf, sizeof(time_buf), "%Y-%m-%d %H:%M:%S", tm_now);
        fprintf(g_log_file, "==================== 抓包会话启动 [%s] ====================\n", time_buf);
        fflush(g_log_file);
        printf("【提示】流量统计日志将自动保存至 traffic_log.txt\n");
    }

    printf("==== C语言数据包捕获解析工具（IPv4+IPv6+DNS完整版）====\n");
    printf("功能：抓包解析 + 实时流量统计 + PCAP保存 + TXT日志\n");
    printf("支持：以太网、IPv4、IPv6、TCP、UDP、ICMPv4、ICMPv6、DNS(UDP53)\n");
    printf("DNS功能：域名解析、A/AAAA IPv4/IPv6记录打印\n");
    printf("停止方式：Ctrl + C\n\n");

    // 枚举网卡
    if (pcap_findalldevs_ex(PCAP_SRC_IF_STRING, NULL, &alldevs, errbuf) == -1)
    {
        printf("网卡枚举失败：%s\n", errbuf);
        if (g_log_file != NULL) fclose(g_log_file);
        return -1;
    }
    for (d = alldevs; d; d = d->next)
    {
        printf("%d. %s | %s\n", ++i, d->name, d->description ? d->description : "无描述");
    }

    printf("\n请输入网卡序号：");
    scanf("%d", &sel);

    d = alldevs;
    for (i = 1; i < sel; i++) d = d->next;

    // 打开网卡混杂模式
    handle = pcap_open(d->name, 65536, PCAP_OPENFLAG_PROMISCUOUS, 1000, NULL, errbuf);
    if (!handle)
    {
        printf("打开网卡失败：%s\n", errbuf);
        pcap_freealldevs(alldevs);
        if (g_log_file != NULL) fclose(g_log_file);
        return -1;
    }
    pcap_freealldevs(alldevs);

    g_link_type = pcap_datalink(handle);
    if (g_link_type == DLT_EN10MB)
    {
        g_ip_offset = 14;
        printf("\n【提示】标准以太网网卡，二层头14字节\n");
    }
    else if (g_link_type == DLT_NULL)
    {
        g_ip_offset = 4;
        printf("\n【提示】环回虚拟网卡\n");
    }
    else
    {
        g_ip_offset = 14;
        printf("\n【警告】未知链路类型，默认14字节二层头\n");
    }

    // PCAP保存
    g_dump = pcap_dump_open(handle, "capture.pcap");
    if (g_dump == NULL)
    {
        printf("PCAP文件创建失败：%s\n", pcap_geterr(handle));
    }
    else
    {
        printf("【提示】抓包数据保存至 capture.pcap\n");
    }

    // BPF过滤
    if (pcap_compile(handle, &fp, filter_rule, 0, PCAP_NETMASK_UNKNOWN) == -1)
    {
        printf("BPF过滤编译失败：%s\n", pcap_geterr(handle));
        pcap_close(handle);
        if (g_log_file != NULL) fclose(g_log_file);
        return -1;
    }
    pcap_setfilter(handle, &fp);
    pcap_freecode(&fp);

    printf("\n==================== 开始抓包 ====================\n\n");
    g_stat.last_print_time = time(NULL);

    pcap_loop(handle, 0, packet_handler, NULL);

    // 释放资源
    if (g_dump != NULL)
    {
        pcap_dump_flush(g_dump);
        pcap_dump_close(g_dump);
        printf("\n【提示】PCAP文件已写入完成\n");
    }

    if (g_log_file != NULL)
    {
        time_t now = time(NULL);
        char time_buf[64];
        struct tm* tm_now = localtime(&now);
        strftime(time_buf, sizeof(time_buf), "%Y-%m-%d %H:%M:%S", tm_now);
        double total_mb = (double)g_stat.total_bytes / 1024 / 1024;
        unsigned long long other_pkt = g_stat.total_pkts - g_stat.tcp_cnt - g_stat.udp_cnt - g_stat.icmp_cnt - g_stat.icmpv6_cnt;

        fprintf(g_log_file, "\n==================== 抓包会话结束 [%s] 汇总 ====================\n", time_buf);
        fprintf(g_log_file, "总捕获数据包：%llu 个 | 总流量：%llu 字节 (%.2f MB)\n", g_stat.total_pkts, g_stat.total_bytes, total_mb);
        fprintf(g_log_file, "TCP：%llu | UDP：%llu | ICMPv4：%llu | ICMPv6：%llu | 其他：%llu\n",
            g_stat.tcp_cnt, g_stat.udp_cnt, g_stat.icmp_cnt, g_stat.icmpv6_cnt, other_pkt);
        fprintf(g_log_file, "================================================================\n\n");
        fclose(g_log_file);
        printf("【提示】流量日志 traffic_log.txt 已保存关闭\n");
    }

    pcap_close(handle);
    printf("程序正常退出\n");
    return 0;
}