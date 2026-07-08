#define _WINSOCK_DEPRECATED_NO_WARNINGS
#define _CRT_SECURE_NO_WARNINGS
#define WIN32
#include <winsock2.h>
#include <windows.h>
#include <pcap.h>
#include <stdio.h>
#include <time.h>
#include <string.h>
#include <stdlib.h>
#pragma comment(lib, "wpcap.lib")
#pragma comment(lib, "Packet.lib")
#pragma comment(lib, "ws2_32.lib")

// ===================== 配置宏 =====================
#define IP_HASH_SIZE 256
#define TOP_IP_PAIR 10
#define DEFAULT_FILTER "ip or ip6 and (tcp or udp or icmp or icmp6)"

// ===================== 全局流量统计结构体 =====================
typedef struct {
    unsigned long long total_pkts;
    unsigned long long total_bytes;
    unsigned long long tcp_cnt;
    unsigned long long udp_cnt;
    unsigned long long icmp_cnt;
    unsigned long long icmpv6_cnt;
    time_t last_print_time;
} TrafficStat;
TrafficStat g_stat = { 0, 0, 0, 0, 0, 0, 0 };
int g_link_type = 0;
int g_ip_offset = 14;
pcap_dumper_t* g_dump = NULL;
FILE* g_log_file = NULL;

// ===================== IP对流量统计哈希表 =====================
typedef struct ip_pair_node {
    int ip_version;
    u_char src_ip[16];
    u_char dst_ip[16];
    unsigned long long pkt_cnt;
    unsigned long long byte_cnt;
    struct ip_pair_node* next;
} ip_pair_node;
ip_pair_node* g_ip_hash[IP_HASH_SIZE] = { NULL };

// ===================== 协议头部结构体 =====================
typedef struct ether_header
{
    u_char ether_dhost[6];
    u_char ether_shost[6];
    u_short ether_type;
} ether_header;

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

typedef struct ipv6_header
{
    u_int vtf;
    u_short payload_len;
    u_char next_header;
    u_char hop_limit;
    u_char src_addr[16];
    u_char dst_addr[16];
} ipv6_header;

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

typedef struct udp_header
{
    u_short uh_sport;
    u_short uh_dport;
    u_short uh_len;
    u_short uh_sum;
} udp_header;

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

// ========== ICMPv6头部结构体 ==========
typedef struct icmpv6_header
{
    u_char icmp6_type;
    u_char icmp6_code;
    u_short icmp6_cksum;
    union {
        struct {
            u_short id;
            u_short seq;
        } echo;
        u_int reserved;
    } un;
} icmpv6_header;

// ========== DNS 相关结构体 ==========
typedef struct dns_header {
    u_short id;
    u_short flags;
    u_short qdcount;
    u_short ancount;
    u_short nscount;
    u_short arcount;
} dns_header;

typedef struct dns_rr {
    u_short type;
    u_short cls;
    u_int ttl;
    u_short rdlength;
} dns_rr;

#define DNS_TYPE_A     1
#define DNS_TYPE_AAAA  28
#define DNS_TYPE_CNAME 5
#define DNS_TYPE_NS    2

// ===================== 工具函数 =====================
void print_mac(u_char* mac)
{
    printf("%02x:%02x:%02x:%02x:%02x:%02x", mac[0], mac[1], mac[2], mac[3], mac[4], mac[5]);
}

void print_ipv6(u_char* addr)
{
    printf("%02x%02x:%02x%02x:%02x%02x:%02x%02x:%02x%02x:%02x%02x:%02x%02x:%02x%02x",
        addr[0], addr[1], addr[2], addr[3],
        addr[4], addr[5], addr[6], addr[7],
        addr[8], addr[9], addr[10], addr[11],
        addr[12], addr[13], addr[14], addr[15]);
}

void ipv6_to_str(const u_char* addr, char* out, int out_len)
{
    snprintf(out, out_len, "%02x%02x:%02x%02x:%02x%02x:%02x%02x:%02x%02x:%02x%02x:%02x%02x:%02x%02x",
        addr[0], addr[1], addr[2], addr[3],
        addr[4], addr[5], addr[6], addr[7],
        addr[8], addr[9], addr[10], addr[11],
        addr[12], addr[13], addr[14], addr[15]);
}

const u_char* dns_parse_domain(const u_char* pkt, const u_char* start, char* out, int out_len)
{
    int pos = 0;
    const u_char* ptr = start;
    while (1)
    {
        u_char len = *ptr++;
        if (len == 0)
            break;
        if ((len & 0xC0) == 0xC0)
        {
            u_short offset = ((len & 0x3F) << 8) | (*ptr++);
            ptr = pkt + offset;
            continue;
        }
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

// ========== ICMPv6类型打印 ==========
void print_icmpv6_type(u_char type, u_char code)
{
    switch (type)
    {
    case 1:
        printf("目的不可达, Code:%d", code);
        break;
    case 2:
        printf("数据包过大(Packet Too Big)");
        break;
    case 3:
        printf("超时(Time Exceeded), Code:%d", code);
        break;
    case 128:
        printf("回显请求(Echo Request)");
        break;
    case 129:
        printf("回显应答(Echo Reply)");
        break;
    case 135:
        printf("邻居请求(Neighbor Solicitation)");
        break;
    case 136:
        printf("邻居公告(Neighbor Advertisement)");
        break;
    default:
        printf("未知类型:%d Code:%d", type, code);
        break;
    }
}

void print_ipv6_proto(u_char proto)
{
    switch (proto)
    {
    case 6: printf("TCP"); break;
    case 17: printf("UDP"); break;
    case 58: printf("ICMPv6"); break;
    default: printf("其他(%d)", proto); break;
    }
}

// ===================== IP对哈希统计工具函数 =====================
static unsigned int ip_hash(int version, const u_char* src, const u_char* dst)
{
    unsigned int hash = 0;
    int len = (version == 4) ? 4 : 16;
    for (int i = 0; i < len; i++) {
        hash = (hash * 31 + src[i]) % IP_HASH_SIZE;
        hash = (hash * 31 + dst[i]) % IP_HASH_SIZE;
    }
    return hash;
}

static int ip_equal(int version, const u_char* a, const u_char* b)
{
    int len = (version == 4) ? 4 : 16;
    return memcmp(a, b, len) == 0;
}

void add_ip_pair(int version, const u_char* src, const u_char* dst, unsigned int bytes)
{
    unsigned int idx = ip_hash(version, src, dst);
    ip_pair_node* node = g_ip_hash[idx];
    while (node != NULL) {
        if (node->ip_version == version &&
            ip_equal(version, node->src_ip, src) &&
            ip_equal(version, node->dst_ip, dst)) {
            node->pkt_cnt++;
            node->byte_cnt += bytes;
            return;
        }
        node = node->next;
    }
    node = (ip_pair_node*)malloc(sizeof(ip_pair_node));
    if (node == NULL) return;
    node->ip_version = version;
    int len = (version == 4) ? 4 : 16;
    memcpy(node->src_ip, src, len);
    memcpy(node->dst_ip, dst, len);
    node->pkt_cnt = 1;
    node->byte_cnt = bytes;
    node->next = g_ip_hash[idx];
    g_ip_hash[idx] = node;
}

static int compare_ip_pair(const void* a, const void* b)
{
    ip_pair_node* na = *(ip_pair_node**)a;
    ip_pair_node* nb = *(ip_pair_node**)b;
    if (na->byte_cnt > nb->byte_cnt) return -1;
    if (na->byte_cnt < nb->byte_cnt) return 1;
    return 0;
}

// ===================== 增强版HTTP协议解析工具 =====================
void parse_http_payload(const u_char* payload, int pay_len)
{
    if (pay_len <= 0) return;
    char buf[2048] = { 0 };
    int copy_len = pay_len > 2047 ? 2047 : pay_len;
    memcpy(buf, payload, copy_len);
    buf[copy_len] = '\0';

    printf("【HTTP协议解析】\n");

    char* line = buf;
    char* next_line = NULL;

    // 解析起始行
    next_line = strstr(line, "\r\n");
    if (next_line == NULL) {
        printf("非完整HTTP报文，载荷预览:\n%.256s\n", buf);
        return;
    }
    *next_line = '\0';
    next_line += 2;

    // 判断请求/响应
    if (strncmp(line, "GET ", 4) == 0 || strncmp(line, "POST ", 5) == 0) {
        char method[16] = { 0 };
        char url[512] = { 0 };
        char version[32] = { 0 };
        sscanf(line, "%s %s %s", method, url, version);
        printf("请求方法: %s | 请求URL: %s | HTTP版本: %s\n", method, url, version);
    }
    else if (strncmp(line, "HTTP/", 5) == 0) {
        char version[32] = { 0 };
        int status_code = 0;
        char reason[128] = { 0 };
        sscanf(line, "%s %d %s", version, &status_code, reason);
        printf("HTTP版本: %s | 状态码: %d | 原因短语: %s\n", version, status_code, reason);
    }
    else {
        printf("无法识别的HTTP起始行: %s\n", line);
    }

    // 逐行解析标准头部字段
    printf("标准头部字段:\n");
    while (next_line != NULL && *next_line != '\r' && *next_line != '\n') {
        char* header_end = strstr(next_line, "\r\n");
        if (header_end == NULL) break;
        *header_end = '\0';

        char* colon = strchr(next_line, ':');
        if (colon != NULL) {
            *colon = '\0';
            char* value = colon + 1;
            while (*value == ' ') value++;

            // 匹配常见头部，不区分大小写
            if (_stricmp(next_line, "Host") == 0) {
                printf("  Host: %s\n", value);
            }
            else if (_stricmp(next_line, "Content-Type") == 0) {
                printf("  Content-Type: %s\n", value);
            }
            else if (_stricmp(next_line, "Content-Length") == 0) {
                printf("  Content-Length: %s\n", value);
            }
            else if (_stricmp(next_line, "User-Agent") == 0) {
                printf("  User-Agent: %.128s\n", value);
            }
        }

        next_line = header_end + 2;
        if (next_line >= buf + copy_len) break;
    }

    // 实体载荷预览
    int header_size = next_line - buf;
    int body_len = copy_len - header_size;
    if (body_len > 0) {
        printf("\n载荷预览(%d字节):\n%.256s\n", body_len, next_line);
    }
}

// ===================== 流量统计打印（含TOP IP对排名） =====================
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

    // TOP IP对流量排名
    ip_pair_node** all = NULL;
    int count = 0;
    int capacity = 128;
    all = (ip_pair_node**)malloc(capacity * sizeof(ip_pair_node*));
    if (all != NULL) {
        for (int i = 0; i < IP_HASH_SIZE; i++) {
            ip_pair_node* node = g_ip_hash[i];
            while (node != NULL) {
                if (count >= capacity) {
                    capacity *= 2;
                    ip_pair_node** tmp = (ip_pair_node**)realloc(all, capacity * sizeof(ip_pair_node*));
                    if (tmp == NULL) break;
                    all = tmp;
                }
                all[count++] = node;
                node = node->next;
            }
        }
        qsort(all, count, sizeof(ip_pair_node*), compare_ip_pair);

        printf("\n---------- TOP %d IP对流量排名 ----------\n", TOP_IP_PAIR < count ? TOP_IP_PAIR : count);
        printf("%-5s %-30s %-30s %10s %12s\n", "排名", "源IP", "目的IP", "包数", "字节数");
        for (int i = 0; i < TOP_IP_PAIR && i < count; i++) {
            printf("%-5d ", i + 1);
            if (all[i]->ip_version == 4) {
                char src_buf[32], dst_buf[32];
                strcpy(src_buf, inet_ntoa(*(struct in_addr*)all[i]->src_ip));
                strcpy(dst_buf, inet_ntoa(*(struct in_addr*)all[i]->dst_ip));
                printf("%-30s %-30s ", src_buf, dst_buf);
            }
            else {
                char src_str[64], dst_str[64];
                ipv6_to_str(all[i]->src_ip, src_str, sizeof(src_str));
                ipv6_to_str(all[i]->dst_ip, dst_str, sizeof(dst_str));
                printf("%-30s %-30s ", src_str, dst_str);
            }
            printf("%10llu %12llu\n", all[i]->pkt_cnt, all[i]->byte_cnt);
        }
        free(all);
    }
    printf("==========================================================\n\n");

    // 日志写入
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
    printf("===== 数据包 总长度:%d =====\n", hdr->len);

    const u_char* net_layer = pkt + g_ip_offset;
    int ip_version = (net_layer[0] >> 4);
    int proto_flag = -1;
    int net_header_len = 0;
    int tcp_data_len = 0;
    const u_char* tcp_payload = NULL;

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

    if (ip_version == 4)
    {
        struct ip_header* ip = (struct ip_header*)net_layer;
        net_header_len = (ip->ip_verlen & 0x0f) * 4;

        // 计入IP对统计
        add_ip_pair(4, (u_char*)&ip->ip_src, (u_char*)&ip->ip_dst, hdr->len);

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
    else if (ip_version == 6)
    {
        struct ipv6_header* ipv6 = (struct ipv6_header*)net_layer;
        net_header_len = sizeof(ipv6_header);

        // 计入IP对统计
        add_ip_pair(6, ipv6->src_addr, ipv6->dst_addr, hdr->len);

        u_int flow_label = ntohl(ipv6->vtf) & 0x000FFFFF;
        u_short payload_len = ntohs(ipv6->payload_len);

        printf("【IPv6报文】\n");
        printf("源IPv6: "); print_ipv6(ipv6->src_addr);
        printf("\n目的IPv6: "); print_ipv6(ipv6->dst_addr);
        printf("\n流标签: 0x%05X | 跳数限制: %d\n", flow_label, ipv6->hop_limit);
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

    const u_char* trans_pkt = net_layer + net_header_len;

    if (proto_flag == 6)
    {
        struct tcp_header* tcp = (struct tcp_header*)trans_pkt;
        u_short sport = ntohs(tcp->th_sport);
        u_short dport = ntohs(tcp->th_dport);
        int tcp_hdr_len = (tcp->th_offx2 >> 4) * 4;
        unsigned int ip_total_len = 0;
        if (ip_version == 4)
            ip_total_len = ntohs(((ip_header*)net_layer)->ip_len);
        else
            ip_total_len = net_header_len + ntohs(((ipv6_header*)net_layer)->payload_len);

        tcp_data_len = ip_total_len - net_header_len - tcp_hdr_len;
        tcp_payload = trans_pkt + tcp_hdr_len;

        printf("【TCP头部】源端口:%d 目的端口:%d\n", sport, dport);
        printf("标志位: ");
        if (tcp->th_flags & 0x02) printf("SYN ");
        if (tcp->th_flags & 0x10) printf("ACK ");
        if (tcp->th_flags & 0x01) printf("FIN ");
        if (tcp->th_flags & 0x04) printf("RST ");
        printf("\n");

        // 扩展支持80/8080/8090等常见Web端口
        if ((sport == 80 || sport == 8080 || sport == 8090 || dport == 80 || dport == 8080 || dport == 8090) && tcp_data_len > 0)
        {
            parse_http_payload(tcp_payload, tcp_data_len);
        }
    }
    else if (proto_flag == 17)
    {
        struct udp_header* udp = (struct udp_header*)trans_pkt;
        u_short sport = ntohs(udp->uh_sport);
        u_short dport = ntohs(udp->uh_dport);
        printf("【UDP头部】源端口:%d  目的端口:%d  报文总长度:%d字节  校验和:0x%04X\n",
            sport, dport, ntohs(udp->uh_len), ntohs(udp->uh_sum));

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
                (flags >> 15) & 1, (flags >> 11) & 0xF,
                (flags >> 10) & 1, (flags >> 9) & 1,
                (flags >> 8) & 1, (flags >> 7) & 1);
            printf("查询段数量: %d | 应答段数量: %d\n", qd, an);

            const u_char* ptr = dns_data + sizeof(dns_header);
            char domain_buf[256];
            for (int i = 0; i < qd; i++)
            {
                ptr = dns_parse_domain(dns_data, ptr, domain_buf, sizeof(domain_buf));
                u_short qtype = ntohs(*(u_short*)(ptr));
                ptr += 4;
                printf("【查询%d】域名:%s 类型:", i + 1, domain_buf);
                print_dns_type(qtype);
                printf("\n");
            }
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
                    printf("%d.%d.%d.%d", ptr[0], ptr[1], ptr[2], ptr[3]);
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
    else if (proto_flag == 1)
    {
        struct icmp_header* icmp = (struct icmp_header*)trans_pkt;
        printf("【ICMPv4头部】类型：");
        print_icmp_type(icmp->icmp_type, icmp->icmp_code);
        printf(" | 校验和:0x%04X\n", ntohs(icmp->icmp_sum));
        if (icmp->icmp_type == 0 || icmp->icmp_type == 8)
        {
            printf("标识ID:%d 序列号:%d\n",
                ntohs(icmp->un.echo.id), ntohs(icmp->un.echo.seq));
        }
    }
    // ICMPv6详细解析
    else if (proto_flag == 58)
    {
        struct icmpv6_header* icmp6 = (struct icmpv6_header*)trans_pkt;
        printf("【ICMPv6头部】类型：");
        print_icmpv6_type(icmp6->icmp6_type, icmp6->icmp6_code);
        printf(" | 校验和:0x%04X\n", ntohs(icmp6->icmp6_cksum));
        if (icmp6->icmp6_type == 128 || icmp6->icmp6_type == 129)
        {
            printf("标识ID:%d 序列号:%d\n",
                ntohs(icmp6->un.echo.id),
                ntohs(icmp6->un.echo.seq));
        }
    }

    printf("\n");
    print_traffic_stat();
}

// ===================== 离线PCAP解析入口（支持自定义过滤规则） =====================
int offline_parse(const char* pcap_file, const char* filter_rule)
{
    pcap_t* handle;
    char errbuf[PCAP_ERRBUF_SIZE];
    struct bpf_program fp;

    handle = pcap_open_offline(pcap_file, errbuf);
    if (handle == NULL)
    {
        printf("打开离线文件失败：%s\n", errbuf);
        return -1;
    }
    g_link_type = pcap_datalink(handle);
    g_ip_offset = (g_link_type == DLT_EN10MB) ? 14 : 4;

    if (pcap_compile(handle, &fp, filter_rule, 0, PCAP_NETMASK_UNKNOWN) == -1)
    {
        printf("离线BPF过滤规则编译失败：%s\n", pcap_geterr(handle));
        printf("请检查过滤表达式语法是否正确\n");
        pcap_close(handle);
        return -1;
    }
    pcap_setfilter(handle, &fp);
    pcap_freecode(&fp);

    printf("\n==================== 开始离线解析 ====================\n");
    printf("解析文件：%s\n", pcap_file);
    printf("BPF过滤规则：%s\n\n", filter_rule);
    g_stat.last_print_time = time(NULL);
    pcap_loop(handle, 0, packet_handler, NULL);

    pcap_close(handle);
    printf("\n==================== 离线解析完成 ====================\n");
    return 0;
}

// ===================== 辅助：清空输入缓冲区 =====================
void clear_stdin()
{
    int c;
    while ((c = getchar()) != '\n' && c != EOF);
}

// ===================== 辅助：读取用户输入的过滤规则 =====================
void input_filter_rule(char* out_buf, int buf_len)
{
    printf("\n请输入BPF过滤规则（直接回车使用默认规则）：\n");
    printf("默认规则：%s\n", DEFAULT_FILTER);
    printf("示例：tcp port 80 and host 192.168.1.1\n");

    fgets(out_buf, buf_len, stdin);
    // 去掉末尾换行符
    size_t len = strlen(out_buf);
    if (len > 0 && out_buf[len - 1] == '\n') {
        out_buf[len - 1] = '\0';
    }
    // 用户直接回车则使用默认
    if (strlen(out_buf) == 0) {
        strcpy(out_buf, DEFAULT_FILTER);
        printf("已使用默认过滤规则\n");
    }
}

// ===================== 主函数 =====================
int main()
{
    pcap_if_t* alldevs, * d;
    pcap_t* handle;
    char errbuf[PCAP_ERRBUF_SIZE];
    int i = 0, sel, menu_opt;
    struct bpf_program fp;
    char filter_rule[256] = DEFAULT_FILTER;
    char pcap_path[256];

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

    printf("==== 网络数据包捕获解析工具（自定义BPF+HTTP全解析+IP对统计+ICMPv6+离线回放）====\n");
    printf("1. 实时网卡抓包\n");
    printf("2. 读取本地PCAP文件离线解析\n");
    printf("请输入功能选项(1/2)：");
    scanf("%d", &menu_opt);
    clear_stdin();

    if (menu_opt == 2)
    {
        printf("请输入pcap文件路径(如 capture.pcap)：");
        scanf("%s", pcap_path);
        clear_stdin();

        // 离线模式也支持自定义过滤规则
        input_filter_rule(filter_rule, sizeof(filter_rule));

        offline_parse(pcap_path, filter_rule);
        goto resource_free;
    }

    printf("\n==== 实时抓包模式 ====\n");
    printf("支持：以太网、IPv4/IPv6、TCP/UDP/ICMP、DNS、HTTP(80/8080/8090)\n");
    printf("功能：自定义BPF过滤、IP对流量TOP排名、ICMPv6详细解析、完整HTTP头部解析\n");
    printf("停止方式：Ctrl + C\n\n");

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
    clear_stdin();

    d = alldevs;
    for (i = 1; i < sel; i++) d = d->next;

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
        printf("\n【提示】标准以太网网卡\n");
    }
    else if (g_link_type == DLT_NULL)
    {
        g_ip_offset = 4;
        printf("\n【提示】环回虚拟网卡\n");
    }
    else
    {
        g_ip_offset = 14;
        printf("\n【警告】未知链路类型，默认按以太网解析\n");
    }

    g_dump = pcap_dump_open(handle, "capture.pcap");
    if (g_dump == NULL)
    {
        printf("PCAP文件创建失败：%s\n", pcap_geterr(handle));
    }
    else
    {
        printf("【提示】实时抓包自动保存至 capture.pcap\n");
    }

    // 实时模式下读取用户自定义过滤规则
    input_filter_rule(filter_rule, sizeof(filter_rule));

    if (pcap_compile(handle, &fp, filter_rule, 0, PCAP_NETMASK_UNKNOWN) == -1)
    {
        printf("BPF过滤规则编译失败：%s\n", pcap_geterr(handle));
        printf("请检查过滤表达式语法，程序将使用默认规则重试\n");
        strcpy(filter_rule, DEFAULT_FILTER);
        if (pcap_compile(handle, &fp, filter_rule, 0, PCAP_NETMASK_UNKNOWN) == -1) {
            printf("默认规则编译失败，程序退出\n");
            pcap_close(handle);
            if (g_log_file != NULL) fclose(g_log_file);
            return -1;
        }
    }
    pcap_setfilter(handle, &fp);
    pcap_freecode(&fp);

    printf("\n当前生效过滤规则：%s\n", filter_rule);
    printf("\n==================== 开始实时抓包 ====================\n\n");
    g_stat.last_print_time = time(NULL);
    pcap_loop(handle, 0, packet_handler, NULL);

    if (g_dump != NULL)
    {
        pcap_dump_flush(g_dump);
        pcap_dump_close(g_dump);
        printf("\n【提示】capture.pcap 已保存完成\n");
    }
    pcap_close(handle);

resource_free:
    if (g_log_file != NULL)
    {
        time_t now = time(NULL);
        char time_buf[64];
        struct tm* tm_now = localtime(&now);
        strftime(time_buf, sizeof(time_buf), "%Y-%m-%d %H:%M:%S", tm_now);
        double total_mb = (double)g_stat.total_bytes / 1024 / 1024;
        unsigned long long other_pkt = g_stat.total_pkts - g_stat.tcp_cnt - g_stat.udp_cnt - g_stat.icmp_cnt - g_stat.icmpv6_cnt;

        fprintf(g_log_file, "\n==================== 会话结束 [%s] 汇总 ====================\n", time_buf);
        fprintf(g_log_file, "总数据包：%llu 个 | 总流量：%llu 字节 (%.2f MB)\n", g_stat.total_pkts, g_stat.total_bytes, total_mb);
        fprintf(g_log_file, "TCP：%llu | UDP：%llu | ICMPv4：%llu | ICMPv6：%llu | 其他：%llu\n",
            g_stat.tcp_cnt, g_stat.udp_cnt, g_stat.icmp_cnt, g_stat.icmpv6_cnt, other_pkt);
        fprintf(g_log_file, "================================================================\n\n");
        fclose(g_log_file);
        printf("【提示】流量日志 traffic_log.txt 已关闭保存\n");
    }

    printf("程序正常退出\n");
    return 0;
}