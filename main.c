#define WIN32
#include <winsock2.h>
#include <windows.h>
#include <pcap.h>
#include <stdio.h>
#pragma comment(lib, "wpcap.lib")
#pragma comment(lib, "Packet.lib")
#pragma comment(lib, "ws2_32.lib")

// 数据包回调函数
void packet_handler(u_char* user, const struct pcap_pkthdr* hdr, const u_char* pkt)
{
    printf("捕获数据包，长度：%d 字节\n", hdr->len);
}

int main()
{
    pcap_if_t* alldevs, * d;
    pcap_t* handle;
    char errbuf[PCAP_ERRBUF_SIZE];
    int i = 0, sel;

    // 1. 枚举所有网卡
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

    // 选中目标网卡
    d = alldevs;
    for (i = 1; i < sel; i++) d = d->next;

    // 2. 打开网卡
    handle = pcap_open(d->name, 65536, PCAP_OPENFLAG_PROMISCUOUS, 1000, NULL, errbuf);
    if (!handle)
    {
        printf("打开网卡失败：%s\n", errbuf);
        pcap_freealldevs(alldevs);
        return -1;
    }
    pcap_freealldevs(alldevs);

    // 3. BPF过滤示例：只抓TCP流量
    struct bpf_program fp;
    pcap_compile(handle, &fp, "tcp", 0, PCAP_NETMASK_UNKNOWN);
    pcap_setfilter(handle, &fp);

    printf("开始抓包，Ctrl+C停止\n");
    // 4. 循环捕获数据包
    pcap_loop(handle, 0, packet_handler, NULL);

    pcap_close(handle);
    return 0;
}