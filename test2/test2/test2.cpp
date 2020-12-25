#include "pcap.h"
#include<iostream>
#include"Windows.h"
#include"remote-ext.h"
#include <stdlib.h>
#include<iomanip>
#include <winsock.h>

using namespace std;
#pragma comment(lib,"wpcap.lib")
#pragma comment(lib,"ws2_32.lib")
#pragma warning(disable : 4996)

#pragma pack(1)

typedef struct FrameHeader_t {
	BYTE DesMAC[6];			//目的地址
	BYTE SrcMAC[6];			//源地址
	WORD FrameType;			//帧类型
};
typedef struct IPHeader_t {
	BYTE Ver_Hlen;			//版本+首部长度
	BYTE TOS;				//服务类型
	WORD TotalLen;			//总长度
	WORD ID;				//标识
	WORD Flag_Segment;		//标志位+段偏移量
	BYTE TTL;				//存活时间
	BYTE Protocol;			//协议
	WORD Checksum;			//首部校验和
	ULONG SrcIP;			//源地址
	ULONG DstIP;				//目的地址
};

typedef struct Data_t {
	FrameHeader_t FrameHeader;
	IPHeader_t IPHeader;
};
#pragma pack()

int main()
{
	pcap_if_t *alldevs;
	pcap_if_t *d;
	int inum;
	int i = 0;
	pcap_t *adhandle;
	int res;
	char errbuf[PCAP_ERRBUF_SIZE];
	struct tm *ltime;
	char timestr[16];
	struct pcap_pkthdr *header;
	const u_char *pkt_data;
	time_t local_tv_sec;
	Data_t *IPPacket;

	/* 获取本机设备列表 */
	if (pcap_findalldevs_ex(PCAP_SRC_IF_STRING, NULL, &alldevs, errbuf) == -1)
	{
		fprintf(stderr, "Error in pcap_findalldevs: %s\n", errbuf);
		exit(1);
	}

	/* 打印列表 */
	for (d = alldevs; d; d = d->next)
	{
		printf("%d. %s", ++i, d->name);
		if (d->description)
			printf(" (%s)\n", d->description);
		else
			printf(" (No description available)\n");
	}

	if (i == 0)
	{
		printf("\nNo interfaces found! Make sure WinPcap is installed.\n");
		return -1;
	}

	printf("Enter the interface number (1-%d):", i);
	scanf_s("%d", &inum);

	if (inum < 1 || inum > i)
	{
		printf("\nInterface number out of range.\n");
		/* 释放设备列表 */
		pcap_freealldevs(alldevs);
		return -1;
	}

	/* 跳转到已选中的适配器 */
	for (d = alldevs, i = 0; i < inum - 1; d = d->next, i++);

	/* 打开设备 */
	if ((adhandle = pcap_open(d->name,          // 设备名
		65536,            // 要捕捉的数据包的部分
						  // 65535保证能捕获到不同数据链路层上的每个数据包的全部内容
		PCAP_OPENFLAG_PROMISCUOUS,    // 混杂模式
		1000,             // 读取超时时间
		NULL,             // 远程机器验证
		errbuf            // 错误缓冲池
	)) == NULL)
	{
		fprintf(stderr, "\nUnable to open the adapter. %s is not supported by WinPcap\n", d->name);
		/* 释放设列表 */
		pcap_freealldevs(alldevs);
		return -1;
	}

	printf("\nlistening on %s...\n", d->description);

	/* 释放设备列表 */
	pcap_freealldevs(alldevs);

	/* 获取数据包 */
	while ((res = pcap_next_ex(adhandle, &header, &pkt_data)) >= 0) {
		if (res == 0)
			/* 超时时间到 */
			continue;

		/* 将时间戳转换成可识别的格式 */
		local_tv_sec = header->ts.tv_sec;
		ltime = localtime(&local_tv_sec);
		strftime(timestr, sizeof timestr, "%H:%M:%S", ltime);

		IPPacket = (Data_t *)pkt_data;

		printf("%s,         len:%d\n", timestr, header->len);
		cout << "源地址：";
		for (int i = 0; i < 6; i++)
		{
			cout << setfill('0') << setw(2) << hex << (unsigned int)IPPacket->FrameHeader.SrcMAC[i] << " ";
		}
		cout << "	" << "目的地址：";
		for (int i = 0; i < 6; i++)
		{
			cout << setfill('0') << setw(2) << hex << (unsigned int)IPPacket->FrameHeader.DesMAC[i] << " ";
		}
		cout << "	" << "帧类型/长度：";
		cout << setfill('0') << setw(4) << hex << ntohs(IPPacket->FrameHeader.FrameType);
		cout << endl;
	}

	if (res == -1) {
		printf("Error reading the packets: %s\n", pcap_geterr(adhandle));
		return -1;
	}
	pcap_freealldevs(alldevs);
	return 0;
}