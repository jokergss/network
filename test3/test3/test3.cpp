#include "pcap.h"
#include<iostream>
#include"Windows.h"
#include"remote-ext.h"
#include <stdio.h>
#include <stdlib.h>
#include<iomanip>
#include <winsock.h>

using namespace std;
#pragma comment(lib,"wpcap.lib")
#pragma comment(lib,"ws2_32.lib")
#pragma warning(disable : 4996)

#pragma pack(1)
typedef struct FrameHeader_t {			//帧首部
	BYTE DesMAC[6];
	BYTE SrcMAC[6];
	WORD FrameType;
};
typedef struct ARPFrame_t {				//ARP帧
	FrameHeader_t FrameHeader;
	WORD HardwareType;					//硬件类型
	WORD ProtocolType;					//协议类型
	BYTE Hlen;							//硬件地址长度
	BYTE Plen;							//协议地址长度
	WORD Operation;						//操作类型
	BYTE SendHa[6];						//源MAC地址
	DWORD SendIP;						//源IP
	BYTE RecvHa[6];						//目的MAC地址
	DWORD RecvIP;						//目的IP
};
#pragma pack()

/*
typedef struct pcap_if pcap_if_t;

struct pcap_if {
	struct pcap_if *next;
	char *name;							//网卡名字
	char *description;					//网卡描述
	struct pcap_addr *addresses;		//网卡的IP地址
	u_int flags;						//网卡的标志
};

struct pcap_addr {
	struct pcap_addr *next;
	struct sockaddr *addr;				//IP地址
	struct sockaddr *netmask;			//网络掩码
	struct sockaddr *broadaddr;			//广播地址
	struct sockaddr *dstaddr;			//目的地址
};
*/

//将数字类型IP地址转换为字符串类型
#define IPTOSBUFFERS    12
char *iptos(u_long in)
{
	static char output[IPTOSBUFFERS][3 * 4 + 3 + 1];
	static short which;
	u_char *p;

	p = (u_char *)&in;
	which = (which + 1 == IPTOSBUFFERS ?
		0 : which + 1);
	sprintf_s(output[which], "%d.%d.%d.%d", p[0], p[1], p[2], p[3]);
	return output[which];
}

//获取IP和子网掩码赋值为ip_addr和ip_netmask
void ifget(pcap_if_t *d, char *ip_addr, char *ip_netmask) {
	pcap_addr_t *a;
	//遍历全部的地址,a代表一个pcap_addr
	for (a = d->addresses; a; a = a->next) {
		switch (a->addr->sa_family) {
		case AF_INET:
			if (a->addr) {
				char *ipstr;
				//将地址转化为字符串
				ipstr = iptos(((struct sockaddr_in *) a->addr)->sin_addr.s_addr); //*ip_addr
				printf("IP地址为:%s\n", ipstr);
				memcpy(ip_addr, ipstr, 16);
			}
			if (a->netmask) {
				char *netmaskstr;
				netmaskstr = iptos(((struct sockaddr_in *) a->netmask)->sin_addr.s_addr);
				printf("子网掩码为:%s\n", netmaskstr);
				memcpy(ip_netmask, netmaskstr, 16);
			}
		case AF_INET6:
			break;
		}
	}
}

// 获取自己主机的MAC地址
unsigned char* GetSelfMac(pcap_t *adhandle, const char *ip_addr, unsigned char *ip_mac) {
	unsigned char sendbuf[42]; //ARP包结构大小
	int i = -1;
	int res;
	ARPFrame_t ah;  //ARP帧
	struct pcap_pkthdr * pkt_header;
	const u_char * pkt_data;
	//填写一个ARP包里的内容
	memset(ah.FrameHeader.DesMAC, 0xff, 6); //目的地址为全为广播地址
	memset(ah.FrameHeader.SrcMAC, 0x0f, 6);
	memset(ah.RecvHa, 0xff, 6);				//下面的目的地址也为广播地址
	memset(ah.SendHa, 0x0f, 6);

	//htons将一个无符号短整型的主机数值转换为网络字节顺序
	ah.FrameHeader.FrameType = htons(0x0806);//		帧类型为ARP
	ah.HardwareType = htons(0x0001);		//硬件类型为以太网
	ah.ProtocolType = htons(0x0800);		//协议类型为IP
	ah.Hlen = 6;							//硬件地址长度为6
	ah.Plen = 4;							//协议地址长度为4
	ah.SendIP = inet_addr("112.112.112.112"); //随便设的发送ip
	ah.Operation = htons(0x0001);			//操作为ARP请求
	ah.RecvIP = inet_addr(ip_addr);
	memset(sendbuf, 0, sizeof(sendbuf));
	memcpy(sendbuf, &ah, sizeof(ah));
	if (pcap_sendpacket(adhandle, sendbuf, 42) == 0) {		//发送成功
		//printf("\nPacketSend succeed\n");
	}
	else {
		printf("PacketSendPacket in getmine Error: %d\n", GetLastError());
		return 0;											//发送失败直接退出函数
	}
	//从interface或离线记录文件获取一个报文
	while ((res = pcap_next_ex(adhandle, &pkt_header, &pkt_data)) >= 0) {
		if (*(unsigned short *)(pkt_data + 12) == htons(0x0806)
			&& *(unsigned short*)(pkt_data + 20) == htons(0x0002)
			&& *(unsigned long*)(pkt_data + 38)
			== inet_addr("112.112.112.112")) {
			for (i = 0; i < 6; i++) {
				ip_mac[i] = *(unsigned char *)(pkt_data + 22 + i);
			}
			//printf("获取自己主机的MAC地址成功!\n");
			break;
		}
	}
	if (i == 6) {
		/*cout << "获得的mac地址为：";
		for (int temp = 0; temp < 6; temp++)
		{
			cout << setfill('0') << setw(2) << hex << (unsigned int)ip_mac[temp] << " ";
		}*/
		return ip_mac;
	}
	else {
		return 0;
	}
}

//知道本地IP和MAC地址后使用这个函数获得其他IP地址发送ARP包对应的MAC地址
int GetMac(pcap_t *adhandle, char *ip_addr, unsigned char *ip_mac, char * newip, unsigned char *newmac) {   //参数为所使用的设备，源IP地址，源MAC，目的IP地址,目的mac。
	unsigned char sendbuf[42]; //ARP包结构大小
	int i = -1;
	int res;
	ARPFrame_t ah;  //ARP帧
	struct pcap_pkthdr * pkt_header;
	const u_char * pkt_data;
	//填写一个ARP包里的内容
	memset(ah.FrameHeader.DesMAC, 0xff, 6); //目的地址为为广播地址
	for (int temp = 0; temp < 6; temp++)
	{
		ah.FrameHeader.SrcMAC[temp] = ip_mac[temp];//源mac地址
	}
	//htons将一个无符号短整型的主机数值转换为网络字节顺序
	ah.FrameHeader.FrameType = htons(0x0806);//		帧类型为ARP
	ah.HardwareType = htons(0x0001);		//硬件类型为以太网
	ah.ProtocolType = htons(0x0800);		//协议类型为IP
	ah.Hlen = 6;							//硬件地址长度为6
	ah.Plen = 4;							//协议地址长度为4
	for (int temp = 0; temp < 6; temp++)
	{
		ah.SendHa[temp] = ip_mac[temp];
	}
	ah.SendIP = inet_addr(ip_addr);			//源IP地址
	ah.Operation = htons(0x0001);			//操作为ARP请求
	//memset(ah.SendHa, (int)ip_mac, 6);		//源mac

	memset(ah.RecvHa, 0x00, 6);				//接收mac置0
	ah.RecvIP = inet_addr(newip);			//目的IP地址
	memset(sendbuf, 0, sizeof(sendbuf));
	memcpy(sendbuf, &ah, sizeof(ah));
	if (pcap_sendpacket(adhandle, sendbuf, 42) == 0) {		//发送成功
		printf("\nPacketSend succeed\n");
	}
	else {
		printf("PacketSendPacket in getmine Error: %d\n", GetLastError());
		return 0;											//发送失败直接退出函数
	}
	//从interface或离线记录文件获取一个报文
	while ((res = pcap_next_ex(adhandle, &pkt_header, &pkt_data)) >= 0) {
		if (*(unsigned short *)(pkt_data + 12) == htons(0x0806)
			&& *(unsigned short*)(pkt_data + 20) == htons(0x0002)
			&& *(unsigned long*)(pkt_data + 38)
			== inet_addr(ip_addr)) {
			for (i = 0; i < 6; i++) {
				newmac[i] = *(unsigned char *)(pkt_data + 22 + i);
			}
			printf("获取MAC地址成功!\n");
			break;
		}
	}
	if (i == 6) {
		cout << "获得的mac地址为：";
		for (int temp = 0; temp < 6; temp++)
		{
			cout << setfill('0') << setw(2) << hex << (unsigned int)newmac[temp] << " ";
		}
		return 1;
	}
	else {
		return 0;
	}
}

//主函数
int main()
{
	pcap_if_t *alldevs;					//指向设备链表首部的指针
	pcap_if_t *d;
	pcap_addr *a;
	char errbuf[PCAP_ERRBUF_SIZE];		//错误信息缓冲区
	pcap_t *adhandle;					//捕捉实例,是pcap_open返回的对象
	char *ip_addr;                      //IP地址
	char *ip_netmask;					//子网掩码
	unsigned char ip_mac[6];				//本机MAC地址
	int num = 1;						//计数
	char judge;							//判断是否继续循环
	char *newaddr;						//用于输入IP地址
	unsigned char newmac[6];						//用于输出对应的MAC

	ip_addr = (char *)malloc(sizeof(char) * 16); //申请内存存放IP地址
	if (ip_addr == NULL)
	{
		printf("申请内存存放IP地址失败!\n");
		return -1;
	}
	ip_netmask = (char *)malloc(sizeof(char) * 16); //申请内存存放NETMASK地址
	if (ip_netmask == NULL)
	{
		printf("申请内存存放NETMASK地址失败!\n");
		return -1;
	}
	/*ip_mac = (unsigned char *)malloc(sizeof(unsigned char) * 6); //申请内存存放MAC地址
	if (ip_mac == NULL)
	{
		printf("申请内存存放MAC地址失败!\n");
		return -1;
	}*/
	newaddr = (char *)malloc(sizeof(char) * 16); //申请内存存放IP地址
	if (newaddr == NULL)
	{
		printf("申请内存存放IP地址失败!\n");
		return -1;
	}

	//获取本机的设备列表
	if (pcap_findalldevs_ex(PCAP_SRC_IF_STRING, NULL, &alldevs, errbuf) == -1)
	{
		//错误处理
		fprintf(stderr, "Error in pcap_findalldevs: %s\n", errbuf);
		exit(1);
	}

	//显示接口列表
	for (d = alldevs; d != NULL; d = d->next)
	{
		cout << num << ":" << d->name << endl;
		cout << d->description << endl;

		//获取该网络接口设备的IP地址信息
		for (a = d->addresses; a != NULL; a = a->next)
		{
			switch (a->addr->sa_family)
			{
			case AF_INET:  //sa_family ：是2字节的地址家族，AF_INET代表IPV4类型地址
				printf("Address Family Name:AF_INET\n");
				if (a->addr) {
					//->的优先级等同于括号,高于强制类型转换,由于addr为sockaddr类型，对其进行操作须转换为sockaddr_in类型
					printf("Address:%s\n", iptos(((struct sockaddr_in *)a->addr)->sin_addr.s_addr));
				}
				if (a->netmask) {
					printf("\tNetmask: %s\n", iptos(((struct sockaddr_in *)a->netmask)->sin_addr.s_addr));
				}
				if (a->broadaddr) {
					printf("\tBroadcast Address: %s\n", iptos(((struct sockaddr_in *)a->broadaddr)->sin_addr.s_addr));
				}
				if (a->dstaddr) {
					printf("\tDestination Address: %s\n", iptos(((struct sockaddr_in *)a->dstaddr)->sin_addr.s_addr));
				}
				break;
			case AF_INET6: //代表IPV6类型地址
				printf("Address Family Name:AF_INET6\n");
				printf("这是一个IPV6的地址\n");
				break;
			default:
				break;
			}
		}
		cout << endl;
		num++;
	}

	//打开用户选择的网卡
	int i;
	printf("Enter the interface number(1-%d):", num - 1);
	cin >> i;
	cout << endl;
	if (i<1 || i>num)
	{
		cout << "输出超过范围" << endl;
		pcap_freealldevs(alldevs);
		return -1;
	}
	//跳转到选择的网卡
	int temp;
	for (d = alldevs, temp = 0; temp < i - 1; d = d->next, temp++);
	//打开网卡
	if ((adhandle = pcap_open(d->name,		//设备名称
		65535,       //存放数据包的内容长度
		PCAP_OPENFLAG_PROMISCUOUS,  //混杂模式
		1000,           //超时时间
		NULL,          //远程验证
		errbuf         //错误缓冲
	)) == NULL)
	{
		//打开适配器失败,打印错误并释放设备列表
		fprintf(stderr, "\nUnable to open the adapter. %s is not supported by WinPcap\n", d->name);
		pcap_freealldevs(alldevs);
		return -1;
	}
	ifget(d, ip_addr, ip_netmask); //获取所选网卡的基本信息--掩码--IP地址
	for (int p = 0; p < 6; p++)
	{
		ip_mac[p] = GetSelfMac(adhandle, ip_addr, ip_mac)[p];
	}
	cout << "获得的地址为：";
	for (int t = 0; t < 6; t++)
	{
		cout << setfill('0') << setw(2) << hex << (unsigned int)ip_mac[t] << " ";
	}
	while (1)
	{
		cout << endl;
		cout << "是否需要输入IP地址来返回MAC地址？（输入1继续）：";
		cin >> judge;
		if (judge == '1')
		{
			for (int o = 0; o < 6; o++)
			{
				newmac[o] = 0;
			}
			memset(newaddr, 0, 4);
			cout << endl;
			cout << "请输入你所要查询的IP：";
			cin >> newaddr;

			GetMac(adhandle, ip_addr, ip_mac, newaddr, newmac);
		}
		else
		{
			break;
		}
	}

	//释放设备列表
	pcap_freealldevs(alldevs);
}