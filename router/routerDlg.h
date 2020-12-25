// routerDlg.h: 头文件
//
#include "pcap.h"
#include<stdlib.h>
#include<string.h>
#pragma once

// CrouterDlg 对话框
class CrouterDlg : public CDialogEx
{
	// 构造
public:
	CrouterDlg(CWnd* pParent = nullptr);	// 标准构造函数

// 对话框数据
#ifdef AFX_DESIGN_TIME
	enum { IDD = IDD_ROUTER_DIALOG };
#endif

protected:
	virtual void DoDataExchange(CDataExchange* pDX);	// DDX/DDV 支持

// 实现
protected:
	HICON m_hIcon;

	// 生成的消息映射函数
	virtual BOOL OnInitDialog();
	afx_msg void OnSysCommand(UINT nID, LPARAM lParam);
	afx_msg void OnPaint();
	afx_msg HCURSOR OnQueryDragIcon();
	DECLARE_MESSAGE_MAP()
public:
	afx_msg void OnStartClickedButton();
	afx_msg void OnBnClickedButton();
	afx_msg void OnAddRouterButton();
	afx_msg void OnDeleteRouterButton();
	// 日志控件变量
	CListBox Logger;
	// 路由表控件变量
	CListBox m_RouteTable;
	// 下一地址控件变量
	CIPAddressCtrl m_Destination;
	// 子网掩码控件变量
	CIPAddressCtrl m_Mask;
	// 下一跳步控件变量
	CIPAddressCtrl m_NextHop;
	afx_msg void OnDestroy();
	afx_msg void OnTimer(UINT_PTR nIDEvent);
};

#define MAX_IF   20			//最大接口数目

#pragma pack(1)
typedef struct FrameHeader_t {	//帧首部
	UCHAR DesMAC[6];		//目的地址
	UCHAR SrcMAC[6];		//源地址
	USHORT FrameType;		//帧类型
};

typedef struct ARPFrame_t {		//ARP帧
	FrameHeader_t FrameHeader;		//帧首部
	WORD HardwareType;				//硬件类型
	WORD ProtocolType;				//协议类型
	BYTE Hlen;						//硬件地址长度
	BYTE Plen;						//协议地址长度
	WORD Operation;					//操作值
	UCHAR SendHa[6];				//源MAC地址
	ULONG SendIP;					//源IP地址
	UCHAR RecvHa[6];				//目的MAC地址
	ULONG RecvIP;					//目的IP地址
};

typedef struct IPHeader_t {		//IP首部
	BYTE Ver_Hlen;					//版本+头部长度
	BYTE TOS;						//服务类型
	WORD TotalLen;					//总长度
	WORD ID;						//标识
	WORD Flag_Segment;				//标志+片偏移
	BYTE TTL;						//生存时间
	BYTE Protocol;					//协议
	WORD Checknum;					//头部校验和
	ULONG SrcIP;					//源IP地址
	ULONG DesIP;					//目的IP地址
};

typedef struct ICMPHeader_t {	//ICMP首部
	BYTE Type;						//类型
	BYTE Code;						//代码
	WORD Checknum;					//校验和
	WORD Id;						//标识
	WORD Sequence;					//序列号
};

typedef struct IPFrame_t {		//IP帧
	FrameHeader_t FrameHeader;		//帧首部
	IPHeader_t IPHeader;			//IP首部
};

typedef struct ip_t {			//网络地址
	ULONG IPAddr;					//IP地址
	ULONG IPMask;					//子网掩码
};

typedef struct IfInfo_t {		//接口信息
	CString DeviceName;				//设备名
	CString Description;			//设备描述
	UCHAR MACAddr[6];				//MAC地址
	CArray <ip_t, ip_t&> ip;		//IP地址列表
	pcap_t *adhandle;				//pcap句柄
};

typedef struct SendPacket_t {	//发送数据报结构
	int len;						//长度
	BYTE PktData[2000];				//数据缓存
	ULONG TargetIP;					//目的IP地址
	UINT_PTR n_mTimer;				//定时器
	UINT IfNo;						//接口序号
};

typedef struct RouteTable_t {	//路由表结构
	ULONG Mask;						//子网掩码
	ULONG DstIP;					//目的IP地址
	ULONG NextHop;					//下一跳步
	UINT IfNo;						//接口序号
};

typedef struct IP_MAC_t {		//IP-MAC地址映射结构
	ULONG IPAddr;					//IP地址
	ULONG MACAddr[6];				//mac地址
};

/*
***********全局函数*************
*/

//IP地址转换
CString IPntoa(ULONG nIPAddr);

//MAC地址转换
CString MACntoa(UCHAR *nMACAddr);

//MAC地址比较
bool cmpMAC(UCHAR *MAC1, UCHAR *MAC2);

//mac地址复制
void cpyMAC(UCHAR *MAC1, UCHAR *MAC2);

//mac地址设置
void setMAC(UCHAR *MAC, UCHAR ch);

//IP地址查询
bool IPLookup(ULONG ipaddr, UCHAR *p);

//数据包捕获线程
UINT Capture(PVOID pParam);

//获取本地接口MAC地址线程
UINT CaptureLocalARP(PVOID pParam);

//发送ARP请求
void ARPRequest(pcap_t *adhandle, UCHAR *srcMAC, ULONG srcIP, ULONG targetIP);

//查询路由表
DWORD RouteLookup(UINT &IFno, DWORD desIP, CList<RouteTable_t, RouteTable_t&> *routeTable);

//处理ARP数据包
void ARPPacketProc(struct pcap_pkthdr *header, const u_char *pkt_data);

//处理IP数据包
void IPPacketProc(IfInfo_t *pIfInfo, struct pcap_pkthdr *header, const u_char *pkt_data);

//处理ICMP数据包
void ICMPPacketProc(IfInfo_t *pIfInfo, BYTE type, BYTE code, const u_char *pkt_data);

//检查IP数据包头部校验和是否正确
int IsChecksumRight(char *buffer);

//计算校验和
unsigned short ChecksumCompute(unsigned short *buffer, int size);
