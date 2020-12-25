// routerDlg.cpp: 实现文件
//

#include "pch.h"
#include "framework.h"
#include "router.h"
#include "routerDlg.h"
#include "afxdialogex.h"
#include "Windows.h"
#include "pcap.h"
#include "remote-ext.h"

#pragma comment(lib,"wpcap.lib")

#ifdef _DEBUG
#define new DEBUG_NEW
#endif

/*
************全局变量***********
*/
IfInfo_t IfInfo[MAX_IF];		//接口信息数组
int IfCount;					//接口个数
UINT_PTR TimerCount;			//定时器个数

CList <SendPacket_t, SendPacket_t&> SP;		//发送数据包缓存队列
CList <IP_MAC_t, IP_MAC_t&> IP_MAC;			//ip-mac地址映射表
CList <RouteTable_t, RouteTable_t&> RouteTable;//路由表
CrouterDlg *pDlg;				//对话框指针
CMutex mMutex(0, 0, 0);			//互斥

/*
************全局变量***********
*/

// 用于应用程序“关于”菜单项的 CAboutDlg 对话框

class CAboutDlg : public CDialogEx
{
public:
	CAboutDlg();

	// 对话框数据
#ifdef AFX_DESIGN_TIME
	enum { IDD = IDD_ABOUTBOX };
#endif

protected:
	virtual void DoDataExchange(CDataExchange* pDX);    // DDX/DDV 支持

// 实现
protected:
	DECLARE_MESSAGE_MAP()
};

CAboutDlg::CAboutDlg() : CDialogEx(IDD_ABOUTBOX)
{
}

void CAboutDlg::DoDataExchange(CDataExchange* pDX)
{
	CDialogEx::DoDataExchange(pDX);
}

BEGIN_MESSAGE_MAP(CAboutDlg, CDialogEx)
END_MESSAGE_MAP()

// CrouterDlg 对话框

CrouterDlg::CrouterDlg(CWnd* pParent /*=nullptr*/)
	: CDialogEx(IDD_ROUTER_DIALOG, pParent)
{
	m_hIcon = AfxGetApp()->LoadIcon(IDR_MAINFRAME);
}

void CrouterDlg::DoDataExchange(CDataExchange* pDX)
{
	CDialogEx::DoDataExchange(pDX);
	DDX_Control(pDX, LOGGER_LIST, Logger);
	DDX_Control(pDX, ROUTER_LIST, m_RouteTable);
	DDX_Control(pDX, IDC_IPADDRESS, m_Destination);
	DDX_Control(pDX, IDC_NETMASK, m_Mask);
	DDX_Control(pDX, IDC_NEXTHOP, m_NextHop);
}

BEGIN_MESSAGE_MAP(CrouterDlg, CDialogEx)
	ON_WM_SYSCOMMAND()
	ON_WM_PAINT()
	ON_WM_QUERYDRAGICON()
	ON_BN_CLICKED(ONSTART_BUTTON, &CrouterDlg::OnStartClickedButton)
	ON_BN_CLICKED(ONSTOP_BUTTON, &CrouterDlg::OnBnClickedButton)
	ON_BN_CLICKED(ADD_ROUTER_BUTTON, &CrouterDlg::OnAddRouterButton)
	ON_BN_CLICKED(DELETE_ROUTER_BUTTON, &CrouterDlg::OnDeleteRouterButton)
	ON_WM_DESTROY()
	ON_WM_TIMER()
END_MESSAGE_MAP()

// CrouterDlg 消息处理程序

BOOL CrouterDlg::OnInitDialog()
{
	CDialogEx::OnInitDialog();

	// 将“关于...”菜单项添加到系统菜单中。

	// IDM_ABOUTBOX 必须在系统命令范围内。
	ASSERT((IDM_ABOUTBOX & 0xFFF0) == IDM_ABOUTBOX);
	ASSERT(IDM_ABOUTBOX < 0xF000);

	CMenu* pSysMenu = GetSystemMenu(FALSE);
	if (pSysMenu != nullptr)
	{
		BOOL bNameValid;
		CString strAboutMenu;
		bNameValid = strAboutMenu.LoadString(IDS_ABOUTBOX);
		ASSERT(bNameValid);
		if (!strAboutMenu.IsEmpty())
		{
			pSysMenu->AppendMenu(MF_SEPARATOR);
			pSysMenu->AppendMenu(MF_STRING, IDM_ABOUTBOX, strAboutMenu);
		}
	}

	// 设置此对话框的图标。  当应用程序主窗口不是对话框时，框架将自动
	//  执行此操作
	SetIcon(m_hIcon, TRUE);			// 设置大图标
	SetIcon(m_hIcon, FALSE);		// 设置小图标

	// TODO: 在此添加额外的初始化代码
	CrouterApp *pApp = (CrouterApp*)AfxGetApp();
	pDlg = (CrouterDlg*)pApp->m_pMainWnd;

	return TRUE;  // 除非将焦点设置到控件，否则返回 TRUE
}

void CrouterDlg::OnSysCommand(UINT nID, LPARAM lParam)
{
	if ((nID & 0xFFF0) == IDM_ABOUTBOX)
	{
		CAboutDlg dlgAbout;
		dlgAbout.DoModal();
	}
	else
	{
		CDialogEx::OnSysCommand(nID, lParam);
	}
}

// 如果向对话框添加最小化按钮，则需要下面的代码
//  来绘制该图标。  对于使用文档/视图模型的 MFC 应用程序，
//  这将由框架自动完成。

void CrouterDlg::OnPaint()
{
	if (IsIconic())
	{
		CPaintDC dc(this); // 用于绘制的设备上下文

		SendMessage(WM_ICONERASEBKGND, reinterpret_cast<WPARAM>(dc.GetSafeHdc()), 0);

		// 使图标在工作区矩形中居中
		int cxIcon = GetSystemMetrics(SM_CXICON);
		int cyIcon = GetSystemMetrics(SM_CYICON);
		CRect rect;
		GetClientRect(&rect);
		int x = (rect.Width() - cxIcon + 1) / 2;
		int y = (rect.Height() - cyIcon + 1) / 2;

		// 绘制图标
		dc.DrawIcon(x, y, m_hIcon);
	}
	else
	{
		CDialogEx::OnPaint();
	}
}

//当用户拖动最小化窗口时系统调用此函数取得光标
//显示。
HCURSOR CrouterDlg::OnQueryDragIcon()
{
	return static_cast<HCURSOR>(m_hIcon);
}

void CrouterDlg::OnStartClickedButton()
{
	// TODO: 在此添加控件通知处理程序代码
	pcap_if_t *alldevs, *d;
	pcap_addr_t *a;
	struct bpf_program fcode;
	char errbuf[PCAP_ERRBUF_SIZE], strbuf[1000];
	int i, j, k;
	ip_t ipaddr;
	UCHAR srcMAC[6];
	ULONG srcIP;
	SetTimer(3999, 10000, 0);
	//获取本机的设备列表
	if (pcap_findalldevs_ex(PCAP_SRC_IF_STRING, NULL, &alldevs, errbuf) == -1)
	{
		//错误
		sprintf_s(strbuf, "pcap_findalldevs_ex错误:%s", errbuf);
		PostMessage(WM_QUIT, 0, 0);
	}
	i = 0;
	j = 0;
	k = 0;
	//获取IP地址信息
	for (d = alldevs; d != NULL; d = d->next)
	{
		if (d->addresses != NULL)//排除集成modem的影响（没有IP地址）
		{
			//得到一个有效的接口和其IP地址列表
			IfInfo[i].DeviceName = d->name;
			IfInfo[i].Description = d->description;
			for (a = d->addresses; a; a = a->next)
			{
				if (a->addr->sa_family == AF_INET)
				{
					ipaddr.IPAddr = (((struct sockaddr_in *)a->addr)->sin_addr.s_addr);
					ipaddr.IPMask = (((struct sockaddr_in *)a->netmask)->sin_addr.s_addr);
					IfInfo[i].ip.Add(ipaddr);
					j++;
				}
			}
			if (i == MAX_IF)//最多处理MAX_IF个接口
			{
				break;
			}
			else
			{
				i++;
			}
		}
	}
	//不符合路由器IP地址数目要求
	if (j < 2)
	{
		MessageBox("该路由程序要求本地主机至少应具有2个IP地址");
		PostMessage(WM_QUIT, 0, 0);
	}
	//保存实际的网卡数
	IfCount = i;
	//打开接口
	for (i = 0; i < IfCount; i++)
	{
		//强制转换CString
		int sizeOfString = (IfInfo[i].DeviceName.GetLength() + 1);
		LPTSTR lpsz = new TCHAR[sizeOfString];
		_tcscpy_s(lpsz, sizeOfString, IfInfo[i].DeviceName);

		if ((IfInfo[i].adhandle = pcap_open((const char *)lpsz,
			65536,//最大长度
			PCAP_OPENFLAG_PROMISCUOUS,//混杂模式
			1000,//超时时间
			NULL,//远程认证
			errbuf//错误缓存
		)) == NULL)
		{
			//错误
			sprintf_s(strbuf, "接口未能打开。WinPcap不支持%s。", IfInfo[i].DeviceName);
			MessageBox(strbuf);
			PostMessage(WM_QUIT, 0, 0);
		}
	}
	//开启数据包捕获线程，获取本地接口的MAC地址，线程数目为网卡数目
	CWinThread *pthread;
	for (i = 0; i < IfCount; i++)
	{
		pthread = AfxBeginThread(CaptureLocalARP, &IfInfo[i], THREAD_PRIORITY_NORMAL);
		if (!pthread)
		{
			MessageBox("创建数据包捕获线程失败！");
			PostMessage(WM_QUIT, 0, 0);
		}
	}
	//将列表中网卡硬件地址清0
	for (i = 0; i < IfCount; i++)
	{
		setMAC(IfInfo[i].MACAddr, 0);
	}
	//为得到真实网卡的地址，使用一个虚拟的MAC地址和IP向本机发送ARP请求
	setMAC(srcMAC, 66);
	srcIP = inet_addr("112.112.112.112");
	for (i = 0; i < IfCount; i++)
	{
		ARPRequest(IfInfo[i].adhandle, srcMAC, srcIP, IfInfo[i].ip[0].IPAddr);
	}
	//确保所有接口的MAC地址完全收到
	setMAC(srcMAC, 0);
	do {
		Sleep(1000);
		k = 0;
		for (i = 0; i < IfCount; i++)
		{
			if (!cmpMAC(IfInfo[i].MACAddr, srcMAC))
			{
				k++;
				continue;
			}
			else
			{
				break;
			}
		}
	} while (!((j++ > 10) || (k == IfCount)));
	if (k != IfCount)
	{
		MessageBox("至少有一个接口的MAC地址没能得到！");
		PostMessage(WM_QUIT, 0, 0);
	}
	//日志输出接口信息
	CString temp2("接口:");
	CString temp3("设备名:");
	CString temp4("设备描述:");
	CString temp5("MAC地址:");
	CString temp6("IP地址:");
	for (i = 0; i < IfCount; i++)
	{
		Logger.InsertString(-1, temp2);
		Logger.InsertString(-1, temp3 + IfInfo[i].DeviceName);
		Logger.InsertString(-1, temp4 + IfInfo[i].Description);
		Logger.InsertString(-1, (temp5 + MACntoa(IfInfo[i].MACAddr)));
		for (j = 0; j < IfInfo[i].ip.GetSize(); j++)
		{
			Logger.InsertString(-1, (temp6 + IPntoa(IfInfo[i].ip[j].IPAddr)));
		}
	}
	//初始化路由表显示
	RouteTable_t rt;
	for (i = 0; i < IfCount; i++)
	{
		for (j = 0; j < IfInfo[i].ip.GetSize(); j++)
		{
			rt.IfNo = i;
			rt.DstIP = IfInfo[i].ip[j].IPAddr&IfInfo[i].ip[j].IPMask;
			rt.Mask = IfInfo[i].ip[j].IPMask;
			rt.NextHop = 0;//直接投递
			RouteTable.AddTail(rt);
			m_RouteTable.InsertString(-1, IPntoa(rt.Mask) + " -- " + IPntoa(rt.DstIP) + " -- " + IPntoa(rt.NextHop) + "直接投递");
		}
	}
	//设置过滤规则：仅仅接受ARP响应和需要路由的帧
	CString Filter, Filter0, Filter1;
	Filter0 = "(";
	Filter1 = "(";
	for (i = 0; i < IfCount; i++)
	{
		Filter0 += "(ether dst " + MACntoa(IfInfo[i].MACAddr) + ")";
		for (j = 0; j < IfInfo[i].ip.GetSize(); j++)
		{
			Filter1 += "(ip dst host " + IPntoa(IfInfo[i].ip[j].IPAddr) + ")";
			if (((j == (IfInfo[i].ip.GetSize() - 1))) && (i == (IfCount - 1)))
			{
				Filter1 += ")";
			}
			else
			{
				Filter1 += " or ";
			}
		}
		if (i == (IfCount - 1))
		{
			Filter0 += ")";
		}
		else
		{
			Filter0 += " or ";
		}
	}
	Filter = Filter0 + " and ((arp and (ether[21]=0x2)) or (not" + Filter1 + "))";
	sprintf_s(strbuf, "%s", Filter);

	for (i = 0; i < IfCount; i++)
	{
		if (pcap_compile(IfInfo[i].adhandle, &fcode, strbuf, 1, IfInfo[i].ip[0].IPMask) < 0)
		{
			MessageBox("过滤规则编译不成功，请检查书写的规则语法是否正确！");
			PostMessage(WM_QUIT, 0, 0);
		}
		if (pcap_setfilter(IfInfo[i].adhandle, &fcode) < 0)
		{
			MessageBox("设置过滤器错误");
			PostMessage(WM_QUIT, 0, 0);
		}
	}
	//释放设备列表
	pcap_freealldevs(alldevs);
	TimerCount = 1;

	//捕获数据包
	for (i = 0; i < IfCount; i++)
	{
		pthread = AfxBeginThread(Capture, &IfInfo[i], THREAD_PRIORITY_NORMAL);
		if (!pthread)
		{
			MessageBox("创建数据包捕获线程失败！");
			PostMessage(WM_QUIT, 0, 0);
		}
	}
}

void CrouterDlg::OnBnClickedButton()
{
	// TODO: 在此添加控件通知处理程序代码
	SendMessage(WM_CLOSE);
}

void CrouterDlg::OnAddRouterButton()
{
	// TODO: 在此添加控件通知处理程序代码
	bool flag;
	int i, j;
	DWORD ipaddr;
	RouteTable_t rt;
	m_NextHop.GetAddress(ipaddr);
	ipaddr = htonl(ipaddr);

	//检查合法性
	flag = false;
	for (i = 0; i < IfCount; i++)
	{
		for (j = 0; j < IfInfo[i].ip.GetSize(); j++)
		{
			if (((IfInfo[i].ip[j].IPAddr)&(IfInfo[i].ip[j].IPMask)) == ((IfInfo[i].ip[j].IPMask)&ipaddr))
			{
				rt.IfNo = i;
				//记录子网掩码
				m_Mask.GetAddress(ipaddr);
				rt.Mask = htonl(ipaddr);
				//记录目的IP
				m_Destination.GetAddress(ipaddr);
				rt.DstIP = htonl(ipaddr);
				//记录下一跳
				m_NextHop.GetAddress(ipaddr);
				rt.NextHop = htonl(ipaddr);
				//添加到路由表
				RouteTable.AddTail(rt);
				//显示该表项
				m_RouteTable.InsertString(-1, IPntoa(rt.Mask) + " -- " + IPntoa(rt.DstIP) + " -- " + IPntoa(rt.NextHop));
				flag = true;
			}
		}
	}
	if (!flag)
	{
		MessageBox("输入错误，请重新输入！");
	}
}

void CrouterDlg::OnDeleteRouterButton()
{
	// TODO: 在此添加控件通知处理程序代码
	int i;
	char str[100], ipaddr[20];
	ULONG mask, destination, nexthop;
	RouteTable_t rt;
	POSITION pos, CurrentPos;
	str[0] = NULL;
	ipaddr[0] = NULL;
	if ((i = m_RouteTable.GetCurSel()) == LB_ERR)
	{
		return;
	}
	m_RouteTable.GetText(i, str);
	//取得子网掩码选项
	strncat_s(ipaddr, str, 15);
	mask = inet_addr(ipaddr);
	//取得目的地址选项
	ipaddr[0] = 0;
	strncat_s(ipaddr, &str[19], 15);
	destination = inet_addr(ipaddr);
	//取得下一跳选项
	ipaddr[0] = 0;
	strncat_s(ipaddr, &str[38], 15);
	nexthop = inet_addr(ipaddr);
	if (nexthop == 0)
	{
		MessageBox("直接连接路由，不允许删除！");
		return;
	}
	//把该路由表项从路由表窗口删除
	m_RouteTable.DeleteString(i);
	//路由表中没有需要处理的内容，返回
	if (RouteTable.IsEmpty())
	{
		return;
	}
	//遍历路由表，把需要删除的路由表项从路由表中删除
	pos = RouteTable.GetHeadPosition();
	for (i = 0; i < RouteTable.GetCount(); i++)
	{
		CurrentPos = pos;
		rt = RouteTable.GetNext(pos);
		if ((rt.Mask == mask) && (rt.DstIP == destination) && (rt.NextHop == nexthop))
		{
			RouteTable.RemoveAt(CurrentPos);
			return;
		}
	}
}

//获取本地接口MAC地址线程
UINT CaptureLocalARP(PVOID pParam)
{
	int res;
	struct pcap_pkthdr *header;
	const u_char *pkt_data;
	IfInfo_t *pIfInfo;
	ARPFrame_t *ARPFrame;
	CString DisplayStr;

	pIfInfo = (IfInfo_t*)pParam;

	while (true)
	{
		Sleep(50);
		res = pcap_next_ex(pIfInfo->adhandle, &header, &pkt_data);
		//超时
		if (res == 0)
			continue;
		if (res > 0)
		{
			ARPFrame = (ARPFrame_t *)(pkt_data);
			//得到本接口的MAC地址
			if ((ARPFrame->FrameHeader.FrameType == htons(0x0806))
				&& (ARPFrame->Operation == htons(0x0002))
				&& (ARPFrame->SendIP == pIfInfo->ip[0].IPAddr))
			{
				cpyMAC(pIfInfo->MACAddr, ARPFrame->SendHa);
				return 0;
			}
		}
	}
}

//设置MAC地址
void setMAC(UCHAR *MAC, UCHAR ch)
{
	for (int i = 0; i < 6; i++)
	{
		MAC[i] = ch;
	}
	return;
}

//发送ARP请求
void ARPRequest(pcap_t *adhandle, UCHAR *srcMAC, ULONG srcIP, ULONG targetIP)
{
	ARPFrame_t ARPFrame;
	int i;
	for (i = 0; i < 6; i++)
	{
		ARPFrame.FrameHeader.DesMAC[i] = 255;
		ARPFrame.FrameHeader.SrcMAC[i] = srcMAC[i];
		ARPFrame.SendHa[i] = srcMAC[i];
		ARPFrame.RecvHa[i] = 0;
	}
	ARPFrame.FrameHeader.FrameType = htons(0x0806);
	ARPFrame.HardwareType = htons(0x0001);
	ARPFrame.ProtocolType = htons(0x0800);
	ARPFrame.Hlen = 6;
	ARPFrame.Plen = 4;
	ARPFrame.Operation = htons(0x0001);
	ARPFrame.SendIP = srcIP;
	ARPFrame.RecvIP = targetIP;

	pcap_sendpacket(adhandle, (u_char*)&ARPFrame, sizeof(ARPFrame_t));
}

//复制MAC地址
void cpyMAC(UCHAR *MAC1, UCHAR *MAC2)
{
	for (int i = 0; i < 6; i++)
	{
		MAC1[i] = MAC2[i];
	}
}

//比较MAC地址
bool cmpMAC(UCHAR *MAC1, UCHAR *MAC2)
{
	for (int i = 0; i < 6; i++)
	{
		if (MAC1[i] == MAC2[i])
		{
			continue;
		}
		else
		{
			return false;
		}
	}
	return true;
}

// IP地址转换
CString IPntoa(ULONG nIPAddr)
{
	char strbuf[50];
	u_char *p;
	CString str;

	p = (u_char *)&nIPAddr;
	sprintf_s(strbuf, "%03d.%03d.%03d.%03d", p[0], p[1], p[2], p[3]);
	str = strbuf;
	return str;
}

//MAC地址转换
CString MACntoa(UCHAR *nMACAddr)
{
	char strbuf[50];
	CString str;
	sprintf_s(strbuf, "%02X:%02X:%02X:%02X:%02X:%02X", nMACAddr[0], nMACAddr[1], nMACAddr[2], nMACAddr[3], nMACAddr[4], nMACAddr[5]);
	str = strbuf;
	return str;
}

// 数据包捕获线程
UINT Capture(PVOID pParam)
{
	int res;
	IfInfo_t *pIfInfo;
	struct pcap_pkthdr *header;
	const u_char *pkt_data;
	pIfInfo = (IfInfo_t *)pParam;

	//开始正式接受并处理帧
	while (true)
	{
		res = pcap_next_ex(pIfInfo->adhandle, &header, &pkt_data);
		if (res == 1)
		{
			FrameHeader_t *fh;
			fh = (FrameHeader_t *)pkt_data;
			switch (ntohs(fh->FrameType))
			{
			case 0x0806:
				ARPFrame_t *ARPf;
				ARPf = (ARPFrame_t *)pkt_data;
				//TRACE1("收到ARP包，源IP为：%d\n", ARPf->SendIP);
				ARPPacketProc(header, pkt_data);
				break;
			case 0x0800:
				IPFrame_t *IPf;
				IPf = (IPFrame_t *)pkt_data;
				//TRACE1("收到IP包，源IP为:%d\n", IPf->IPHeader.SrcIP);
				IPPacketProc(pIfInfo, header, pkt_data);
				break;
			default:
				break;
			}
		}
		else if (res == 0)//超时
		{
			continue;
		}
		else
		{
			MessageBox(NULL, _T("pcap_next_ex函数出错！！"), _T("Error"), MB_OK);
		}
	}
	return 0;
}

//处理ARP数据包
void ARPPacketProc(struct pcap_pkthdr *header, const u_char *pkt_data)
{
	bool flag;
	ARPFrame_t ARPf;
	IPFrame_t *IPf;
	SendPacket_t sPacket;
	POSITION pos, CurrentPos;
	IP_MAC_t ip_mac;
	UCHAR macAddr[6];

	ARPf = *(ARPFrame_t *)pkt_data;

	if (ARPf.Operation == ntohs(0x0002))
	{
		pDlg->Logger.InsertString(-1, _T("收到ARP响应包"));
		CString cs("	ARP");
		pDlg->Logger.InsertString(-1, (cs + (IPntoa(ARPf.SendIP)) + "	 " + MACntoa(ARPf.SendHa)));
		if (IPLookup(ARPf.SendIP, macAddr))
		{
			CString temp("	该对应关系已经存在于IP-MAC地址映射表中");
			pDlg->Logger.InsertString(-1, temp);
			return;
		}
		else
		{
			ip_mac.IPAddr = ARPf.SendIP;
			memcpy(ip_mac.MACAddr, ARPf.SendHa, 6);
			IP_MAC.AddHead(ip_mac);
			//日志输出信息
			CString temp("	将该对应关系存于IP-MAC地址映射表中");
			pDlg->Logger.InsertString(-1, temp);
		}
		mMutex.Lock(INFINITE);
		do {
			//查看是否能转发缓存中的IP数据报
			flag = false;
			//没有需要处理的内容
			if (SP.IsEmpty())
			{
				break;
			}
			//遍历转发缓存区
			pos = SP.GetHeadPosition();
			for (int i = 0; i < SP.GetCount(); i++)
			{
				CurrentPos = pos;
				sPacket = SP.GetNext(pos);
				if (sPacket.TargetIP == ARPf.SendIP)
				{
					IPf = (IPFrame_t *)sPacket.PktData;
					cpyMAC(IPf->FrameHeader.DesMAC, ARPf.SendHa);
					for (int t = 0; t < 6; t++)
					{
						IPf->FrameHeader.SrcMAC[t] = IfInfo[sPacket.IfNo].MACAddr[t];
					}
					//发送IP数据包
					pcap_sendpacket(IfInfo[sPacket.IfNo].adhandle, (u_char *)sPacket.PktData, sPacket.len);
					SP.RemoveAt(CurrentPos);
					//日志输出信息
					CString temp1("	转发缓存区中的目的地址是该MAC地址的IP数据包");
					CString temp2("			发送IP数据包：");
					pDlg->Logger.InsertString(-1, temp1);
					pDlg->Logger.InsertString(-1, (temp2 + IPntoa(IPf->IPHeader.SrcIP) + "->" + IPntoa(IPf->IPHeader.DesIP)
						+ "		" + MACntoa(IPf->FrameHeader.SrcMAC) + "->" + MACntoa(IPf->FrameHeader.DesMAC)));
					flag = true;
					break;
				}
			}
		} while (flag);
		mMutex.Unlock();
	}
}

//IP地址查询
bool IPLookup(ULONG ipaddr, UCHAR *p)
{
	IP_MAC_t ip_mac;
	POSITION pos;
	if (IP_MAC.IsEmpty())
		return false;
	pos = IP_MAC.GetHeadPosition();
	for (int i = 0; i < IP_MAC.GetCount(); i++)
	{
		ip_mac = IP_MAC.GetNext(pos);
		if (ipaddr == ip_mac.IPAddr)
		{
			for (int j = 0; j < 6; j++)
			{
				p[j] = ip_mac.MACAddr[j];
			}
			return true;
		}
	}
	return false;
}

//处理IP数据包
void IPPacketProc(IfInfo_t *pIfInfo, struct pcap_pkthdr *header, const u_char *pkt_data)
{
	IPFrame_t *IPf;
	SendPacket_t sPacket;
	IPf = (IPFrame_t *)pkt_data;
	CString temp1("收到IP数据包:");
	pDlg->Logger.InsertString(-1, (temp1 + IPntoa(IPf->IPHeader.SrcIP) + "->" + IPntoa(IPf->IPHeader.DesIP)));

	//ICMP超时
	if (IPf->IPHeader.TTL <= 0)
	{
		ICMPPacketProc(pIfInfo, 11, 0, pkt_data);
		return;
	}

	IPHeader_t *IpHeader = &(IPf->IPHeader);
	//ICMP差错
	if (IsChecksumRight((char *)IpHeader) == 0)
	{
		//日志输出信息
		CString temp2("	IP数据包包头校验和错误，丢弃数据包");
		pDlg->Logger.InsertString(-1, temp2);
		return;
	}

	//路由查询
	DWORD nextHop;		//经过路由选择算法得到的下一站目的IP地址
	UINT ifNo = 3;			//下一跳的接口序号
	if ((nextHop = RouteLookup(ifNo, IPf->IPHeader.DesIP, &RouteTable)) == -1)
	{
		//ICMP目的不可达
		ICMPPacketProc(pIfInfo, 3, 0, pkt_data);
		return;
	}
	else
	{
		sPacket.IfNo = ifNo;
		sPacket.TargetIP = nextHop;
		cpyMAC(IPf->FrameHeader.SrcMAC, IfInfo[sPacket.IfNo].MACAddr);
		//TTL-1
		IPf->IPHeader.TTL -= 1;
		unsigned short check_buff[sizeof(IPHeader_t)];
		//设IP头中的校验和为0
		IPf->IPHeader.Checknum = 0;
		memset(check_buff, 0, sizeof(IPHeader_t));
		IPHeader_t *ip_header = &(IPf->IPHeader);
		memcpy(check_buff, ip_header, sizeof(IPHeader_t));
		//计算头部校验和
		IPf->IPHeader.Checknum = ChecksumCompute(check_buff, sizeof(IPHeader_t));
		//地址映射表中存在该映射关系
		if (IPLookup(sPacket.TargetIP, IPf->FrameHeader.DesMAC))
		{
			memcpy(sPacket.PktData, pkt_data, header->len);
			sPacket.len = header->len;
			if (pcap_sendpacket(IfInfo[sPacket.IfNo].adhandle, (u_char *)sPacket.PktData, sPacket.len) != 0)
			{
				//错误处理
				MessageBox(NULL, "发送IP数据包时出错！", "Error", MB_OK);
				return;
			}
			//日志输出信息
			CString temp3("	转发IP数据包：");
			pDlg->Logger.InsertString(-1, temp3);
			pDlg->Logger.InsertString(-1, (IPntoa(IPf->IPHeader.SrcIP) + "->" + IPntoa(IPf->IPHeader.DesIP) +
				"	" + MACntoa(IPf->FrameHeader.SrcMAC) + "->" + MACntoa(IPf->FrameHeader.DesMAC)));
		}
		//IP-mac地址映射表不存在该映射关系
		else
		{
			if (SP.GetCount() < 65530)//存入缓存队列
			{
				sPacket.len = header->len;
				//将需要转发的数据报存入缓存区
				memcpy(sPacket.PktData, pkt_data, header->len);
				//在某一时刻之允许一个线程维护链表
				mMutex.Lock(INFINITE);

				sPacket.n_mTimer = TimerCount;
				if (TimerCount++ > 65533)
				{
					TimerCount = 1;
				}
				pDlg->SetTimer(sPacket.n_mTimer, 10000, NULL);
				SP.AddTail(sPacket);
				mMutex.Unlock();
				//日志输出信息
				CString temp4("	缺少目的MAC地址，将IP数据包存入转发缓冲区");
				CString temp5("	存入转发缓冲区的数据包为：");
				pDlg->Logger.InsertString(-1, temp4);
				pDlg->Logger.InsertString(-1, (temp5 + IPntoa(IPf->IPHeader.SrcIP) + "->" + IPntoa(IPf->IPHeader.DesIP) +
					"	" + MACntoa(IPf->FrameHeader.SrcMAC) + "->xx:xx:xx:xx:xx:xx"));
				CString temp6("发送ARP请求");
				pDlg->Logger.InsertString(-1, temp6);

				//发送ARP请求
				ARPRequest(IfInfo[sPacket.IfNo].adhandle, IfInfo[sPacket.IfNo].MACAddr, IfInfo[sPacket.IfNo].ip[1].IPAddr, sPacket.TargetIP);
			}
			else//如缓存队列太长，抛弃该报
			{
				//日志输出信息
				CString temp7("	转发缓冲区溢出，丢弃IP数据包");
				CString temp8("	丢弃的数据包为：");
				pDlg->Logger.InsertString(-1, temp7);
				pDlg->Logger.InsertString(-1, (temp8 + IPntoa(IPf->IPHeader.SrcIP) + "->" + IPntoa(IPf->IPHeader.DesIP)
					+ "	" + MACntoa(IPf->FrameHeader.SrcMAC) + "->xx:xx:xx:xx:xx:xx"));
			}
		}
	}
}

//检查IP数据包头部校验和是否正确
int IsChecksumRight(char *buffer)
{
	//获得IP头内容
	IPHeader_t *ip_header = (IPHeader_t*)buffer;
	//备份原来的校验和
	unsigned short checksumBuf = ip_header->Checknum;
	unsigned short check_buff[sizeof(IPHeader_t)];
	//设IP头中的校验和为0
	ip_header->Checknum = 0;

	memset(check_buff, 0, sizeof(IPHeader_t));
	memcpy(check_buff, ip_header, sizeof(IPHeader_t));

	//计算IP头部的校验和
	ip_header->Checknum = ChecksumCompute(check_buff, sizeof(IPHeader_t));

	//与备份的校验和进行比较
	if (ip_header->Checknum == checksumBuf)
	{
		return 1;
	}
	else
	{
		return 0;
	}
}

//查询路由表
DWORD RouteLookup(UINT &IFno, DWORD desIP, CList<RouteTable_t, RouteTable_t&> *routeTable)
{
	//desIP为网络序
	DWORD MaxMask = 0;//获得最大的子网掩码的地址，没有获得时初始化为0
	int Index = -1;//获得最大的子网掩码的地址对应的路由表索引，以便获得下一站路由器的地址
	POSITION pos;
	RouteTable_t rt;
	DWORD tmp;
	pos = routeTable->GetHeadPosition();
	for (int i = 0; i < routeTable->GetCount(); i++)
	{
		rt = routeTable->GetNext(pos);
		if ((desIP&rt.Mask) == rt.DstIP)
		{
			Index = i;
			if (rt.Mask >= MaxMask)
			{
				IFno = rt.IfNo;
				if (rt.NextHop == 0)//直接投递
				{
					tmp = desIP;
				}
				else
				{
					tmp = rt.NextHop;
				}
			}
		}
	}
	if (Index == -1)//目的不可达
	{
		return -1;
	}
	else//找到了下一跳地址
	{
		return tmp;
	}
}

//处理ICMP数据包
void ICMPPacketProc(IfInfo_t *pIfInfo, BYTE type, BYTE code, const u_char *pkt_data)
{
	u_char *ICMPBuf = new u_char[70];
	//填充帧首部
	memcpy(((FrameHeader_t *)ICMPBuf)->DesMAC, ((FrameHeader_t *)pkt_data)->SrcMAC, 6);
	memcpy(((FrameHeader_t *)ICMPBuf)->SrcMAC, ((FrameHeader_t *)pkt_data)->DesMAC, 6);
	((FrameHeader_t *)ICMPBuf)->FrameType = htons(0x0800);

	//填充IP首部
	((IPHeader_t *)(ICMPBuf + 14))->Ver_Hlen = ((IPHeader_t *)(pkt_data + 14))->Ver_Hlen;
	((IPHeader_t *)(ICMPBuf + 14))->TOS = ((IPHeader_t *)(pkt_data + 14))->TOS;
	((IPHeader_t *)(ICMPBuf + 14))->TotalLen = htons(56);
	((IPHeader_t *)(ICMPBuf + 14))->ID = ((IPHeader_t *)(pkt_data + 14))->ID;
	((IPHeader_t *)(ICMPBuf + 14))->Flag_Segment = ((IPHeader_t*)(pkt_data + 14))->Flag_Segment;
	((IPHeader_t *)(ICMPBuf + 14))->TTL = 64;
	((IPHeader_t *)(ICMPBuf + 14))->Protocol = 1;
	((IPHeader_t *)(ICMPBuf + 14))->SrcIP = ((IPHeader_t *)(pkt_data + 14))->DesIP;
	((IPHeader_t *)(ICMPBuf + 14))->DesIP = ((IPHeader_t *)(pkt_data + 14))->SrcIP;
	((IPHeader_t *)(ICMPBuf + 14))->Checknum = htons(ChecksumCompute((unsigned short *)(ICMPBuf + 14), 20));
	//填充ICMP首部
	((ICMPHeader_t *)(ICMPBuf + 34))->Type = type;
	((ICMPHeader_t *)(ICMPBuf + 34))->Code = code;
	((ICMPHeader_t *)(ICMPBuf + 34))->Id = 0;
	((ICMPHeader_t *)(ICMPBuf + 34))->Sequence = 0;
	((ICMPHeader_t *)(ICMPBuf + 34))->Checknum = htons(ChecksumCompute((unsigned short *)(ICMPBuf + 34), 8));

	//填充数据
	memcpy((u_char *)(ICMPBuf + 42), (IPHeader_t *)(pkt_data + 14), 20);
	memcpy((u_char *)(ICMPBuf + 62), (u_char *)(pkt_data + 34), 8);

	//发送数据包
	pcap_sendpacket(pIfInfo->adhandle, (u_char *)ICMPBuf, 70);

	//日志输出信息
	if (type == 11)
	{
		CString temp1("	发送ICMP超时数据包：");
		pDlg->Logger.InsertString(-1, temp1);
	}
	if (type == 3)
	{
		CString temp2("	发送ICMP目的不可达数据包：");
		pDlg->Logger.InsertString(-1, temp2);
	}
	CString temp3("	ICMP->");
	pDlg->Logger.InsertString(-1, (temp3 + IPntoa(((IPHeader_t *)(ICMPBuf + 14))->DesIP) + "-" + MACntoa(((FrameHeader_t *)ICMPBuf)->DesMAC)));
	delete[]ICMPBuf;
}

//计算校验和
unsigned short ChecksumCompute(unsigned short *buffer, int size)
{
	//32位，延迟进位
	unsigned long cksum = 0;
	while (size > 1)
	{
		cksum += *buffer++;
		//16位相加
		size -= sizeof(unsigned short);
	}
	if (size)
	{
		//最后有可能单独8位
		cksum += *(unsigned char *)buffer;
	}
	//将高16位进位至低16位
	cksum = (cksum >> 16) + (cksum & 0xffff);
	cksum += (cksum >> 16);
	//取反
	return (unsigned short)(~cksum);
}

void CrouterDlg::OnDestroy()
{
	CDialogEx::OnDestroy();

	// TODO: 在此处添加消息处理程序代码
	SP.RemoveAll();
	IP_MAC.RemoveAll();
	RouteTable.RemoveAll();
	for (int i = 0; i < IfCount; i++)
	{
		IfInfo[i].ip.RemoveAll();
	}
}

void CrouterDlg::OnTimer(UINT_PTR nIDEvent)
{
	// TODO: 在此添加消息处理程序代码和/或调用默认值
	SendPacket_t sPacket;
	POSITION pos, CurrentPos;
	IPFrame_t *IPf;
	//没有需要处理的内容
	if (SP.IsEmpty())
	{
		return;
	}
	mMutex.Lock(INFINITE);

	//遍历转发缓存区
	pos = SP.GetHeadPosition();
	for (int i = 0; i < SP.GetCount(); i++)
	{
		CurrentPos = pos;
		sPacket = SP.GetNext(pos);
		if (sPacket.n_mTimer == nIDEvent)
		{
			IPf = (IPFrame_t *)sPacket.PktData;
			//日志输出信息
			Logger.InsertString(-1, "IP数据报在转发队列中等待10秒后还未能被转发");
			Logger.InsertString(-1, ("定时器中删除该IP数据报：" + IPntoa(IPf->IPHeader.SrcIP) + "->" + IPntoa(IPf->IPHeader.DesIP) + "   " + MACntoa(IPf->FrameHeader.SrcMAC) + "->xx:xx:xx:xx:xx:xx"));
			KillTimer(sPacket.n_mTimer);
			SP.RemoveAt(CurrentPos);
		}
	}
	mMutex.Unlock();
	CDialogEx::OnTimer(nIDEvent);
}