
// MFCTTDlg.cpp: 实现文件
//

#include "pch.h"
#include "framework.h"
#include "MFCTT.h"
#include "MFCTTDlg.h"
#include "afxdialogex.h"
#include <iostream>
#include <netioapi.h>

#ifdef _DEBUG
#define new DEBUG_NEW
#endif


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


// CMFCTTDlg 对话框



CMFCTTDlg::CMFCTTDlg(CWnd* pParent /*=nullptr*/)
	: CDialogEx(IDD_MFCTT_DIALOG, pParent)
{
	m_hIcon = AfxGetApp()->LoadIcon(IDR_MAINFRAME);
}

void CMFCTTDlg::DoDataExchange(CDataExchange* pDX)
{
	CDialogEx::DoDataExchange(pDX);
	DDX_Control(pDX, IDC_START, startButton);
	DDX_Control(pDX, IDC_STOP, stopButton);
	DDX_Control(pDX, IDC_DEVCOMBO, devCombo);
	DDX_Control(pDX, IDC_FILTERCOMBO, filterCombo);
	DDX_Control(pDX, IDC_PKTLIST, pktListContrl);
	DDX_Text(pDX, IDC_STATETEXT, stateMsg);
	DDX_Text(pDX, IDC_TOTALCOUNT, totalCount);
	DDX_Text(pDX, IDC_TCPCOUNT, tcpCount);
	DDX_Text(pDX, IDC_UDPCOUNT, udpCount);
	DDX_Text(pDX, IDC_HTTPCOUNT, igmpCount);
	DDX_Text(pDX, IDC_IPV4COUNT, ipv4Count);
	DDX_Text(pDX, IDC_IPV6COUNT, ipv6Count);
	DDX_Text(pDX, IDC_ICMPCOUNT, icmpCount);
	DDX_Control(pDX, IDC_DETAILTREE, detailTree);
}

BEGIN_MESSAGE_MAP(CMFCTTDlg, CDialogEx)
	ON_WM_SYSCOMMAND()
	ON_WM_PAINT()
	ON_WM_QUERYDRAGICON()
	ON_BN_CLICKED(IDC_START, &CMFCTTDlg::OnBnClickedStart)
	ON_BN_CLICKED(IDC_STOP, &CMFCTTDlg::OnBnClickedStop)
	ON_BN_CLICKED(IDC_CLEARBUTTON, &CMFCTTDlg::OnBnClickedClearbutton)
	ON_BN_CLICKED(IDC_FILTERBUTTON, &CMFCTTDlg::OnBnClickedFilterbutton)
	ON_NOTIFY(NM_CLICK, IDC_PKTLIST, &CMFCTTDlg::OnNMClickPktlist)
END_MESSAGE_MAP()


// CMFCTTDlg 消息处理程序

BOOL CMFCTTDlg::OnInitDialog()
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
	s_font.CreatePointFont(150, _T("微软雅黑"), NULL);
	startButton.SetFont(&s_font, false);
	stopButton.SetFont(&s_font, false);

	//初始化状态
	UpdateData(true);
	stateMsg = _T("未启动");
	UpdateData(false);

	//获取所有设备
	devList = GetAllDevs();
	//显示所有设备
	pcap_if_t* device = devList;

	while (device != NULL) {
		CString n = (CString)device->name;
		devCombo.AddString(n);
		device = device->next;
	}

	devCombo.SetCurSel(0);

	//显示所有过滤规则
	filterCombo.AddString(_T("无"));
	filterCombo.AddString(_T("TCP"));
	filterCombo.AddString(_T("UDP"));
	filterCombo.AddString(_T("IGMP"));
	filterCombo.AddString(_T("ICMP"));
	filterCombo.AddString(_T("ARP"));
	filterCombo.AddString(_T("IPv4"));
	filterCombo.AddString(_T("IPv6"));

	filterCombo.SetCurSel(0);

	//初始化数据包列表各列名
	CRect rectL;
	pktListContrl.GetWindowRect(&rectL);
	int widL = rectL.right - rectL.left;
	int nColL = widL / 6;  //列宽
	pktListContrl.SetExtendedStyle(LVS_EX_FULLROWSELECT | LVS_EX_GRIDLINES);

	pktListContrl.InsertColumn(0, _T("序号"), LVCFMT_LEFT, 60);
	pktListContrl.InsertColumn(1, _T("时间"), LVCFMT_LEFT, 150);
	pktListContrl.InsertColumn(2, _T("长度"), LVCFMT_LEFT, 60);
	pktListContrl.InsertColumn(3, _T("源IP地址"), LVCFMT_LEFT, 200);
	pktListContrl.InsertColumn(4, _T("目的IP地址"), LVCFMT_LEFT, 200);
	pktListContrl.InsertColumn(5, _T("协议类型"), LVCFMT_LEFT, 100);

	UpdateData(true);
	//清除数据统计
	tcpCount = 0;
	udpCount = 0;
	icmpCount = 0;
	igmpCount = 0;
	ipv4Count = 0;
	ipv6Count = 0;
	totalCount = 0;
	UpdateData(false);


	return TRUE;  // 除非将焦点设置到控件，否则返回 TRUE
}

void CMFCTTDlg::OnSysCommand(UINT nID, LPARAM lParam)
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

void CMFCTTDlg::OnPaint()
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
HCURSOR CMFCTTDlg::OnQueryDragIcon()
{
	return static_cast<HCURSOR>(m_hIcon);
}

simple_packet_gui* CMFCTTDlg::GetSimplePacketGui(simple_packet* p) {
	simple_packet_gui* r = new simple_packet_gui;
	CString t;

	t.Format(_T("%d"), p->no);
	r->no = t;

	t.Format(_T("%f"), p->time);
	r->time = t;

	t.Format(_T("%d"), p->len);
	r->len = t;

	t = inet_ntoa(p->ip_srcaddr);
	r->srcaddr = t;

	t = inet_ntoa(p->ip_destaddr);
	r->destaddr = t;

	t = IpproToProType(p->ip_protocol);
	r->protocol = t;

	return r;
}

pcap_if_t* CMFCTTDlg::GetAllDevs() {
	pcap_if_t* alldevs;
	char errbuf[PCAP_ERRBUF_SIZE];
	if (pcap_findalldevs(&alldevs, errbuf) == -1) {
		std::cerr << "获取设备错误: " << errbuf << std::endl;
		return NULL;
	}

	return alldevs;
}

pcap_if_t* CMFCTTDlg::GetDev(pcap_if_t* head, int count) {

	pcap_if_t* r = head;
	int c = count;
	while (c > 0) {
		r = r->next;
		c--;
	}

	return r;
}

int CMFCTTDlg::LengthOfPPIT(pcap_if_t* tar) {
	pcap_if_t* t = tar;
	int le = 0;
	while (t != NULL)
	{
		t = t->next;
		le++;
	}
	return le;

}

pcap_t* CMFCTTDlg::OpenDev(pcap_if_t* device) {
	pcap_t* handle;
	char errbuf[PCAP_ERRBUF_SIZE];
	handle = pcap_open_live(device->name, BUFSIZ, 1, 1000, errbuf);
	if (handle == nullptr) {
		std::cout << "打开设备失败！" << std::endl;
	}
	return handle;
}

void CMFCTTDlg::CloseDevs(pcap_if_t* allDevs, pcap_t* handle) {
	pcap_close(handle);
}

simple_packet* CMFCTTDlg::GetSimplePacket(int num, float time, const pcap_pkthdr* pkt_header, const u_char* pkt) {

	simple_packet* result = new simple_packet;
	ipv4_header* ip_h = (ipv4_header*)(pkt + sizeof(ether_header));
	result->no = num;
	result->len = pkt_header->len;
	result->time = time;
	result->ip_srcaddr = ip_h->ip_srcaddr;
	result->ip_destaddr = ip_h->ip_destaddr;
	result->ip_protocol = ip_h->ip_protocol;

	return result;

}



DWORD WINAPI CMFCTTDlg::GetPackFunc(LPVOID lp) {
	CMFCTTDlg* cp = (CMFCTTDlg*)lp;
	int num;

	cp->pkt_List.clear();

	simple_packet* s_pkt;
	simple_packet_gui* s_pkt_gui;
	struct	pcap_pkthdr* pkt_header;
	const u_char* pkt;
	ether_header* eh;

	long s = GetTickCount();

	CString css;

	//开始获取数据包
	while (cp->activeState) {


		int r = pcap_next_ex(cp->currentHandle, &pkt_header, &pkt);
		if (r == 1 || r == -2) {


			long c = GetTickCount();
			num = cp->pktListContrl.GetItemCount();
			float timeD = (c - s) / 1000.0;//时间差

			eh = cp->GetMacData(pkt);

			s_pkt = cp->GetSimplePacket(num, timeD, pkt_header, pkt);

			s_pkt_gui = cp->GetSimplePacketGui(s_pkt);

			if (s_pkt_gui->protocol == "Unkown") {
				s_pkt_gui->protocol = cp->MacProType(eh);
			}
			//添加数据包
			save_packet* newS = new save_packet;
			u_char* newP = (u_char*)pkt;
			newS->pkt = newP;
			newS->pkt_h = pkt_header;

			cp->pkt_List.push_back(newS);

			//将包渲染到列表中
			cp->pktListContrl.InsertItem(num, s_pkt_gui->no);
			cp->pktListContrl.SetItemText(num, 1, s_pkt_gui->time);
			cp->pktListContrl.SetItemText(num, 2, s_pkt_gui->len);
			cp->pktListContrl.SetItemText(num, 3, s_pkt_gui->srcaddr);
			cp->pktListContrl.SetItemText(num, 4, s_pkt_gui->destaddr);
			cp->pktListContrl.SetItemText(num, 5, s_pkt_gui->protocol);

			num++;
			//更新包的数据
			switch (s_pkt->ip_protocol)
			{
			case TCP:
				cp->tcpCount++;
				break;
			case UDP:
				cp->udpCount++;
				break;
			case ICMP:
				cp->icmpCount++;
				break;
			case IGMP:
				cp->igmpCount++;
			default:
				break;
			}
			u_short e_type = ntohs(eh->ether_type);
			switch (e_type) {
			case 0x0800:
				cp->ipv4Count++;
				break;
			case 0x86dd:
				cp->ipv6Count++;
				break;
			default:
				break;
			}
			cp->totalCount++;

			css.Format(_T("%d"), cp->totalCount);
			cp->GetDlgItem(IDC_TOTALCOUNT)->SetWindowText(css);
			css.Format(_T("%d"), cp->tcpCount);
			cp->GetDlgItem(IDC_TCPCOUNT)->SetWindowText(css);
			css.Format(_T("%d"), cp->udpCount);
			cp->GetDlgItem(IDC_UDPCOUNT)->SetWindowText(css);
			css.Format(_T("%d"), cp->icmpCount);
			cp->GetDlgItem(IDC_ICMPCOUNT)->SetWindowText(css);
			css.Format(_T("%d"), cp->igmpCount);
			cp->GetDlgItem(IDC_IGMPCOUNT)->SetWindowText(css);
			css.Format(_T("%d"), cp->ipv4Count);
			cp->GetDlgItem(IDC_IPV4COUNT)->SetWindowText(css);
			css.Format(_T("%d"), cp->ipv6Count);
			cp->GetDlgItem(IDC_IPV6COUNT)->SetWindowText(css);


		}

	}


	return 0;

}

ether_header* CMFCTTDlg::GetMacData(const u_char* packet) {
	struct ether_header* eth_header = (struct ether_header*)packet;
	return eth_header;
}

CString CMFCTTDlg::MacProType(const ether_header* eh) {
	CString r;
	u_short type = ntohs(eh->ether_type);
	switch (type) {
	case 0x0806:r = _T("ARP");
		break;
	case 0x0800:r = _T("IPv4");
		break;
	case 0x86dd:r = _T("IPv6");
		break;
	default:
		r = _T("Unkown");
		break;
	}

	return r;
}

CString CMFCTTDlg::IpproToProType(u_char ipp) {
	CString r;
	switch ((unsigned int)ipp) {
	case ICMP:
		r = _T("ICMP");
		break;
	case TCP:
		r = _T("TCP");
		break;
	case UDP:
		r = _T("UDP");
		break;
	case IGMP:
		r = _T("IGMP");
		break;
	default:
		r.Format(_T("Unkown"));
		break;
	}

	return r;
}

ipv4_header* CMFCTTDlg::ToIpHead(const pcap_pkthdr* pkt_header, const u_char* pkt) {
	ipv4_header* ip_h = (ipv4_header*)(pkt + sizeof(ether_header));
	return ip_h;
}

void CMFCTTDlg::OnBnClickedStart()
{
	// TODO: 在此添加控件通知处理程序代码
	//获取被选择的设备
	UpdateData(true);

	int selN = devCombo.GetCurSel();
	selDevice = GetDev(devList, selN);
	currentHandle = OpenDev(selDevice);
	if (currentHandle == NULL) {
		MessageBox(_T("设备开启失败！请重试"));
	}
	else {
		//按钮
		activeState = true;

		stopButton.EnableWindow(true);
		startButton.EnableWindow(false);
		GetDlgItem(IDC_FILTERBUTTON)->EnableWindow(true);

		stateMsg = _T("捕获中");
		//开始获取数据包
		thHandle = CreateThread(NULL, 0, GetPackFunc, this, 0, NULL);
	}
	UpdateData(false);
}





void CMFCTTDlg::OnBnClickedStop()
{
	// TODO: 在此添加控件通知处理程序代码


	activeState = false;
	//关闭线程
	CloseHandle(thHandle);
	//关闭设备
	CloseDevs(selDevice, currentHandle);

	//清除数据统计
	UpdateData(true);
	tcpCount = 0;
	udpCount = 0;
	icmpCount = 0;
	igmpCount = 0;
	ipv4Count = 0;
	ipv6Count = 0;
	totalCount = 0;

	stateMsg = _T("未启动");
	UpdateData(false);

	stopButton.EnableWindow(false);
	startButton.EnableWindow(true);
	GetDlgItem(IDC_FILTERBUTTON)->EnableWindow(false);

}


void CMFCTTDlg::DetailToBuf(const u_char* pkt, int size_pkt, CString* buf)
{
	int i = 0, j = 0, rowcount;
	u_char ch;

	char tempbuf[256];
	memset(tempbuf, 0, 256);

	for (i = 0; i < size_pkt; i += 16)
	{
		buf->AppendFormat(_T("%04x:  "), (u_int)i);
		rowcount = (size_pkt - i) > 16 ? 16 : (size_pkt - i);

		for (j = 0; j < rowcount; j++)
			buf->AppendFormat(_T("%02x  "), (u_int)pkt[i + j]);

		//不足16，用空格补足
		if (rowcount < 16)
			for (j = rowcount; j < 16; j++)
				buf->AppendFormat(_T("    "));


		for (j = 0; j < rowcount; j++)
		{
			ch = pkt[i + j];
			ch = isprint(ch) ? ch : '.';
			buf->AppendFormat(_T("%c"), ch);
		}

		buf->Append(_T("\r\n"));
		if (rowcount < 16)
			return;
	}
}

arphdr* CMFCTTDlg::ToArpHead(u_char* pkt) {
	arphdr* r = (arphdr*)(pkt + 14);
	return r;
}



void CMFCTTDlg::OnBnClickedClearbutton()
{
	// TODO: 在此添加控件通知处理程序代码
	pktListContrl.DeleteAllItems();
	pkt_List.clear();
}


void CMFCTTDlg::OnBnClickedFilterbutton()
{

	//编译过滤器

	char* filter_ruleC;
	int c = filterCombo.GetCurSel();
	CString sulS;
	char errBuf[PCAP_ERRBUF_SIZE];


	filterCombo.GetLBText(c, sulS);
	if (sulS == "TCP") {
		filter_ruleC = "ip proto \\tcp";
	}
	else if (sulS == "UDP") {
		filter_ruleC = "ip proto \\udp";
	}
	else if (sulS == "ICMP") {
		filter_ruleC = "ip proto \\icmp";
	}
	else if (sulS == "IGMP") {
		filter_ruleC = "ip proto 2";
	}
	else if (sulS == "ARP") {
		filter_ruleC = "ether proto \\arp";
	}
	else if (sulS == "IPv4") {
		filter_ruleC = "ether proto \\ip";
	}
	else if (sulS == "IPv6") {
		filter_ruleC = "ether proto \\ip6";
	}
	else if (sulS == "无") {
		filter_ruleC = "";
	}

	//获取网络参数
	if (pcap_lookupnet(selDevice->name, &netp, &maskp, errBuf) == -1) {
		MessageBox(_T("获取网络参数失败!"));
		return;
	}

	//编译过滤器
	if (pcap_compile(currentHandle, &fcode, filter_ruleC, 0, maskp) == -1) {
		MessageBox(_T("过滤器编译失败!"));
		return;
	}

	pktListContrl.DeleteAllItems();

	if (pcap_setfilter(currentHandle, &fcode) == -1) {
		MessageBox(_T("设置过滤器失败！"));


		activeState = false;
		//关闭线程
		CloseHandle(thHandle);
		//关闭设备
		CloseDevs(selDevice, currentHandle);

		//清除数据统计
		UpdateData(true);
		tcpCount = 0;
		udpCount = 0;
		icmpCount = 0;
		igmpCount = 0;
		ipv4Count = 0;
		ipv6Count = 0;
		totalCount = 0;

		stateMsg = _T("未启动");
		UpdateData(false);

		stopButton.EnableWindow(false);
		startButton.EnableWindow(true);
		return;
	}

}



void CMFCTTDlg::OnNMClickPktlist(NMHDR* pNMHDR, LRESULT* pResult)
{
	detailTree.DeleteAllItems();
	HTREEITEM eroot;
	HTREEITEM iproot;
	HTREEITEM arproot;
	save_packet* selP;
	CString tcs;
	LPNMITEMACTIVATE pNMItemActivate = reinterpret_cast<LPNMITEMACTIVATE>(pNMHDR);
	// TODO: 在此添加控件通知处理程序代码
	*pResult = 0;
	int selC = pktListContrl.GetSelectionMark();
	if (selC >= 0) {
		std::list<save_packet*>::iterator it;
		if (pkt_List.empty()) {
			return;
		}
		// 遍历
		for (it = pkt_List.begin(); it != pkt_List.end(); it++) {
			if (selC == 0) {
				selP = *it;
			}
			selC--;
		}
		if (selP == NULL)return;
		//显示数据

		//16进制 数据包
		DetailToBuf(selP->pkt, selP->pkt_h->len, &tcs);
		GetDlgItem(IDC_DETAILEDIT)->SetWindowText(tcs);
		//以太网头
		ether_header* spe = GetMacData(selP->pkt);
		eroot = detailTree.InsertItem(_T("以太网帧头"));
		tcs.Format(_T("源MAC地址: %.2x::%.2x::%.2x::%.2x::%.2x::%.2x"), spe->ether_shost[0], spe->ether_shost[1], spe->ether_shost[2], spe->ether_shost[3], spe->ether_shost[4], spe->ether_shost[5]);
		detailTree.InsertItem(tcs, eroot);
		tcs.Format(_T("目的MAC地址:  %.2x::%.2x::%.2x::%.2x::%.2x::%.2x"), spe->ether_dhost[0], spe->ether_dhost[1], spe->ether_dhost[2], spe->ether_dhost[3], spe->ether_dhost[4], spe->ether_dhost[5]);
		detailTree.InsertItem(tcs, eroot);
		tcs.Format(_T("以太网类型：%.2x"), spe->ether_type);
		detailTree.InsertItem(tcs, eroot);

		CString ehT = MacProType(spe);
		if (ehT == "ARP") {
			//ARP帧头
			arphdr* arp_h = ToArpHead(selP->pkt);
			arproot = detailTree.InsertItem(_T("ARP帧头"));
			tcs.Format(_T("硬件类型：%d"), ntohs(arp_h->ar_hrd));
			detailTree.InsertItem(tcs, arproot);
			tcs.Format(_T("协议类型：%d"), ntohs(arp_h->ar_pro));
			detailTree.InsertItem(tcs, arproot);
			tcs.Format(_T("硬件地址长度：%c"), (int)arp_h->ar_hln);
			detailTree.InsertItem(tcs, arproot);
			tcs.Format(_T("协议地址长度：%c"), (int)arp_h->ar_pln);
			detailTree.InsertItem(tcs, arproot);
			tcs.Format(_T("操作码(1为请求 2为回复)：%d"), ntohs(arp_h->ar_op));
			detailTree.InsertItem(tcs, arproot);
			tcs.Format(_T("发送方MAC：%.2x::%.2x::%.2x::%.2x::%.2x::%.2x"), arp_h->ar_srcmac[0], arp_h->ar_srcmac[1], arp_h->ar_srcmac[2], arp_h->ar_srcmac[3], arp_h->ar_srcmac[4], arp_h->ar_srcmac[5]);
			detailTree.InsertItem(tcs, arproot);
			tcs.Format(_T("发送方IP ：%d.%d.%d.%d"), arp_h->ar_srcip[0], arp_h->ar_srcip[1], arp_h->ar_srcip[2], arp_h->ar_srcip[3]);
			detailTree.InsertItem(tcs, arproot);
			tcs.Format(_T("接收方MAC ：%.2x::%.2x::%.2x::%.2x::%.2x::%.2x"), arp_h->ar_destmac[0], arp_h->ar_destmac[1], arp_h->ar_destmac[2], arp_h->ar_destmac[3], arp_h->ar_destmac[4], arp_h->ar_destmac[5]);
			detailTree.InsertItem(tcs, arproot);
			tcs.Format(_T("接收方IP ：%d.%d.%d.%d"), arp_h->ar_destip[0], arp_h->ar_destip[1], arp_h->ar_destip[2], arp_h->ar_destip[3]);
			detailTree.InsertItem(tcs, arproot);

		}
		else {
			//IPv4帧头
			ipv4_header* ip_h = ToIpHead(selP->pkt_h, selP->pkt);
			iproot = detailTree.InsertItem(_T("IP帧头"));
			tcs.Format(_T("头部长度：%d"), (int)ip_h->ip_header_len);
			detailTree.InsertItem(tcs, iproot);
			tcs.Format(_T("版本：%d"), (int)ip_h->ip_version);
			detailTree.InsertItem(tcs, iproot);
			tcs.Format(_T("服务类型：%d"), (int)ip_h->ip_tos);
			detailTree.InsertItem(tcs, iproot);
			tcs.Format(_T("总长度：%d", ntohs(ip_h->ip_total_length)));
			detailTree.InsertItem(tcs, iproot);
			tcs.Format(_T("标识：%d"), ntohs(ip_h->ip_id));
			detailTree.InsertItem(tcs, iproot);
			tcs.Format(_T("分片偏移：%d"), ntohs(ip_h->ip_frag_offset));
			detailTree.InsertItem(tcs, iproot);
			tcs.Format(_T("生存时间：%d"), (int)ip_h->ip_ttl);
			detailTree.InsertItem(tcs, iproot);
			tcs.Format(_T("协议：%d"), (int)ip_h->ip_protocol);
			detailTree.InsertItem(tcs, iproot);
			tcs.Format(_T("校验和：%hd", ntohs(ip_h->ip_checksum)));
			detailTree.InsertItem(tcs, iproot);
			tcs.Format(_T("源地址："));
			tcs += inet_ntoa(ip_h->ip_srcaddr);
			detailTree.InsertItem(tcs, iproot);
			tcs.Format(_T("目的地址："));
			tcs += inet_ntoa(ip_h->ip_destaddr);
			detailTree.InsertItem(tcs, iproot);

			switch ((unsigned int)ip_h->ip_protocol)
			{
			case TCP:
			case UDP:
			case ICMP:
			case IGMP:
			default:
				break;
			}
		}


	}
}
