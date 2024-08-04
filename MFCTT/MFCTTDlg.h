
// MFCTTDlg.h: 头文件
//

#pragma once
#include <pcap.h>
#include <windows.h>
#include <list>
#include "MyStruct.h"
#define _WINSOCK_DEPRECATED_NO_WARNINGS

// 暂时取消定义 `inline` 宏（如果有定义的话）
//#ifdef inline
//#undef inline
//#endif

//// 恢复 `inline` 宏定义
//#ifdef _MSC_VER
//#define inline __inline
//#endif


// CMFCTTDlg 对话框
class CMFCTTDlg : public CDialogEx
{
	// 构造
public:
	CMFCTTDlg(CWnd* pParent = nullptr);	// 标准构造函数

	// 对话框数据
#ifdef AFX_DESIGN_TIME
	enum { IDD = IDD_MFCTT_DIALOG };
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

private:
	bool activeState;

	CString stateMsg;

	int tcpCount;
	int udpCount;
	int icmpCount;
	int igmpCount;
	int ipv4Count;
	int ipv6Count;
	int totalCount;

	CFont s_font;
	//设备列表
	pcap_if_t* devList;
	//所选设备
	pcap_if_t* selDevice;
	//处理句柄
	pcap_t* currentHandle;
	//存储的数据包
	std::list <save_packet*> pkt_List;
	//线程句柄
	HANDLE thHandle;
	//过滤参数
	struct bpf_program fcode;
	//网络号
	bpf_u_int32 netp;
	//子网掩码
	bpf_u_int32	maskp;
	//过滤规则
	ProtocolType filter_rule;
	//获取设备列表长度
	int LengthOfPPIT(pcap_if_t* tar);
	//获取所有设备
	pcap_if_t* GetAllDevs();
	//获取设备
	pcap_if_t* GetDev(pcap_if_t* head, int count);
	//打开设备
	pcap_t* OpenDev(pcap_if_t* device);
	//关闭设备
	void CloseDevs(pcap_if_t* allDevs, pcap_t* handle);
	//获取数据包
	simple_packet* GetSimplePacket(int num, float time, const pcap_pkthdr* pkt_header, const u_char* pkt);
	//数据包转GUI版
	simple_packet_gui* GetSimplePacketGui(simple_packet* p);
	//获取数据包完整方法 由其他线程调用
	static DWORD WINAPI GetPackFunc(LPVOID lp);
	//获取MAC类型数据
	ether_header* GetMacData(const u_char* packet);
	//分辨网络层协议
	CString MacProType(const ether_header* eh);
	//解析ip
	ipv4_header* ToIpHead(const pcap_pkthdr* pkt_header, const u_char* pkt);
	//通过ip头获取协议类型
	CString IpproToProType(u_char ipp);
	//解析arp
	arphdr* ToArpHead(u_char* pkt);
	//数据转换为字符
	void DetailToBuf(const u_char* pkt, int size_pkt, CString* buf);
public:
	afx_msg void OnBnClickedStart();
private:
	// 停止按钮
	CButton stopButton;
	// 启动设备按钮
	CButton startButton;
	// 可选设备下拉菜单
	CComboBox devCombo;
	// 过滤规则下拉菜单
	CComboBox filterCombo;
	// 数据包列表
	CListCtrl pktListContrl;
public:
	afx_msg void OnBnClickedStop();
	afx_msg void OnBnClickedClearbutton();
	afx_msg void OnBnClickedFilterbutton();
private:
	// 详情树
	CTreeCtrl detailTree;
public:
	afx_msg void OnNMClickPktlist(NMHDR* pNMHDR, LRESULT* pResult);
};
