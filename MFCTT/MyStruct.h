#pragma once
#include <Winsock2.h>

//存储数据包的结构
struct save_packet {
	struct	pcap_pkthdr* pkt_h;
	struct simple_packet* sm_p;
	u_char* pkt;
};

//简易数据包信息
struct simple_packet {
	int no;                     //包序号
	float time;                 //抓包所用时间
	struct in_addr ip_srcaddr;  // 源地址
	struct in_addr ip_destaddr; // 目的地址
	u_char ip_protocol;         // IP协议
	int len;                    //长度
};

//数据包GUI显示
struct simple_packet_gui {
	CString no;
	CString time;
	CString len;
	CString srcaddr;
	CString destaddr;
	CString protocol;
};

// 以太网头部结构
struct ether_header {
	u_char ether_dhost[6]; // 目的MAC地址
	u_char ether_shost[6]; // 源MAC地址
	u_short ether_type;    // 以太网类型
};

// IP头部结构
struct ipv4_header {
	u_char ip_header_len : 4;    // 头部长度
	u_char ip_version : 4;       // 版本
	u_char ip_tos;              // 服务类型
	u_short ip_total_length;    // 总长度
	u_short ip_id;              // 标识
	u_short ip_frag_offset;     // 分片偏移
	u_char ip_ttl;              // 生存时间
	u_char ip_protocol;         // 协议
	u_short ip_checksum;        // 校验和
	struct in_addr ip_srcaddr;  // 源地址
	struct in_addr ip_destaddr; // 目的地址
};

// TCP头部结构
struct tcp_header {
	u_short source_port;   // 源端口
	u_short dest_port;     // 目的端口
	u_int sequence;        // 序列号
	u_int ack;             // 确认号
	u_char data_offset : 4; // 数据偏移
	u_char reserved : 4;    // 保留
	u_char flags;          // 标志位
	u_short window;        // 窗口大小
	u_short checksum;      // 校验和
	u_short urgent_pointer;// 紧急指针
};

// UDP头部结构
struct udp_header {
	u_short source_port;   // 源端口
	u_short dest_port;     // 目的端口
	u_short udp_length;    // 长度
	u_short udp_checksum;  // 校验和
};

//ARP头部结构  
struct arphdr
{
	u_short ar_hrd;                     //硬件类型  
	u_short ar_pro;                     //协议类型  
	u_char ar_hln;                      //硬件地址长度  
	u_char ar_pln;                      //协议地址长度  
	u_short ar_op;                      //操作码，1为请求 2为回复  
	u_char ar_srcmac[6];            //发送方MAC  
	u_char ar_srcip[4];             //发送方IP  
	u_char ar_destmac[6];           //接收方MAC  
	u_char ar_destip[4];                //接收方IP  
};

//定义ICMP  
struct icmphdr
{
	u_char type;            //8位 类型  
	u_char code;            //8位 代码  
	u_char seq;         //序列号 8位  
	u_char chksum;      //8位校验和  
}; 

// IP协议类型定义
enum ProtocolType {
	NUL = -1,
	ICMP = 1,
	IGMP = 2,
	TCP = 6,
	UDP = 17,
};

