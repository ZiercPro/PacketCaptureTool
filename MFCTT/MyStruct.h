#pragma once
#include <Winsock2.h>

//�洢���ݰ��Ľṹ
struct save_packet {
	struct	pcap_pkthdr* pkt_h;
	struct simple_packet* sm_p;
	u_char* pkt;
};

//�������ݰ���Ϣ
struct simple_packet {
	int no;                     //�����
	float time;                 //ץ������ʱ��
	struct in_addr ip_srcaddr;  // Դ��ַ
	struct in_addr ip_destaddr; // Ŀ�ĵ�ַ
	u_char ip_protocol;         // IPЭ��
	int len;                    //����
};

//���ݰ�GUI��ʾ
struct simple_packet_gui {
	CString no;
	CString time;
	CString len;
	CString srcaddr;
	CString destaddr;
	CString protocol;
};

// ��̫��ͷ���ṹ
struct ether_header {
	u_char ether_dhost[6]; // Ŀ��MAC��ַ
	u_char ether_shost[6]; // ԴMAC��ַ
	u_short ether_type;    // ��̫������
};

// IPͷ���ṹ
struct ipv4_header {
	u_char ip_header_len : 4;    // ͷ������
	u_char ip_version : 4;       // �汾
	u_char ip_tos;              // ��������
	u_short ip_total_length;    // �ܳ���
	u_short ip_id;              // ��ʶ
	u_short ip_frag_offset;     // ��Ƭƫ��
	u_char ip_ttl;              // ����ʱ��
	u_char ip_protocol;         // Э��
	u_short ip_checksum;        // У���
	struct in_addr ip_srcaddr;  // Դ��ַ
	struct in_addr ip_destaddr; // Ŀ�ĵ�ַ
};

// TCPͷ���ṹ
struct tcp_header {
	u_short source_port;   // Դ�˿�
	u_short dest_port;     // Ŀ�Ķ˿�
	u_int sequence;        // ���к�
	u_int ack;             // ȷ�Ϻ�
	u_char data_offset : 4; // ����ƫ��
	u_char reserved : 4;    // ����
	u_char flags;          // ��־λ
	u_short window;        // ���ڴ�С
	u_short checksum;      // У���
	u_short urgent_pointer;// ����ָ��
};

// UDPͷ���ṹ
struct udp_header {
	u_short source_port;   // Դ�˿�
	u_short dest_port;     // Ŀ�Ķ˿�
	u_short udp_length;    // ����
	u_short udp_checksum;  // У���
};

//ARPͷ���ṹ  
struct arphdr
{
	u_short ar_hrd;                     //Ӳ������  
	u_short ar_pro;                     //Э������  
	u_char ar_hln;                      //Ӳ����ַ����  
	u_char ar_pln;                      //Э���ַ����  
	u_short ar_op;                      //�����룬1Ϊ���� 2Ϊ�ظ�  
	u_char ar_srcmac[6];            //���ͷ�MAC  
	u_char ar_srcip[4];             //���ͷ�IP  
	u_char ar_destmac[6];           //���շ�MAC  
	u_char ar_destip[4];                //���շ�IP  
};

//����ICMP  
struct icmphdr
{
	u_char type;            //8λ ����  
	u_char code;            //8λ ����  
	u_char seq;         //���к� 8λ  
	u_char chksum;      //8λУ���  
}; 

// IPЭ�����Ͷ���
enum ProtocolType {
	NUL = -1,
	ICMP = 1,
	IGMP = 2,
	TCP = 6,
	UDP = 17,
};

