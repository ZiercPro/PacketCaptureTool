//#pragma once
//#include "MyStruct.h"
//#include "pch.h"
//#include <pcap.h>
//
//// ��ʱȡ������ `inline` �꣨����ж���Ļ���
//#ifdef inline
//#undef inline
//#endif
//
////// �ָ� `inline` �궨��
////#ifdef _MSC_VER
////#define inline __inline
////#endif
//
////��ȡ�豸�б���
//int LengthOfPPIT(pcap_if_t* tar);
////��ȡ�����豸
//pcap_if_t* GetAllDevs();
////��ȡ�豸
//pcap_if_t* GetDev(pcap_if_t* head, int count);
////���豸
//pcap_t* OpenDev(pcap_if_t* device);
////�ر��豸
//void CloseDevs(pcap_if_t* allDevs, pcap_t* handle);
////��ȡ���ݰ�
////simple_packet* GetSImplePacket(int num, float time, const pcap_pkthdr* pkt_header, const u_char* pkt);
////����GUI��ʾ
//void UpdateGui();
//
