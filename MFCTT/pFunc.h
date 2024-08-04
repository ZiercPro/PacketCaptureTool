//#pragma once
//#include "MyStruct.h"
//#include "pch.h"
//#include <pcap.h>
//
//// 暂时取消定义 `inline` 宏（如果有定义的话）
//#ifdef inline
//#undef inline
//#endif
//
////// 恢复 `inline` 宏定义
////#ifdef _MSC_VER
////#define inline __inline
////#endif
//
////获取设备列表长度
//int LengthOfPPIT(pcap_if_t* tar);
////获取所有设备
//pcap_if_t* GetAllDevs();
////获取设备
//pcap_if_t* GetDev(pcap_if_t* head, int count);
////打开设备
//pcap_t* OpenDev(pcap_if_t* device);
////关闭设备
//void CloseDevs(pcap_if_t* allDevs, pcap_t* handle);
////获取数据包
////simple_packet* GetSImplePacket(int num, float time, const pcap_pkthdr* pkt_header, const u_char* pkt);
////更新GUI显示
//void UpdateGui();
//
