#include "pFunc.h"
#include "pch.h"
#include<iostream>

#ifdef _DEBUG
#define new DEBUG_NEW
#endif

pcap_if_t* GetAllDevs() {
	pcap_if_t* alldevs;
	char errbuf[PCAP_ERRBUF_SIZE];
	if (pcap_findalldevs(&alldevs, errbuf) == -1) {
		std::cerr << "获取设备错误: " << errbuf << std::endl;
		return NULL;
	}

	return alldevs;
}

pcap_if_t* GetDev(pcap_if_t* head, int count) {

	pcap_if_t* r = head;
	int c = count;
	while (c > 0) {
		r = r->next;
		c--;
	}

	return r;
}

int LengthOfPPIT(pcap_if_t* tar) {
	pcap_if_t* t = tar;
	int le = 0;
	while (t != NULL)
	{
		t = t->next;
		le++;
	}
	return le;

}

pcap_t* OpenDev(pcap_if_t* device) {
	pcap_t* handle;
	char errbuf[PCAP_ERRBUF_SIZE];
	handle = pcap_open_live(device->name, BUFSIZ, 1, 1000, errbuf);
	if (handle == nullptr) {
		std::cout << "打开设备失败！" << std::endl;
	}
	return handle;
}

void CloseDevs(pcap_if_t* allDevs, pcap_t* handle) {
	pcap_close(handle);
	pcap_freealldevs(allDevs);
}

simple_packet* GetSImplePacket(int num, float time, const pcap_pkthdr* pkt_header, const u_char* pkt) {

	simple_packet* result = new simple_packet;
	ip_header* ip_h = (ip_header*)(pkt + sizeof(ether_header));
	result->no = num;
	result->len = pkt_header->len;
	result->time = time;
	result->ip_srcaddr = ip_h->ip_srcaddr;
	result->ip_destaddr = ip_h->ip_destaddr;
	result->ip_protocol = ip_h->ip_protocol;

	return result;

}