#pragma once
#ifndef SENDARPREPLY_H
#define SENDARPREPLY_H
#include "..\common.h"
#include "..\interface\interface.h"
#include "..\layer2\layer2.h"

void sendARPReply(Iface *iface, const uint8_array_6 &request_mac ,uint32_t request_ip){
  Layer2 l2;
	std::deque<uint8_t> packet;
	
	uint8_array_6 src_mac;
	iface->getMAC(src_mac);
	
	uint32_t src_ip = iface->getIPV4();
  
	l2.addArpHeader( packet, PROTOCOL::arp_op_reply, src_mac, src_ip, request_mac, request_ip);

	l2.addEthernetHeader(packet, src_mac, request_mac, PROTOCOL::ethertype_arp);

	std::cout<<"Dhcp(ARP Reply): "<<packet.size()<<std::endl;
	iface->putMessageInOutputIface(&packet);
}

#endif // SENDARPREPLY_H