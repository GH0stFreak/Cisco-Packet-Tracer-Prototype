#pragma once
#ifndef LAYER3_H
#define LAYER3_H
#include "..\layer2\layer2.h"
#include "..\interface\serverIface.h"
//#include "..\interface\clientIface.h"



enum Icmp_state {
	PENDING,  // Request sent waiting for reply
	REPLIED,  // Not needed
	TIMEOUT,  // Timeout exceeded
	FAILED    // Retry count exceeded
};

const static uint8_t DEFAULT_RETRY_COUNT = 3;		// Default should be 3 attempts
const static uint8_t DEFAULT_TIMEOUT_TIME = 3;	// Default should be 1 second but have it as 3 seconds for my system speed 

struct Icmp_pkt_status {
	uint16_t identifier {};  	// Used to match icmp req and reply
	uint16_t sequence_no {};  // Used to match icmp req and reply
	uint32_t send_timestamp;  // Used to know the Round Trip Time 
	uint32_t src_ip {};  // Used for multiple interfaces like router or server
	uint32_t dst_ip {};  			// Used for matching destination
	Icmp_state curr_state;  	// Current State of the icmp
	uint8_t retry_count {};  	// Whenever timeout timer runs out another packet is sent as retry th
	uint8_t timeout_timer {}; // Timeout timer for retry
	uint8_t send_data[ICMP_DATA_SIZE] {0};  // Used to match the payload sent

	Icmp_pkt_status(uint16_t tempId, uint16_t tempSeq, uint32_t tempTime, uint32_t tempSrcIp, uint32_t tempDstIp, uint8_t payload[ICMP_DATA_SIZE]){
		identifier	= tempId;
		sequence_no = tempSeq;
		send_timestamp = tempTime;
		src_ip 			= tempSrcIp;
		dst_ip 			= tempDstIp;
		curr_state  = PENDING;
		for(size_t i {}; i<ICMP_DATA_SIZE; i++){
			send_data[i] = payload[i];
		}
	}

};

//template <typename T, typename U>
//class RouterIface;
// template <typename T>
// class Layer3 : public Layer2<T> {

class Layer3 : public Layer2 {
public:
  
PROTOCOL::ip_protocol processIPv4Header(ClientIface *iface, PROTOCOL::ipv4_hdr &ipv4_hdr){
		
		std::list<uint8_t> temp;
		ipv4_hdr.serialize(temp);

		if(!verifyChecksum(temp)) { return PROTOCOL::ip_protocol_ERROR; }

		if(IS_LITTLE_ENDIAN) {
			if((((ipv4_hdr.ip_v_hl & IP_V)>>4) != 4) || (((ipv4_hdr.ip_v_hl & IP_HL)<<2) < 20) ){
				return PROTOCOL::ip_protocol_ERROR;
			}
		}else{
			if(((ipv4_hdr.ip_v_hl & IP_V) != 4) || (((ipv4_hdr.ip_v_hl & IP_HL)>>2) < 20) ){
				return PROTOCOL::ip_protocol_ERROR;
			}
		}

		if((ipv4_hdr.ip_dst == iface->getIPV4()) || (ipv4_hdr.ip_dst == PROTOCOL::BroadcastIPAddr)) { 
			
			switch(ipv4_hdr.ip_p) 
				{
					case PROTOCOL::ip_protocol_icmp:
						return PROTOCOL::ip_protocol_icmp;
					case PROTOCOL::ip_protocol_tcp:
						return PROTOCOL::ip_protocol_tcp;
					case PROTOCOL::ip_protocol_udp:
						return PROTOCOL::ip_protocol_udp;
					default: 
						return PROTOCOL::ip_protocol_ERROR;
				}
		}
		return PROTOCOL::ip_protocol_ERROR;
	}

PROTOCOL::ip_protocol processIPv4Header(DhcpIface *iface, PROTOCOL::ipv4_hdr &ipv4_hdr){
	
	std::list<uint8_t> temp;
  ipv4_hdr.serialize(temp);

	if(!verifyChecksum(temp)) { return PROTOCOL::ip_protocol_ERROR; }

	if(IS_LITTLE_ENDIAN) {
    if((((ipv4_hdr.ip_v_hl & IP_V)>>4) != 4) || (((ipv4_hdr.ip_v_hl & IP_HL)<<2) < 20) ){
			return PROTOCOL::ip_protocol_ERROR;
    }
	}else{
		if(((ipv4_hdr.ip_v_hl & IP_V) != 4) || (((ipv4_hdr.ip_v_hl & IP_HL)>>20) < 20) ){
			return PROTOCOL::ip_protocol_ERROR;
    }
	}

	if((ipv4_hdr.ip_dst == iface->getIPV4()) || (ipv4_hdr.ip_dst == PROTOCOL::BroadcastIPAddr)) { 
		
		switch(ipv4_hdr.ip_p) 
			{
				case PROTOCOL::ip_protocol_icmp:
					return PROTOCOL::ip_protocol_icmp;
				case PROTOCOL::ip_protocol_tcp:
					return PROTOCOL::ip_protocol_tcp;
				case PROTOCOL::ip_protocol_udp:
					return PROTOCOL::ip_protocol_udp;
				default: 
					return PROTOCOL::ip_protocol_ERROR;
			}
	}

	// TODO: Process options field as well

	return PROTOCOL::ip_protocol_ERROR; 
}

template <typename QueueType, typename BufferType>
PROTOCOL::ip_protocol processIPv4Header(RouterIface<QueueType,BufferType> *iface, PROTOCOL::ipv4_hdr &ipv4_hdr){
	std::list<uint8_t> temp;
  ipv4_hdr.serialize(temp);

	if(!verifyChecksum(temp)) { return PROTOCOL::ip_protocol_ERROR; }

	if(IS_LITTLE_ENDIAN) {
    if((((ipv4_hdr.ip_v_hl & IP_V)>>4) != 4) || (((ipv4_hdr.ip_v_hl & IP_HL)<<2) < 20) ){
			return PROTOCOL::ip_protocol_ERROR;
    }
	}else{
		if(((ipv4_hdr.ip_v_hl & IP_V) != 4) || (((ipv4_hdr.ip_v_hl & IP_HL)>>20) < 20) ){
			return PROTOCOL::ip_protocol_ERROR;
    }
	}

	if(--ipv4_hdr.ip_ttl<1) return PROTOCOL::ip_protocol_ERROR;

	if(ipv4_hdr.ip_dst == PROTOCOL::BroadcastIPAddr) return PROTOCOL::ip_protocol_ERROR;

	if(ipv4_hdr.ip_dst == iface->getIPV4() && ipv4_hdr.ip_p == PROTOCOL::ip_protocol_icmp) return PROTOCOL::ip_protocol_PROCESS;

	return PROTOCOL::ip_protocol_FORWARD;
}

PROTOCOL::action processICMPHeader(Iface *iface, PROTOCOL::icmp_t0_hdr icmp_t0_hdr){
	// std::cout<<"ProcessICMP: "<<ipToString(iface->getIPV4())<<std::endl;
	uint16_t checksum = icmp_t0_hdr.icmp_sum;
	icmp_t0_hdr.icmp_sum = 0;
	//icmp_t0_hdr.display();
	std::list<uint8_t> temp;
  icmp_t0_hdr.serialize(temp);

	if(checksum != calculateChecksum(temp)){ return PROTOCOL::PACKET_ERROR; }
	// std::cout<<"No checksum error\n";

	if(icmp_t0_hdr.icmp_type == 0 && icmp_t0_hdr.icmp_code == 0){
		// std::cout<<"receive req\n";
		return PROTOCOL::RECEIVE_ICMP_REQUEST;
	}else if(icmp_t0_hdr.icmp_type == 8 && icmp_t0_hdr.icmp_code == 0){
		// std::cout<<"receive reply\n";
		return PROTOCOL::RECEIVE_ICMP_REPLY;
	}

	return PROTOCOL::PACKET_ERROR;
}

void processICMPReply(Iface *iface, PROTOCOL::icmp_t0_hdr icmp_t0_hdr, uint32_t curr_time){
	// std::cout<<"REPLYHERE: "<<icmp_pkt_status.size()<<std::endl;
	
	
	for(Icmp_pkt_status &stat: icmp_pkt_status){
		if(icmp_t0_hdr.icmp_id == stat.identifier && icmp_t0_hdr.icmp_seq == stat.sequence_no && stat.curr_state == PENDING){
			for(size_t i{}; i<ICMP_DATA_SIZE;i++){
				// std::cout<<"DATA: "<<+stat.send_data[i]<<" "<<+icmp_t0_hdr.data[i]<<" "<<+i<<"\n";
				if(stat.send_data[i] != icmp_t0_hdr.data[i]) return;
			}
			stat.curr_state = REPLIED;
			uint32_t time{};
			uint8_t* bBytes = reinterpret_cast<uint8_t*>(&time);
			size_t size = sizeof(time);
			if(IS_LITTLE_ENDIAN) {
				for(size_t i = 0; i < size; i++) {
					bBytes[size-i-1] = icmp_t0_hdr.data[i];
				}
			} else {
				for(size_t i = 0; i < size; i++) {
					bBytes[i] = icmp_t0_hdr.data[i];
				}
			}
			iface->logger->info("Ctime: {}", curr_time);
			iface->logger->info("Ptime: {}", time);
			iface->logger->info("Dtime: {}",curr_time-time);
			return;
		}
	}
	// std::cout<<"GOT ICMP REPLY!: "<<+ICMP_DATA_SIZE;
	

	return;

}

void addIPv4Header(std::deque<uint8_t> &packet, uint8_t hl, PROTOCOL::ip_protocol type, uint32_t ip_src, uint32_t ip_dst, uint16_t ip_id){
  uint16_t size {static_cast<uint16_t>(packet.size())};  

  PROTOCOL::ipv4_hdr ipv4_hdr(hl,size+hl,(uint8_t)type,ip_src,ip_dst,ip_id);
  // ipv4_hdr.display();
	// std::cout<<"Len: "<<+(size+hl)<<std::endl;
	// std::cout<<"Len: "<<+ipv4_hdr.ip_len<<std::endl;
	
  std::list<uint8_t> temp;
  ipv4_hdr.serialize(temp);

	uint16_t checksum = calculateChecksum(temp);
  // std::cout << "Checksum: " << std::to_string(checksum) << std::endl;

  std::list<uint8_t>::iterator it = temp.begin(); 
  std::advance(it, 10); // Move the iterator to the index of checksum 

  *it = checksum>>8;
  std::advance(it, 1);
  *it = checksum&0xFF;

	// std::cout << "Checksum" << std::to_string(checksum) << std::endl; 
	// for (auto i : temp) {
  //       std::cout << +i << ' ';
  // }
  // std::cout<<std::endl;

  packet.insert(packet.begin(),temp.begin(),temp.end());
  //std::cout<<"L3: "<<packet.size()<<std::endl;
	// for(size_t i{}; i <packet.size();i++){
	// 	std::cout<<" "<<+packet[i];
  // }
  // std::cout<<std::endl;
}

void addIcmpT0Header(std::deque<uint8_t> &packet, PROTOCOL::icmp_type type, uint8_t code, uint16_t identifier, uint16_t sequence_no, uint8_t payload[ICMP_DATA_SIZE]){
  PROTOCOL::icmp_t0_hdr icmp_t0_hdr(type, code, identifier, sequence_no, payload);

	std::list<uint8_t> temp;
  icmp_t0_hdr.serialize(temp);

	uint16_t checksum = calculateChecksum(temp);

	std::list<uint8_t>::iterator it = temp.begin(); 
  std::advance(it, 2); // Move the iterator to the index of checksum 

  *it = checksum>>8;
  std::advance(it, 1);
  *it = checksum&0xFF;

  packet.insert(packet.begin(),temp.begin(),temp.end());

}

// TODO: nned to make it so mutex is used for proper working
std::vector<Icmp_pkt_status> icmp_pkt_status;

};

#endif
