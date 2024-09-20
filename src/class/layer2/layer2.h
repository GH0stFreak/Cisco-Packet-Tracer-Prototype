#pragma once
#ifndef LAYER2_H
#define LAYER2_H

#include "..\interface\dhcpIface.h"
#include "..\interface\clientIface.h"
//#include "..\switch\switch.h"
#include "..\protocol.h"


class ClientIface;
class DhcpIface;
class ServerIface;

//template <class R>
//class SwitchIface;

template <typename T,typename U>
class RouterIface;

class Switch;

// template <typename T>
class Layer2
{
public:
	Layer2(){};

	PROTOCOL::ethertype processEthernetHeader(Iface *iface,PROTOCOL::ethernet_hdr &ether_hdr){
		
		switch(ether_hdr.ether_type)
		{
			case PROTOCOL::ethertype_ip:
				return PROTOCOL::ethertype_ip;
			case PROTOCOL::ethertype_arp:
				return PROTOCOL::ethertype_arp;
			default: 
				return PROTOCOL::ethertype_ERROR;
		}

	};

	PROTOCOL::ethertype processEthernetHeader(Switch* sw, PROTOCOL::ethernet_hdr& ether_hdr) {
	  
		if (ether_hdr.ether_type < 1500 && ether_hdr.ether_type > 0) {
			return PROTOCOL::ethertype_llc;
		}
	  
		switch (ether_hdr.ether_type)
		{
		case PROTOCOL::ethertype_ip:
			return PROTOCOL::ethertype_ip;
		case PROTOCOL::ethertype_arp:
			return PROTOCOL::ethertype_arp;
		default:
			return PROTOCOL::ethertype_ERROR;
		}
	  
	}

	PROTOCOL::ethertype processEthernetHeader(PROTOCOL::ethernet_hdr& ether_hdr) {

		if (ether_hdr.ether_type < 1500 && ether_hdr.ether_type > 0) {
			return PROTOCOL::ethertype_llc;
		}

		switch (ether_hdr.ether_type)
		{
		case PROTOCOL::ethertype_ip:
			return PROTOCOL::ethertype_ip;
		case PROTOCOL::ethertype_arp:
			return PROTOCOL::ethertype_arp;
		default:
			return PROTOCOL::ethertype_ERROR;
		}

	}

	PROTOCOL::action processARPHeader(ClientIface *iface,PROTOCOL::arp_hdr &arp_hdr){
		uint8_array_6 mac{};
		iface->getMAC(mac);
		iface->logger->info("Got client arp");
		// arp_hdr.display();
		if( arp_hdr.arp_hrd != 0x0006 ||  
  			arp_hdr.arp_pro != 0x0800 ||
				arp_hdr.arp_hln != 0x06 ||
  			arp_hdr.arp_pln != 0x04) return PROTOCOL::PACKET_ERROR;
		
		if(arp_hdr.arp_op == PROTOCOL::arp_op_request){
			
			if(arp_hdr.arp_tip == iface->getIPV4()){
				return PROTOCOL::SEND_ARP_REPLY;
			}
		
		} else if(arp_hdr.arp_op == PROTOCOL::arp_op_reply){
			/*uint8_array_6 mac;
			iface->getMAC(mac);*/

			if(arp_hdr.arp_tip == iface->getIPV4() && check_uint8_array_6(arp_hdr.arp_tha,mac)){
				return PROTOCOL::RECEIVE_ARP_REPLY;
			}
		}

		return PROTOCOL::PACKET_ERROR;
	}

	template<typename T, typename U>
	PROTOCOL::action processARPHeader(RouterIface<T,U> *iface,PROTOCOL::arp_hdr &arp_hdr){
		uint8_array_6 mac{};
		iface->getMAC(mac);
		iface->logger->info("Got router arp");
		// arp_hdr.display();
		if( arp_hdr.arp_hrd != 0x0006 ||  
  			arp_hdr.arp_pro != 0x0800 ||
				arp_hdr.arp_hln != 0x06 ||
  			arp_hdr.arp_pln != 0x04) return PROTOCOL::PACKET_ERROR;
		
		if(arp_hdr.arp_op == PROTOCOL::arp_op_request){
			
			if(arp_hdr.arp_tip == iface->getIPV4()){
				return PROTOCOL::SEND_ARP_REPLY;
			}
		
		} else if(arp_hdr.arp_op == PROTOCOL::arp_op_reply){
			/*uint8_array_6 mac{};
			iface->getMAC(mac);*/

			if(arp_hdr.arp_tip == iface->getIPV4() && check_uint8_array_6(arp_hdr.arp_tha,mac)){
				return PROTOCOL::RECEIVE_ARP_REPLY;
			}
		}

		return PROTOCOL::PACKET_ERROR;
	}

	PROTOCOL::action processARPHeader(DhcpIface *iface,PROTOCOL::arp_hdr &arp_hdr){
		if( arp_hdr.arp_hrd != 0x0006 ||  
  			arp_hdr.arp_pro != 0x0800 ||
				arp_hdr.arp_hln != 0x06 ||
  			arp_hdr.arp_pln != 0x04) return PROTOCOL::PACKET_ERROR;
		if(arp_hdr.arp_op == PROTOCOL::arp_op_request){
			
			if(arp_hdr.arp_tip == iface->getIPV4()){
				return PROTOCOL::SEND_ARP_REPLY;
			}
		
		} else if(arp_hdr.arp_op == PROTOCOL::arp_op_reply){
			uint8_array_6 mac;
			iface->getMAC(mac);

			if(arp_hdr.arp_tip == iface->getIPV4() && check_uint8_array_6(arp_hdr.arp_tha,mac)){
				return PROTOCOL::RECEIVE_ARP_REPLY;
			}
		}

		return PROTOCOL::PACKET_ERROR;
	}

	PROTOCOL::llc_sap processLlcHeader(Switch *sw, PROTOCOL::llc_hdr& llc_hdr){
		if (llc_hdr.llc_control != PROTOCOL::llc_control_unnumbered) return PROTOCOL::llc_sap_ERROR;

		if (llc_hdr.llc_dsap == PROTOCOL::llc_sap_stp && llc_hdr.llc_ssap == PROTOCOL::llc_sap_stp) return PROTOCOL::llc_sap_stp;

		return PROTOCOL::llc_sap_ERROR;
	}

	PROTOCOL::action processBpduHeader(Switch* sw, PROTOCOL::bpdu_hdr &bpdu_hdr) {
		if (bpdu_hdr.bpdu_p_id != 0 || bpdu_hdr.bpdu_v_id != 0 || bpdu_hdr.bpdu_flags != 0) return PROTOCOL::PACKET_ERROR;

		switch (bpdu_hdr.bpdu_type) {
		case PROTOCOL::bpdu_configuration:
			return PROTOCOL::RECEIVE_BPDU_CONFIGURATION;
		case PROTOCOL::bpdu_tcn:
			return PROTOCOL::RECEIVE_BPDU_TOPOLOGY_CHANGE;
		default:
			return PROTOCOL::PACKET_ERROR;
		}
	}

		//Would like to do this but then would a override function on each class which inherits this class
	//virtual PROTOCOL::action processBpduConfiguration(Switch* sw, PROTOCOL::bpdu_hdr& bpdu_hdr, uint16_t input_port) = 0;

	void addEthernetHeader(std::deque<uint8_t> &packet, const uint8_array_6 &src_mac,const uint8_array_6 &dst_mac, uint16_t ether_type){
		
		if (ether_type == 0) {
			if (packet.size() < 1500) {
				ether_type = static_cast<uint16_t>(packet.size());
			}
			else throw std::runtime_error("Error: Incorrect Packet Size and Ethertype");
		}
		
		PROTOCOL::ethernet_hdr ethernet_hdr(dst_mac,src_mac,ether_type);

		std::list<uint8_t> temp;
  		ethernet_hdr.serialize(temp);
		// ethernet_hdr.display();
  		packet.insert(packet.begin(),temp.begin(),temp.end());

		// Minimum Ethernet Frame size is 64 bytes which doesn't include premable and crc fields since we have added the premable to the packet which is 8 bytes so 64 + 8 = 72 adding padding till it becomes 64 bytes or 72 in our case
		int count = 0;
		while(packet.size()<72){
			packet.push_back(0);
			count++;
		}
		//std::cout<<"Padding: "<<+count<<std::endl;

		PROTOCOL::ethernet_trailer ethernet_trailer(packet);
		// ethernet_trailer.display();
		
		//std::cout<<"L2(Ethernet): "<<packet.size()<<std::endl;
			// for(size_t i{}; i <packet.size();i++){
		//         std::cout<<" "<<+packet[i];
		//     }
		// std::cout<<std::endl;
			// if(packet.size()<72){
					// std::cout<<"Padding count: "<<count<<"\n ";
			// }
			std::list<uint8_t> tempTrailer;
  		ethernet_trailer.serialize(tempTrailer);

  		packet.insert(packet.end(),tempTrailer.begin(),tempTrailer.end());
		//std::cout<<"L2: "<<packet.size()<<std::endl;
			// for(size_t i{}; i <packet.size();i++){
		//         std::cout<<" "<<+packet[i];
		//     }
		// std::cout<<std::endl;
	}

	void addEthernetHeader(std::vector<uint8_t> &packet, const uint8_array_6 &src_mac,const uint8_array_6 &dst_mac, uint16_t ether_type) {
		
		if (ether_type == 0) {
			if (packet.size() < 1500) {
				ether_type = static_cast<uint16_t>(packet.size());
			}
			else throw std::runtime_error("Error: Incorrect Packet Size and Ethertype");
		}
		PROTOCOL::ethernet_hdr ethernet_hdr(dst_mac, src_mac, ether_type);

		std::list<uint8_t> temp;
  	ethernet_hdr.serialize(temp);
		// ethernet_hdr.display();
  	packet.insert(packet.begin(),temp.begin(),temp.end());

		// Minimum Ethernet Frame size is 64 bytes which doesn't include premable and crc fields since we have added the premable to the packet which is 8 bytes so 64 + 8 = 72 adding padding till it becomes 64 bytes or 72 in our case
		int count = 0;
		while(packet.size()<72){
			packet.push_back(0);
			count++;
		}
		//std::cout<<"Padding: "<<+count<<std::endl;

		PROTOCOL::ethernet_trailer ethernet_trailer(packet, true);
		// ethernet_trailer.display();
		// }
		std::list<uint8_t> tempTrailer;
  		ethernet_trailer.serialize(tempTrailer);

  		packet.insert(packet.end(),tempTrailer.begin(),tempTrailer.end());
		/*std::cout<<"L2: "<<packet.size()<<std::endl;
			for(size_t i{}; i <packet.size();i++){
				std::cout<<+packet[i]<<" ";
			}
		std::cout<<std::endl;*/
	}

	void addArpHeader(std::deque<uint8_t> &packet, uint16_t opcode, const uint8_array_6 &src_mac, uint32_t src_ip, const uint8_array_6 &request_mac, uint32_t request_ip){

		std::list<uint8_t> temp;
		PROTOCOL::arp_hdr arp_hdr(opcode, src_mac, src_ip, request_mac, request_ip);
		arp_hdr.serialize(temp);

		packet.insert(packet.begin(),temp.begin(),temp.end());
		//std::cout<<"L2(ARP): "<<packet.size()<<std::endl;

		// for(size_t i{}; i <packet.size();i++){
		// 	std::cout<<" "<<+packet[i];
		// }
		// std::cout<<std::endl;

	}


	void addLLCHeader(std::deque<uint8_t>& packet, const uint8_t dsap, const uint8_t ssap, const uint8_t control, const std::optional< uint8_t> control_2byte = std::nullopt) {
		if (control_2byte.has_value()) {
			PROTOCOL::llc_hdr llc_hdr(dsap, ssap, control, control_2byte.value());
			std::list<uint8_t> temp;
			llc_hdr.serialize(temp);
			// llc_hdr.display();
			packet.insert(packet.begin(), temp.begin(), temp.end());
		}
		else {
			PROTOCOL::llc_hdr llc_hdr(dsap, ssap, control);
			std::list<uint8_t> temp;
			llc_hdr.serialize(temp);
			// llc_hdr.display();
			packet.insert(packet.begin(), temp.begin(), temp.end());
		}
		
	}

	void addInternalHeader(std::deque<uint8_t> &packet, uint8_t iface){
		PROTOCOL::internal_hdr internal_hdr(static_cast<uint16_t>(packet.size()+PROTOCOL::internal_hdr_size), iface);

		std::list<uint8_t> temp;
		internal_hdr.serialize(temp);

		packet.insert(packet.begin(),temp.begin(),temp.end());
	}

	void addInternalHeader(std::vector<uint8_t>& packet, uint8_t iface) {

		PROTOCOL::internal_hdr internal_hdr(static_cast<uint16_t>(packet.size() + PROTOCOL::internal_hdr_size), iface);

		std::list<uint8_t> temp;
		internal_hdr.serialize(temp);

		packet.insert(packet.begin(), temp.begin(), temp.end());
	}

	void addRouterInternalHeader(std::deque<uint8_t>& packet, uint8_t iface, const uint8_array_6& next_hop_mac, PROTOCOL::ethertype type) {

		PROTOCOL::router_internal_hdr router_internal_hdr(static_cast<uint16_t>(packet.size() + PROTOCOL::router_internal_hdr_size), iface, next_hop_mac, type);


		std::list<uint8_t> temp;
		router_internal_hdr.serialize(temp);

		packet.insert(packet.begin(), temp.begin(), temp.end());
	}

	void addRouterInternalHeader(std::vector<uint8_t>& packet, uint8_t iface,const uint8_array_6 &next_hop_mac, PROTOCOL::ethertype type) {

		PROTOCOL::router_internal_hdr router_internal_hdr(static_cast<uint16_t>(packet.size()+PROTOCOL::router_internal_hdr_size), iface, next_hop_mac, type);


		std::list<uint8_t> temp;
		router_internal_hdr.serialize(temp);

		packet.insert(packet.begin(), temp.begin(), temp.end());
	}

	void addBPDUHeader(std::deque<uint8_t>& packet, uint16_t p_id, uint8_t v_id, PROTOCOL::bpdu_type type, uint8_t flags, uint64_t root_id, uint32_t root_cost, uint64_t bridge_id, uint16_t port_id, uint16_t message_age, uint16_t max_age = 20, uint16_t hello_time = 2, uint16_t forward_delay = 15){
		PROTOCOL::bpdu_hdr bpdu_hdr(p_id, v_id, type, flags, root_id, root_cost, bridge_id, port_id, message_age, max_age, hello_time, forward_delay);

		std::list<uint8_t> temp;
		bpdu_hdr.serialize(temp);

		packet.insert(packet.begin(), temp.begin(), temp.end());
	}

  ~Layer2()=default;
};

#endif




/*
	// TODO: Make the change and correct it to standard protocol rules
	PROTOCOL::action processBpduConfiguration(Switch* sw, PROTOCOL::bpdu_hdr& bpdu_hdr, uint16_t input_port) {
		if (bpdu_hdr.bpdu_r_id < sw->root_id) {
			sw->root_bridge = false;
			sw->root_id = bpdu_hdr.bpdu_r_id;
			sw->root_cost = bpdu_hdr.bpdu_r_cost + 4;
			sw->bridge_id = bpdu_hdr.bpdu_b_id;
			sw->port_id = bpdu_hdr.bpdu_port_id;
			for (auto& iface : sw->ifaces) {
				if (input_port != iface.id) {
					iface.state = NON_DESIGNATED;
				}
				else if (input_port == iface.id) {
					iface.state = ROOT;
				}
				else if (iface.link->getState() == NON_DESIGNATED && iface.state == NON_DESIGNATED) {
					// This is wrong according to standard STP but to make it easier have done this 
					// otherwise the switch interface whose switch has the lowest root cost that side of interface should become DESIGNATED
					// if cost is same then the switch interface whose switch has the lowest bridge id that side of interface should become DESIGNATED
					iface.state = DESIGNATED;
				}
			}
		}
		else if (bpdu_hdr.bpdu_r_id == sw->root_id) {
			if ((bpdu_hdr.bpdu_r_cost + 4) < sw->root_cost) {
				sw->root_cost = bpdu_hdr.bpdu_r_cost + 4;
				sw->bridge_id = bpdu_hdr.bpdu_b_id;
				sw->port_id = bpdu_hdr.bpdu_port_id;
				for (auto& iface : sw->ifaces) {
					if (input_port != iface.id) {
						iface.state = NON_DESIGNATED;
					}
					else if (input_port == iface.id) {
						iface.state = ROOT;
					}
					else if (iface.link->getState() == NON_DESIGNATED && iface.state == NON_DESIGNATED) {
						// This is wrong according to standard STP but to make it easier have done this 
						// otherwise the switch interface whose switch has the lowest root cost that side of interface should become DESIGNATED
						// if cost is same then the switch interface whose switch has the lowest bridge id that side of interface should become DESIGNATED
						iface.state = DESIGNATED;
					}
				}
			}
			else if ((bpdu_hdr.bpdu_r_cost + 4) == sw->root_cost) {
				if (bpdu_hdr.bpdu_b_id < sw->bridge_id) {
					sw->bridge_id = bpdu_hdr.bpdu_b_id;
					sw->port_id = bpdu_hdr.bpdu_port_id;
					for (auto& iface : sw->ifaces) {
						if (input_port != iface.id) {
							iface.state = NON_DESIGNATED;
						}
						else if (input_port == iface.id) {
							iface.state = ROOT;
						}
						else if (iface.link->getState() == NON_DESIGNATED && iface.state == NON_DESIGNATED) {
							// This is wrong according to standard STP but to make it easier have done this 
							// otherwise the switch interface whose switch has the lowest root cost that side of interface should become DESIGNATED
							// if cost is same then the switch interface whose switch has the lowest bridge id that side of interface should become DESIGNATED
							iface.state = DESIGNATED;
						}
					}
				}
				else if (bpdu_hdr.bpdu_b_id == sw->bridge_id) {
					if (bpdu_hdr.bpdu_port_id < sw->port_id) {
						sw->port_id = bpdu_hdr.bpdu_port_id;
						for (auto& iface : sw->ifaces) {
							if (input_port != iface.id) {
								iface.state = NON_DESIGNATED;
							}
							else if (input_port == iface.id) {
								iface.state = ROOT;
							}
							else if (iface.link->getState() == NON_DESIGNATED && iface.state == NON_DESIGNATED) {
								// This is wrong according to standard STP but to make it easier have done this 
								// otherwise the switch interface whose switch has the lowest root cost that side of interface should become DESIGNATED
								// if cost is same then the switch interface whose switch has the lowest bridge id that side of interface should become DESIGNATED
								iface.state = DESIGNATED;
							}
						}
					}
				}
			}
		}
		return PROTOCOL::PACKET_ERROR;
	}*/
