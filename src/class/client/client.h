#pragma once
#ifndef CLIENT_H
#define CLIENT_H
#include "..\common.h"
#include "..\interface\clientIface.h"
#include "..\arpCache\arpCache.h"
#include "..\layer5\layer5.h"
#include "..\dhcpTable\dhcpTable.h"
#include "..\logger.h"
#include "..\stopThread.h"
#include "..\deviceWindow.h"
#include "..\pcapWriter.h"

class Client : public Layer5, public Loggable
{
public:
	//You get the data and add the follwoing headers in order then place in input buffer of interface
	Client() : count(0), count2(0), Loggable::Loggable("Client "+ std::to_string(++counter)), hostname("Client " + std::to_string(counter)), pcapFile("Client" + std::to_string(counter)){
		this->start();

		// TODO: Write logic for the main cpu
		cpu = nullptr;

		cpu = std::make_unique<std::thread>([&]() {
			printMessage(CONSOLE_INFO, "CPU Thread called: ", macToString(iface.mac));
			//logger->info("CPU Thread called: ");
			// Never ending loop so thread runs the entire lifetime
			while (true) {
				{
					std::unique_lock<std::mutex> lock(mtx);

					// Checks the bool meaning the NIC-RAM has a packet which needs to be processed so copy it to CPU memory
					if (flag.load()) {
						printMessage(CONSOLE_INFO, "Loaded: ", macToString(iface.mac));

						memory->enqueue(&iface.ram);
						flag.store(false, std::memory_order_release);
						cond_var_copy.notify_one();
					}

					if (memory->is_empty() == false) {
						if (count.try_acquire()) {
							printMessage(CONSOLE_INFO, "CPU waiting!: ", macToString(iface.mac));
							// Waiting for a packet to be in Memory
							// cond_var_memory.wait(lock);   
							printMessage(CONSOLE_INFO, "CPU can run!: ", macToString(iface.mac));
							memory->insert_copy_in_ram(ram, cond_var_memory);
							// for(auto el:ram_)
							// std::cout<<+el<<" ";
							processPacket();
							memory->drop_packet();
							ram.clear();
							// Notifying the scheduler the processing is done on the RAM
							cond_var_memory.notify_one();
						}
					}
				}
				std::this_thread::sleep_for(std::chrono::milliseconds(200)); // Sleep for 200 seconds just so my cpu doesnt just keep locking and unlocking the mutex
				// std::cout<<"sleep200"<<std::endl;
				{
					std::unique_lock<std::mutex> lk(cv_m);
					cv.wait(lk, [] { return !paused; });
				}
			}

			});
		cpu->detach();
	}

	virtual void processPacket() {
		// TODO: Deserialize the pkt ethernet header
		if (ram.empty()) return;
		printMessage(CONSOLE_INFO, "Processing Packet");

		/*for (auto el : ram) {
			std::cout << +el << " ";
		}
		std::cout << std::endl;*/

		size_t offset{};
		// std::cout<<;
		PROTOCOL::internal_hdr internal_hdr(ram);
		// PROTOCOL::internal_hdr internal_hdr(ram, offset);
		// PROTOCOL::internal_hdr internal_hdr(ram_);
		// internal_hdr.display();
		
		//printMessage(CONSOLE_INFO, "WRITING");

		pcapFile.write(ram,0);

		PROTOCOL::ethernet_hdr ethernet_hdr(ram);
		// PROTOCOL::ethernet_hdr ethernet_hdr(ram, offset);
		// ethernet_hdr.display();

		PROTOCOL::ethernet_trailer ethernet_trailer(ram);
		// ethernet_trailer.display();


		PROTOCOL::ethertype ether_type = processEthernetHeader(&iface, ethernet_hdr);

		switch (ether_type)
		{
		case PROTOCOL::ethertype_ip:
		{
			//logger->info("HERE");

			PROTOCOL::ipv4_hdr ipv4_hdr(ram);
			// PROTOCOL::ipv4_hdr ipv4_hdr(ram,offset);
			// PROTOCOL::ipv4_hdr ipv4_hdr(ram_);
			PROTOCOL::ip_protocol ip_type = processIPv4Header(&iface, ipv4_hdr);

			//ipv4_hdr.display();

			/*for (auto el : ram) {
				std::cout << +el << " ";
			}
			std::cout << std::endl;*/

			// Removes the padding of the packet
			auto actual_bytes_size = ipv4_hdr.ip_len - ((ipv4_hdr.ip_v_hl & IP_HL) << 2);
			auto start_it = ram.begin() + actual_bytes_size;
			if (start_it < ram.end())
				ram.erase(start_it, ram.end());
			//std::cout << "Reach!" << std::endl;


			switch (ip_type)
			{
			case PROTOCOL::ip_protocol_icmp:
			{
				// TODO:
				PROTOCOL::icmp_t0_hdr icmp_t0_hdr(ram);

				PROTOCOL::action next_action = processICMPHeader(&iface, icmp_t0_hdr);


				switch (next_action)
				{
				case PROTOCOL::RECEIVE_ICMP_REQUEST: {

					sendICMPEchoReply(ipv4_hdr.ip_src, icmp_t0_hdr.icmp_id, icmp_t0_hdr.icmp_seq, icmp_t0_hdr.data);
					return;
				}

				case PROTOCOL::RECEIVE_ICMP_REPLY: {
					processICMPReply(&iface, icmp_t0_hdr, clock);

					return;
				}

				case PROTOCOL::PACKET_ERROR:
				default:
					return;
				}

				break;
			}

			case PROTOCOL::ip_protocol_tcp:
			{

				// TODO:
				PROTOCOL::pseudo_hdr pseudo_hdr(ipv4_hdr.ip_src, ipv4_hdr.ip_dst, ip_type, ipv4_hdr.ip_len - ((ipv4_hdr.ip_v_hl & IP_HL) * 4));

				processTCPHeader();

				break;
			}

			case PROTOCOL::ip_protocol_udp:
			{
				// TODO:
				// As UDP checksum is calulated for pseudo, udp header and payload so need to send all 
				/*std::cout << "BEFORE" << std::endl;
				for (auto el : ram) {
					std::cout << +el << " ";
				}
				std::cout << std::endl;*/
				PROTOCOL::udp_hdr udp_hdr(ram);
				//std::cout << "AFTER" << std::endl;
				//std::cout << "UDP process!" << std::endl;

				// PROTOCOL::udp_hdr udp_hdr(ram, offset);
				// PROTOCOL::udp_hdr udp_hdr(ram_);
				//udp_hdr.display();

				PROTOCOL::pseudo_hdr pseudo_hdr(ipv4_hdr.ip_src, ipv4_hdr.ip_dst, ip_type, ipv4_hdr.ip_len - ((ipv4_hdr.ip_v_hl & IP_HL) * 4));
				// pseudo_hdr.display();

				std::deque<uint8_t> payload;
				//auto start = ram.begin() + offset;
				//auto end = ram.begin() + offset + udp_hdr.udp_len - 8;

				auto start = ram.begin();
				auto end = ram.end();

				std::copy(start, end, std::back_inserter(payload));

				// std::deque<uint8_t> payload;
				// auto start = ram_.begin();
				// auto end = ram_.begin() + udp_hdr.udp_len - 8;

				// std::copy(start, end, std::back_inserter(payload));


				PROTOCOL::tl_ports port = processUDPHeader(&iface, pseudo_hdr, udp_hdr, payload);

				if (port == PROTOCOL::tl_ERROR || port == PROTOCOL::dhcp_server) {
					printMessage(CONSOLE_WARN, "Wrong Port Dropped: {}", +port);
					return;
				}



				switch (port)
				{
				case PROTOCOL::dhcp_client: {

					PROTOCOL::dhcp_hdr dhcp_hdr(ram);
					// PROTOCOL::dhcp_hdr dhcp_hdr(ram, offset);
					// PROTOCOL::dhcp_hdr dhcp_hdr(ram_);
					PROTOCOL::action next_action_dhcp = processDHCPHeader(&iface, dhcp_hdr);
					uint8_array_6 mac;
					getMAC(mac);
					switch (next_action_dhcp)
					{
					case PROTOCOL::RECEIVE_DHCP_OFFER: {

						PROTOCOL::action next_action = processDHCPOffer(&iface, dhcp_hdr, offer, mac, dhcp_server_ip);
						switch (next_action)
						{
						case PROTOCOL::SEND_DHCP_REQUEST:
							sendDHCPRequest(offer.xid, dhcp_hdr.dhcp_ycip, ipv4_hdr.ip_src);
							return;

						case PROTOCOL::PACKET_ERROR:
						default:
							printMessage(CONSOLE_WARN, "DHCP Offer not for the client");
							return;
						}

						return;
					}

					case PROTOCOL::RECEIVE_DHCP_ACKNOWLEDGE: {

						PROTOCOL::action next_action = processDHCPAcknowledge(&iface, dhcp_hdr, offer, mac, dhcp_server_ip);

						if (next_action == PROTOCOL::PACKET_ERROR) {
							printMessage(CONSOLE_WARN, "DHCP Acknowledgement not for the client");
							return;
						}
						if (next_action == PROTOCOL::DONE) {

							iface.setIPV4(offer.leased_ip);
							iface.setSUBNET_MASK(offer.option.mask);
							iface.setGATEWAY(offer.option.gateway);
							iface.setDNS(offer.option.dns);

							offer.binding_state = BOUND;

						}
						return;
					}

					case PROTOCOL::PACKET_ERROR: {
						return;
					}
					default: {
						printMessage(CONSOLE_WARN, "Dropped");
						return;
					}
					}
					return;
				}

				case PROTOCOL::message: {
					std::vector<uint8_t> message;

					deserializer(&message, ram, ram.size());

					std::string str(message.begin(), message.end());
					printMessage(CONSOLE_INFO, "Message: {}", str);
					return;
				}

				default:
					printMessage(CONSOLE_WARN, "Dropped");
					return;
				}
			}

			case PROTOCOL::ip_protocol_ERROR:
			default:
				printMessage(CONSOLE_WARN, "Dropped");
				return;
			}

			break;
		}

		case PROTOCOL::ethertype_arp:
		{
			PROTOCOL::arp_hdr arp_hdr(ram);
			// PROTOCOL::arp_hdr arp_hdr(ram, offset);
			// PROTOCOL::arp_hdr arp_hdr(ram_);

			PROTOCOL::action next_action_arp = processARPHeader(&iface, arp_hdr);

			switch (next_action_arp)
			{
			case PROTOCOL::SEND_ARP_REPLY:
				printMessage(CONSOLE_INFO, "Sending ARP Reply");
				sendARPReply(arp_hdr.arp_sha, arp_hdr.arp_sip);
				arp_table.checkARPTable(arp_hdr.arp_sha, arp_hdr.arp_sip);

				return;

			case PROTOCOL::RECEIVE_ARP_REPLY:
				printMessage(CONSOLE_INFO, "Recived ARP Reply");
				arp_table.checkPendingEntry(arp_hdr.arp_sha, arp_hdr.arp_sip);
				return;

			case PROTOCOL::PACKET_ERROR:
			default:
				printMessage(CONSOLE_WARN, "Dropped");
				break;
			}

			break;
		}

		case PROTOCOL::ethertype_ERROR:
		default:
			printMessage(CONSOLE_WARN, "Dropped");
			return;
		}
		// return;

  }

	void sendMessage(uint32_t dst_ip, std::string message) {
	  std::deque<uint8_t> packet;

	  uint32_t src_ip = iface.getIPV4();

	  uint8_array_6 src_mac;
	  iface.getMAC(src_mac);

	  // addDhcpDiscoverHeader(packet, src_mac, id);
	  addMessage(packet, message);

	  addUDPHeader(packet, generateRandomNumber(16, 1024), generateRandomNumber(16, 1024), src_ip, dst_ip, PROTOCOL::ip_protocol_udp);

	  addIPv4Header(packet, 20, PROTOCOL::ip_protocol_udp, src_ip, dst_ip, (uint16_t)generateRandomNumber(16));

	  // std::cout<<"Gateway: "<<ipToString(iface.getGATEWAY())<<"\n";
	  // std::cout<<"Subnet: "<<ipToString(iface.getSUBNET_MASK())<<"\n";
	  // std::cout<<"Src: "<<ipToString((src_ip&iface.getSUBNET_MASK()))<<"\n";
	  // std::cout<<"Dst: "<<ipToString((dst_ip&iface.getSUBNET_MASK()))<<"\n";

	  uint8_array_6 dst_mac{};
	  if ((src_ip & iface.getSUBNET_MASK()) == (dst_ip & iface.getSUBNET_MASK())) {
		  arp_table.getIPtoMac(dst_ip, dst_mac);
		  if (check_uint8_array_6(dst_mac, PROTOCOL::NoEtherAddr)) {
			  addInternalHeader(packet,0);
			  // arp_table.addPendingEntry(dst_ip);
			  shared_arp_memory->enqueue(&packet, dst_ip);
			  return;
		  }
	  }
	  else {
		  arp_table.getIPtoMac(iface.getGATEWAY(), dst_mac);
		  if (check_uint8_array_6(dst_mac, PROTOCOL::NoEtherAddr)) {
			  addInternalHeader(packet, 0);
			  // arp_table.addPendingEntry(dst_ip);
			  shared_arp_memory->enqueue(&packet, iface.getGATEWAY());
			  return;
		  }
	  }

	  addEthernetHeader(packet, src_mac, dst_mac, PROTOCOL::ethertype_ip);

	  addInternalHeader(packet,0);

	  printMessage(CONSOLE_INFO, "Client(Message) Sent: {}", packet.size());

	  // for(auto el: packet){
		// 	std::cout<<+el<<" ";
		// }
		// std::cout<<"\n";

	  iface.putMessageInOutputIface(&packet);
	}
	
	void sendDHCPDiscover() {
		// To know if client is actively going for dhcp process
		offer.binding_state = INIT;

		std::deque<uint8_t> packet;

		uint8_array_6 src_mac;
		iface.getMAC(src_mac);

		uint32_t id = generateRandomNumber(32);
		// Store the identification number so we know the dhcp process 
		offer.xid = id;

		addDhcpDiscoverHeader(packet, src_mac, id);

		addUDPHeader(packet, PROTOCOL::dhcp_client, PROTOCOL::dhcp_server, 0, PROTOCOL::BroadcastIPAddr, PROTOCOL::ip_protocol_udp);

		addIPv4Header(packet, 20, PROTOCOL::ip_protocol_udp, 0, PROTOCOL::BroadcastIPAddr, (uint16_t)generateRandomNumber(16));
		// std::cout<<"Hi";

		addEthernetHeader(packet, src_mac, PROTOCOL::BroadcastEtherAddr, PROTOCOL::ethertype_ip);

		addInternalHeader(packet, 0);

		printMessage(CONSOLE_INFO, "Client(DHCP Discover) Sent: {}", packet.size());

		std::ostringstream out;

		for (auto el : packet) {
			out << +el << " ";
		}
		std::cout << out.str() << std::endl;

		iface.putMessageInOutputIface(&packet);
	}
	
	void sendDHCPRequest(uint32_t id, uint32_t offered_ip, uint32_t dhcp_server_ip) {
		offer.binding_state = REQUESTING;

		std::deque<uint8_t> packet;

		uint8_array_6 src_mac;
		iface.getMAC(src_mac);

		addDhcpRequestHeader(packet, src_mac, id, offered_ip, dhcp_server_ip);

		addUDPHeader(packet, PROTOCOL::dhcp_client, PROTOCOL::dhcp_server, 0, PROTOCOL::BroadcastIPAddr, PROTOCOL::ip_protocol_udp);

		addIPv4Header(packet, 20, PROTOCOL::ip_protocol_udp, 0, PROTOCOL::BroadcastIPAddr, (uint16_t)generateRandomNumber(16));

		addEthernetHeader(packet, src_mac, PROTOCOL::BroadcastEtherAddr, PROTOCOL::ethertype_ip);

		addInternalHeader(packet, 0);

		printMessage(CONSOLE_INFO, "Client(DHCP Request) Sent: {}", packet.size());

		iface.putMessageInOutputIface(&packet);
	}
	
	void sendARPRequest(uint32_t request_ip) {
		std::deque<uint8_t> packet;

		uint8_array_6 src_mac;
		iface.getMAC(src_mac);

		uint32_t src_ip = iface.getIPV4();

		addArpHeader(packet, PROTOCOL::arp_op_request, src_mac, src_ip, PROTOCOL::NoEtherAddr, request_ip);

		addEthernetHeader(packet, src_mac, PROTOCOL::BroadcastEtherAddr, PROTOCOL::ethertype_arp);

		addInternalHeader(packet, 0);
		
		// for(auto el:packet){
		// 	std::cout<<+el<<" ";
		// }

		arp_table.addPendingEntry(request_ip);

		printMessage(CONSOLE_INFO, "ARP Request: {}", ipToString(request_ip));

		printMessage(CONSOLE_INFO, "Client(ARP Request) Sent: {}", packet.size());
		// TODO: Put the packet in buffer
		iface.putMessageInOutputIface(&packet);
	}
	
	void sendARPReply(const uint8_array_6& request_mac, uint32_t request_ip) {
		std::deque<uint8_t> packet;

		uint8_array_6 src_mac;
		iface.getMAC(src_mac);

		uint32_t src_ip = iface.getIPV4();
		addArpHeader(packet, PROTOCOL::arp_op_reply, src_mac, src_ip, request_mac, request_ip);

		addEthernetHeader(packet, src_mac, request_mac, PROTOCOL::ethertype_arp);

		addInternalHeader(packet, 0);

		// for(auto el : packet){
		// 	std::cout<<+el<<" ";
		// }
		printMessage(CONSOLE_INFO, ("Client(ARP Reply) Sent: {} {}", ipToString(request_ip), macToString(request_mac)));
		// TODO: Put the packet in buffer
		iface.putMessageInOutputIface(&packet);
	}
	
	void sendICMPEchoRequest(uint32_t dst_ip) {
		std::deque<uint8_t> packet;

		uint32_t src_ip = iface.getIPV4();

		uint8_array_6 src_mac;
		iface.getMAC(src_mac);

		uint8_t payload[ICMP_DATA_SIZE]{ 0 };
		payload[0] = static_cast<uint8_t>((clock >> (24)) & 0xFF);
		payload[1] = static_cast<uint8_t>((clock >> (16)) & 0xFF);
		payload[2] = static_cast<uint8_t>((clock >> (8)) & 0xFF);
		payload[3] = static_cast<uint8_t>((clock) & 0xFF);

		uint16_t identifier = (uint16_t)generateRandomNumber(16);  // same will be used for all 5(Default) icmp request packet for a single ping
		uint16_t sequence_no = (uint16_t)generateRandomNumber(16);  // increment and then will be used for all 5(Default) icmp request packet for a single ping

		addIcmpT0Header(packet, PROTOCOL::icmp_echo_request, 0, identifier, sequence_no, payload);

		Icmp_pkt_status icmp_stat{ identifier, sequence_no, clock, src_ip, dst_ip, payload };

		icmp_pkt_status.push_back(icmp_stat);

		addIPv4Header(packet, 20, PROTOCOL::ip_protocol_icmp, src_ip, dst_ip, (uint16_t)generateRandomNumber(16));

		// std::cout<<"ECHO REQUEST!"<<"\n";
		// for(auto el: packet){
		// 	std::cout<<+el<<" ";
		// }
		// std::cout<<"\n";

		// std::cout<<"Gateway: "<<ipToString(iface.getGATEWAY())<<"\n";
		// std::cout<<"Subnet: "<<ipToString(iface.getSUBNET_MASK())<<"\n";
		// std::cout<<"Src: "<<ipToString((src_ip&iface.getSUBNET_MASK()))<<"\n";
		// std::cout<<"Dst: "<<ipToString((dst_ip&iface.getSUBNET_MASK()))<<"\n";

		uint8_array_6 dst_mac{};

		if ((src_ip & iface.getSUBNET_MASK()) == (dst_ip & iface.getSUBNET_MASK())) {
			arp_table.getIPtoMac(dst_ip, dst_mac);
			if (check_uint8_array_6(dst_mac, PROTOCOL::NoEtherAddr)) {
				//sendARPRequest(dst_ip);
				addInternalHeader(packet, 0);
				// arp_table.addPendingEntry(dst_ip);
				shared_arp_memory->enqueue(&packet, dst_ip);
				return;
			}
		}
		else {
			arp_table.getIPtoMac(iface.getGATEWAY(), dst_mac);
			if (check_uint8_array_6(dst_mac, PROTOCOL::NoEtherAddr)) {
				//sendARPRequest(iface.getGATEWAY());
				addInternalHeader(packet, 0);
				// arp_table.addPendingEntry(dst_ip);
				shared_arp_memory->enqueue(&packet, iface.getGATEWAY());
				return;
			}
		}

		addEthernetHeader(packet, src_mac, dst_mac, PROTOCOL::ethertype_ip);

		addInternalHeader(packet, 0);

		printMessage(CONSOLE_INFO, "Client(Icmp Request) Sent: {}", packet.size());

		// for(auto el: packet){
		  // 	std::cout<<+el<<" ";
		  // }
		  // std::cout<<"\n";

		iface.putMessageInOutputIface(&packet);
	}
	
	void sendICMPEchoReply(uint32_t dst_ip, uint16_t identifier, uint16_t sequence_no, uint8_t payload[ICMP_DATA_SIZE]) {
		std::deque<uint8_t> packet;

		uint32_t src_ip = iface.getIPV4();

		uint8_array_6 src_mac;
		iface.getMAC(src_mac);

		addIcmpT0Header(packet, PROTOCOL::icmp_echo_reply, 0, identifier, sequence_no, payload);

		addIPv4Header(packet, 20, PROTOCOL::ip_protocol_icmp, src_ip, dst_ip, generateRandomNumber(16));

		// std::cout<<"Gateway: "<<ipToString(iface.getGATEWAY())<<"\n";
		// std::cout<<"Subnet: "<<ipToString(iface.getSUBNET_MASK())<<"\n";
		// std::cout<<"Src: "<<ipToString((src_ip&iface.getSUBNET_MASK()))<<"\n";
		// std::cout<<"ECHO REPLY!"<<"\n";
		// for(auto el: packet){
		// 	std::cout<<+el<<" ";
		// }
		// std::cout<<"\n";

		uint8_array_6 dst_mac{};

		if ((src_ip & iface.getSUBNET_MASK()) == (dst_ip & iface.getSUBNET_MASK())) {
			arp_table.getIPtoMac(dst_ip, dst_mac);
			if (check_uint8_array_6(dst_mac, PROTOCOL::NoEtherAddr)) {
				//sendARPRequest(dst_ip);
				addInternalHeader(packet, 0);
				// arp_table.addPendingEntry(dst_ip);
				shared_arp_memory->enqueue(&packet, dst_ip);
				return;
			}
		}
		else {
			arp_table.getIPtoMac(iface.getGATEWAY(), dst_mac);
			if (check_uint8_array_6(dst_mac, PROTOCOL::NoEtherAddr)) {
				//sendARPRequest(iface.getGATEWAY());
				addInternalHeader(packet, 0);
				// arp_table.addPendingEntry(dst_ip);
				shared_arp_memory->enqueue(&packet, iface.getGATEWAY());
				return;
			}
		}

		addEthernetHeader(packet, src_mac, dst_mac, PROTOCOL::ethertype_ip);

		addInternalHeader(packet, 0);

		printMessage(CONSOLE_INFO, "Client(Icmp Reply) Sent: {}", packet.size());

		// for(auto el: packet){
		  // 	std::cout<<+el<<" ";
		  // }
		  // std::cout<<"\n";

		iface.putMessageInOutputIface(&packet);
	}
	
	void sendDNSQuery(std::vector<std::string> domains) {
		std::deque<uint8_t> packet;

		for (std::string domain : domains) {
			std::string word;
			for (char c : domain) {
				if (c == '.') {
					std::list<uint8_t> temp;
					serializer(&word, temp, word.length());
					packet.push_back(static_cast<uint8_t>(word.length()));
					packet.insert(packet.end(), temp.begin(), temp.end());
					word.clear();
				}
				else {
					word += c;
				}
			}
			std::list<uint8_t> temp;
			serializer(&word, temp, word.length());
			packet.push_back(static_cast<uint8_t>(word.length()));
			packet.insert(packet.end(), temp.begin(), temp.end());

			std::list<uint8_t> temp1;

			uint8_t domain_null_byte{ 0 };
			uint16_t query_type{ 1 };
			uint16_t query_class{ 1 };

			serializer(&domain_null_byte, temp1, sizeof(domain_null_byte));
			serializer(&query_type, temp1, sizeof(query_type));
			serializer(&query_class, temp1, sizeof(query_class));
			packet.insert(packet.end(), temp1.begin(), temp1.end());

		}


		addDNSHeader(packet, generateRandomNumber(16), false, 0, false, false, false, false, 0, static_cast<uint16_t>(domains.size()), 0, 0, 0);

		uint32_t src_ip = iface.getIPV4();
		uint32_t dst_ip = iface.getDNS();

		uint8_array_6 src_mac;
		iface.getMAC(src_mac);

		addUDPHeader(packet, generateRandomNumber(16, 1024), PROTOCOL::dns_server, src_ip, dst_ip, PROTOCOL::ip_protocol_udp);

		addIPv4Header(packet, 20, PROTOCOL::ip_protocol_udp, src_ip, dst_ip, generateRandomNumber(16));

		uint8_array_6 dst_mac{};
		if ((src_ip & iface.getSUBNET_MASK()) == (dst_ip & iface.getSUBNET_MASK())) {
			arp_table.getIPtoMac(dst_ip, dst_mac);
			if (check_uint8_array_6(dst_mac, PROTOCOL::NoEtherAddr)) {
				//sendARPRequest(dst_ip);
				// arp_table.addPendingEntry(dst_ip);
				addInternalHeader(packet, 0);
				shared_arp_memory->enqueue(&packet, dst_ip);
				return;
			}
		}
		else {
			arp_table.getIPtoMac(iface.getGATEWAY(), dst_mac);
			if (check_uint8_array_6(dst_mac, PROTOCOL::NoEtherAddr)) {
				//sendARPRequest(iface.getGATEWAY());
				// arp_table.addPendingEntry(dst_ip);
				addInternalHeader(packet, 0);
				shared_arp_memory->enqueue(&packet, iface.getGATEWAY());
				return;
			}
		}

		addEthernetHeader(packet, src_mac, dst_mac, PROTOCOL::ethertype_ip);
		
		addInternalHeader(packet, 0);

		printMessage(CONSOLE_INFO, "Client(DNS Query) Sent: {}", packet.size());

		// for(auto el: packet){
		  // 	std::cout<<+el<<" ";
		  // }
		  // std::cout<<"\n";

		iface.putMessageInOutputIface(&packet);
	}

	void IpConfig() {
		printMessage(CONSOLE_INFO, "IPV4: {}", ipToString(iface.getIPV4()));
		printMessage(CONSOLE_INFO, "Subnet: {}", ipToString(iface.getSUBNET_MASK()));
		printMessage(CONSOLE_INFO, "Gateway: {}", ipToString(iface.getGATEWAY()));
		std::cout << std::endl;
	}

	template <typename... Args>
	void printMessage(consoleType level, const std::string& format, Args&&... args) {
		std::lock_guard<std::mutex> lock(consoleMutex);

		std::string message = format_string(format, std::forward<Args>(args)...);

		switch (level) {
		case CONSOLE_TRACE:
			logger->trace("{}", message);
			break;
		case CONSOLE_DEBUG:
			logger->debug("{}", message);
			break;
		case CONSOLE_INFO:
			logger->info("{}", message);
			break;
		case CONSOLE_WARN:
			logger->warn("{}", message);
			break;
		case CONSOLE_ERROR:
			logger->error("{}", message);
			break;
		case CONSOLE_CRITICAL:
			logger->critical("{}", message);
			break;
		}

		//std::string captured_log = get_captured_log();

		wndClass->addData(get_captured_log());
		logger->flush();
	}

	void ShowPacketCount() {
		iface.BufferPacketCount();
	}
	

	// void setPKTMAC(__uint128_t &src);
	void getMAC(uint8_array_6 &mac) const { iface.getMAC(mac); }

	// Start the decrementing thread
	void start() {  
		time_thread = std::thread([this]() {
			while (!stop_thread) {
			  // Check the time against expire time
			  {   
				  std::lock_guard<std::mutex> lock(muxTable);
								if(offer.leased_expire_time < std::chrono::high_resolution_clock::now()){
									offer.binding_state = EXPIRED;
								}
								clock++;

			  } // Release the lock when lock goes out of scope
      
      			// Sleep after processing for 1 second
      			std::this_thread::sleep_for(std::chrono::seconds(1));
			}
		});

		time_thread.detach();
	};

	void setHostname(std::string host_str) {
		hostname = host_str;
	}

	/*void ShowWindow() override {
		::ShowWindow(wndClass.wnd, SW_SHOW);
	}*/

	~Client(){ stop_thread = true; }

	bool stop_thread = false;
	std::thread time_thread;
	std::mutex muxTable;

	mutable std::mutex mtx;

	static uint8_t counter;

	std::string hostname;


	pcapWriter pcapFile;


	/* == For Device Control Window == */

	std::mutex consoleMutex;

	std::shared_ptr<DeviceWindow<Client>> wndClass = std::make_shared<DeviceWindow<Client>>(this, 1, clientWindowClass, CLIENT_CLASS_NAME);

	/* ====================== */
	
	/* == For Interface == */

	std::atomic<bool> flag;
	std::condition_variable cond_var_copy;

	ClientIface iface{flag,cond_var_copy, ("Client " + std::to_string(counter) + " Iface"),wndClass};

	/* ====================== */

	/* == For DHCP process == */

	DhcpNetworkEntry offer;
	uint32_t dhcp_server_ip;

	/* ====================== */

	/* == For ARP process == */

	std::counting_semaphore<10> count2;
	std::condition_variable cond_var_arp;
	std::shared_ptr<Buffer::CircularPtrQueue<8192, 512, Client>> shared_arp_memory = std::make_shared<Buffer::CircularPtrQueue<8192, 512, Client>>(cond_var_arp, count2, this);
	ArpCache<ArpUserEntry, Buffer::CircularPtrQueue<8192, 512, Client>> arp_table{shared_arp_memory};

	/* ====================== */

	/* == For ICMP process == */

	uint32_t clock{0};

	/* ====================== */

	/* == For processed packets == */

	std::counting_semaphore<10> count;
	std::condition_variable cond_var_memory;
	
	std::shared_ptr<Buffer::CircularQueue<8192, 512>> memory = std::make_shared<Buffer::CircularQueue<8192, 512>>(cond_var_memory, count);

	/* ====================== */


	std::unique_ptr<std::thread> cpu;

	std::vector<uint8_t> ram;
	
};

#endif