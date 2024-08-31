#pragma once
#ifndef DHCP_H
#define DHCP_H
#include "..\common.h"
#include "..\interface\dhcpIface.h"
#include "..\arpCache\arpCache.h"
#include "..\layer5\layer5.h"
#include "..\dhcpTable\dhcpTable.h"
#include "..\logger.h"
#include "..\stopThread.h"
#include "..\deviceWindow.h"
#include "..\pcapWriter.h"


class Dhcp : public Layer5, public Loggable 
{
public:
	//You get the data and add the follwoing headers in order then place in input buffer of interface
	Dhcp(std::vector<IpPool>& ipPools) : ipPools_(ipPools), count(0), count2(0), Loggable::Loggable("DHCP " + std::to_string(++counter)), hostname("DHCP " + std::to_string(counter)), pcapFile("DHCP" + std::to_string(counter)) {
		// Assigned the first assignable ip of the ip pool to the dhcp itself

		ipPools_[0].getFirst(&iface);

		// TODO: Write logic for the main cpu
		cpu = nullptr;

		cpu = std::make_unique<std::thread>([&]() {
			printMessage(CONSOLE_INFO, "CPU Thread called");
			// Never ending loop so thread runs the entire lifetime
			while (true) {
				{
					std::unique_lock<std::mutex> lock(mtx);

					// Checks the bool meaning the NIC-RAM has a packet which needs to be processed so copy it to CPU memory
					if (flag.load()) {

						memory->enqueue(&iface.ram);
						flag.store(false, std::memory_order_release);
						// Tell the interface it has copied the packet in CPU memory so can clear the packet in interface
						cond_var_copy.notify_one();
					}

					if (memory->is_empty() == false) {
						if (count.try_acquire()) {
							//logger->info("CPU waiting!");
							// Waiting for a packet to be in Memory
							// cond_var_memory.wait(lock);
							printMessage(CONSOLE_INFO, "CPU can run!");
							// Copy the packet from CPU memory into RAM for processing
							memory->insert_copy_in_ram(ram, cond_var_memory);
							processPacket();

							// Packet processed so drop the packet from CPU memory and clear RAM
							memory->drop_packet();
							ram.clear();

							// Notifying the scheduler the processing is done on the RAM
							cond_var_memory.notify_one();
						}
					}
				}
				std::this_thread::sleep_for(std::chrono::milliseconds(200)); // Sleep for 200 seconds just so my cpu doesnt just keep locking and unlocking the mutex
				{
					std::unique_lock<std::mutex> lk(cv_m);
					cv.wait(lk, [] { return !paused; });
				}
			}

			});
		cpu->detach();
	}

	virtual void processPacket() {

		printMessage(CONSOLE_INFO, "Processing Packet!");
		size_t offset{};
		PROTOCOL::internal_hdr internal_hdr(ram);
		// PROTOCOL::internal_hdr internal_hdr(ram, offset);
		// internal_hdr.display();

		pcapFile.write(ram, 0);


		PROTOCOL::ethernet_hdr ethernet_hdr(ram);
		// PROTOCOL::ethernet_hdr ethernet_hdr(ram, offset);

		PROTOCOL::ethernet_trailer ethernet_trailer(ram);
		// ethernet_trailer.display();

		PROTOCOL::ethertype ether_type = processEthernetHeader(&iface, ethernet_hdr);

		switch (ether_type)
		{
		case PROTOCOL::ethertype_ip:
		{
			PROTOCOL::ipv4_hdr ipv4_hdr(ram);
			// PROTOCOL::ipv4_hdr ipv4_hdr(ram, offset);
			PROTOCOL::ip_protocol ip_type = processIPv4Header(&iface, ipv4_hdr);
			
			// Removes the padding of the packet
			auto actual_bytes_size = ipv4_hdr.ip_len - ((ipv4_hdr.ip_v_hl & IP_HL) << 2);
			auto start_it = ram.begin() + actual_bytes_size;
			if (start_it < ram.end())
				ram.erase(start_it, ram.end());


			switch (ip_type)
			{
			case PROTOCOL::ip_protocol_icmp:
			{
				// TODO:
				// processICMPHeader();

				break;
			}

			case PROTOCOL::ip_protocol_udp:
			{
				// TODO:
				PROTOCOL::udp_hdr udp_hdr(ram);
				// PROTOCOL::udp_hdr udp_hdr(ram, offset);

				// As UDP checksum is calulated for pseudo, udp header and payload so need to send all 
				PROTOCOL::pseudo_hdr pseudo_hdr(ipv4_hdr.ip_src, ipv4_hdr.ip_dst, ip_type, ipv4_hdr.ip_len - ((ipv4_hdr.ip_v_hl & IP_HL) * 4));


				std::deque<uint8_t> payload;
				auto start = ram.begin();
				auto end = ram.end();

				std::copy(start, end, std::back_inserter(payload));

				PROTOCOL::tl_ports port = processUDPHeader(&iface, pseudo_hdr, udp_hdr, payload);

				if (port == PROTOCOL::tl_ERROR || port == PROTOCOL::dhcp_client) {
					/*for (auto el : ram) {
						std::cout << +el << " ";
					}
					logger->warn("Here!: {}",std::to_string(port));*/
					printMessage(CONSOLE_WARN, "Dropped");
					return;
				}

				switch (port)
				{
				case PROTOCOL::dhcp_server: {

					PROTOCOL::dhcp_hdr dhcp_hdr(ram);
					// PROTOCOL::dhcp_hdr dhcp_hdr(ram, offset);
					// dhcp_hdr.display();
					PROTOCOL::action next_action_dhcp = processDHCPHeader(&iface, dhcp_hdr);

					switch (next_action_dhcp)
					{
					case PROTOCOL::RECEIVE_DHCP_DISCOVER: {

						//logger->warn("Get DHCP!");
						uint32_t id;
						uint8_array_6 client_mac;

						PROTOCOL::action next_action = processDHCPDiscover(&iface, dhcp_hdr, id, client_mac);

						switch (next_action)
						{
						case PROTOCOL::SEND_DHCP_OFFER:
							sendDHCPOffer(id, client_mac);
							return;

						case PROTOCOL::PACKET_ERROR:
						default:
							return;
						}

						return;
					}

					case PROTOCOL::RECEIVE_DHCP_REQUEST: {

						uint32_t id;
						uint8_array_6 client_mac;

						PROTOCOL::action next_action = processDHCPRequest(&iface, dhcp_hdr, &dhcp_table, iface.getIPV4(), id, client_mac);


						switch (next_action)
						{
						case PROTOCOL::SEND_DHCP_ACKNOWLEDGE:
							sendDHCPAcknowledgement(id, client_mac);
							return;

						case PROTOCOL::PACKET_ERROR:
						default:
							return;
						}

						return;
					}

					case PROTOCOL::PACKET_ERROR:
					default:
						//logger->warn("Here2!");
						printMessage(CONSOLE_WARN, "Dropped");
						break;
					}
					return;
				}

				default:
					return;
				}
			}

			case PROTOCOL::ip_protocol_tcp:
			case PROTOCOL::ip_protocol_ERROR:
			default:
				return;
			}

			break;
		}

		case PROTOCOL::ethertype_arp:
		{
			PROTOCOL::arp_hdr arp_hdr(ram);
			// PROTOCOL::arp_hdr arp_hdr(ram, offset);
			// std::cout<<"RECEIVE DHCP REQ\n";

			PROTOCOL::action next_action = processARPHeader(&iface, arp_hdr);
			// std::cout<<"prot"<<next_action<<std::endl;

			switch (next_action)
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
				//logger->warn("Here3!");
				printMessage(CONSOLE_WARN, "Dropped");
				break;
			}

			break;
		}

		case PROTOCOL::ethertype_ERROR:
		default:
			return;
		}

	}

	void sendDHCPOffer(uint32_t id, const uint8_array_6 &client_mac) {
		std::deque<uint8_t> packet;

		DhcpNetworkEntry offer = dhcp_table.getOffer(client_mac, id);

		//logger->warn("IP: {}", ipToString(offer.leased_ip));
		// Check if leased_ip not zero as zero means the Ip Pool is empty
		if (offer.leased_ip == 0) {
			printMessage(CONSOLE_WARN, "Warning: Ip Pool Empty");
			return;
		}

		uint8_array_6 src_mac;
		iface.getMAC(src_mac);

		uint32_t src_ip = iface.getIPV4();

		// Get the offered leased duration in seconds
		auto duration = std::chrono::duration_cast<std::chrono::seconds>(offer.leased_expire_time - offer.leased_start_time);
		uint32_t duration_seconds = static_cast<uint32_t>(duration.count());

		addDhcpOfferHeader(packet, id, offer.leased_ip, client_mac, offer.option.mask, offer.option.gateway, offer.option.dns, duration_seconds, src_ip);

		addUDPHeader(packet, PROTOCOL::dhcp_server, PROTOCOL::dhcp_client, src_ip, PROTOCOL::BroadcastIPAddr, PROTOCOL::ip_protocol_udp);

		addIPv4Header(packet, 20, PROTOCOL::ip_protocol_udp, src_ip, PROTOCOL::BroadcastIPAddr, generateRandomNumber(16));

		addEthernetHeader(packet, src_mac, PROTOCOL::BroadcastEtherAddr, PROTOCOL::ethertype_ip);

		addInternalHeader(packet, 0);

		printMessage(CONSOLE_INFO, "Client(DHCP Offer): {}", packet.size());

		// for(auto el : packet){
		// 	std::cout<<+el<<" ";
		// }

		iface.putMessageInOutputIface(&packet);
	}
	
	void sendDHCPAcknowledgement(uint32_t id, const uint8_array_6 &client_mac) {
		std::deque<uint8_t> packet;

		dhcp_table.changeBindingState(client_mac, BOUND);

		DhcpNetworkEntry offer = dhcp_table.getExistingOffer(client_mac, id);

		if (offer.leased_ip == 0) {
			printMessage(CONSOLE_WARN, "Not Present");
			return;
		}

		uint8_array_6 src_mac;
		iface.getMAC(src_mac);

		uint32_t src_ip = iface.getIPV4();

		// Get the offered leased duration in seconds
		auto duration = std::chrono::duration_cast<std::chrono::seconds>(offer.leased_expire_time - offer.leased_start_time);
		uint32_t duration_seconds = static_cast<uint32_t>(duration.count());

		addDhcpAcknowledgementHeader(packet, id, offer.leased_ip, client_mac, offer.option.mask, offer.option.gateway, offer.option.dns, duration_seconds);

		addUDPHeader(packet, PROTOCOL::dhcp_server, PROTOCOL::dhcp_client, src_ip, PROTOCOL::BroadcastIPAddr, PROTOCOL::ip_protocol_udp);

		addIPv4Header(packet, 20, PROTOCOL::ip_protocol_udp, src_ip, PROTOCOL::BroadcastIPAddr, (uint16_t)generateRandomNumber(16));

		addEthernetHeader(packet, src_mac, PROTOCOL::BroadcastEtherAddr, PROTOCOL::ethertype_ip);

		addInternalHeader(packet, 0);

		printMessage(CONSOLE_INFO, "Client(DHCP Acknowledgement): {}", packet.size());

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

		printMessage(CONSOLE_INFO, "Client(ARP Request): {}", packet.size());
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

		printMessage(CONSOLE_INFO, "Dhcp(ARP Reply): {}", packet.size());
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

		uint16_t identifier = generateRandomNumber(16);  // same will be used for all 5(Default) icmp request packet for a single ping
		uint16_t sequence_no = generateRandomNumber(16);  // increment and then will be used for all 5(Default) icmp request packet for a single ping

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
				sendARPRequest(dst_ip);
				// arp_table.addPendingEntry(dst_ip);
				shared_arp_memory->enqueue(&packet, dst_ip);
				return;
			}
		}
		else {
			arp_table.getIPtoMac(iface.getGATEWAY(), dst_mac);
			if (check_uint8_array_6(dst_mac, PROTOCOL::NoEtherAddr)) {
				sendARPRequest(iface.getGATEWAY());
				// arp_table.addPendingEntry(dst_ip);
				shared_arp_memory->enqueue(&packet, iface.getGATEWAY());
				return;
			}
		}

		addEthernetHeader(packet, src_mac, dst_mac, PROTOCOL::ethertype_ip);

		addInternalHeader(packet, 0);

		printMessage(CONSOLE_INFO, "Dhcp(Icmp Request) Sent: {}", packet.size());

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

		addIPv4Header(packet, 20, PROTOCOL::ip_protocol_icmp, src_ip, dst_ip, (uint16_t)generateRandomNumber(16));

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
				sendARPRequest(dst_ip);
				// arp_table.addPendingEntry(dst_ip);
				shared_arp_memory->enqueue(&packet, dst_ip);
				return;
			}
		}
		else {
			arp_table.getIPtoMac(iface.getGATEWAY(), dst_mac);
			if (check_uint8_array_6(dst_mac, PROTOCOL::NoEtherAddr)) {
				sendARPRequest(iface.getGATEWAY());
				// arp_table.addPendingEntry(dst_ip);
				shared_arp_memory->enqueue(&packet, iface.getGATEWAY());
				return;
			}
		}

		addEthernetHeader(packet, src_mac, dst_mac, PROTOCOL::ethertype_ip);

		addInternalHeader(packet, 0);

		printMessage(CONSOLE_INFO, "Dhcp(Icmp Reply) Sent: {}", packet.size());

		// for(auto el: packet){
		  // 	std::cout<<+el<<" ";
		  // }
		  // std::cout<<"\n";

		iface.putMessageInOutputIface(&packet);
	}

	void setHostname(std::string host_str){
		hostname = host_str;
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

	void getMAC(uint8_array_6 &mac) const { iface.getMAC(mac); }

	// Start the decrementing thread
	void start() {
		time_thread = std::thread([this]() {
			while (!stop_thread) {
				// Check the time against expire time
				{
					clock++;

				} // Release the lock when lock goes out of scope

				  // Sleep after processing for 1 second
				std::this_thread::sleep_for(std::chrono::seconds(1));
			}
			});

		time_thread.detach();
	};

	~Dhcp() { stop_thread = true; };

	bool stop_thread = false;
	std::thread time_thread;
	std::mutex muxTable;

	mutable std::mutex mtx;

	static uint8_t counter;

	std::string hostname;


	pcapWriter pcapFile;

	/* == For Device Control Window == */

	std::mutex consoleMutex;

	std::shared_ptr<DeviceWindow<Dhcp>> wndClass = std::make_shared<DeviceWindow<Dhcp>>(this, 4, dhcpWindowClass, DHCP_CLASS_NAME);

	//DeviceWindow<Dhcp> wndClass{this, 4, dhcpWindowClass, DHCP_CLASS_NAME };

	/* ====================== */

	/* == For Interface == */

	std::atomic<bool> flag;
	std::condition_variable cond_var_copy;

	DhcpIface iface{ flag, cond_var_copy, "DHCP " + std::to_string(counter) + " Iface" ,wndClass };

	/* ====================== */

	/* == For ARP process == */

	std::counting_semaphore<10> count2;
	std::condition_variable cond_var_arp;
	std::shared_ptr<Buffer::CircularPtrQueue<8192, 512, Dhcp>> shared_arp_memory = std::make_shared<Buffer::CircularPtrQueue<8192, 512, Dhcp>>(cond_var_arp, count2, this);
	ArpCache<ArpUserEntry, Buffer::CircularPtrQueue<8192, 512, Dhcp>> arp_table{ shared_arp_memory };

	/* ====================== */

	/* == For ICMP process == */

	uint32_t clock{ 0 };

	/* ====================== */

	/* == For processed packets == */

	std::counting_semaphore<10> count;
	std::condition_variable cond_var_memory;

	std::shared_ptr<Buffer::CircularQueue<8192, 512>> memory = std::make_shared<Buffer::CircularQueue<8192, 512>>(cond_var_memory, count);

	/* ====================== */
	

	std::vector<IpPool> &ipPools_;

	DhcpNetworkTable dhcp_table{ipPools_};

	std::unique_ptr<std::thread> cpu;
	std::vector<uint8_t> ram;

};

#endif