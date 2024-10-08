#pragma once
#ifndef ROUTERIFACE_H
#define ROUTERIFACE_H
#include "interface.h"
//#include "..\layer3\layer3.h"
#include "..\arpCache\arpCache.h"
#include "..\routingTable\routingTable.h"
#include "..\pcapWriter.h"

template <typename QueueType, typename BufferType>
class RouterIface :  public Iface, public Layer3 {

public:
  RouterIface(uint8_t id,
              std::atomic<bool> &flag,
              std::condition_variable &cond_var_copy,
              std::shared_ptr<QueueType> queue, 
              std::shared_ptr<RoutingTable> routing_table, 
              std::shared_ptr<ArpCache<ArpRouterEntry, BufferType>> arp_table, 
              std::shared_ptr<BufferType> shared_arp_memory,
              uint32_t *clock,
              std::string_view sv,
              std::shared_ptr<DeviceWindowBase> consoleWindow,
              pcapWriter* pcapFile
        )
            : id(id), 
              flag_(flag), 
              signal(cond_var_copy), 
              memory_(queue), 
              forwarding_table_(routing_table), 
              arp_table_(arp_table), 
              arp_waiting_queue_(shared_arp_memory),
              clock_(clock),
              Iface(sv.data(), consoleWindow),
              pcapFile_(pcapFile) {}

  void processInputPktRam(){
    // TODO: Deserialize the pkt ethernet header
    //std::cout<<"Router input process"<<std::endl;
    size_t offset{};
    PROTOCOL::internal_hdr internal_hdr(ram);
    // PROTOCOL::internal_hdr internal_hdr(ram,offset);
    // internal_hdr.display();

    pcapFile_->write(ram,0);

    PROTOCOL::ethernet_hdr ethernet_hdr(ram);
    // PROTOCOL::ethernet_hdr ethernet_hdr(ram,offset);
    // ethernet_hdr.display();

    PROTOCOL::ethernet_trailer ethernet_trailer(ram);
    
    // Checking Destination MAC if not equal to broadcast address or to client mac then drop by just clearing RAM
    bool for_broadcast = check_uint8_array_6(ethernet_hdr.ether_dhost, PROTOCOL::BroadcastEtherAddr);

    uint8_array_6 routerMac; 
    getMAC(routerMac);

    bool for_router = check_uint8_array_6(ethernet_hdr.ether_dhost, routerMac);

		std::unique_lock<std::mutex> lock(mtx);
    // if (!flag_.load(std::memory_order_acquire)) {
    //   flag_.store(true, std::memory_order_release);
    // }
    if(!(for_broadcast || for_router)){

      ram.clear();
      return;
    }

    if(for_broadcast) { 
        printMessage(CONSOLE_INFO, "Got Broadcast Router");
        processBroadcastPacket(ethernet_hdr, offset);
    }
    else if(for_router) { 
        printMessage(CONSOLE_INFO, "Got Unicast Router");
      processUnicastPacket(ethernet_hdr, offset, routerMac);
    }
    
    ram.clear();
  }

  void processOutputPktRam(){
      //size_t offset{};
      PROTOCOL::router_internal_hdr router_internal_hdr(ram);
      
      uint8_array_6 src_mac{};
      getMAC(src_mac);

      addEthernetHeader(ram, src_mac, router_internal_hdr.next_hop_mac, router_internal_hdr.type);

      addInternalHeader(ram,id);
  }
  
  // TODO: need to check
  void processBroadcastPacket(PROTOCOL::ethernet_hdr &ether_hdr, size_t &offset){
    PROTOCOL::ethertype ether_type = processEthernetHeader(this, ether_hdr);

    switch(ether_type)
      {
        case PROTOCOL::ethertype_arp:
        {
          PROTOCOL::arp_hdr arp_hdr(ram);
          // PROTOCOL::arp_hdr arp_hdr(ram, offset);

          PROTOCOL::action next_action_arp = processARPHeader(this, arp_hdr);
          printMessage(CONSOLE_INFO, "ARP Action: {}", +next_action_arp);

          switch (next_action_arp)
            {
            // TODO: NEED to change here
            case PROTOCOL::SEND_ARP_REPLY:
                printMessage(CONSOLE_INFO, "SEND Reply ARP");
              sendARPReply(arp_hdr.arp_sha, arp_hdr.arp_sip);
              arp_table_->checkARPTable(arp_hdr.arp_sha, arp_hdr.arp_sip, id);
              return;
            
            /*case PROTOCOL::RECEIVE_ARP_REPLY: {

               logger->info("RECEIVE ARP\n");
               arp_table_->checkPendingEntry(arp_hdr.arp_sha, arp_hdr.arp_sip, id);
               return;
            }*/
            
            case PROTOCOL::PACKET_ERROR:
            default:
                printMessage(CONSOLE_WARN, "Dropped!");
              break;
            }

          break;
        }

        case PROTOCOL::ethertype_ip:
        case PROTOCOL::ethertype_ERROR:
        default: 
            printMessage(CONSOLE_WARN, "Dropped!");
          return;
      }
  }

  // TODO: need to check
  void processUnicastPacket(PROTOCOL::ethernet_hdr &ether_hdr, size_t &offset, uint8_array_6 &routerMac){
    PROTOCOL::ethertype ether_type = processEthernetHeader(this, ether_hdr);
    // ether_hdr.display();
    switch(ether_type)
	{
		case PROTOCOL::ethertype_ip:{
            //size_t offset{};
            PROTOCOL::ipv4_hdr ipv4_hdr(ram);
            // ipv4_hdr.display();
		    PROTOCOL::ip_protocol ip_type = processIPv4Header(this, ipv4_hdr);

            switch (ip_type)
            {
                  case PROTOCOL::ip_protocol_FORWARD:{
                ipv4_hdr.ip_sum = 0;

                std::list<uint8_t> temp;
                ipv4_hdr.serialize(temp);

                uint16_t checksum = calculateChecksum(temp);

                std::list<uint8_t>::iterator it = temp.begin(); 
                std::advance(it, 10); // Move the iterator to the index of checksum 

                *it = checksum>>8;
                std::advance(it, 1);
                *it = checksum&0xFF;

                ram.insert(ram.begin(),temp.begin(),temp.end());
                uint8_t iface {};
                uint32_t next_hop_ip {};
                uint8_array_6 next_hop_mac {};
                std::vector<char> flags {};
                RouteType type{};

                // TODO: Need to make changes so that the packet is sent when arp doesn't have entry as well
                forwarding_table_->getRouteInfo(ipv4_hdr.ip_dst, &iface, &next_hop_ip, &flags, &type);

                printMessage(CONSOLE_INFO, "Route: {} {} {}", ipToString(ipv4_hdr.ip_dst), iface, ipToString(next_hop_ip));

                // No route found so discard
                if(iface == 0) return;

                // IF: Route found is directly connected so we get mac for destination ip and send
                // ELSE: Route found is not directly connected so we get mac for next hop ip and send
                if(iface != 0 && next_hop_ip == 0){
                  arp_table_->getIPtoMac(ipv4_hdr.ip_dst, next_hop_mac);


                  if(check_uint8_array_6(next_hop_mac, PROTOCOL::NoEtherAddr)){
                    // sendARPRequest(ipv4_hdr.ip_dst, iface);
                    // arp_table_->addPendingEntry(next_hop_ip, iface);
                          addRouterInternalHeader(ram, iface, next_hop_mac, PROTOCOL::ethertype_ip);
                          arp_waiting_queue_->enqueue(&ram, ipv4_hdr.ip_dst, iface);
                          return;
                  } 
                }else{
                  arp_table_->getIPtoMac(next_hop_ip, next_hop_mac);

                  if(check_uint8_array_6(next_hop_mac, PROTOCOL::NoEtherAddr)){
                    // sendARPRequest(next_hop_ip, iface);
                    // arp_table_->addPendingEntry(next_hop_ip, iface);
                        addRouterInternalHeader(ram,iface, next_hop_mac, PROTOCOL::ethertype_ip);
                        arp_waiting_queue_->enqueue(&ram, next_hop_ip, iface);
                        return;
                  } 
                }


                //this->addEthernetHeader(ram, routerMac, next_hop_mac, PROTOCOL::ethertype_ip);

                this->addRouterInternalHeader(ram, iface, next_hop_mac, PROTOCOL::ethertype_ip);

                // for(auto el:ram){
                //   std::cout<<+el<<" ";
                // }
                // std::cout<<std::endl;

                memory_->enqueue(&ram);
                printMessage(CONSOLE_INFO, "Router Fabric memory: ");
                // signal.notify_one();
                return;
              }

                  case PROTOCOL::ip_protocol_PROCESS:{
                      printMessage(CONSOLE_INFO, "For router!");
                    PROTOCOL::icmp_t0_hdr icmp_t0_hdr(ram);

				    PROTOCOL::action next_action = processICMPHeader(this, icmp_t0_hdr);

                    switch (next_action)
				    {
					    case PROTOCOL::RECEIVE_ICMP_REQUEST:{
						    sendICMPEchoReply(ipv4_hdr.ip_src,icmp_t0_hdr.icmp_id, icmp_t0_hdr.icmp_seq, icmp_t0_hdr.data);
						    return;
					    }
								
					    case PROTOCOL::RECEIVE_ICMP_REPLY:{
						    processICMPReply(this, icmp_t0_hdr, *clock_);
						    return;
					    }
								
					    case PROTOCOL::PACKET_ERROR:
					    default:
						    return;
				    }
                return;
              }

                  case PROTOCOL::ip_protocol_ERROR:
		          default:
                      printMessage(CONSOLE_WARN, "unicast ip Dropped!");
		    	        return;
                  }
        }
      
        case PROTOCOL::ethertype_arp:{
            PROTOCOL::arp_hdr arp_hdr(ram);
			// PROTOCOL::arp_hdr arp_hdr(ram, offset);
			// PROTOCOL::arp_hdr arp_hdr(ram_);

			PROTOCOL::action next_action_arp = processARPHeader(this, arp_hdr);

            switch (next_action_arp)
			{
                case PROTOCOL::RECEIVE_ARP_REPLY: {
                    printMessage(CONSOLE_INFO, "RECEIVE ARP");
                    arp_table_->checkPendingEntry(arp_hdr.arp_sha, arp_hdr.arp_sip, id);
                    return;
                }
          
                case PROTOCOL::PACKET_ERROR:
                default:
                    printMessage(CONSOLE_WARN, "Dropped!");
                    break;
			}
        }

        case PROTOCOL::ethertype_ERROR: {
            printMessage(CONSOLE_WARN, "unicast ether Dropped!");
            return;
        }
        default: {
            printMessage(CONSOLE_WARN, "unicast ether Dropped!");
            return;
        }
	}
  }

    // TODO: need to check
    void sendARPReply(const uint8_array_6 &request_mac ,uint32_t request_ip){
        std::deque<uint8_t> packet;
	
        uint8_array_6 src_mac;
        getMAC(src_mac);
    
        uint32_t src_ip;
        src_ip = getIPV4();

        addArpHeader( packet, PROTOCOL::arp_op_reply, src_mac, src_ip, request_mac, request_ip);

        //this->addEthernetHeader(packet, src_mac, request_mac, PROTOCOL::ethertype_arp);

        //this->addInternalHeader(packet, 0);
        addRouterInternalHeader(packet, 0, request_mac, PROTOCOL::ethertype_arp);

        /*std::ostringstream out;

        for (auto el : packet) {
            out << +el << " ";
        }
        std::cout << out.str() << std::endl;*/

        printMessage(CONSOLE_INFO, "Router(ARP Reply) Sent: {} {}", ipToString(request_ip), macToString(request_mac));
        // TODO: Put the packet in buffer
        putMessageInOutputIface(&packet);
    }

    // TODO: need to check and make alot of changes
    void sendARPRequest(uint32_t request_ip, uint8_t iface){
        printMessage(CONSOLE_INFO, "Router: ");
        std::deque<uint8_t> packet;

        uint8_array_6 src_mac;
        this->getMAC(src_mac);

        uint32_t src_ip = getIPV4();

        addArpHeader( packet, PROTOCOL::arp_op_request, src_mac, src_ip, PROTOCOL::NoEtherAddr, request_ip);

        addRouterInternalHeader(packet, iface, PROTOCOL::BroadcastEtherAddr, PROTOCOL::ethertype_arp);

        arp_table_->addPendingEntry(request_ip, iface);

        printMessage(CONSOLE_INFO, "Router(ARP Request) Sent: {}", ipToString(request_ip));
        memory_->enqueue(&packet);
    }


  // TODO: Need to make changes to payload 
  void sendICMPEchoRequest(uint32_t dst_ip){
    std::deque<uint8_t> packet;

    uint32_t src_ip = getIPV4();
    
    uint8_array_6 src_mac;
    getMAC(src_mac);

    uint8_t payload[ICMP_DATA_SIZE] {0};
    payload[0] = static_cast<uint8_t>((*clock_ >> (24)) & 0xFF);
    payload[1] = static_cast<uint8_t>((*clock_ >> (16)) & 0xFF);
    payload[2] = static_cast<uint8_t>((*clock_ >> (8)) & 0xFF);
    payload[3] = static_cast<uint8_t>((*clock_) & 0xFF);

    uint16_t identifier = generateRandomNumber(16);  // same will be used for all 5(Default) icmp request packet for a single ping
    uint16_t sequence_no = generateRandomNumber(16);  // increment and then will be used for all 5(Default) icmp request packet for a single ping

    addIcmpT0Header(packet, PROTOCOL::icmp_echo_request, 0, identifier, sequence_no, payload);

    Icmp_pkt_status icmp_stat {identifier, sequence_no, *clock_, src_ip, dst_ip, payload};

    icmp_pkt_status.push_back(icmp_stat);
    
    addIPv4Header(packet, 20, PROTOCOL::ip_protocol_icmp, src_ip, dst_ip, generateRandomNumber(16));
    
    /*std::cout<<"ECHO REQUEST!"<<"\n";
    for(auto el: packet){
    	std::cout<<+el<<" ";
    }
    std::cout<<"\n";*/

    uint8_t iface {};
    uint32_t next_hop_ip {};
    uint8_array_6 next_hop_mac {};
    std::vector<char> flags {};
    RouteType type{};

    forwarding_table_->getRouteInfo(dst_ip, &iface, &next_hop_ip, &flags, &type);

    // No route found so discard
    if(iface == 0) return;

    // uint8_array_6 dst_mac {};

    // IF: Route found is directly connected so we get mac for destination ip and send
    // ELSE: Route found is not directly connected so we get mac for next hop ip and send
    if(iface != 0 && next_hop_ip == 0){
      arp_table_->getIPtoMac(dst_ip, next_hop_mac);
      if(check_uint8_array_6(next_hop_mac, PROTOCOL::NoEtherAddr)){
        arp_waiting_queue_->enqueue(&packet, dst_ip, iface);
        return;
      }
    }else{
      arp_table_->getIPtoMac(next_hop_ip, next_hop_mac);
      if(check_uint8_array_6(next_hop_mac, PROTOCOL::NoEtherAddr)){
        arp_waiting_queue_->enqueue(&packet, next_hop_ip, iface);
        return;
      } 
    }

    //addEthernetHeader(packet, src_mac, next_hop_mac, PROTOCOL::ethertype_ip);

    //addInternalHeader(packet, iface);
    addRouterInternalHeader(packet, iface, next_hop_mac, PROTOCOL::ethertype_ip);
    printMessage(CONSOLE_INFO, "Router(Icmp Request) Sent: {}", packet.size());
      
    /*for(auto el: packet){
    	std::cout<<+el<<" ";
    }
    std::cout<<"\n";*/
    
    memory_->enqueue(&packet);
  }

  // TODO: Need to make changes to payload 
    void sendICMPEchoReply(uint32_t dst_ip, uint16_t identifier, uint16_t sequence_no, uint8_t payload[ICMP_DATA_SIZE]){
        std::deque<uint8_t> packet;

        uint32_t src_ip = getIPV4();
	
        uint8_array_6 src_mac;
        getMAC(src_mac);

        addIcmpT0Header(packet, PROTOCOL::icmp_echo_reply, 0, identifier, sequence_no, payload);

        addIPv4Header(packet, 20, PROTOCOL::ip_protocol_icmp, src_ip, dst_ip, generateRandomNumber(16));

        uint8_t iface {};
        uint32_t next_hop_ip {};
        uint8_array_6 next_hop_mac {};
        std::vector<char> flags {};
        RouteType type{};

        forwarding_table_->getRouteInfo(dst_ip, &iface, &next_hop_ip, &flags, &type);

        // No route found so discard
        if(iface == 0) return;

        // IF: Route found is directly connected so we get mac for destination ip and send
        // ELSE: Route found is not directly connected so we get mac for next hop ip and send
        if(iface != 0 && next_hop_ip == 0){
        arp_table_->getIPtoMac(dst_ip, next_hop_mac);
        if(check_uint8_array_6(next_hop_mac, PROTOCOL::NoEtherAddr)){
            arp_waiting_queue_->enqueue(&packet, dst_ip, iface);
            return;
        }
        }else{
        arp_table_->getIPtoMac(next_hop_ip, next_hop_mac);
        if(check_uint8_array_6(next_hop_mac, PROTOCOL::NoEtherAddr)){
            arp_waiting_queue_->enqueue(&packet, next_hop_ip, iface);
            return;
        } 
        }

        addRouterInternalHeader(packet, iface, next_hop_mac, PROTOCOL::ethertype_ip);
        printMessage(CONSOLE_INFO, "Router(Icmp Reply) Sent: {}", packet.size());
	
        memory_->enqueue(&packet);
    }


    iFaceState getState() const override { return NON_DESIGNATED; }
    void setState(iFaceState st) override {}

    // Getter methods 
    uint32_t getIPV4()        const { return ipv4; } 
    uint32_t getSUBNET_MASK() const { return subnet_mask; } 
    uint32_t getGATEWAY()     const { return gateway_ipv4; } 
    uint32_t getDNS()         const { return dns_ipv4; } 

    // Setter methods 
    void setPrivateIPV4(uint32_t ip) { 
        is_private_ip = true;
        ipv4 = ip; 
    } 
    void setPublicIPV4(uint32_t ip) { 
        is_private_ip = false;
        ipv4 = ip; 
    } 
    void setSUBNET_MASK(uint32_t mask) { subnet_mask = mask; } 
    void setGATEWAY(uint32_t default_gateway) { gateway_ipv4 = default_gateway; }
    void setDNS(uint32_t dns) { dns_ipv4 = dns; }
  
    bool is_private_ip{ false };

    uint32_t ipv4 {};           // 
    uint32_t subnet_mask {};    // 
    uint32_t gateway_ipv4 {};   // 
    uint32_t dns_ipv4 {};       // 

    uint8_t id;
    // std::shared_ptr<Buffer::CircularQueue<8192, 512>> memory_;
    std::shared_ptr<QueueType> memory_;
    std::shared_ptr<BufferType> arp_waiting_queue_;
    std::shared_ptr<ArpCache<ArpRouterEntry, BufferType>> arp_table_;
  
    std::atomic<bool> &flag_;
    std::condition_variable &signal;
    mutable std::mutex mtx;

    pcapWriter* pcapFile_ = nullptr;

    std::shared_ptr<RoutingTable> forwarding_table_;
    // ArpCache<ArpRouterEntry> arp_table;

    uint32_t *clock_;
};


#endif