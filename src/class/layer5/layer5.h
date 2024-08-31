#pragma once
#ifndef LAYER5_H
#define LAYER5_H
#include "..\layer4\layer4.h"
#include "..\dhcpTable\dhcpTable.h"

struct DhcpNetworkEntry;
class DhcpNetworkTable;
// template <typename T>
// class Layer5 : public Layer4<T> {
class Layer5 : public Layer4 {
public:

  PROTOCOL::action processDHCPHeader(ClientIface *iface, PROTOCOL::dhcp_hdr &dhcp_hdr){
    try{
      iface->logger->info("Process Client Dhcp!");

      if(dhcp_hdr.dhcp_hrd != 6 || dhcp_hdr.dhcp_hln != 6 || dhcp_hdr.dhcp_op != PROTOCOL::dhcp_op_reply || !dhcp_hdr.dhcp_opt.has_value()) return PROTOCOL::PACKET_ERROR;

      std::vector<uint8_t> options = dhcp_hdr.dhcp_opt.value();
      size_t i{};

      if(options[i++]!=99 && options[i++]!=130 && options[i++]!=83 && options[i++]!=99) return PROTOCOL::PACKET_ERROR;


      for(i; i < options.size(); i++){
        if(options[i++]  != PROTOCOL::MSG_TYPE){
          //size_t len = options[i++];
          continue;
        }

        if(options[i++]!=1) return PROTOCOL::PACKET_ERROR;

        switch(options[i++])
          {
            case PROTOCOL::dhcp_offer_code:
              return PROTOCOL::RECEIVE_DHCP_OFFER;   
            case PROTOCOL::dhcp_acknowledge_code:
              return PROTOCOL::RECEIVE_DHCP_ACKNOWLEDGE;
            default:
              return PROTOCOL::PACKET_ERROR;
          }
      }
    }catch(...){
      return PROTOCOL::PACKET_ERROR;
    }
    return PROTOCOL::PACKET_ERROR;

  }

  // TODO: nned to test
  PROTOCOL::action processDHCPHeader(DhcpIface *iface, PROTOCOL::dhcp_hdr &dhcp_hdr){
    try{


        iface->logger->info("Process Server Dhcp!");
      if(dhcp_hdr.dhcp_hrd != 6 || dhcp_hdr.dhcp_hln != 6 || dhcp_hdr.dhcp_op != PROTOCOL::dhcp_op_request || !dhcp_hdr.dhcp_opt.has_value()) return PROTOCOL::PACKET_ERROR;

      std::vector<uint8_t> options = dhcp_hdr.dhcp_opt.value();

      size_t i{};

      if(options[i++]!=99 && options[i++]!=130 && options[i++]!=83 && options[i++]!=99) return PROTOCOL::PACKET_ERROR;
      
      for(i; i < options.size(); i++){
        if(options[i++]  != PROTOCOL::MSG_TYPE){
          //size_t len = options[i++];
          continue;
        }

        if(options[i++]!=1) return PROTOCOL::PACKET_ERROR;

        switch(options[i++])
          {
            case PROTOCOL::dhcp_discover_code:
              return PROTOCOL::RECEIVE_DHCP_DISCOVER;   
            case PROTOCOL::dhcp_request_code:
              return PROTOCOL::RECEIVE_DHCP_REQUEST;
            default:
              return PROTOCOL::PACKET_ERROR;
          }
      }
      
      return PROTOCOL::PACKET_ERROR;
    }catch(...){
      return PROTOCOL::PACKET_ERROR;
    }

  }

  // TICK: DONE need to test
  PROTOCOL::action processDHCPDiscover(DhcpIface *iface, PROTOCOL::dhcp_hdr &dhcp_hdr, uint32_t &id, uint8_array_6 &client_mac){
        iface->logger->info("Process Dhcp Discover!");
        if(dhcp_hdr.dhcp_op != PROTOCOL::dhcp_op_request) return PROTOCOL::PACKET_ERROR;
        //iface->logger->info("Here");

        id = dhcp_hdr.dhcp_id;  // Need to use this while sending offer

        client_mac[0] = dhcp_hdr.dhcp_cadr[0];
        client_mac[1] = dhcp_hdr.dhcp_cadr[1];
        client_mac[2] = dhcp_hdr.dhcp_cadr[2];
        client_mac[3] = dhcp_hdr.dhcp_cadr[3];
        client_mac[4] = dhcp_hdr.dhcp_cadr[4];
        client_mac[5] = dhcp_hdr.dhcp_cadr[5];

        //iface->logger->info("Here");
        return PROTOCOL::SEND_DHCP_OFFER;
  }

  // TICK: need to test
  // TODO: make the logic
  template<typename T>
  PROTOCOL::action processDHCPOffer(T *iface, PROTOCOL::dhcp_hdr &dhcp_hdr, DhcpNetworkEntry &offer, const uint8_array_6 &mac, uint32_t &dhcp_server_ip){
      iface->logger->info("Process Dhcp Offer!");
    if(dhcp_hdr.dhcp_op != PROTOCOL::dhcp_op_reply) return PROTOCOL::PACKET_ERROR;
    
    if(offer.xid != dhcp_hdr.dhcp_id) return PROTOCOL::PACKET_ERROR;

    uint8_array_6 pkt_mac {};
    pkt_mac[0] = dhcp_hdr.dhcp_cadr[0];
    pkt_mac[1] = dhcp_hdr.dhcp_cadr[1];
    pkt_mac[2] = dhcp_hdr.dhcp_cadr[2];
    pkt_mac[3] = dhcp_hdr.dhcp_cadr[3];
    pkt_mac[4] = dhcp_hdr.dhcp_cadr[4];
    pkt_mac[5] = dhcp_hdr.dhcp_cadr[5];

    if(!check_uint8_array_6(pkt_mac,mac)) return PROTOCOL::PACKET_ERROR;

    if(!dhcp_hdr.dhcp_opt.has_value()) return PROTOCOL::PACKET_ERROR;

    offer.leased_ip = dhcp_hdr.dhcp_ycip;

    std::vector<uint8_t> options = dhcp_hdr.dhcp_opt.value();
    
    for(size_t i{4}; i < options.size(); ){
      try{

        uint8_t code = options[i++];
        if( code == PROTOCOL::MSG_TYPE ){
          size_t len = options[i++];  
          if(len != 1 || options[i++] != PROTOCOL::dhcp_offer_code) return PROTOCOL::PACKET_ERROR;
          continue;
        } 
        if( code == PROTOCOL::SUBNET_MASK ){
          size_t len = options[i++];
          deserializer(&offer.option.mask,options,len,i);
          continue;
        }
        if( code == PROTOCOL::ROUTER ){
          size_t len = options[i++];
          deserializer(&offer.option.gateway,options,len,i);
          continue;
        }
        if( code == PROTOCOL::DNS ){
          size_t len = options[i++];
          deserializer(&offer.option.dns,options,len,i);
          continue;
        }
        if( code == PROTOCOL::LEASE_TIME ){
          size_t len = options[i++];
          if(len != 4) return PROTOCOL::PACKET_ERROR;
          uint32_t lease_duration_sec;
          deserializer(&lease_duration_sec,options,len,i);
          offer.leased_start_time = std::chrono::high_resolution_clock::now();
          offer.leased_expire_time = offer.leased_start_time + std::chrono::seconds(lease_duration_sec);

          continue;
        }
        if( code == PROTOCOL::DHCP_SERVER_IP ){
          size_t len = options[i++];
          deserializer(&dhcp_server_ip,options,len,i);
          continue;
        }
        if( code == PROTOCOL::END){
          return PROTOCOL::SEND_DHCP_REQUEST;
        }

      }catch(...){
        return PROTOCOL::PACKET_ERROR;
      }

    }
    return PROTOCOL::PACKET_ERROR;

  }

  // TICK: need to test
  PROTOCOL::action processDHCPRequest(DhcpIface *iface, PROTOCOL::dhcp_hdr &dhcp_hdr,DhcpNetworkTable *dhcp_table, uint32_t server_ip, uint32_t &id, uint8_array_6 &client_mac){
      iface->logger->info("Process Dhcp Request!");
    if(dhcp_hdr.dhcp_op != PROTOCOL::dhcp_op_request) return PROTOCOL::PACKET_ERROR;

    id = dhcp_hdr.dhcp_id;  // Need to use this while sending offer

    client_mac[0] = dhcp_hdr.dhcp_cadr[0];
    client_mac[1] = dhcp_hdr.dhcp_cadr[1];
    client_mac[2] = dhcp_hdr.dhcp_cadr[2];
    client_mac[3] = dhcp_hdr.dhcp_cadr[3];
    client_mac[4] = dhcp_hdr.dhcp_cadr[4];
    client_mac[5] = dhcp_hdr.dhcp_cadr[5];

    if(!dhcp_table->checkMACInDHCPProcess(client_mac)) return PROTOCOL::PACKET_ERROR;

    if(!dhcp_hdr.dhcp_opt.has_value()) return PROTOCOL::PACKET_ERROR;

    std::vector<uint8_t> options = dhcp_hdr.dhcp_opt.value();

    uint32_t requested_ip{};
    uint32_t pkt_server_ip{};

    for(size_t i{4}; i < options.size(); ){
      try{

        uint8_t code = options[i++];
        if( code == PROTOCOL::MSG_TYPE ){
          // std::cout<<"HERE1\n";
          size_t len = options[i++];  
          if(len != 1 || options[i++] != PROTOCOL::dhcp_request_code) return PROTOCOL::PACKET_ERROR;
          continue;
        } 
        if( code == PROTOCOL::REQUESTED_IP ){
          // std::cout<<"HERE2\n";
          size_t len = options[i++];
          deserializer(&requested_ip,options,len,i);
          continue;
        }
        if( code == PROTOCOL::DHCP_SERVER_IP ){
          // std::cout<<"HERE3\n";
          size_t len = options[i++];
          deserializer(&pkt_server_ip,options,len,i);
          // If dhcp server ip not same 
          // std::cout<<"HERE4\n";
          // std::cout<<"SERVER IP"<<ipToString(server_ip)<<std::endl;
          // std::cout<<"PKT SERVER IP"<<ipToString(pkt_server_ip)<<std::endl;
          if(pkt_server_ip != server_ip) return PROTOCOL::PACKET_ERROR;
          continue;
        }
        if( code == PROTOCOL::END){
          break;
        }

      }catch(...){
        return PROTOCOL::PACKET_ERROR;
      }

    }

    if(!dhcp_table->checkMACRequestPhase(client_mac,requested_ip)) return PROTOCOL::PACKET_ERROR;

    // std::cout<<"HERE2\n";
    return PROTOCOL::SEND_DHCP_ACKNOWLEDGE;
  }
  
  // TODO: make the logic
  template<typename T>
  PROTOCOL::action processDHCPAcknowledge(T *iface, PROTOCOL::dhcp_hdr &dhcp_hdr, DhcpNetworkEntry &offer, const uint8_array_6 mac, uint32_t &dhcp_server_ip){
      iface->logger->info("Process Dhcp Acknowledgement!");
    if(dhcp_hdr.dhcp_op != PROTOCOL::dhcp_op_reply) return PROTOCOL::PACKET_ERROR;
    
    if(offer.xid != dhcp_hdr.dhcp_id) return PROTOCOL::PACKET_ERROR;

    uint8_array_6 pkt_mac{};
    pkt_mac[0] = dhcp_hdr.dhcp_cadr[0];
    pkt_mac[1] = dhcp_hdr.dhcp_cadr[1];
    pkt_mac[2] = dhcp_hdr.dhcp_cadr[2];
    pkt_mac[3] = dhcp_hdr.dhcp_cadr[3];
    pkt_mac[4] = dhcp_hdr.dhcp_cadr[4];
    pkt_mac[5] = dhcp_hdr.dhcp_cadr[5];

    if(!check_uint8_array_6(pkt_mac,mac)) return PROTOCOL::PACKET_ERROR;

    if(!dhcp_hdr.dhcp_opt.has_value()) return PROTOCOL::PACKET_ERROR;

    offer.leased_ip = dhcp_hdr.dhcp_ycip;

    std::vector<uint8_t> options = dhcp_hdr.dhcp_opt.value();
    
    for(size_t i{4}; i < options.size(); ){
      try{
        uint8_t code = options[i++];
        if( code == PROTOCOL::MSG_TYPE ){
          size_t len = options[i++];  
          if(len != 1 || options[i++] != PROTOCOL::dhcp_acknowledge_code) return PROTOCOL::PACKET_ERROR;
          continue;
        } 
        if( code == PROTOCOL::SUBNET_MASK ){
          size_t len = options[i++];
          uint32_t mask;
          deserializer(&mask,options,len,i);
          if(offer.option.mask != mask) return PROTOCOL::PACKET_ERROR;
          continue;
        }
        if( code == PROTOCOL::ROUTER ){
          size_t len = options[i++];
          uint32_t gateway;
          deserializer(&gateway,options,len,i);
          if(offer.option.gateway != gateway) return PROTOCOL::PACKET_ERROR;
          continue;
        }
        if( code == PROTOCOL::DNS ){
          size_t len = options[i++];
          uint32_t dns;
          deserializer(&dns,options,len,i);
          if(offer.option.dns != dns) return PROTOCOL::PACKET_ERROR;
          continue;
        }
        if( code == PROTOCOL::LEASE_TIME ){
          size_t len = options[i++];
          if(len != 4) return PROTOCOL::PACKET_ERROR;
          uint32_t lease_duration_sec;
          deserializer(&lease_duration_sec,options,len,i);

          offer.leased_start_time = std::chrono::high_resolution_clock::now();
          offer.leased_expire_time = offer.leased_start_time + std::chrono::seconds(lease_duration_sec);

          continue;
        }
        if( code == PROTOCOL::DHCP_SERVER_IP ){
          size_t len = options[i++];
          uint32_t server_ip;
          deserializer(&server_ip,options,len,i);

          if(server_ip != dhcp_server_ip) return PROTOCOL::PACKET_ERROR;  

          continue;
        }
        if( code == PROTOCOL::END){
          return PROTOCOL::DONE;
        }

      }catch(...){
        return PROTOCOL::PACKET_ERROR;
      }

    }
    return PROTOCOL::PACKET_ERROR;
  }



  void addDhcpDiscoverHeader(std::deque<uint8_t> &packet, const uint8_array_6 &src_mac, uint32_t id) {
    PROTOCOL::dhcp_hdr dhcp_hdr;
    dhcp_hdr.dhcp_discover(src_mac,id);
    // dhcp_hdr.display();

    std::list<uint8_t> temp;
    dhcp_hdr.serialize(temp);
    
    packet.insert(packet.begin(),temp.begin(),temp.end());

    uint16_t size {static_cast<uint16_t>(packet.size())};  // Would be default the dhcp discover header size = 44 bytes 
    
    //std::cout<<"L5: "<<size<<std::endl;
    // for(size_t i{}; i <packet.size();i++){
    //         std::cout<<" "<<+packet[i];
    //     }
    // std::cout<<std::endl;
  }

  void addDhcpOfferHeader(std::deque<uint8_t> &packet, uint32_t id, uint32_t offer_ip, const uint8_array_6 &src_mac, uint32_t mask, uint32_t gateway, uint32_t dns, uint32_t lease_time, uint32_t server_ip){
    PROTOCOL::dhcp_hdr dhcp_hdr;
    dhcp_hdr.dhcp_offer(id,offer_ip,src_mac,mask,gateway,dns,lease_time,server_ip);
    //dhcp_hdr.display();

    std::list<uint8_t> temp;
    dhcp_hdr.serialize(temp);
    
    packet.insert(packet.begin(),temp.begin(),temp.end());

    uint16_t size {static_cast<uint16_t>(packet.size())};  // Would be default the dhcp discover header size = 44 bytes 
    
    //std::cout<<"L5: "<<size<<std::endl;
    // for(size_t i{}; i <packet.size();i++){
    //         std::cout<<" "<<+packet[i];
    //     }
    // std::cout<<std::endl;
  }

	void addDhcpRequestHeader(std::deque<uint8_t> &packet, const uint8_array_6 &src_mac, uint32_t id, uint32_t offered_ip, uint32_t dhcp_server_ip) {
    PROTOCOL::dhcp_hdr dhcp_hdr;
    dhcp_hdr.dhcp_request(src_mac,id,offered_ip,dhcp_server_ip);
    // dhcp_hdr.display();

    std::list<uint8_t> temp;
    dhcp_hdr.serialize(temp);
    
    packet.insert(packet.begin(),temp.begin(),temp.end());

    uint16_t size {static_cast<uint16_t>(packet.size())};  // Would be default the dhcp discover header size = 44 bytes 
    
    //std::cout<<"L5: "<<size<<std::endl;
     //for(size_t i{}; i <packet.size();i++){
    //         std::cout<<" "<<+packet[i];
    //     }
    // std::cout<<std::endl;
  }

  void addDhcpAcknowledgementHeader(std::deque<uint8_t> &packet, uint32_t id, uint32_t offer_ip, const uint8_array_6 &src_mac, uint32_t mask, uint32_t gateway, uint32_t dns, uint32_t lease_time){
    PROTOCOL::dhcp_hdr dhcp_hdr;
    dhcp_hdr.dhcp_acknowlegement(id,offer_ip,src_mac,mask,gateway,dns,lease_time);
    // dhcp_hdr.display();

    std::list<uint8_t> temp;
    dhcp_hdr.serialize(temp);
    
    packet.insert(packet.begin(),temp.begin(),temp.end());

    uint16_t size {static_cast<uint16_t>(packet.size())};  // Would be default the dhcp discover header size = 44 bytes 
    
    //std::cout<<"L5: "<<size<<std::endl;
    // for(size_t i{}; i <packet.size();i++){
    //         std::cout<<" "<<+packet[i];
    //     }
    // std::cout<<std::endl;
  }

  void addDNSHeader(std::deque<uint8_t> &packet, uint16_t id, bool qr, uint8_t op, bool aa, bool tc, bool rd, bool ra, uint8_t rCode, uint16_t QDCOUNT, uint16_t ANCOUNT, uint16_t NSCOUNT, uint16_t ARCOUNT){
    PROTOCOL::dns_hdr dns_hdr(id, qr, op, aa, tc, rd, ra, rCode, QDCOUNT, ANCOUNT, NSCOUNT, ARCOUNT);

    std::list<uint8_t> dns_hdr_bytes;
    dns_hdr.serialize(dns_hdr_bytes);

    packet.insert(packet.begin(),dns_hdr_bytes.begin(),dns_hdr_bytes.end());

    //std::cout<<"L5: "<<packet.size()<<std::endl;
  }

  void addMessage(std::deque<uint8_t> &packet, std::string message){
    std::list<uint8_t> temp;
    serializer(&message,temp,message.length());

    packet.insert(packet.begin(),temp.begin(),temp.end());

  }

};

#endif
