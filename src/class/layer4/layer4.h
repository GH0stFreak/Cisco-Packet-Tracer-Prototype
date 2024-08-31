#pragma once
#ifndef LAYER4_H
#define LAYER4_H
#include "..\layer3\layer3.h"

enum TCP_state {
	CLOSED, 
  LISTEN, 
  SYN_SENT, 
  SYN_RECEIVED, 
  ESTABLISHED, 
  FIN_WAIT_1, 
  FIN_WAIT_2, 
  TIME_WAIT, 
  CLOSE_WAIT, 
  LAST_ACK,
  CLOSING, 
};

struct TCPConnection {
    // IP Addresses and Ports
    uint32_t src_ip;  // Needed for connection identification
    uint32_t dst_ip;
    uint16_t source_port;
    uint16_t dest_port;

    // Sequence and Acknowledgment Numbers
    uint32_t seq_num;
    uint32_t ack_num;
    uint32_t initial_seq_num;
    uint32_t initial_ack_num;

    // TCP Flags
    bool syn_sent;
    bool syn_received;
    bool ack_sent;
    bool fin_sent;
    bool fin_received;

    // Window Sizes
    uint16_t send_window;
    uint16_t recv_window;

    // Connection State
    TCP_state connection_state;

    // Timers
    double retransmission_timer;
    double persistence_timer;
    double keepalive_timer;
    double time_wait_timer;

    // RTT and Related Variables
    double rtt;           // Round-trip time
    double rtt_variance;  // Variance of the round-trip time
    double srtt;          // Smoothed RTT
    double rto;           // Retransmission timeout

    // Buffers
    std::vector<char> send_buffer;  // Holds data to be sent
    std::vector<char> recv_buffer;  // Holds received data

    // Congestion Control Variables
    uint32_t cwnd;          // Congestion window
    uint32_t ssthresh;      // Slow start threshold
    uint32_t dup_ack_count; // Count of duplicate ACKs received

    // Other Flags
    bool is_retransmission; //Flag indicating if the current transmission is a retransmission
};


// template <typename T>
// class Layer4 : public Layer3<T> {
class Layer4 : public Layer3 {
public:
  
virtual void processTCPHeader(){}
template<typename T>
PROTOCOL::tl_ports processUDPHeader(T *iface, PROTOCOL::pseudo_hdr &pseudo_hdr, PROTOCOL::udp_hdr &udp_hdr, std::deque<uint8_t> payload){


  // TODO: Write the logic
  std::list<uint8_t> pseudo_hdr_bytes;
  pseudo_hdr.serialize(pseudo_hdr_bytes);
  // pseudo_hdr.display();

	// std::cout<<"Pseudo\n";
  // for(auto i : pseudo_hdr_bytes){
	// 						std::cout<<+i<<" ";
	// 					}
	// std::cout<<"\n";

  std::list<uint8_t> udp_hdr_bytes;
  udp_hdr.serialize(udp_hdr_bytes);
  // udp_hdr.display();

	// std::cout<<"Udp\n";
  // for(auto i : udp_hdr_bytes){
	// 						std::cout<<+i<<" ";
	// 					}
	// std::cout<<"\n";

  // std::cout<<"Payload\n";
  // for(auto i : payload){
	// 						std::cout<<+i<<" ";
	// 					}
	// std::cout<<"\n";
	
  if(verifyChecksum(pseudo_hdr_bytes, udp_hdr_bytes, payload) == false) { 
    return PROTOCOL::tl_ERROR; 
  }


  if(udp_hdr.udp_sport == PROTOCOL::dhcp_client && udp_hdr.udp_dport == PROTOCOL::dhcp_server){
      return PROTOCOL:: dhcp_server;
  }
  else if(udp_hdr.udp_sport == PROTOCOL::dhcp_server && udp_hdr.udp_dport == PROTOCOL::dhcp_client){
      return PROTOCOL:: dhcp_client;
  }
  else {
      return PROTOCOL::message;
  }


  return PROTOCOL::tl_ERROR;
}

void addUDPHeader(std::deque<uint8_t> &packet, uint16_t sport, uint16_t dport, uint32_t src_ip, uint32_t dst_ip, PROTOCOL::ip_protocol protocol){

  uint16_t size {static_cast<uint16_t>(packet.size())};  

  PROTOCOL::udp_hdr udp_hdr(sport, dport, size);
	// udp_hdr.display();
  std::list<uint8_t> udp_hdr_bytes;
  udp_hdr.serialize(udp_hdr_bytes);

  PROTOCOL::pseudo_hdr pseudo_hdr(src_ip, dst_ip, (uint8_t)protocol, size + 8);
	// pseudo_hdr.display();
  
  std::list<uint8_t> pseudo_hdr_bytes;
  pseudo_hdr.serialize(pseudo_hdr_bytes);

  // Calculate checksum for pseudo, udp headers and payload
  uint16_t checksum = calculateChecksum(pseudo_hdr_bytes, udp_hdr_bytes, packet);
  
  // std::cout<<"Checksum: " <<(checksum>>8)<<" "<<(checksum&0xff) <<"\n";


  // Initialize iterator to the beginning of udp_hdr bytes list
  std::list<uint8_t>::iterator it = udp_hdr_bytes.begin(); 

  std::advance(it, 6); // Move the iterator to the index of checksum 
  *it = checksum>>8;
  std::advance(it, 1);
  *it = checksum&0xFF;

  // std::cout<<"Packet\n";
  // for(auto i : packet){
	// 						std::cout<<+i<<" ";
	// 					}
	// std::cout<<"\n";

  packet.insert(packet.begin(),udp_hdr_bytes.begin(),udp_hdr_bytes.end());


  //std::cout<<"L4: "<<packet.size()<<std::endl;
  // for(size_t i{}; i <packet.size();i++){
  //           std::cout<<" "<<+packet[i];
  //       }
  // std::cout<<std::endl;
}

void addTCPHeader(std::deque<uint8_t> &packet, uint16_t sport, uint16_t dport, uint32_t seq_num, uint32_t ack_num, uint8_t hlen, bool urg, bool ack, bool psh, bool rst, bool syn, bool fin, uint16_t window_size, uint32_t src_ip, uint32_t dst_ip, PROTOCOL::ip_protocol protocol){
  
  uint16_t size {static_cast<uint16_t>(packet.size())};  

  PROTOCOL::tcp_hdr tcp_hdr(sport, dport, seq_num, ack_num, hlen, urg, ack, psh, rst, syn, fin, window_size);
	// udp_hdr.display();
  std::list<uint8_t> tcp_hdr_bytes;
  tcp_hdr.serialize(tcp_hdr_bytes);

  PROTOCOL::pseudo_hdr pseudo_hdr(src_ip, dst_ip, protocol, size + hlen);
	// pseudo_hdr.display();
  
  std::list<uint8_t> pseudo_hdr_bytes;
  pseudo_hdr.serialize(pseudo_hdr_bytes);

  // Calculate checksum for pseudo, udp headers and payload
  uint16_t checksum = calculateChecksum(pseudo_hdr_bytes, tcp_hdr_bytes, packet);
  
  // std::cout<<"Checksum: " <<(checksum>>8)<<" "<<(checksum&0xff) <<"\n";


  // Initialize iterator to the beginning of udp_hdr bytes list
  std::list<uint8_t>::iterator it = tcp_hdr_bytes.begin(); 

  std::advance(it, 16); // Move the iterator to the index of checksum 
  *it = checksum>>8;
  std::advance(it, 1);
  *it = checksum&0xFF;

  // std::cout<<"Packet\n";
  // for(auto i : packet){
	// 						std::cout<<+i<<" ";
	// 					}
	// std::cout<<"\n";

  packet.insert(packet.begin(),tcp_hdr_bytes.begin(),tcp_hdr_bytes.end());


  //std::cout<<"L4: "<<packet.size()<<std::endl;
}

std::vector<TCPConnection> connections{};

};

#endif
