/* -*- Mode:C++; c-file-style:"gnu"; indent-tabs-mode:nil; -*- */
/*
 * Copyright (c) 2017 Alexander Afanasyev
 * Copyright (c) 1998, 1999, 2000 Mike D. Schiffman <mike@infonexus.com>
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 *
 * THIS SOFTWARE IS PROVIDED BY THE AUTHOR AND CONTRIBUTORS ``AS IS'' AND
 * ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED.  IN NO EVENT SHALL THE AUTHOR OR CONTRIBUTORS BE LIABLE
 * FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
 * DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS
 * OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
 * LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY
 * OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
 * SUCH DAMAGE.
 *
 */

// TODO: Need to see if these are necessary
// #include <arpa/inet.h>
// #include <boost/detail/endian.hpp>
#pragma once
#ifndef PROTOCOL_H
#define PROTOCOL_H

#include "utils.h"

namespace PROTOCOL {

#ifdef _LINUX_
#include <stdint.h>
#endif /* _LINUX_ */


#ifndef IP_MAXPACKET
#define IP_MAXPACKET 65535
#endif

#define ICMP_DATA_SIZE 32


static const uint8_array_6 BroadcastEtherAddr = {0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF};
static const uint8_array_6 NoEtherAddr = {0x0, 0x0, 0x0, 0x0, 0x0, 0x0};
static const uint32_t BroadcastIPAddr = 0xFFFFFFFF;
static const uint32_t NoIPAddr = 0x0;

static const uint8_array_6 MulticastSTPEtherAddr = { 0x01, 0x80, 0xC2, 0x00, 0x00, 0x00 };
/* PVST & PVST+ are mostly same but just that PVST supports ISL trunk encapsulation only 
   & PVST+ supports 802.1Q. PVST is seen rarely.
*/
static const uint8_array_6 MulticastPVSTEtherAddr = {0x01, 0x00, 0x0C, 0xCC, 0xCC, 0xCD };

enum ethertype {
    ethertype_ERROR = 0,
    ethertype_arp = 0x0806,
    ethertype_ip = 0x0800,
    ethertype_llc,
};

enum llc_sap {
    llc_sap_ERROR,
    llc_sap_stp = 0x42,
};

enum llc_control {
    llc_control_informattion = 0x00,
    llc_control_supervisory = 0x01,
    llc_control_unnumbered = 0x03,
};

enum bpdu_type {
    bpdu_configuration = 0x00,
    bpdu_tcn = 0x01,
};

enum ip_protocol {
    ip_protocol_ERROR = 0,
    ip_protocol_FORWARD,
    ip_protocol_PROCESS,
    ip_protocol_icmp = 0x01,
    ip_protocol_tcp = 0x06,
    ip_protocol_udp = 0x11,
};

enum arp_opcode {
    arp_op_request = 0x0001,
    arp_op_reply = 0x0002,
};

enum icmp_type {
    icmp_echo_request = 0x00,
    icmp_dst_unreachable = 0x03,
    icmp_echo_reply = 0x08,
    icmp_timestamp = 0x0D,
    icmp_timestamp_reply = 0x0E,
    icmp_extended_echo_request = 0x2A,
    icmp_extended_echo_reply = 0x2B,
};

enum icmp_protocol {
    icmp_protocol_ERROR = 0,
    icmp_protocol_FORWARD,
    icmp_protocol_icmp = 0x01,
    icmp_protocol_tcp = 0x06,
    icmp_protocol_udp = 0x11,
};

enum dhcp_opcode {
    dhcp_op_request           = 0x0001,
    dhcp_op_reply             = 0x0002,
};
enum dhcp_type_options {
    dhcp_discover_code        = 0x0001,
    dhcp_offer_code           = 0x0002,
    dhcp_request_code         = 0x0003,
    dhcp_decline_code         = 0x0004,
    dhcp_acknowledge_code     = 0x0005,
    dhcp_neg_acknowledge_code = 0x0006,
    dhcp_release_code         = 0x0007,
    dhcp_inform_code          = 0x0008,
};

enum arp_hrd_fmt {
    arp_hrd_ethernet = 0x0001,  
};

enum tl_ports {
    tl_ERROR,
    dns_server = 0x35,                 /* 53 used by dns server */
    dhcp_server = 0x43,                /* 67 used by dhcp server */
    dhcp_client = 0x44,                /* 68 used by dhcp client */
    message,                           /* Message           */
};

enum action {
    PACKET_ERROR,
    DONE,
    SEND_ARP_REQUEST,
    RECEIVE_ARP_REQUEST,
    SEND_ARP_REPLY,
    RECEIVE_ARP_REPLY,
    SEND_DHCP_DISCOVER,
    RECEIVE_DHCP_DISCOVER,
    SEND_DHCP_OFFER,
    RECEIVE_DHCP_OFFER,
    SEND_DHCP_REQUEST,
    RECEIVE_DHCP_REQUEST,
    SEND_DHCP_ACKNOWLEDGE,
    RECEIVE_DHCP_ACKNOWLEDGE,
    SEND_ICMP_REQUEST,
    RECEIVE_ICMP_REQUEST,
    SEND_ICMP_REPLY,
    RECEIVE_ICMP_REPLY,
    RECEIVE_BPDU_CONFIGURATION,
    RECEIVE_BPDU_TOPOLOGY_CHANGE,
};

/* 
 * Structure of a internal header
 */
struct internal_hdr {
  uint16_t length = 0;
  uint8_t outport_port = 0;

  internal_hdr (uint16_t len) {
    length = len;
  }

  internal_hdr (uint16_t len, uint8_t op) {
    length = len;
    outport_port = op;
  }

  // Deserialize the header
  internal_hdr (std::queue<uint8_t> &pkt) {

    // Pushing the length value
    deserializer(&length, pkt, sizeof(length));
    // Pushing the output port value
    deserializer(&outport_port, pkt, sizeof(outport_port));
    
  }

  internal_hdr (std::vector<uint8_t> &pkt, size_t &offset) {

    // Pushing the length value
    deserializer(&length, pkt, sizeof(length), offset);
    // Pushing the output port value
    deserializer(&outport_port, pkt, sizeof(outport_port), offset);
  
  }

  internal_hdr (std::vector<uint8_t> &pkt) {

    // Pushing the length value
    deserializer(&length, pkt, sizeof(length));
    // Pushing the output port value
    deserializer(&outport_port, pkt, sizeof(outport_port));
  
  }

  internal_hdr (std::deque<uint8_t> &pkt) {

    // Pushing the length value
    deserializer(&length, pkt, sizeof(length));
    // Pushing the output port value
    deserializer(&outport_port, pkt, sizeof(outport_port));
    
  }

  // Serialize the header
  template<typename T>
  void serialize (T &pkt) {
    // Pushing the length value
    serializer(&length, pkt, sizeof(length));
    // Pushing the output port value
    serializer(&outport_port, pkt, sizeof(outport_port));

  }

  uint16_t size(){
    return sizeof(internal_hdr);
  }

  void display()const{
    std::cout << "Internal Header" << std::endl;
    std::cout << "Length: " << std::to_string(length) << std::endl;
    std::cout << "Output Port: " << std::to_string(outport_port) << std::endl;
  }
};
// __attribute__ ((packed)) ;
struct router_internal_hdr {
    uint16_t length = 0;
    uint8_t outport_port = 0;
    uint8_array_6 next_hop_mac = {0};
    uint16_t type {};

    router_internal_hdr(uint16_t len) {
        length = len;
    }

    router_internal_hdr(uint16_t len, uint8_t op) {
        length = len;
        outport_port = op;
    }

    router_internal_hdr(uint16_t len, uint8_t op,const uint8_array_6 &mac, uint16_t tempType) {
        length = len;
        outport_port = op;
        assign_uint8_array_6(next_hop_mac,mac);
        type = tempType;
    }

    router_internal_hdr(std::queue<uint8_t>& pkt) {

        // Pushing the length value
        deserializer(&length, pkt, sizeof(length));
        // Pushing the output port value
        deserializer(&outport_port, pkt, sizeof(outport_port));
        // Pushing the next-hop ip value
        deserializer(&next_hop_mac, pkt, MAC_ADDR_LEN);
        // Pushing the ethertype value
        deserializer(&type, pkt, sizeof(type));

    }

    router_internal_hdr(std::vector<uint8_t>& pkt, size_t& offset) {

        // Pushing the length value
        deserializer(&length, pkt, sizeof(length), offset);
        // Pushing the output port value
        deserializer(&outport_port, pkt, sizeof(outport_port), offset);
        // Pushing the next-hop ip value
        deserializer(&next_hop_mac, pkt, MAC_ADDR_LEN, offset);
        // Pushing the ethertype value
        deserializer(&type, pkt, sizeof(type));

    }

    router_internal_hdr(std::vector<uint8_t>& pkt) {

        // Pushing the length value
        deserializer(&length, pkt, sizeof(length));
        // Pushing the output port value
        deserializer(&outport_port, pkt, sizeof(outport_port));
        // Pushing the next-hop ip value
        deserializer(&next_hop_mac, pkt, MAC_ADDR_LEN);
        // Pushing the ethertype value
        deserializer(&type, pkt, sizeof(type));

    }

    router_internal_hdr(std::deque<uint8_t>& pkt) {

        // Pushing the length value
        deserializer(&length, pkt, sizeof(length));
        // Pushing the output port value
        deserializer(&outport_port, pkt, sizeof(outport_port));
        // Pushing the next-hop ip value
        deserializer(&next_hop_mac, pkt, MAC_ADDR_LEN);
        // Pushing the ethertype value
        deserializer(&type, pkt, sizeof(type));

    }

    // Serialize the header
    template<typename T>
    void serialize(T& pkt) {
        // Pushing the length value
        serializer(&length, pkt, sizeof(length));
        // Pushing the output port value
        serializer(&outport_port, pkt, sizeof(outport_port));
        // Pushing the next-hop ip value
        serializer(next_hop_mac, pkt, MAC_ADDR_LEN);
        // Pushing the ethertype value
        serializer(&type, pkt, sizeof(type));

    }

    void display() const {
        std::cout << "Internal Header" << std::endl;
        std::cout << "Length: " << std::to_string(length) << std::endl;
        std::cout << "Output Port: " << std::to_string(outport_port) << std::endl;
        std::cout << "Next-hop MAC: " << macToString(next_hop_mac) << std::endl;
        std::cout << "Type: " << std::to_string(type) << std::endl;
    }
};

/*
 *  Ethernet packet header prototype.  Too many O/S's define this differently.
 *  Easy enough to solve that and define it here.
 *  This explains the ethernet and different type and the other LLC and SNAP headers difference 
 *  It was confusing for me to understand it but this summarized it pretty well
 *  https://learningnetwork.cisco.com/s/article/ethernet-standards
 */
struct ethernet_hdr
{
  uint64_t       premable = 0xAAAAAAAAAAAAAAAB;    /* schronization bits */
  uint8_array_6  ether_dhost{};                    /* destination ethernet address */
  uint8_array_6  ether_shost{};                    /* source ethernet address */
  uint16_t       ether_type{};                     /* packet type ID */

  // Constructor that takes the byte vector and interprets the bytes
  ethernet_hdr(){}
  ethernet_hdr(const uint8_array_6 dhost,const uint8_array_6 shost,const uint16_t type){

    for(size_t i{}; i < MAC_ADDR_LEN; i++){
      ether_dhost[i] = dhost[i];
      ether_shost[i] = shost[i];
    }

    ether_type = type;
  }

  ethernet_hdr (std::queue<uint8_t> &pkt) {
    // Pushing the premable value
    deserializer(&premable, pkt, sizeof(premable));
    // Pushing the destination mac address value
    deserializer(&ether_dhost, pkt, MAC_ADDR_LEN);
    // Pushing the source mac address value
    deserializer(&ether_shost, pkt, MAC_ADDR_LEN);
    // Pushing the ethertype value
    deserializer(&ether_type, pkt, sizeof(ether_type));     
    
  }

  ethernet_hdr (std::vector<uint8_t> &pkt, size_t &offset) {
    // Pushing the premable value
    deserializer(&premable, pkt, sizeof(premable), offset);
    // Pushing the destination mac address value
    deserializer(&ether_dhost, pkt, MAC_ADDR_LEN, offset);
    // Pushing the source mac address value
    deserializer(&ether_shost, pkt, MAC_ADDR_LEN, offset);
    // Pushing the ethertype value
    deserializer(&ether_type, pkt, sizeof(ether_type), offset);     
    
  }

  ethernet_hdr (std::vector<uint8_t> &pkt) {
    // Pushing the premable value
    deserializer(&premable, pkt, sizeof(premable));
    // Pushing the destination mac address value
    deserializer(&ether_dhost, pkt, MAC_ADDR_LEN);
    // Pushing the source mac address value
    deserializer(&ether_shost, pkt, MAC_ADDR_LEN);
    // Pushing the ethertype value
    deserializer(&ether_type, pkt, sizeof(ether_type));     
    
  }

  ethernet_hdr (std::deque<uint8_t> &pkt) {
    // Pushing the premable value
    deserializer(&premable, pkt, sizeof(premable));
    // Pushing the destination mac address value
    deserializer(&ether_dhost, pkt, MAC_ADDR_LEN);
    // Pushing the source mac address value
    deserializer(&ether_shost, pkt, MAC_ADDR_LEN);
    // Pushing the ethertype value
    deserializer(&ether_type, pkt, sizeof(ether_type));     
    
  }
  
  template<typename T>
  void serialize(T &pkt){

    // Pushing the version&header length value
    serializer(&premable, pkt, sizeof(premable));
    // Pushing the tos value
    serializer(ether_dhost, pkt, MAC_ADDR_LEN);
    // Pushing the total length value
    serializer(ether_shost, pkt, MAC_ADDR_LEN);
    // Pushing the id value
    serializer(&ether_type,pkt,sizeof(ether_type));      
    
  }

  void display()const{
    std::cout << "Ethernet Header" << std::endl;
    std::cout << "Premable: " << std::to_string(premable) << std::endl;
    std::cout << "Destination MAC: " << macToString(ether_dhost) << std::endl;
    std::cout << "Source MAC: " << macToString(ether_shost) << std::endl;
    std::cout << "Type: " << std::to_string(ether_type) << std::endl;
  }

};
// __attribute__ ((packed)) ;

// Ethernet & LLC information 

// https://www.cisco.com/c/en/us/support/docs/ibm-technologies/logical-link-control-llc/12247-45.html
// https://www.liveaction.com/glossary/service-access-point-sap/
struct llc_hdr
{
    uint8_t  llc_dsap{};                        /* Destination Service Access Point */
    uint8_t  llc_ssap{};                        /* Source Service Access Point */
    uint8_t  llc_control{};   
#define LLC_INFORMATION_CONTROL 0x00             
#define LLC_SUPERVISORY_CONTROL 0x01             
#define LLC_UNNUMBERED_CONTROL 0x03             
    /* Control Field */
    /* This is not code just representing this way was easier
    *  If(llc_control == XXXXXX11) {
    *      then llc_control_2byte is not present and frame type is unnumbered frame
    *  }else if(llc_control == XXXXXX01) {
    *      then llc_control_2byte is present and frame type is supervisory frame
    *  }else if(llc_control == XXXXXXX0) {
    *      then llc_control_2byte is present and frame type is information frame
    *  }
    */                                              
    std::optional<uint8_t> llc_control_2byte;   /* Control Field 2nd byte */
                                                   

    // Constructor that takes the byte vector and interprets the bytes
    llc_hdr() {}
    llc_hdr(const uint8_t dsap, const uint8_t ssap, const uint8_t control, const std::optional< uint8_t> control_2byte = std::nullopt) {

        llc_dsap = dsap;
        llc_ssap = ssap;
        llc_control = control;
        if((llc_control & LLC_UNNUMBERED_CONTROL) == LLC_UNNUMBERED_CONTROL) {
            if(control_2byte.has_value())
                throw std::invalid_argument("Received an argument when not possible for control");
        }else{
            if (control_2byte.has_value()) llc_control_2byte = control_2byte.value();
            else throw std::invalid_argument("Received Incorrect Control Value");
        }
    }

    llc_hdr(std::vector<uint8_t>& pkt, size_t& offset) {
        // Pushing the dsap value
        deserializer(&llc_dsap, pkt, sizeof(llc_dsap), offset);
        // Pushing the ssap value
        deserializer(&llc_ssap, pkt, sizeof(llc_ssap), offset);
        // Pushing the control byte 1 value
        deserializer(&llc_control, pkt, sizeof(llc_control), offset);

        // Pushing the Control byte 2 value
        if ((llc_control & LLC_UNNUMBERED_CONTROL) != LLC_UNNUMBERED_CONTROL) {
            llc_control_2byte = pkt[offset++];
        }

    }

    llc_hdr(std::vector<uint8_t>& pkt, uint16_t &length) {
        // Pushing the dsap value
        deserializer(&llc_dsap, pkt, sizeof(llc_dsap));
        length-= sizeof(llc_dsap);
        // Pushing the ssap value
        deserializer(&llc_ssap, pkt, sizeof(llc_ssap));
        length -= sizeof(llc_ssap);
        // Pushing the control byte 1 value
        deserializer(&llc_control, pkt, sizeof(llc_control));
        length -= sizeof(llc_control);

        // Pushing the Control byte 2 value
        if ((llc_control & LLC_UNNUMBERED_CONTROL) != LLC_UNNUMBERED_CONTROL) {
            llc_control_2byte = pkt.front();
            pkt.erase(pkt.begin());
            length -= sizeof(llc_control_2byte);
        }
    }

    llc_hdr(std::deque<uint8_t>& pkt) {
        // Pushing the dsap value
        deserializer(&llc_dsap, pkt, sizeof(llc_dsap));
        // Pushing the ssap value
        deserializer(&llc_ssap, pkt, sizeof(llc_ssap));
        // Pushing the control byte 1 value
        deserializer(&llc_control, pkt, sizeof(llc_control));

        // Pushing the Control byte 2 value
        if ((llc_control & LLC_UNNUMBERED_CONTROL) != LLC_UNNUMBERED_CONTROL) {
            llc_control_2byte = pkt.front();
            pkt.erase(pkt.begin());
        }

    }

    template<typename T>
    void serialize(T& pkt) {

        // Pushing the dsap value
        serializer(&llc_dsap, pkt, sizeof(llc_dsap));
        // Pushing the ssap value
        serializer(&llc_ssap, pkt, sizeof(llc_ssap));
        // Pushing the control byte 1 value
        serializer(&llc_control, pkt, sizeof(llc_control));

        // Pushing the Control byte 2 value
        if (llc_control_2byte.has_value()) {
            uint8_t val = llc_control_2byte.value();
            serializer(&val, pkt, sizeof(llc_control_2byte));
        }

    }

    void display() const {
        std::cout << "LLC Header" << std::endl;
        std::cout << "DSAP: " << std::to_string(llc_dsap) << std::endl;
        std::cout << "SSAP: " << std::to_string(llc_ssap) << std::endl;
        std::cout << "Control: " << std::to_string(llc_control) << std::endl;
        if (llc_control_2byte.has_value()) {
            std::cout << "Control_2: " << std::to_string(llc_control_2byte.value()) << std::endl;
        }
    }

};

//https://support.hpe.com/techhub/eginfolib/networking/docs/switches/5980/5200-3921_l2-lan_cg/content/499036672.htm
struct bpdu_hdr {
    uint16_t bpdu_p_id;             /* Protocol Identification */
    uint8_t bpdu_v_id;              /* Protocol Version Identification */
    uint8_t bpdu_type;              /* BPDU Type */
    uint8_t bpdu_flags;             /* Flags */
    uint64_t bpdu_r_id;             /* Root Identification */
    uint32_t bpdu_r_cost;           /* Root Path Cost */
    uint64_t bpdu_b_id;             /* Bridge Identification */
    uint16_t bpdu_port_id;          /* Port Identification */
    uint16_t bpdu_message_age;      /* Message Age */
    uint16_t bpdu_max_age;          /* Max Age */
    uint16_t bpdu_hello_time;       /* Hello Time */
    uint16_t bpdu_forward_delay;    /* Forward Delay */

    bpdu_hdr(uint16_t p_id, uint8_t v_id, uint8_t type, uint8_t flags, uint64_t root_id, uint32_t root_cost, uint64_t bridge_id, uint16_t port_id, uint16_t message_age, uint16_t max_age, uint16_t hello_time, uint16_t forward_delay) {
        bpdu_p_id = p_id;             
        bpdu_v_id = v_id;              
        bpdu_type = type;              
        bpdu_flags = flags;             
        bpdu_r_id = root_id;             
        bpdu_r_cost = root_cost;           
        bpdu_b_id = bridge_id;             
        bpdu_port_id = port_id;          
        bpdu_message_age = message_age;      
        bpdu_max_age = max_age;          
        bpdu_hello_time = hello_time;       
        bpdu_forward_delay = forward_delay;
    }

    bpdu_hdr(std::vector<uint8_t>& pkt, size_t& offset) {
        deserializer(&bpdu_p_id, pkt, sizeof(bpdu_p_id), offset);
        deserializer(&bpdu_v_id, pkt, sizeof(bpdu_v_id), offset);
        deserializer(&bpdu_type, pkt, sizeof(bpdu_type), offset);
        deserializer(&bpdu_flags, pkt, sizeof(bpdu_flags), offset);
        deserializer(&bpdu_r_id, pkt, sizeof(bpdu_r_id), offset);
        deserializer(&bpdu_r_cost, pkt, sizeof(bpdu_r_cost), offset);
        deserializer(&bpdu_b_id, pkt, sizeof(bpdu_b_id), offset);
        deserializer(&bpdu_port_id, pkt, sizeof(bpdu_port_id), offset);
        deserializer(&bpdu_message_age, pkt, sizeof(bpdu_message_age), offset);
        deserializer(&bpdu_max_age, pkt, sizeof(bpdu_max_age), offset);
        deserializer(&bpdu_hello_time, pkt, sizeof(bpdu_hello_time), offset);
        deserializer(&bpdu_forward_delay, pkt, sizeof(bpdu_forward_delay), offset);
    }

    bpdu_hdr(std::vector<uint8_t>& pkt, uint16_t& length) {
        deserializer(&bpdu_p_id, pkt, sizeof(bpdu_p_id));
        length -= sizeof(bpdu_p_id);
        deserializer(&bpdu_v_id, pkt, sizeof(bpdu_v_id));
        length -= sizeof(bpdu_v_id);
        deserializer(&bpdu_type, pkt, sizeof(bpdu_type));
        length -= sizeof(bpdu_type);
        deserializer(&bpdu_flags, pkt, sizeof(bpdu_flags));
        length -= sizeof(bpdu_flags);
        deserializer(&bpdu_r_id, pkt, sizeof(bpdu_r_id));
        length -= sizeof(bpdu_r_id);
        deserializer(&bpdu_r_cost, pkt, sizeof(bpdu_r_cost));
        length -= sizeof(bpdu_r_cost);
        deserializer(&bpdu_b_id, pkt, sizeof(bpdu_b_id));
        length -= sizeof(bpdu_b_id);
        deserializer(&bpdu_port_id, pkt, sizeof(bpdu_port_id));
        length -= sizeof(bpdu_port_id);
        deserializer(&bpdu_message_age, pkt, sizeof(bpdu_message_age));
        length -= sizeof(bpdu_message_age);
        deserializer(&bpdu_max_age, pkt, sizeof(bpdu_max_age));
        length -= sizeof(bpdu_max_age);
        deserializer(&bpdu_hello_time, pkt, sizeof(bpdu_hello_time));
        length -= sizeof(bpdu_hello_time);
        deserializer(&bpdu_forward_delay, pkt, sizeof(bpdu_forward_delay));
        length -= sizeof(bpdu_forward_delay);
    }

    bpdu_hdr(std::deque<uint8_t>& pkt) {
        deserializer(&bpdu_p_id, pkt, sizeof(bpdu_p_id));
        deserializer(&bpdu_v_id, pkt, sizeof(bpdu_v_id));
        deserializer(&bpdu_type, pkt, sizeof(bpdu_type));
        deserializer(&bpdu_flags, pkt, sizeof(bpdu_flags));
        deserializer(&bpdu_r_id, pkt, sizeof(bpdu_r_id));
        deserializer(&bpdu_r_cost, pkt, sizeof(bpdu_r_cost));
        deserializer(&bpdu_b_id, pkt, sizeof(bpdu_b_id));
        deserializer(&bpdu_port_id, pkt, sizeof(bpdu_port_id));
        deserializer(&bpdu_message_age, pkt, sizeof(bpdu_message_age));
        deserializer(&bpdu_max_age, pkt, sizeof(bpdu_max_age));
        deserializer(&bpdu_hello_time, pkt, sizeof(bpdu_hello_time));
        deserializer(&bpdu_forward_delay, pkt, sizeof(bpdu_forward_delay));
    }

    template<typename T>
    void serialize(T& pkt) {
        serializer(&bpdu_p_id, pkt, sizeof(bpdu_p_id));
        serializer(&bpdu_v_id, pkt, sizeof(bpdu_v_id));
        serializer(&bpdu_type, pkt, sizeof(bpdu_type));
        serializer(&bpdu_flags, pkt, sizeof(bpdu_flags));
        serializer(&bpdu_r_id, pkt, sizeof(bpdu_r_id));
        serializer(&bpdu_r_cost, pkt, sizeof(bpdu_r_cost));
        serializer(&bpdu_b_id, pkt, sizeof(bpdu_b_id));
        serializer(&bpdu_port_id, pkt, sizeof(bpdu_port_id));
        serializer(&bpdu_message_age, pkt, sizeof(bpdu_message_age));
        serializer(&bpdu_max_age, pkt, sizeof(bpdu_max_age));
        serializer(&bpdu_hello_time, pkt, sizeof(bpdu_hello_time));
        serializer(&bpdu_forward_delay, pkt, sizeof(bpdu_forward_delay));
    }
};

struct bpdu_tcn_hdr {
    uint16_t bpdu_p_id;             /* Protocol Identification */
    uint8_t bpdu_v_id;              /* Protocol Version Identification */
    uint8_t bpdu_type;              /* BPDU Type */
};


struct ethernet_trailer
{
  uint32_t ether_crc;                  /* packet CRC */
  ethernet_trailer(std::deque<uint8_t> &packet){
    // CRC doesn't include the premable so remove it from data and calculate for entire packet 
    // for(size_t i{}; i< 8;i++) packet.pop_front();
    ether_crc = compute_crc32(packet);
  }

  ethernet_trailer(std::vector<uint8_t> &packet, bool _){
    // CRC doesn't include the premable so remove it from data and calculate for entire packet 
    // for(size_t i{}; i< 8;i++) packet.pop_front();
    ether_crc = compute_crc32(packet);
  }

  // ethernet_trailer(std::vector<uint8_t> &packet){
  //   // CRC doesn't include the premable so remove it from data and calculate for entire packet 
  //   // for(size_t i{}; i< 8;i++) packet.pop_front();
  //   ether_crc = compute_crc32(packet);
  // }

  ethernet_trailer (std::queue<uint8_t> &pkt) {
    // Pushing the crc value
    deserializer(&ether_crc, pkt, sizeof(ether_crc));
  }
  
  ethernet_trailer (std::vector<uint8_t> &pkt, size_t &offset) {
    // Pushing the crc value
    deserializer(&ether_crc, pkt, sizeof(ether_crc), offset);
  }

  ethernet_trailer (std::vector<uint8_t> &pkt) {
    // Pushing the crc value
    deserializer(&ether_crc, pkt, sizeof(ether_crc), true);
  }

  ethernet_trailer (std::deque<uint8_t> &pkt, bool reverse) {
    // Pushing the crc value
    deserializer(&ether_crc, pkt, sizeof(ether_crc), reverse);
  }

  template<typename T>
  void serialize(T &pkt){
      // Pushing the crc value
      serializer(&ether_crc,pkt,sizeof(ether_crc));
  }

  void display()const{
    std::cout << "Ethernet Trailer" << std::endl;
    std::cout << "CRC: " << std::to_string(ether_crc) << std::endl;
    
  }
}; 
// __attribute__ ((packed)) ;

struct arp_hdr
{
  uint16_t        arp_hrd = 0x0006;  /* format of hardware address: 6(ethernet) default */
  uint16_t        arp_pro = 0x0800;  /* format of protocol address: 2048(ipv4) default */
  uint8_t         arp_hln = 0x06;    /* length of hardware address: 6(mac) default */
  uint8_t         arp_pln = 0x04;    /* length of protocol address: 4(ipv4) default */
  uint16_t        arp_op;            /* ARP opcode (command)         */
  uint8_array_6   arp_sha;           /* sender hardware address      */
  uint32_t        arp_sip;           /* sender IP address            */
  uint8_array_6   arp_tha;           /* target hardware address      */
  uint32_t        arp_tip;           /* target IP address            */

  arp_hdr(uint16_t opcode, const uint8_array_6 &src_mac, uint32_t src_ip, const uint8_array_6 &request_mac, uint32_t request_ip){

    arp_op = opcode;      /* 1 for request & 2 for reply */
    assign_uint8_array_6(arp_sha,src_mac);
    arp_sip = src_ip;
    assign_uint8_array_6(arp_tha,request_mac);
    arp_tip = request_ip;
  }

  arp_hdr(std::vector<uint8_t> &pkt, size_t &offset){
    deserializer(&arp_hrd, pkt, sizeof(arp_hrd), offset);
    deserializer(&arp_pro, pkt, sizeof(arp_pro), offset);
    deserializer(&arp_hln, pkt, sizeof(arp_hln), offset);
    deserializer(&arp_pln, pkt, sizeof(arp_pln), offset);
    deserializer(&arp_op, pkt, sizeof(arp_op), offset);
    deserializer(&arp_sha, pkt, sizeof(arp_sha), offset);
    deserializer(&arp_sip, pkt, sizeof(arp_sip), offset);
    deserializer(&arp_tha, pkt, sizeof(arp_tha), offset);
    deserializer(&arp_tip, pkt, sizeof(arp_tip), offset);

  }

  arp_hdr(std::vector<uint8_t> &pkt){
    deserializer(&arp_hrd, pkt, sizeof(arp_hrd));
    deserializer(&arp_pro, pkt, sizeof(arp_pro));
    deserializer(&arp_hln, pkt, sizeof(arp_hln));
    deserializer(&arp_pln, pkt, sizeof(arp_pln));
    deserializer(&arp_op,  pkt, sizeof(arp_op));
    deserializer(&arp_sha, pkt, sizeof(arp_sha));
    deserializer(&arp_sip, pkt, sizeof(arp_sip));
    deserializer(&arp_tha, pkt, sizeof(arp_tha));
    deserializer(&arp_tip, pkt, sizeof(arp_tip));

  }

  arp_hdr(std::deque<uint8_t> &pkt){
    deserializer(&arp_hrd, pkt, sizeof(arp_hrd));
    deserializer(&arp_pro, pkt, sizeof(arp_pro));
    deserializer(&arp_hln, pkt, sizeof(arp_hln));
    deserializer(&arp_pln, pkt, sizeof(arp_pln));
    deserializer(&arp_op,  pkt, sizeof(arp_op));
    deserializer(&arp_sha, pkt, sizeof(arp_sha));
    deserializer(&arp_sip, pkt, sizeof(arp_sip));
    deserializer(&arp_tha, pkt, sizeof(arp_tha));
    deserializer(&arp_tip, pkt, sizeof(arp_tip));

  }

  template<typename T>
  void serialize(T &pkt){
    // Pushing the hardware address value
    serializer(&arp_hrd, pkt, sizeof(arp_hrd));
    // Pushing the protocol value
    serializer(&arp_pro, pkt, sizeof(arp_pro));
    // Pushing the length of hardware address value
    serializer(&arp_hln, pkt, sizeof(arp_hln));
    // Pushing the length of protocol address value
    serializer(&arp_pln, pkt, sizeof(arp_pln));
    // Pushing the opcode value
    serializer(&arp_op, pkt, sizeof(arp_op));
    // Pushing the source hardware address
    serializer(arp_sha, pkt, sizeof(arp_sha));
    // Pushing the source protocol address
    serializer(&arp_sip, pkt, sizeof(arp_sip));
    // Pushing the target hardware address
    serializer(arp_tha, pkt, sizeof(arp_tha));
    // Pushing the target protocol address
    serializer(&arp_tip, pkt, sizeof(arp_tip));
  }

  void display()const{
    std::cout << "ARP Header" << std::endl;
    std::cout << "Hardware format: " << std::to_string(arp_hrd) << std::endl;
    std::cout << "Protocol format: " << std::to_string(arp_pro) << std::endl;
    std::cout << "Hardware length: " << std::to_string(arp_hln) << std::endl;
    std::cout << "Protocol length: " << std::to_string(arp_pln) << std::endl;
    std::cout << "Opcode: " << std::to_string(arp_op) << std::endl;
    std::cout << "Sender MAC: " << macToString(arp_sha) << std::endl;
    std::cout << "Sender Ip: " << ipToString(arp_sip) << std::endl;
    std::cout << "Target MAC: " << macToString(arp_tha) << std::endl;
    std::cout << "Target Ip: " << ipToString(arp_tip) << std::endl;
  }
};
//  __attribute__ ((packed)) ;

/*
 * Structure of the IP header, naked of options.
 */

struct ipv4_hdr
{
// #if defined(IS_LITTLE_ENDIAN)
//   #define IP_HL 0xF0                 /* mask for header length */
//   #define IP_V  0x0F                 /* mask for version  */
// #else
//   #define IP_V  0xF0                 /* mask for version  */
//   #define IP_HL 0x0F                 /* mask for header length */
// #endif
  uint8_t ip_v_hl = 0x45;          /* version & header length (default value: Version 4 and header length 20/4 = 5)*/
#define IP_V  0xF0                 /* mask for version  */
#define IP_HL 0x0F                 /* mask for header length */
  uint8_t ip_tos {};             /* type of service */
  uint16_t ip_len {};            /* total length */
  uint16_t ip_id{};                  /* identification */
  uint16_t ip_off = 0x4000;        /* fragment offset field: dont frag default*/
#define IP_RF 0x8000               /* reserved fragment flag */
#define IP_DF 0x4000               /* dont fragment flag */
#define IP_MF 0x2000               /* more fragments flag */
#define IP_OFFMASK 0x1FFF          /* mask for fragmenting bits */
  uint8_t ip_ttl = 0x40;           /* time to live: 64 default*/
  uint8_t ip_p{};                    /* protocol */
  uint16_t ip_sum = {};            /* checksum */
  uint32_t ip_src{};
  uint32_t ip_dst{};         /* source and dest address */

  std::optional<std::vector<uint8_t>> ip_opt;    /* options containing */
  ipv4_hdr(){}

  ipv4_hdr(uint8_t hl, uint16_t len, uint8_t type, uint32_t src, uint32_t dst, uint16_t id) {
    if(hl<20) return;

    ip_v_hl = 0x40 | (hl / 4);
    ip_len  = len;
    ip_id   = id;
    ip_p    = type;
    ip_src  = src;
    ip_dst  = dst;
  }

  ipv4_hdr (std::queue<uint8_t> &pkt) {
    // Pushing the version&header length value
    deserializer(&ip_v_hl, pkt, sizeof(ip_v_hl));
    // Pushing the tos value
    deserializer(&ip_tos, pkt, sizeof(ip_tos));
    // Pushing the total length value
    deserializer(&ip_len, pkt, sizeof(ip_len));
    // Pushing the id value
    deserializer(&ip_id, pkt, sizeof(ip_id));      
    // Pushing the offset value
    deserializer(&ip_off, pkt, sizeof(ip_off));
    // Pushing the hop limit value
    deserializer(&ip_ttl, pkt, sizeof(ip_ttl));
    // Pushing the protocol value
    deserializer(&ip_p, pkt, sizeof(ip_p));
    // Pushing the checksum value
    deserializer(&ip_sum, pkt, sizeof(ip_sum));
    // Pushing the source ip value
    deserializer(&ip_src, pkt, sizeof(ip_src));
    // Pushing the destination ip value
    deserializer(&ip_dst, pkt, sizeof(ip_dst));

    if((ip_v_hl | IP_HL) > 5){
      ip_opt = std::vector<uint8_t> ();
      uint8_t options_len = ((ip_v_hl | IP_HL)*4) - 20 ;

      while(options_len>0){
        ip_opt->push_back(pkt.front());
        pkt.pop();
        options_len--;
      }
    }
  }

  ipv4_hdr (std::vector<uint8_t> &pkt, size_t &offset) {
    // Pushing the version&header length value
    deserializer(&ip_v_hl, pkt, sizeof(ip_v_hl), offset);
    // Pushing the tos value
    deserializer(&ip_tos, pkt, sizeof(ip_tos), offset);
    // Pushing the total length value
    deserializer(&ip_len, pkt, sizeof(ip_len), offset);
    // Pushing the id value
    deserializer(&ip_id, pkt, sizeof(ip_id), offset);      
    // Pushing the offset value
    deserializer(&ip_off, pkt, sizeof(ip_off), offset);
    // Pushing the hop limit value
    deserializer(&ip_ttl, pkt, sizeof(ip_ttl), offset);
    // Pushing the protocol value
    deserializer(&ip_p, pkt, sizeof(ip_p), offset);
    // Pushing the checksum value
    deserializer(&ip_sum, pkt, sizeof(ip_sum), offset);
    // Pushing the source ip value
    deserializer(&ip_src, pkt, sizeof(ip_src), offset);
    // Pushing the destination ip value
    deserializer(&ip_dst, pkt, sizeof(ip_dst), offset);

    if(IS_LITTLE_ENDIAN) {

      if((ip_v_hl & IP_HL) > 5){
        ip_opt = std::vector<uint8_t> ();
        uint8_t options_len = ((ip_v_hl & IP_HL)<<2) - 20 ;

        while(options_len>0){
          ip_opt->push_back(pkt[offset++]);
          options_len--;
        }
      }
    }else{
      if(((ip_v_hl & IP_HL)>>4) > 5){
        ip_opt = std::vector<uint8_t> ();
        uint8_t options_len = ((ip_v_hl & IP_HL)>>2) - 20 ;

        while(options_len>0){
          ip_opt->push_back(pkt[offset++]);
          options_len--;
        }
      }
    }
  }

  ipv4_hdr (std::deque<uint8_t> &pkt) {
    // Pushing the version&header length value
    deserializer(&ip_v_hl, pkt, sizeof(ip_v_hl));
    // Pushing the tos value
    deserializer(&ip_tos, pkt, sizeof(ip_tos));
    // Pushing the total length value
    deserializer(&ip_len, pkt, sizeof(ip_len));
    // Pushing the id value
    deserializer(&ip_id, pkt, sizeof(ip_id));      
    // Pushing the offset value
    deserializer(&ip_off, pkt, sizeof(ip_off));
    // Pushing the hop limit value
    deserializer(&ip_ttl, pkt, sizeof(ip_ttl));
    // Pushing the protocol value
    deserializer(&ip_p, pkt, sizeof(ip_p));
    // Pushing the checksum value
    deserializer(&ip_sum, pkt, sizeof(ip_sum));
    // Pushing the source ip value
    deserializer(&ip_src, pkt, sizeof(ip_src));
    // Pushing the destination ip value
    deserializer(&ip_dst, pkt, sizeof(ip_dst));

    if(IS_LITTLE_ENDIAN) {
      if((ip_v_hl & IP_HL) > 5){
        ip_opt = std::vector<uint8_t> ();
        uint8_t options_len = ((ip_v_hl & IP_HL)<<2) - 20 ;

        while(options_len>0){
          ip_opt->push_back(pkt.front());
          pkt.pop_front();
          options_len--;
        }
      }
    }else{
      if(((ip_v_hl & IP_HL)>>4) > 5){
        ip_opt = std::vector<uint8_t> ();
        uint8_t options_len = ((ip_v_hl & IP_HL)>>2) - 20 ;

        while(options_len>0){
          ip_opt->push_back(pkt.front());
          pkt.pop_front();
          options_len--;
        }
      }
    }

  }

  ipv4_hdr (std::vector<uint8_t> &pkt) {
    // Pushing the version&header length value
    deserializer(&ip_v_hl, pkt, sizeof(ip_v_hl));
    // Pushing the tos value
    deserializer(&ip_tos, pkt, sizeof(ip_tos));
    // Pushing the total length value
    deserializer(&ip_len, pkt, sizeof(ip_len));
    // Pushing the id value
    deserializer(&ip_id, pkt, sizeof(ip_id));      
    // Pushing the offset value
    deserializer(&ip_off, pkt, sizeof(ip_off));
    // Pushing the hop limit value
    deserializer(&ip_ttl, pkt, sizeof(ip_ttl));
    // Pushing the protocol value
    deserializer(&ip_p, pkt, sizeof(ip_p));
    // Pushing the checksum value
    deserializer(&ip_sum, pkt, sizeof(ip_sum));
    // Pushing the source ip value
    deserializer(&ip_src, pkt, sizeof(ip_src));
    // Pushing the destination ip value
    deserializer(&ip_dst, pkt, sizeof(ip_dst));

    if(IS_LITTLE_ENDIAN) {

      if((ip_v_hl & IP_HL) > 5){
        ip_opt = std::vector<uint8_t> ();
        uint8_t options_len = ((ip_v_hl & IP_HL)<<2) - 20 ;

        while(options_len>0){
          ip_opt->push_back(pkt.front());
          pkt.erase(pkt.begin());
          options_len--;
        }

        // std::cout << "LENGTH: " << ip_len << std::endl;
        // std::cout << "LENGTH: " << ((ip_v_hl & IP_HL)<<2) << std::endl;
        // std::cout << "LENGTH: " << pkt.size() << std::endl;

        // while((ip_len - (ip_v_hl&IP_HL)<<2 ) < pkt.size()){
        //   std::cout << "REmoving Padding: " << ip_len << std::endl;
        //   pkt.pop_back();
        // }
      }
    }else{
      if(((ip_v_hl & IP_HL)>>4) > 5){
        ip_opt = std::vector<uint8_t> ();
        uint8_t options_len = ((ip_v_hl & IP_HL)>>2) - 20 ;

        while(options_len>0){
          ip_opt->push_back(pkt.front());
          pkt.erase(pkt.begin());
          options_len--;
        }

        // while((ip_len - (ip_v_hl&IP_HL)>>2 ) < pkt.size()){
        //   pkt.pop_back();
        // }
      }
    }
    
  }

  template<typename T>
  void serialize(T &pkt){
    // Pushing the version&header length value
    serializer(&ip_v_hl,pkt,sizeof(ip_v_hl));
    // Pushing the tos value
    serializer(&ip_tos,pkt,sizeof(ip_tos));
    // Pushing the total length value
    serializer(&ip_len,pkt,sizeof(ip_len));
    // Pushing the id value
    serializer(&ip_id,pkt,sizeof(ip_id));      
    // Pushing the offset value
    serializer(&ip_off,pkt,sizeof(ip_off));
    // Pushing the hop limit value
    serializer(&ip_ttl,pkt,sizeof(ip_ttl));
    // Pushing the protocol value
    serializer(&ip_p,pkt,sizeof(ip_p));
    // Pushing the checksum value
    serializer(&ip_sum,pkt,sizeof(ip_sum));
    // Pushing the source ip value
    serializer(&ip_src,pkt,sizeof(ip_src));
    // Pushing the destination ip value
    serializer(&ip_dst,pkt,sizeof(ip_dst));

    if(ip_opt.has_value()){
      // Pushing the options value 
      std::vector<uint8_t> vec = ip_opt.value();
      serializer(&vec, pkt, vec.size());
    }
  }

  ipv4_hdr(std::vector<uint8_t>* bytes) {
    if (bytes == nullptr){
      // Handle error: null
      return;
    }
    if (bytes->size() < sizeof(ipv4_hdr)) {
      // Handle error: not enough bytes provided
      return;
    }

    ip_v_hl = bytes->at(0);
    ip_tos = bytes->at(1);
    ip_len = bytes->at(2) << 8 | bytes->at(3);
    ip_id = bytes->at(4) << 8 | bytes->at(5);
    ip_off = bytes->at(6) << 8 | bytes->at(7);
    ip_ttl = bytes->at(8);

    ip_p = bytes->at(9);
    ip_sum = bytes->at(10) << 8 | bytes->at(11);

    ip_src =  bytes->at(12) << 24 |
              bytes->at(13) << 16 |
              bytes->at(14) << 8 |
              bytes->at(15);

    ip_dst =  bytes->at(16) << 24 |
              bytes->at(17) << 16 |
              bytes->at(18) << 8 |
              bytes->at(19);
  }

  void display()const{
    std::cout << "IPv4 Header" << std::endl;
    if(IS_LITTLE_ENDIAN) {
      std::cout << "Version: " << std::to_string((ip_v_hl & IP_V)>>4) << std::endl;
      std::cout << "Header length: " << std::to_string((ip_v_hl & IP_HL)<<2) << std::endl;
    }else{
      std::cout << "Version: " << std::to_string(ip_v_hl & IP_V) << std::endl;
      std::cout << "Header length: " << std::to_string((ip_v_hl & IP_HL)>>2) << std::endl;
    }
    std::cout << "TOS: " << std::to_string(ip_tos) << std::endl;
    std::cout << "Packet length: " << std::to_string(ip_len) << std::endl;
    std::cout << "Identification: " << std::to_string(ip_id) << std::endl;
    std::cout << "Offset: " << std::to_string(ip_off) << std::endl;
    std::cout << "Time to live: " << std::to_string(ip_ttl) << std::endl;
    std::cout << "Type: " << std::to_string(ip_p) << std::endl;
    std::cout << "Checksum: " << std::to_string(ip_sum) << std::endl;
    std::cout << "Source Ip: " << ipToString(ip_src) << std::endl;
    std::cout << "Destination Ip: " << ipToString(ip_dst) << std::endl;
    if(ip_opt.has_value()){
      std::cout << "Options Length: " << ip_opt.value().size() << std::endl;
    }

    // std::cout << "LENGTH: " << ip_len << std::endl;
    // std::cout << "LENGTH: " << ((ip_v_hl & IP_HL)<<2) << std::endl;
    // std::cout << "LENGTH: " << pkt.size() << std::endl;
  }
};
//  __attribute__ ((packed)) ;

/* 
 * Structure of a ICMP header
 */
struct icmp_hdr {
    uint8_t icmp_type{};
    uint8_t icmp_code{};
    uint16_t icmp_sum{};

  // Serialize the header
  template<typename T>
  void serialize (T &pkt) {

    // Pushing the type value
    serializer(&icmp_type, pkt, sizeof(icmp_type));
    // Pushing the opcode value
    serializer(&icmp_code, pkt, sizeof(icmp_code));
    // Pushing the checksum value
    serializer(&icmp_sum, pkt, sizeof(icmp_sum));

  }
};
// __attribute__ ((packed)) ;

/*
 * Structure of a type0 ICMP header
 */
struct icmp_t0_hdr {
    uint8_t icmp_type{};              /* type of service */
    uint8_t icmp_code{};              /* code of packet structure */
  uint16_t icmp_sum {};              /* checksum */
  uint16_t icmp_id{};               /* identifier */
  uint16_t icmp_seq{};              /* sequence no. */
  uint8_t data[ICMP_DATA_SIZE] {0};   /* data */

  
  icmp_t0_hdr (uint8_t type, uint8_t code, uint16_t id, uint16_t seq, uint8_t tempData[ICMP_DATA_SIZE]) {
    icmp_type = type;
    icmp_code = code;
    icmp_id = id;
    icmp_seq = seq;
    for(size_t i {}; i<ICMP_DATA_SIZE;i++){
      data[i] = tempData[i];
    }
  }

  icmp_t0_hdr (std::vector<uint8_t> &pkt) {
    // Pushing the type value
    deserializer(&icmp_type, pkt, sizeof(icmp_type));
    // Pushing the code value
    deserializer(&icmp_code, pkt, sizeof(icmp_code));
    // Pushing the checksum value
    deserializer(&icmp_sum, pkt, sizeof(icmp_sum));
    // Pushing the identificatiom value
    deserializer(&icmp_id, pkt, sizeof(icmp_id));     
    // Pushing the sequence no. value
    deserializer(&icmp_seq, pkt, sizeof(icmp_seq));
    // Pushing the data value
    deserializer(data, pkt, sizeof(ICMP_DATA_SIZE));     

    
  }

  template<typename T>
  void serialize (T &pkt) {
    // Pushing the type value
    serializer(&icmp_type, pkt, sizeof(icmp_type));
    // Pushing the opcode value
    serializer(&icmp_code, pkt, sizeof(icmp_code));
    // Pushing the checksum value
    serializer(&icmp_sum, pkt, sizeof(icmp_sum));
    // Pushing the identifier value
    serializer(&icmp_id, pkt, sizeof(icmp_id));
    // Pushing the sequence number value
    serializer(&icmp_seq, pkt, sizeof(icmp_seq));
    // Pushing the data value
    serializer(&data, pkt, sizeof(ICMP_DATA_SIZE));
  }

  void display()const{
    std::cout << "ICMP Header" << std::endl;
    
    std::cout << "Type: " << std::to_string(icmp_type) << std::endl;
    std::cout << "Code: " << std::to_string(icmp_code) << std::endl;
    std::cout << "Checksum: " << std::to_string(icmp_sum) << std::endl;
    std::cout << "Identification: " << std::to_string(icmp_id) << std::endl;
    std::cout << "Sequence No.: " << std::to_string(icmp_seq) << std::endl;
    std::cout << "Data: ";
    for(auto el : data){
      std::cout << std::to_string(el) << " ";
    }
    std::cout << std::endl;
  }
};

/*
 * Structure of a type3 ICMP header
 */
struct icmp_t3_hdr {
    uint8_t icmp_type{};
    uint8_t icmp_code{};
    uint16_t icmp_sum{};
    uint16_t unused{};
    uint16_t next_mtu{};
    uint8_t data[ICMP_DATA_SIZE]{};
};
// __attribute__ ((packed)) ;



struct udp_hdr
{
  uint16_t  udp_sport{};    /* source port                */
  uint16_t  udp_dport{};    /* destination port           */
  uint16_t  udp_len{};      /* length of packet           */
  uint16_t  udp_sum{};      /* length of protocol address */

  udp_hdr () {}

  udp_hdr (uint16_t dst_port, uint16_t len) {
    udp_sport = (uint16_t)generateRandomNumber(16, 1025);
    udp_dport = dst_port;
    udp_len = len;
  }

  udp_hdr (uint16_t src_port, uint16_t dst_port, uint16_t len) {
    udp_sport = src_port;
    udp_dport = dst_port;
    udp_len = len + 8;
  }

  // Deserialize the header
  udp_hdr(std::queue<uint8_t> &pkt) {

    // Pushing the source port value
    deserializer(&udp_sport, pkt, sizeof(udp_sport));
    // Pushing the destination port value
    deserializer(&udp_dport, pkt, sizeof(udp_dport));
    // Pushing the length value
    deserializer(&udp_len, pkt, sizeof(udp_len));
    // Pushing the checksum value
    deserializer(&udp_sum, pkt, sizeof(udp_sum));

  }

  udp_hdr(std::vector<uint8_t> &pkt, size_t &offset) {
    // Pushing the source port value
    deserializer(&udp_sport, pkt, sizeof(udp_sport), offset);
    // Pushing the destination port value
    deserializer(&udp_dport, pkt, sizeof(udp_dport), offset);
    // Pushing the length value
    deserializer(&udp_len, pkt, sizeof(udp_len), offset);
    // Pushing the checksum value
    deserializer(&udp_sum, pkt, sizeof(udp_sum), offset);
  }

  udp_hdr(std::vector<uint8_t> &pkt) {
    // Pushing the source port value
    deserializer(&udp_sport, pkt, sizeof(udp_sport));
    // Pushing the destination port value
    deserializer(&udp_dport, pkt, sizeof(udp_dport));
    // Pushing the length value
    deserializer(&udp_len, pkt, sizeof(udp_len));
    // Pushing the checksum value
    deserializer(&udp_sum, pkt, sizeof(udp_sum));
  }

  udp_hdr(std::deque<uint8_t> &pkt) {

    // Pushing the source port value
    deserializer(&udp_sport, pkt, sizeof(udp_sport));
    // Pushing the destination port value
    deserializer(&udp_dport, pkt, sizeof(udp_dport));
    // Pushing the length value
    deserializer(&udp_len, pkt, sizeof(udp_len));
    // Pushing the checksum value
    deserializer(&udp_sum, pkt, sizeof(udp_sum));

  }

  // Serialize the header
  template<typename T>
  void serialize (T &pkt) {

    // Pushing the source port value
    serializer(&udp_sport, pkt, sizeof(udp_sport));
    // Pushing the destination port value
    serializer(&udp_dport, pkt, sizeof(udp_dport));
    // Pushing the length value
    serializer(&udp_len, pkt, sizeof(udp_len));
    // Pushing the checksum value
    serializer(&udp_sum, pkt, sizeof(udp_sum));

  }

  void display()const{
    std::cout << "UDP Header" << std::endl;
    std::cout << "Source port: " << std::to_string(udp_sport) << std::endl;
    std::cout << "Destination port: " << std::to_string(udp_dport) << std::endl;
    std::cout << "Packet length: " << std::to_string(udp_len) << std::endl;
    std::cout << "Checksum: " << std::to_string(udp_sum) << std::endl;
  }
};
// __attribute__ ((packed)) ;

struct pseudo_hdr 
{
    uint32_t pseudo_src{};        /* Source IP      */
    uint32_t pseudo_dst{};        /* Destination IP */
  uint8_t  pseudo_zero {0};   /* Padding zeros  */
  uint8_t  pseudo_p{};          /* Protocol       */
  uint16_t pseudo_len{};        /* Length         */

  pseudo_hdr(uint32_t src_ip, uint32_t dst_ip, uint8_t protocol, uint16_t length){
    pseudo_src = src_ip;
    pseudo_dst = dst_ip;
    pseudo_p = protocol;
    pseudo_len = length;
  }

  template<typename T>
  void serialize (T &pkt) {

    // Pushing the source ip value
    serializer(&pseudo_src, pkt, sizeof(pseudo_src));
    // Pushing the destination ip value
    serializer(&pseudo_dst, pkt, sizeof(pseudo_dst));
    // Pushing the padding zeroes value
    serializer(&pseudo_zero, pkt, sizeof(pseudo_zero));
    // Pushing the protocol value
    serializer(&pseudo_p, pkt, sizeof(pseudo_p));
    // Pushing the length value
    serializer(&pseudo_len, pkt, sizeof(pseudo_len));

  }

  void display()const{
    std::cout << "Pseudo Header" << std::endl;
    std::cout << "Source Ip: " << ipToString(pseudo_src) << std::endl;
    std::cout << "Destination Ip: " << ipToString(pseudo_dst) << std::endl;
    std::cout << "Pad: " << std::to_string(pseudo_zero) << std::endl;
    std::cout << "Type: " << std::to_string(pseudo_p) << std::endl;
    std::cout << "Packet length: " << std::to_string(pseudo_len) << std::endl;
  }
};

struct tcp_hdr
{
    uint16_t  tcp_sport{};    /* source port                    */
    uint16_t  tcp_dport{};    /* destination port               */
    uint32_t  tcp_seq{};      /* sequence no                    */
    uint32_t  tcp_ack{};      /* acknowledgement no             */
    uint16_t  tcp_hl_flags{}; /* header length & flags          */
#define TCP_HL 0xF000     /* mask for header length         */
#define TCP_R  0x0FC0     /* mask for reservation bits      */
#define TCP_URG  0x0020   /* mask for urgent flag           */
#define TCP_ACK  0x0010   /* mask for acknowledgement flag  */
#define TCP_PSH  0x0008   /* mask for push flag             */
#define TCP_RST  0x0004   /* mask for reset flag            */
#define TCP_SYN  0x0002   /* mask for synchronization flag  */
#define TCP_FIN  0x0001   /* mask for end connection flag   */
    uint16_t  tcp_window{};   /* window size                    */
  uint16_t  tcp_sum {0};  /* checksum                       */
  uint16_t  tcp_urg_ptr{};  /* urgent pointer                 */

  tcp_hdr(uint16_t src_port, uint16_t dst_port, uint32_t seq_num, uint32_t ack_num, uint8_t hlen, bool urg, bool ack, bool psh, bool rst, bool syn, bool fin, uint16_t window_size){
    hlen = hlen >> 2;
    if(hlen > 15 && hlen < 5 ) return;
    tcp_sport       = src_port;
    tcp_dport       = dst_port;
    tcp_seq         = seq_num;
    tcp_ack         = ack_num;

    uint16_t tempFlags{0};
    tempFlags = tempFlags + (hlen << 12);
    if(urg) tempFlags = tempFlags + (urg << 5);
    if(ack) tempFlags = tempFlags + (ack << 4);
    if(psh) tempFlags = tempFlags + (psh << 3);
    if(rst) tempFlags = tempFlags + (rst << 2);
    if(syn) tempFlags = tempFlags + (syn << 1);
    if(fin) tempFlags = tempFlags + (fin);

    tcp_hl_flags = tempFlags;

    tcp_window = window_size;

  }

  tcp_hdr(std::vector<uint8_t> &pkt, size_t &offset){
    deserializer(&tcp_sport,    pkt, sizeof(tcp_sport),    offset);
    deserializer(&tcp_dport,    pkt, sizeof(tcp_dport),    offset);
    deserializer(&tcp_seq,      pkt, sizeof(tcp_seq),      offset);
    deserializer(&tcp_ack,      pkt, sizeof(tcp_ack),      offset);
    deserializer(&tcp_hl_flags, pkt, sizeof(tcp_hl_flags), offset);
    deserializer(&tcp_window,   pkt, sizeof(tcp_window),   offset);
    deserializer(&tcp_sum,      pkt, sizeof(tcp_sum),      offset);
    deserializer(&tcp_urg_ptr,  pkt, sizeof(tcp_urg_ptr),  offset);

  }

  tcp_hdr(std::vector<uint8_t> &pkt){
    deserializer(&tcp_sport,    pkt, sizeof(tcp_sport));
    deserializer(&tcp_dport,    pkt, sizeof(tcp_dport));
    deserializer(&tcp_seq,      pkt, sizeof(tcp_seq));
    deserializer(&tcp_ack,      pkt, sizeof(tcp_ack));
    deserializer(&tcp_hl_flags, pkt, sizeof(tcp_hl_flags));
    deserializer(&tcp_window,   pkt, sizeof(tcp_window));
    deserializer(&tcp_sum,      pkt, sizeof(tcp_sum));
    deserializer(&tcp_urg_ptr,  pkt, sizeof(tcp_urg_ptr));

  }

  tcp_hdr(std::deque<uint8_t> &pkt){
    deserializer(&tcp_sport,    pkt, sizeof(tcp_sport));
    deserializer(&tcp_dport,    pkt, sizeof(tcp_dport));
    deserializer(&tcp_seq,      pkt, sizeof(tcp_seq));
    deserializer(&tcp_ack,      pkt, sizeof(tcp_ack));
    deserializer(&tcp_hl_flags, pkt, sizeof(tcp_hl_flags));
    deserializer(&tcp_window,   pkt, sizeof(tcp_window));
    deserializer(&tcp_sum,      pkt, sizeof(tcp_sum));
    deserializer(&tcp_urg_ptr,  pkt, sizeof(tcp_urg_ptr));

  }

  template<typename T>
  void serialize(T &pkt){
    // Pushing the source port value
    serializer(&tcp_sport, pkt, sizeof(tcp_sport));
    // Pushing the destination port value
    serializer(&tcp_dport, pkt, sizeof(tcp_dport));
    // Pushing the sequence number
    serializer(&tcp_seq, pkt, sizeof(tcp_seq));
    // Pushing the acknowledgement number
    serializer(&tcp_ack, pkt, sizeof(tcp_ack));
    // Pushing the header length and flags
    serializer(&tcp_hl_flags, pkt, sizeof(tcp_hl_flags));
    // Pushing the window size
    serializer(&tcp_window, pkt, sizeof(tcp_window));
    // Pushing the checksum
    serializer(&tcp_sum, pkt, sizeof(tcp_sum));
    // Pushing the urgent value
    serializer(&tcp_urg_ptr, pkt, sizeof(tcp_urg_ptr));
  }
};


enum options_code_type{
  PAD            = 0,
  SUBNET_MASK    = 1,
  ROUTER         = 3,
  DNS            = 6,
  REQUESTED_IP   = 50,
  LEASE_TIME     = 51,
  MSG_TYPE       = 53,
  DHCP_SERVER_IP = 54,
  END            = 255
};

static const std::unordered_map<uint8_t, options_code_type> optionsMap = {
    {0, PAD}, {1, SUBNET_MASK}, {3, ROUTER}, {6, DNS}, {51, LEASE_TIME}, {53, MSG_TYPE}, {255, END}
  };

struct dhcp_hdr
{
    uint8_t   dhcp_op{};                  /* DHCP opcode (command)         */
  uint8_t   dhcp_hrd = 0x06;          /* format of hardware address: 6(ethernet) default */
  uint8_t   dhcp_hln = 0x06;          /* length of hardware address: 6(mac) default */
  uint8_t   dhcp_hop = 0x00;          /* hop count: 0(used by relay agent) default */
  uint32_t  dhcp_id{};                  /* identification (random)       */
  uint16_t  dhcp_sec = {};            /* number of seconds elapsed     */
  uint16_t  dhcp_flags = 0x8000;      /* flags if the reply needs to be a broadcast
                                          message then 0x8000. if unicast then 0x0000   */
  uint32_t  dhcp_cip = 0x0;           /* client IP address             */
  uint32_t  dhcp_ycip = 0x0;          /* your client IP address        */
  uint32_t  dhcp_sip = 0x0;           /* server IP address             */
  uint32_t  dhcp_gip = 0x0;           /* gateway IP address            */
  uint8_t   dhcp_cadr[16] = {};       /* client hardware address       */

  /* These field is part of the dhcp fixed-length packet structure
    but optional to use but still sent in all packets for my case 
    no need and too big for cpp so would need to use a array or 
    create a new datatype struct so just commented the fields */
  // std::array<uint8_t, 64> dhcp_sname = {0x0};  
  // std::array<uint8_t, 128> dhcp_file = {0x0};  

  std::optional<std::vector<uint8_t>> dhcp_opt;    /* options containing the offers */
  
  /* TODO: For reference: 
  https://www.incognito.com/tutorials/dhcp-options-in-plain-english/ 
  https://www.iana.org/assignments/bootp-dhcp-parameters/bootp-dhcp-parameters.xhtml
    The options field will be variable and contains option code(1B) and length(1B) then contains the field like
  - Option Code: 1 (Subnet Mask)
  - Option Length: 4 bytes
  - Option Data: 255 255 255 0  (Represents 255.255.255.0)
  - Option Code: 3 (Default Router)
  - Option Length: 4 bytes
  - Option Data: 192 168 1  1  (Represents 192.168.1.1)
  - Option Code: 6 (DNS Server)
  - Option Length: 4 bytes
  - Option Data: 8   8   8   8  (Represents 8.8.8.8)
  - Option Code: 51 (Lease Time)  
  - Option Length: 4 bytes                                   |
  - Option Data: 86400 (Represents 24 hours - binary: 00000000.00000000.00100001.00000000)
  - ... (Other options might follow) 
  this fields are the most used ones and needs to be a vector of uint8_t
  */

  dhcp_hdr(){}
  dhcp_hdr(uint8_t opcode){
    dhcp_op = opcode;
  }

  void dhcp_discover(const uint8_array_6 mac, uint32_t id){
    dhcp_op = dhcp_op_request;           /* 1 for discover */
    dhcp_id = id;   /* random id */
    dhcp_flags = 0x8000;                  /* broadcast */
    dhcp_cip = 0x0;                       /* no ip yet */
    dhcp_ycip = 0x0;                      /* used in reply */
    dhcp_sip = 0x0;                       /* no need */
    dhcp_gip = 0x0;                       /* no need */
            
    dhcp_cadr[0] = mac[0];                /* your mac at MSB */
    dhcp_cadr[1] = mac[1]; 
    dhcp_cadr[2] = mac[2];            
    dhcp_cadr[3] = mac[3];           
    dhcp_cadr[4] = mac[4];            
    dhcp_cadr[5] = mac[5];  

    // 51 means dhcp type then 1 means the length of type and the code is dhcp discover unique code each type has a unique code
    dhcp_opt = {  99, 130, 83, 99,
                  MSG_TYPE, 1, dhcp_discover_code,   
                  END  // END Delimiter
    };         
  }

  void dhcp_offer(uint32_t id, uint32_t offer_ip, const uint8_array_6 mac, uint32_t mask, uint32_t gateway, uint32_t dns, uint32_t lease_time, uint32_t dhcp_server_ip){
    dhcp_op = dhcp_op_reply;              /* 2 for offer */
    dhcp_id = id;                         /* same id as discover */
    dhcp_cip = 0x0;                       /* no ip yet */
    dhcp_ycip = offer_ip;                 /* what ip we offer */
    dhcp_sip = 0x0;                       /* no need */
    dhcp_gip = 0x0;                       /* no need */
    
    dhcp_cadr[0] = mac[0];                /* your mac at MSB */
    dhcp_cadr[1] = mac[1]; 
    dhcp_cadr[2] = mac[2];            
    dhcp_cadr[3] = mac[3];           
    dhcp_cadr[4] = mac[4];            
    dhcp_cadr[5] = mac[5];   

    // Initializes the options field with subnet mask, default gateway, dns ips 
    dhcp_opt = {  99, 130, 83, 99, // Magic Cookie as DHCP and BOOTP packet are similar in format this is used to distinguish the packets. All DHCP packets need this as first four bytes of the options field
                  MSG_TYPE, 1, dhcp_offer_code,     
                  SUBNET_MASK, 4, static_cast<uint8_t>((mask >> (24)) & 0xFF), 
                        static_cast<uint8_t>((mask >> (16)) & 0xFF), 
                        static_cast<uint8_t>((mask >> (8)) & 0xFF), 
                        static_cast<uint8_t>((mask) & 0xFF),
                  ROUTER, 4, static_cast<uint8_t>((gateway >> (24)) & 0xFF),
                        static_cast<uint8_t>((gateway >> (16)) & 0xFF), 
                        static_cast<uint8_t>((gateway >> (8)) & 0xFF), 
                        static_cast<uint8_t>((gateway) & 0xFF), 
                  DNS, 4, static_cast<uint8_t>((dns >> (24)) & 0xFF),
                        static_cast<uint8_t>((dns >> (16)) & 0xFF), 
                        static_cast<uint8_t>((dns >> (8)) & 0xFF), 
                        static_cast<uint8_t>((dns) & 0xFF),
                  LEASE_TIME, 4, static_cast<uint8_t>((lease_time >> (24)) & 0xFF),
                        static_cast<uint8_t>((lease_time >> (16)) & 0xFF), 
                        static_cast<uint8_t>((lease_time >> (8)) & 0xFF), 
                        static_cast<uint8_t>((lease_time) & 0xFF), 
                  DHCP_SERVER_IP, 4,  static_cast<uint8_t>((dhcp_server_ip >> (24)) & 0xFF),
                        static_cast<uint8_t>((dhcp_server_ip >> (16)) & 0xFF), 
                        static_cast<uint8_t>((dhcp_server_ip >> (8)) & 0xFF), 
                        static_cast<uint8_t>((dhcp_server_ip) & 0xFF),
                  END 
    };
  }

  void dhcp_request(const uint8_array_6 mac, uint32_t id, uint32_t offered_ip, uint32_t dhcp_server_ip){
    dhcp_op = dhcp_op_request;           /* 1 for discover */
    dhcp_id = id;   /* random id */
    dhcp_flags = 0x8000;                  /* broadcast */
    dhcp_cip = 0x0;                       /* no ip yet */
    dhcp_ycip = 0x0;                      /* used in reply */
    dhcp_sip = 0x0;                       /* no need */
    dhcp_gip = 0x0;                       /* no need */
            
    dhcp_cadr[0] = mac[0];                /* your mac at MSB */
    dhcp_cadr[1] = mac[1]; 
    dhcp_cadr[2] = mac[2];            
    dhcp_cadr[3] = mac[3];           
    dhcp_cadr[4] = mac[4];            
    dhcp_cadr[5] = mac[5];  

    // 51 means dhcp type then 1 means the length of type and the code is dhcp discover unique code each type has a unique code
    dhcp_opt = {  99, 130, 83, 99,
                  MSG_TYPE, 1, dhcp_request_code,
                  REQUESTED_IP, 4, static_cast<uint8_t>((offered_ip >> (24)) & 0xFF),
                        static_cast<uint8_t>((offered_ip >> (16)) & 0xFF), 
                        static_cast<uint8_t>((offered_ip >> (8)) & 0xFF), 
                        static_cast<uint8_t>((offered_ip) & 0xFF),
                  DHCP_SERVER_IP, 4, static_cast<uint8_t>((dhcp_server_ip >> (24)) & 0xFF),
                        static_cast<uint8_t>((dhcp_server_ip >> (16)) & 0xFF), 
                        static_cast<uint8_t>((dhcp_server_ip >> (8)) & 0xFF), 
                        static_cast<uint8_t>((dhcp_server_ip) & 0xFF),
                  END  // END Delimiter
    };         
    // std::cout<<"SERVER IP"<<ipToString(dhcp_server_ip)<<std::endl;

  }

  void dhcp_acknowlegement(uint32_t id, uint32_t offer_ip, const uint8_array_6 mac, uint32_t mask, uint32_t gateway, uint32_t dns, uint32_t lease_time){
    dhcp_op = dhcp_op_reply;              /* 2 for offer */
    dhcp_id = id;                         /* same id as discover */
    dhcp_cip = 0x0;                       /* no ip yet */
    dhcp_ycip = offer_ip;                 /* what ip we offer */
    dhcp_sip = 0x0;                       /* no need */
    dhcp_gip = 0x0;                       /* no need */
    
    dhcp_cadr[0] = mac[0];                /* your mac at MSB */
    dhcp_cadr[1] = mac[1]; 
    dhcp_cadr[2] = mac[2];            
    dhcp_cadr[3] = mac[3];           
    dhcp_cadr[4] = mac[4];            
    dhcp_cadr[5] = mac[5];   

    // Initializes the options field with subnet mask, default gateway, dns ips 
    dhcp_opt = {  99, 130, 83, 99, // Magic Cookie as DHCP and BOOTP packet are similar in format this is used to distinguish the packets. All DHCP packets need this as first four bytes of the options field
                  MSG_TYPE, 1, dhcp_acknowledge_code,     
                  SUBNET_MASK, 4, static_cast<uint8_t>((mask >> (24)) & 0xFF),
                        static_cast<uint8_t>((mask >> (16)) & 0xFF), 
                        static_cast<uint8_t>((mask >> (8)) & 0xFF), 
                        static_cast<uint8_t>((mask) & 0xFF), 
                  ROUTER, 4, static_cast<uint8_t>((gateway >> (24)) & 0xFF),
                        static_cast<uint8_t>((gateway >> (16)) & 0xFF), 
                        static_cast<uint8_t>((gateway >> (8)) & 0xFF), 
                        static_cast<uint8_t>((gateway) & 0xFF),
                  DNS, 4, static_cast<uint8_t>((dns >> (24)) & 0xFF),
                        static_cast<uint8_t>((dns >> (16)) & 0xFF), 
                        static_cast<uint8_t>((dns >> (8)) & 0xFF), 
                        static_cast<uint8_t>((dns) & 0xFF), 
                  LEASE_TIME, 4, static_cast<uint8_t>((lease_time >> (24)) & 0xFF),
                        static_cast<uint8_t>((lease_time >> (16)) & 0xFF), 
                        static_cast<uint8_t>((lease_time >> (8)) & 0xFF), 
                        static_cast<uint8_t>((lease_time) & 0xFF), 
                  END 
    };
  }

  dhcp_hdr(std::queue<uint8_t> &pkt){

      // Pushing the opcode value
      deserializer(&dhcp_op,pkt,sizeof(dhcp_op));
      // Pushing the format of hardware address value
      deserializer(&dhcp_hrd,pkt,sizeof(dhcp_hrd));
      // Pushing the length of hardware address value
      deserializer(&dhcp_hln,pkt,sizeof(dhcp_hln));
      // Pushing the hop limit value
      deserializer(&dhcp_hop,pkt,sizeof(dhcp_hop));      
      // Pushing the id value
      deserializer(&dhcp_id,pkt,sizeof(dhcp_id));
      // Pushing the seconds elapsed value
      deserializer(&dhcp_sec,pkt,sizeof(dhcp_sec));
      // Pushing the flags value
      deserializer(&dhcp_flags,pkt,sizeof(dhcp_flags));
      // Pushing the client ip value
      deserializer(&dhcp_cip,pkt,sizeof(dhcp_cip));
      // Pushing the your client ip value
      deserializer(&dhcp_ycip,pkt,sizeof(dhcp_ycip));
      // Pushing the server ip value
      deserializer(&dhcp_sip,pkt,sizeof(dhcp_sip));
      // Pushing the gateway ip value
      deserializer(&dhcp_gip,pkt,sizeof(dhcp_gip));
      // Pushing the client hardware value
      deserializer(dhcp_cadr,pkt,16);

      if(!pkt.empty()){
        dhcp_opt = std::vector<uint8_t> ();

        // Pushing the options value 
        while(!pkt.empty()){
          dhcp_opt->push_back(pkt.front());
          pkt.pop();
        }
    }
  }

  dhcp_hdr(std::vector<uint8_t> &pkt, size_t &offset){

      // Pushing the opcode value
      deserializer(&dhcp_op,pkt,sizeof(dhcp_op), offset);
      // Pushing the format of hardware address value
      deserializer(&dhcp_hrd,pkt,sizeof(dhcp_hrd), offset);
      // Pushing the length of hardware address value
      deserializer(&dhcp_hln,pkt,sizeof(dhcp_hln), offset);
      // Pushing the hop limit value
      deserializer(&dhcp_hop,pkt,sizeof(dhcp_hop), offset);      
      // Pushing the id value
      deserializer(&dhcp_id,pkt,sizeof(dhcp_id), offset);
      // Pushing the seconds elapsed value
      deserializer(&dhcp_sec,pkt,sizeof(dhcp_sec), offset);
      // Pushing the flags value
      deserializer(&dhcp_flags,pkt,sizeof(dhcp_flags), offset);
      // Pushing the client ip value
      deserializer(&dhcp_cip,pkt,sizeof(dhcp_cip), offset);
      // Pushing the your client ip value
      deserializer(&dhcp_ycip,pkt,sizeof(dhcp_ycip), offset);
      // Pushing the server ip value
      deserializer(&dhcp_sip,pkt,sizeof(dhcp_sip), offset);
      // Pushing the gateway ip value
      deserializer(&dhcp_gip,pkt,sizeof(dhcp_gip), offset);
      // Pushing the client hardware value
      deserializer(dhcp_cadr,pkt,16, offset);

      if(!pkt.empty()){
        dhcp_opt = std::vector<uint8_t> ();

        // Pushing the options value 
        while(offset < pkt.size()-4){
          dhcp_opt->push_back(pkt[offset++]);
        }
      }

  }

  dhcp_hdr(std::vector<uint8_t> &pkt){

      // Pushing the opcode value
      deserializer(&dhcp_op,pkt,sizeof(dhcp_op));
      // Pushing the format of hardware address value
      deserializer(&dhcp_hrd,pkt,sizeof(dhcp_hrd));
      // Pushing the length of hardware address value
      deserializer(&dhcp_hln,pkt,sizeof(dhcp_hln));
      // Pushing the hop limit value
      deserializer(&dhcp_hop,pkt,sizeof(dhcp_hop));      
      // Pushing the id value
      deserializer(&dhcp_id,pkt,sizeof(dhcp_id));
      // Pushing the seconds elapsed value
      deserializer(&dhcp_sec,pkt,sizeof(dhcp_sec));
      // Pushing the flags value
      deserializer(&dhcp_flags,pkt,sizeof(dhcp_flags));
      // Pushing the client ip value
      deserializer(&dhcp_cip,pkt,sizeof(dhcp_cip));
      // Pushing the your client ip value
      deserializer(&dhcp_ycip,pkt,sizeof(dhcp_ycip));
      // Pushing the server ip value
      deserializer(&dhcp_sip,pkt,sizeof(dhcp_sip));
      // Pushing the gateway ip value
      deserializer(&dhcp_gip,pkt,sizeof(dhcp_gip));
      // Pushing the client hardware value
      deserializer(dhcp_cadr,pkt,16);

      if(!pkt.empty()){
        dhcp_opt = std::vector<uint8_t> ();

        // Pushing the options value 
        // while(pkt.size() > 4){
        //   dhcp_opt->push_back(pkt.front());
        //   pkt.erase(pkt.begin());
        // }
        while(!pkt.empty()){
          dhcp_opt->push_back(pkt.front());
          pkt.erase(pkt.begin());
        }
      }

  }

  dhcp_hdr(std::deque<uint8_t> &pkt){

      // Pushing the opcode value
      deserializer(&dhcp_op,pkt,sizeof(dhcp_op));
      // Pushing the format of hardware address value
      deserializer(&dhcp_hrd,pkt,sizeof(dhcp_hrd));
      // Pushing the length of hardware address value
      deserializer(&dhcp_hln,pkt,sizeof(dhcp_hln));
      // Pushing the hop limit value
      deserializer(&dhcp_hop,pkt,sizeof(dhcp_hop));      
      // Pushing the id value
      deserializer(&dhcp_id,pkt,sizeof(dhcp_id));
      // Pushing the seconds elapsed value
      deserializer(&dhcp_sec,pkt,sizeof(dhcp_sec));
      // Pushing the flags value
      deserializer(&dhcp_flags,pkt,sizeof(dhcp_flags));
      // Pushing the client ip value
      deserializer(&dhcp_cip,pkt,sizeof(dhcp_cip));
      // Pushing the your client ip value
      deserializer(&dhcp_ycip,pkt,sizeof(dhcp_ycip));
      // Pushing the server ip value
      deserializer(&dhcp_sip,pkt,sizeof(dhcp_sip));
      // Pushing the gateway ip value
      deserializer(&dhcp_gip,pkt,sizeof(dhcp_gip));
      // Pushing the client hardware value
      deserializer(dhcp_cadr,pkt,16);

      if(!pkt.empty()){
        dhcp_opt = std::vector<uint8_t> ();

        // Pushing the options value 
        while(pkt.size() > 4){
          dhcp_opt->push_back(pkt.front());
          pkt.pop_front();
        }
      }

  }

  template<typename T>
  void serialize(T &pkt){

      // Pushing the opcode value
      serializer(&dhcp_op,pkt,sizeof(dhcp_op));
      // Pushing the format of hardware address value
      serializer(&dhcp_hrd,pkt,sizeof(dhcp_hrd));
      // Pushing the length of hardware address value
      serializer(&dhcp_hln,pkt,sizeof(dhcp_hln));
      // Pushing the hop limit value
      serializer(&dhcp_hop,pkt,sizeof(dhcp_hop));      
      // Pushing the id value
      serializer(&dhcp_id,pkt,sizeof(dhcp_id));
      // Pushing the seconds elapsed value
      serializer(&dhcp_sec,pkt,sizeof(dhcp_sec));
      // Pushing the flags value
      serializer(&dhcp_flags,pkt,sizeof(dhcp_flags));
      // Pushing the client ip value
      serializer(&dhcp_cip,pkt,sizeof(dhcp_cip));
      // Pushing the your client ip value
      serializer(&dhcp_ycip,pkt,sizeof(dhcp_ycip));
      // Pushing the server ip value
      serializer(&dhcp_sip,pkt,sizeof(dhcp_sip));
      // Pushing the gateway ip value
      serializer(&dhcp_gip,pkt,sizeof(dhcp_gip));
      // Pushing the client hardware value
      serializer(&dhcp_cadr,pkt,16);

      if(dhcp_opt.has_value()){

        // Pushing the options value 
        std::vector<uint8_t> vec = dhcp_opt.value();
        serializer(&vec, pkt, vec.size());
      }
  }

  void display()const{
    std::cout << "DHCP Header"        << std::endl;
    std::cout << "Hardware format: "  << std::to_string(dhcp_hrd) << std::endl;
    std::cout << "Hardware length: "  << std::to_string(dhcp_hln) << std::endl;
    std::cout << "Hop count: "        << std::to_string(dhcp_hop) << std::endl;
    std::cout << "Identification: "   << std::to_string(dhcp_id) << std::endl;
    std::cout << "Seconds: "          << std::to_string(dhcp_sec) << std::endl;
    std::cout << "Flags: "            << std::to_string(dhcp_flags) << std::endl;
    std::cout << "Client Ip: "        << ipToString(dhcp_cip) << std::endl;
    std::cout << "Your Client Ip: "   << ipToString(dhcp_ycip) << std::endl;
    std::cout << "Server Ip: "        << ipToString(dhcp_sip) << std::endl;
    std::cout << "Gateway Ip: "       << ipToString(dhcp_gip) << std::endl;
    
  }
}; 

struct dns_hdr {
    uint16_t dns_id{};
    uint16_t dns_flags {};
    uint16_t dns_question_count{};
    uint16_t dns_answer_count{};
    uint16_t dns_nameserver_count{};
    uint16_t dns_additional_record_count{};

    dns_hdr(uint16_t id, bool qr, uint8_t op, bool aa, bool tc, bool rd, bool ra, uint8_t rCode, uint16_t QDCOUNT, uint16_t ANCOUNT, uint16_t NSCOUNT, uint16_t ARCOUNT){
        dns_id = id;
        if(op > 15 && rCode > 15 ) return;

        uint16_t tempFlags{0};
        if(qr) tempFlags = tempFlags + (qr << 15);
        tempFlags = tempFlags + (op << 11);
        if(aa) tempFlags = tempFlags + (aa << 10);
        if(tc) tempFlags = tempFlags + (tc << 9);
        if(rd) tempFlags = tempFlags + (rd << 8);
        if(ra) tempFlags = tempFlags + (ra << 7);
        tempFlags = tempFlags + (rCode);
    
        dns_flags = tempFlags;

        dns_question_count = QDCOUNT ;
        dns_answer_count = ANCOUNT ;
        dns_nameserver_count = NSCOUNT ;
        dns_additional_record_count = ARCOUNT ;
    }

    template<typename T>
    void serialize(T &pkt){
        serializer(&dns_id, pkt, sizeof(dns_id));
        serializer(&dns_flags, pkt, sizeof(dns_flags));
        serializer(&dns_question_count, pkt, sizeof(dns_question_count));
        serializer(&dns_answer_count, pkt, sizeof(dns_answer_count));
        serializer(&dns_nameserver_count, pkt, sizeof(dns_nameserver_count));
        serializer(&dns_additional_record_count, pkt, sizeof(dns_additional_record_count));
    }
};


enum size {
  internal_hdr_size = 3,
  router_internal_hdr_size = 11,
  ethernet_hdr_size = 22,
  ethernet_trailer_size = 4,
  ipv4_hdr_size = 20,
  udp_hdr_size = 8,
  dhcp_hdr_size = 44,                    // Withput options
  bpdu_hdr_size = 35,
};

} // END NAMESPACE PROTOCOL

#endif