#pragma once
#ifndef SERVERIFACE_H
#define SERVERIFACE_H
#include "interface.h"

class ServerIface : public Iface {
public:
   ServerIface(std::string_view sv, std::shared_ptr<DeviceWindowBase> consoleWindow): Iface(sv.data(), consoleWindow) {}
  // SeverIface(){return;}

  // Getter methods 
  uint32_t getIPV4() const { return ipv4; } 
  uint32_t getSUBNET_MASK() const { return subnet_mask; } 
  uint32_t getGATEWAY() const { return gateway_ipv4; } 
  uint32_t getDNS() const { return dns_ipv4; } 

	// Setter methods 
  void setIPV4(uint32_t ip) { ipv4 = ip; } 
  void setSUBNET_MASK(uint32_t mask) { subnet_mask = mask; } 
  void setGATEWAY(uint32_t default_gateway) { gateway_ipv4 = default_gateway; }
  void setDNS(uint32_t dns) { dns_ipv4 = dns; }

	uint32_t ipv4 {};
	uint32_t subnet_mask {};
	uint32_t gateway_ipv4 {};
	uint32_t dns_ipv4 {};

  // std::atomic<bool> &flag_;    
  // std::condition_variable &signal;
	// mutable std::mutex mtx;
};

#endif