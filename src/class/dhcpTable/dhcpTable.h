#pragma once 
#ifndef DHCPTABLE_H
#define DHCPTABLE_H

//#include "..\interface\interface.h"
//#include "..\layer5\layer5.h"
#include "..\interface\dhcpIface.h"

class DhcpIface;

enum State {
  INIT,	        //Client starts the process of acquiring a lease
  SELECTING,	//Client waits for offers from DHCP servers
  REQUESTING,	//Client requests a specific lease from a DHCP server
  BOUND,	    //Client has an assigned IP address and lease period begins
  RENEWING,  	//Client attempts to renew the current lease with the original server
  REBINDING,	//Client attempts to renew the lease with any available server
  RELEASED,	    //Client releases the IP address and terminates the lease
  EXPIRED,	    //Lease duration has elapsed without renewal; IP address becomes available
  DECLINED,	    //Client detects the offered IP address is already in use
  INFORM        //Client requests additional configuration parameters without obtaining an IP address
};

// TODO: need to make the options field according to the routers ip which would be static so would need to put an ip for indefinite time as well
struct Options {
    uint32_t mask{0};
    uint32_t gateway{0};
  uint32_t dns = 0x01010101;
  // uint32_t dns_2;
  Options() {};
  Options(uint32_t mask_, uint32_t gateway_, uint32_t dns_){
    mask = mask_;
    gateway = gateway_;
    dns = dns_;
  }
};

struct IpPool {
    uint32_t ip{};
  Options option;
  uint32_t start_ip{};    // First assignable ip
  uint32_t end_ip{};      // Last assignable ip
  uint32_t offering_ip{}; // The current ip we offer
  std::chrono::hours lease_duration = std::chrono::hours(8); 
  std::vector<uint32_t> free_ip_list {};

  IpPool(uint32_t tempIp, uint32_t tempMask, uint32_t tempGateway, uint32_t tempDns) {
    ip 			=	tempIp;
    option.mask = tempMask;
    option.gateway = tempGateway;
    option.dns = tempDns;
  }


	IpPool(uint32_t tempIp, uint32_t tempMask, uint32_t tempGateway, uint32_t tempDns, std::chrono::hours tempLeaseDuration) {
    ip 			=	tempIp;
    option.mask = tempMask;
    option.gateway = tempGateway;
    option.dns = tempDns;

    start_ip    = (tempIp & tempMask)+1;
    offering_ip = (tempIp & tempMask)+1;
    end_ip      = (tempIp | (~tempMask))-1;

    // std::cout<<ipToString(start_ip)<<"\n";
    // std::cout<<ipToString(offering_ip)<<"\n";
    // std::cout<<ipToString(end_ip)<<"\n";

    lease_duration = tempLeaseDuration;

    while (offering_ip<=end_ip) {
      if(offering_ip != option.gateway){
        free_ip_list.push_back(offering_ip);
      }
      offering_ip++;
    }
    // std::cout<<ipToString(free_ip_list.back())<<"\n";
    // std::cout<<"LENGTH: "<<free_ip_list.size()<<"\n";

  }

  void getFirst(DhcpIface *iface){
    if(free_ip_list.front() == ((ip&option.mask) +1)) return;

    auto it = free_ip_list.begin();
    free_ip_list.erase(it);
    
    iface->setIPV4(start_ip);
    iface->setSUBNET_MASK(option.mask);
    iface->setGATEWAY(option.gateway);
    iface->setDNS(option.dns);
  }
};

struct DhcpNetworkEntry {
    uint8_array_6 mac{};
    uint32_t leased_ip{};
    std::chrono::time_point<std::chrono::high_resolution_clock> leased_start_time{};
    std::chrono::time_point<std::chrono::high_resolution_clock> leased_expire_time{};
    std::string hostname{};
    uint32_t xid{};           // The transaction id in each packet
    State binding_state{};
    Options option;

    DhcpNetworkEntry() = default;

    // Creating ARP table entries 
    DhcpNetworkEntry(const uint8_array_6 &tempMac, uint32_t tempLeasedIp, std::chrono::hours lease_duration, uint32_t id, State tempState, Options tempOption){
        assign_uint8_array_6(mac, tempMac);
        leased_ip = tempLeasedIp;
        leased_start_time = std::chrono::high_resolution_clock::now();
        leased_expire_time = std::chrono::high_resolution_clock::now() + lease_duration;
        xid = id;
        binding_state = tempState;
        option = tempOption;
    }
};

class DhcpNetworkTable {
public:

    DhcpNetworkTable(std::vector<IpPool> &ipPools): ipPools_(ipPools) {
        this->start();

    } // Calling the decrementing thread which decrements each entries lease time each second 
  
    ~DhcpNetworkTable(){stop_thread=true;} // Just making sure that the thread doesn't run anymore

   DhcpNetworkEntry getOffer(const uint8_array_6 &mac, uint32_t id){
    // No Ip avaiable 
    IpPool &pool = ipPools_.front();
    if(pool.free_ip_list.empty()) {
      DhcpNetworkEntry offer;
      return offer;
    }
		std::scoped_lock lock(muxTable);

    uint32_t offer_ip = pool.free_ip_list.back(); // Get the last element
    pool.free_ip_list.pop_back(); // Remove the last element

    DhcpNetworkEntry offer( mac, offer_ip, pool.lease_duration, id, SELECTING, pool.option);

    dhcp_network_table.push_back(offer);

    return offer;
  }

  // This poolIp is taken to know from which IP pool is the IP needed
  DhcpNetworkEntry getOffer(const uint8_array_6 &mac, uint32_t id, uint32_t poolIp){
    // No Ip avaiable 
    for(IpPool &pool : ipPools_){
      if((poolIp & pool.option.mask) == pool.ip){
        if(pool.free_ip_list.empty()){
          DhcpNetworkEntry offer;
          return offer;
        }
        std::scoped_lock lock(muxTable);
        uint32_t offer_ip = pool.free_ip_list.back(); // Get the last element
        pool.free_ip_list.pop_back(); // Remove the last element

        DhcpNetworkEntry offer( mac,offer_ip,pool.lease_duration,id,SELECTING,pool.option);
        dhcp_network_table.push_back(offer);
        return offer;

      }
    }

    DhcpNetworkEntry offer;
    return offer;

  }

  DhcpNetworkEntry getExistingOffer(const uint8_array_6 &mac, uint32_t id){
    for ( auto &entry : dhcp_network_table )
    {
      if(id == entry.xid && check_uint8_array_6(entry.mac,mac)){
        
        return entry;

      }
    }
    DhcpNetworkEntry offer;
    return offer;
  }

  bool checkMACInDHCPProcess(const uint8_array_6 &mac){
    for ( auto &entry : dhcp_network_table )
    {
      if(check_uint8_array_6(entry.mac,mac)) return true;
    }
    return false;
  }

  bool checkMACRequestPhase(const uint8_array_6 &mac,uint32_t requested_ip){
    for ( auto &entry : dhcp_network_table )
    {
      if(check_uint8_array_6(entry.mac,mac)){
        
        if(entry.binding_state == SELECTING && entry.leased_ip == requested_ip){
          return true;
        }

      }
    }
    return false;
  }

  void changeBindingState(const uint8_array_6 &mac, State next_state){
    for ( auto &entry : dhcp_network_table )
    {
      if(check_uint8_array_6(entry.mac,mac)){
        
        entry.binding_state = next_state;
      }
    }
  }
/* 
  // Check Mac Table to see if entry already present if present just update to port if not then add entry
  void checkMacTable(const uint8_array_6 &mac, uint8_t port){
    for(auto &entry : dhcp_network_table){
      if(check_uint8_array_6(entry.mac, mac)) {
        entry.port =  port;
        return;
      }
    }

    addEntry(mac, port);
  } */
/*
  // Return the output interface from table if not present return zero
  uint8_t getInterface(const uint8_array_6 &mac){

    for(auto entry : dhcp_network_table){
      if(check_uint8_array_6(entry.mac, mac)){
        return entry.port;
      }
    }
    return 0;
  } */
/*
  // Add Entry to the Mac Table
  void addEntry(const uint8_array_6 &mac, uint8_t port){

      DhcpNetworkEntry entry;
      entry.createEntry(mac, port);
      dhcp_network_table.push_back(entry);
  }*/

  // Start the decrementing thread
  void start() {
    time_thread = std::thread([this]() {
        while (!stop_thread) {
            {
                // Decrease the time for each entry
                std::chrono::time_point time = std::chrono::high_resolution_clock::now();

                std::lock_guard<std::mutex> lock(muxTable);
                for (DhcpNetworkEntry &entry : dhcp_network_table) {
                  if((entry.binding_state == BOUND) && (time > entry.leased_expire_time)){
                    entry.binding_state = EXPIRED;
                  }
                }
                
                {   // Remove the entry 
                    
                    // Remove entries from ARP table where time < 0
                    // dhcp_network_table.erase(std::remove_if(dhcp_network_table.begin(), dhcp_network_table.end(),
                    //                                [time,lease_duration](const DhcpNetworkEntry& entry) {
                    //                                    return (entry.leased_start_time - time > lease_duration);
                    //                                }), dhcp_network_table.end());

                } // Release the lock when lock goes out of scope
            }
            
            // Sleep after processing inside the while loop
            std::this_thread::sleep_for(std::chrono::seconds(10));
        }
    });

    time_thread.detach();
}


private:

  std::vector<IpPool> &ipPools_;

  // TODO: maybe better to just fill the table with all ip we can offer
  std::vector<DhcpNetworkEntry> dhcp_network_table {};

  bool stop_thread = false;
  std::thread time_thread;
	std::mutex muxTable;


};

#endif