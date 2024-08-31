#pragma once 
#ifndef ARPCACHE_H
#define ARPCACHE_H
#include "..\common.h"

struct ArpUserEntry {
  uint8_array_6 mac{};
  uint32_t ip = 0; //< IP addr in network byte order
  uint16_t time = 0; 

  ArpUserEntry()=default;
  ArpUserEntry(const uint8_array_6 &tempMac, uint32_t tempIp, std::optional<uint8_t> iface = std::nullopt){
    if(!iface.has_value()){
      assign_uint8_array_6(mac,tempMac);
      ip = tempIp;
    }
  };

  // Creating ARP table entries 
  void createEntry(const uint8_array_6 &tempMac, uint32_t tempIp){
    assign_uint8_array_6(mac, tempMac);
    ip = tempIp;
    time = 120; // Initialised by default as 120 seconds = 2 minutes
  }

  // Creating ARP Pending Request meaning the ARP Request we have sent and waiting for replies on
  void createPendingEntry(uint32_t tempIp){
    ip = tempIp;
    time = 20; // Initialised as 20 seconds but usually 1 or 2 seconds only
  }
};

struct ArpRouterEntry {
  uint8_array_6 mac{};
  uint32_t ip = 0; //< IP addr in network byte order
  uint8_t iface = 0;
  uint16_t time = 0; 

  ArpRouterEntry()=default;
  ArpRouterEntry(const uint8_array_6 &tempMac, uint32_t tempIp, std::optional<uint8_t> iface = std::nullopt){
    if(iface.has_value()){
      assign_uint8_array_6(mac,tempMac);
      ip = tempIp;
      iface = iface.value();
    }
  };

  // Creating ARP table entries 
  void createEntry(const uint8_array_6 &tempMac, uint32_t tempIp, uint8_t tempInterface){
    assign_uint8_array_6(mac,tempMac);
    ip = tempIp;
    iface = tempInterface;
    time = 120; // Initialised by default as 120 seconds = 2 minutes
  }

  // Creating ARP Pending Request meaning the ARP Request we have sent and waiting for replies on
  void createPendingEntry(uint32_t tempIp, uint8_t tempInterface){
    ip = tempIp;
    iface = tempInterface;
    time = 20; // Initialised as 20 seconds but usually 1 or 2 seconds only
  }
};

template <typename T, typename BufferType>
class ArpCache {

public:

  ArpCache(std::shared_ptr<BufferType> arp_queue): arp_waiting_queue_(arp_queue){this->start();} // Calling the decrementing thread which decrements each entries lease time each second 
  ~ArpCache(){stop_thread=true;} // Just making sure that the thread doesnt run anymore

  void getIPtoMac(uint32_t ip, uint8_array_6 &mac){
    for(auto &entry : arp_table){
      if(entry.ip == ip) {
        assign_uint8_array_6(mac, entry.mac);
        return;
      }
    }
  }

  void checkARPTable(const uint8_array_6 &mac, uint32_t ip, std::optional<uint8_t> iface = std::nullopt){
    for(auto &entry : arp_table){
      if(entry.ip == ip) {
        assign_uint8_array_6(entry.mac, mac);
        return;
      }
    }

    addEntry(mac, ip, iface);
  }

  // Direct ARP Requests: When the router itself sends an ARP request and receives a reply.
  // ARP Replies: When the router receives an ARP reply in response to a previous ARP request it sent.
  void addEntry(const uint8_array_6 &mac, uint32_t ip, std::optional<uint8_t> iface = std::nullopt){

    if(std::is_same<T, ArpRouterEntry>::value){

      if(iface.has_value()){
        T entry(mac, ip, iface.value());
        // entry.createEntry(mac, ip, iface.value());
        arp_table.push_back(entry);
      }
    } else if(std::is_same<T, ArpUserEntry>::value) {
      T entry(mac,ip);
      // entry.createEntry(mac, ip);
      arp_table.push_back(entry);
    }

    // if(arp_waiting_queue_->hashmap.contains(ip)){
    //   if(iface.has_value()) arp_waiting_queue_->sendPacket(ip, mac, iface.value());
    //   else arp_waiting_queue_->sendPacket(ip, mac);
    // }
  }

  // The ARP request have been sent for and waiting for ARP Replies on
  void addPendingEntry( uint32_t ip ){
  	spdlog::info("ADDED USER PENDING ENTRY: {}", ipToString(ip));
    ArpUserEntry entry;
    entry.createPendingEntry(ip);
    arp_request_pending.push_back(entry);
  }

  void addPendingEntry(uint32_t ip, uint8_t iface ){
      spdlog::info("ADDED ROUTER PENDING ENTRY: {} {}",ipToString(ip),+iface);
    if constexpr(std::is_same<T, ArpRouterEntry>::value){

      ArpRouterEntry entry;
      entry.createPendingEntry(ip, iface);
      arp_request_pending.push_back(entry);
    }
  
  }

  void display(){
    if(std::is_same<T, ArpUserEntry>::value){
        spdlog::info("USER ARP TABLE");
    }else{
        spdlog::info("ROUTER ARP TABLE");
    }
    for(auto entry : arp_table){
        spdlog::info("{}   {}", macToString(entry.mac), ipToString(entry.ip));
    }

    if(std::is_same<T, ArpUserEntry>::value){
        spdlog::info("USER PENDING TABLE");
    }else{
        spdlog::info("ROUTER PENDING TABLE");
    }
    for(auto entry : arp_request_pending){
        spdlog::info("{}   {}", macToString(entry.mac), ipToString(entry.ip));
    }
  }

  // Check if the ARP Reply is a Reply and not a bogus Reply 
  // TODO: Need to perform ARP handling for Gratuitous ARP
  void checkPendingEntry(const uint8_array_6 &mac, uint32_t ip, std::optional<uint8_t> iface = std::nullopt){
	  
    for(auto &el : arp_request_pending){
      if(el.ip == ip){
        checkARPTable(mac, ip, iface);
        if(arp_waiting_queue_->hashmap.contains(ip)){

          if(iface.has_value()) arp_waiting_queue_->sendPacket(ip, mac, iface.value());
          else arp_waiting_queue_->sendPacket(ip, mac);
          }
      }

    }
    arp_request_pending.erase(std::remove_if(arp_request_pending.begin(), arp_request_pending.end(),
                                                   [&](const T& entry) {
                                                       return entry.ip == ip;
                                                   }), arp_request_pending.end());
  }
  
  // Start the decrementing thread
  void start() {
    time_thread = std::thread([this]() {
        while (!stop_thread) {
            {
                // Decrease the time for each entry
                for (T &entry : arp_table) {
                    --entry.time;
                }
                for (T &pendingEntry : arp_request_pending){
                    --pendingEntry.time;
                }
                
                {   // Remove the entry 
                    std::lock_guard<std::mutex> lock(muxTable);
                    
                    // Remove entries from ARP table where time < 0
                    arp_table.erase(std::remove_if(arp_table.begin(), arp_table.end(),
                                                   [](const T& entry) {
                                                       return entry.time <= 0;
                                                   }), arp_table.end());

                    // Remove entries from Pending ARP Request table where time < 0
                    arp_request_pending.erase(std::remove_if(arp_request_pending.begin(), arp_request_pending.end(),
                                                   [](const T& entry) {
                                                       return entry.time <= 0;
                                                   }), arp_request_pending.end());
                } // Release the lock when lock goes out of scope
            }
            
            // Sleep after processing inside the while loop
            std::this_thread::sleep_for(std::chrono::seconds(1));
        }
    });

    time_thread.detach();
}

private:
  std::vector<T> arp_table {};
  
  // std::vector<T> arp_request_pending {};
  std::vector<T> arp_request_pending {};
  std::shared_ptr<BufferType> arp_waiting_queue_;
  
    bool stop_thread = false;
    std::thread time_thread;
	std::mutex muxTable;


};


#endif