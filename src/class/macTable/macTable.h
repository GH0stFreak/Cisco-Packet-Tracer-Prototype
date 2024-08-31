#pragma once 
#ifndef MACTABLE_H
#define MACTABLE_H
#include "..\common.h"
#include "..\interface\interface.h"
#include "..\layer5\layer5.h"

struct MacTableEntry {
    uint8_array_6 mac{};
    uint8_t port{};
  uint16_t time{300}; // Initialised by default as 300 seconds = 5 minutes

  MacTableEntry()=default;

  // Creating ARP table entries 
  void createEntry(const uint8_array_6 &tempMac, uint8_t tempPort){
    assign_uint8_array_6(mac, tempMac);
    port = tempPort;
  }
};

class MacTable {
public:

  MacTable(){this->start();} // Calling the decrementing thread which decrements each entries lease time each second 
  ~MacTable(){stop_thread=true;} // Just making sure that the thread doesn't run anymore

    // Check Mac Table to see if entry already present if present just update the port if not then add a new entry
    void checkMacTable(const uint8_array_6 &mac, uint8_t port){
	    std::scoped_lock lock(muxTable);
        for(auto &entry : mac_table){
            if(check_uint8_array_6(entry.mac, mac)) {
            entry.port =  port;
            return;
            }
        }

        addEntry(mac, port);
    }

    // Return the output interface from table if not present return zero
    uint8_t getInterface(const uint8_array_6 &mac){
	    std::scoped_lock lock(muxTable);
        for(MacTableEntry entry : mac_table){
            if(check_uint8_array_6(entry.mac, mac)){
                return entry.port;
            }
        }
        return 0;
    }

  // Add Entry to the Mac Table
  void addEntry(const uint8_array_6 &mac, uint8_t port){
		// std::scoped_lock lock(muxTable);
      spdlog::info("MAC TABLE ADDED ENTRY");
    MacTableEntry entry;
    entry.createEntry(mac, port);
    mac_table.push_back(entry);
  }

  void display()const{
    if(mac_table.empty()){
      spdlog::info("MAC TABLE EMPTY!");
      return;
    }
    spdlog::info("     MAC         PORT");

    for(MacTableEntry entry : mac_table){
        spdlog::info("{}   {}",macToString(entry.mac), +entry.port);
    }
  }

  // Start the decrementing thread
  void start() {  
    time_thread = std::thread([this]() {
        while (!stop_thread) {
            {
                // Decrease the time for each entry
                for (MacTableEntry &entry : mac_table) {
                    --entry.time;
                }
                
                {   // Remove the entry 
                    std::lock_guard<std::mutex> lock(muxTable);
                    
                    // Remove entries from ARP table where time < 0
                    mac_table.erase(std::remove_if(mac_table.begin(), mac_table.end(),
                                                   [](const MacTableEntry& entry) {
                                                       return entry.time <= 0;
                                                   }), mac_table.end());

                } // Release the lock when lock goes out of scope
            }
            
            // Sleep after processing inside the while loop
            std::this_thread::sleep_for(std::chrono::seconds(1));
        }
    });

    time_thread.detach();
  }


private:
  std::vector<MacTableEntry> mac_table {};

  bool stop_thread = false;
  std::thread time_thread;
	std::mutex muxTable;

  mutable std::mutex mtx;
	std::condition_variable cvBlocking;
	// mutable std::mutex muxBlocking;

};

#endif