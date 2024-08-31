#pragma once
#ifndef DHCPIFACE_H
#define DHCPIFACE_H
#include "serverIface.h"

class DhcpIface : public ServerIface {
public: 
    DhcpIface(std::atomic<bool> &flag, 
                std::condition_variable &cond_var_copy,
                std::string_view sv,
                std::shared_ptr<DeviceWindowBase> consoleWindow)
                : flag_(flag), 
                signal_(cond_var_copy), 
                ServerIface(sv.data(), consoleWindow) {};

    virtual void processInputPktRam(){

            size_t offset{};
            PROTOCOL::internal_hdr internal_hdr(ram,offset);
            // internal_hdr.display();

            PROTOCOL::ethernet_hdr ethernet_hdr(ram,offset);
            // ethernet_hdr.display();

            // Checking Destination MAC if not equal to broadcast address or to client mac then drop by just clearing RAM
            bool for_client = check_uint8_array_6(ethernet_hdr.ether_dhost, mac);
            bool for_broadcast = check_uint8_array_6(ethernet_hdr.ether_dhost, PROTOCOL::BroadcastEtherAddr);
    
            if(for_client || for_broadcast){
		          std::unique_lock<std::mutex> lock(mtx);
                  if (!flag_.load(std::memory_order_acquire)) {
                        flag_.store(true, std::memory_order_release);
                  }
                  signal_.wait(lock);
            }

            ram.clear();
    }

    virtual void processOutputPktRam() {}

    iFaceState getState() const override { return NON_DESIGNATED; }
    void setState(iFaceState st) override {}


    std::atomic<bool> &flag_;    
    std::condition_variable &signal_;
	mutable std::mutex mtx;
};

#endif