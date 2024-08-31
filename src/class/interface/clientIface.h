#pragma once
#ifndef CLIENTIFACE_H
#define CLIENTIFACE_H
#include "interface.h"

class ClientIface : public Iface {
public:
    ClientIface(std::atomic<bool> &flag,
                std::condition_variable &cond_var_copy, 
                std::string_view sv, 
                std::shared_ptr<DeviceWindowBase> consoleWindow)
            : flag_(flag), 
                signal(cond_var_copy), 
                Iface(sv.data(), consoleWindow) {}

    virtual void processInputPktRam(){
        // TODO: Deserialize the pkt ethernet header
        size_t offset{};
        // std::cout<<;
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
            signal.wait(lock);
        }else{

            //logger->warn("Wrong Address Dropped!");
            printMessage(CONSOLE_INFO, "Wrong Address Dropped!");
            //logger->info("Our addr: {}", macToString(mac));
            printMessage(CONSOLE_INFO, "Our addr: {}", macToString(mac));
            //logger->info("Pkt addr: {}", macToString(ethernet_hdr.ether_dhost));
            printMessage(CONSOLE_INFO, "Pkt addr: {}", macToString(ethernet_hdr.ether_dhost));
        }

        ram.clear();
    }

    virtual void processOutputPktRam() {}

    iFaceState getState() const override { return NON_DESIGNATED; }
    void setState(iFaceState st) override {}

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

    std::chrono::time_point<std::chrono::high_resolution_clock> lease_start;

    std::atomic<bool> &flag_;    
    std::condition_variable &signal;
	mutable std::mutex mtx;

};

#endif