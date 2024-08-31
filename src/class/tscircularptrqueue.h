

#pragma once
#ifndef TSCIRCULARPTRQUEUE_H
#define TSCIRCULARPTRQUEUE_H

#include "common.h"
#include "protocol.h"

class Client;
class Dhcp;
class Router;

namespace Buffer {

template <std::size_t Size, std::size_t Max_Pkt_Size, class Device>
class CircularPtrQueue {
public:
    CircularPtrQueue(  std::condition_variable &cond_var,
                    std::counting_semaphore<10> &sem_ref,
                    Device *user) 
                :   count(0), 
                    signal(cond_var), 
                    sema(sem_ref), 
                    buffer(std::make_unique<uint8_t[]>(Size)), 
                    user_(user) {

        size_t counter{1};
        while((Max_Pkt_Size*counter)<Size){
          indexes.push_back(Max_Pkt_Size*counter);
          counter++;
        }
    }
        
        
    // TICK: Need to test
    void enqueue(std::vector<uint8_t> *data, uint32_t ip) {
        if (is_full() || indexes.empty()) {
            throw std::overflow_error("Queue is full");
        }
        
        // Check for null pointer 
        if (data == nullptr) {
            return;
        }
        // Lock the buffer to add a packet
        std::scoped_lock lock(muxQueue);
        // std::cout<<"Enqueue: "<<data->size()<<std::endl;
        spdlog::info("PTR ADDED");
        //std::cout<<+data->size()<<" ";
        // for(auto index: data){
        //     std::cout<<+data->at(i)<<" ";
        //     std::cout<<+index<<" ";
        // }
        //std::cout<<"\n";

        size_t index = indexes.back();
        indexes.pop_back();

        hashmap[ip] = std::make_pair(index, 15);
        
        // Loop till end of vector and place it in the buffer
        for (size_t i {}; i < data->size(); i++) {
            // std::cout<<+data->at(i)<<" ";
            buffer[index + i] = data->at(i);
        }

        if constexpr (std::is_same<Device, Client>::value) {
            user_->sendARPRequest(ip);
        }
        
        // Increased the packet count
        ++count;

        // Increased the counting semaphore
        sema.release();

        // Notify waiting scheduler
        signal.notify_one(); 
        // signal.notify_one(); 
        spdlog::info("NEW ADDED");
    }

    // TICK: Need to test
    void enqueue(std::vector<uint8_t> *data, uint32_t ip, uint8_t iface) {
        if (is_full() || indexes.empty()) {
            throw std::overflow_error("Queue is full");
        }
        
        // Check for null pointer 
        if (data == nullptr) {
            return;
        }
        // Lock the buffer to add a packet
        std::scoped_lock lock(muxQueue);
        // std::cout<<"Enqueue: "<<data->size()<<std::endl;
        spdlog::info("PTR ADDED");
        // std::cout<<+data->size()<<" ";
        // for(auto index: data){
        //     std::cout<<+data->at(i)<<" ";
        //     std::cout<<+index<<" ";
        // }
        // std::cout<<"\n";

        size_t index = indexes.back();
        indexes.pop_back();

        hashmap[ip] = std::make_pair(index, 15);
        
        // Loop till end of vector and place it in the buffer
        for (size_t i {}; i < data->size(); i++) {
            // std::cout<<+data->at(i)<<" ";
            buffer[index + i] = data->at(i);
        }

        if constexpr(std::is_same<Device, Router>::value){
            for(auto &iface_: user_->ifaces){
                if(iface_.id == iface){
                    iface_.sendARPRequest(ip, iface);
                }
            }
        }
        // Increased the packet count
        ++count;

        // Increased the counting semaphore
        sema.release();

        // Notify waiting scheduler
        signal.notify_one(); 
        // signal.notify_one(); 
        spdlog::info("NEW ADDED");
    }


    void enqueue(std::deque<uint8_t> *data, uint32_t ip) {
        if (is_full() || indexes.empty()) {
            throw std::overflow_error("Queue is full");
        }
        
        // Check for null pointer 
        if (data == nullptr) {
            return;
        }
        // Lock the buffer to add a packet
        std::scoped_lock lock(muxQueue);
        // std::cout<<"Enqueue: "<<data->size()<<std::endl;
        // std::cout<<"\n Sending"<<std::endl;
        // std::cout<<"Size: "<<+data->size()<<"\n";

        // Inserting additional internal packet 
        /*PROTOCOL::internal_hdr internal_hdr(static_cast<uint16_t>(data->size()));

        std::list<uint8_t> temp;
        internal_hdr.serialize(temp);
        data->insert(data->begin(),temp.begin(),temp.end());*/

        size_t index = indexes.back();
        indexes.pop_back();

        hashmap[ip] = std::make_pair(index, 15);
        
        for (size_t i {}; !data->empty(); i++) {
            // std::cout<<+data->front()<<" ";
            
            buffer[index + i] = data->front();
            data->pop_front();
        }

        if constexpr (std::is_same<Device, Client>::value) {
            user_->sendARPRequest(ip);
        }

        // Increased the packet count
        ++count;

        // Increased the counting semaphore
        sema.release();

        // Notify waiting scheduler
        signal.notify_one(); 
        // signal.notify_one(); 
        spdlog::info("NEW ADDED");
    }

    void enqueue(std::deque<uint8_t> *data, uint32_t ip, uint8_t iface) {
        if (is_full() || indexes.empty()) {
            throw std::overflow_error("Queue is full");
        }
        
        // Check for null pointer 
        if (data == nullptr) {
            return;
        }
        // Lock the buffer to add a packet
        std::scoped_lock lock(muxQueue);
        // std::cout<<"Enqueue: "<<data->size()<<std::endl;
        // std::cout<<"\n Sending"<<std::endl;
        // std::cout<<"Size: "<<+data->size()<<"\n";

        // Inserting additional internal packet 
        /*PROTOCOL::internal_hdr internal_hdr(static_cast<uint16_t>(data->size()), iface);

        std::list<uint8_t> temp;
        internal_hdr.serialize(temp);
        data->insert(data->begin(),temp.begin(),temp.end());*/

        size_t index = indexes.back();
        indexes.pop_back();

        hashmap[ip] = std::make_pair(index, 15);
        
        for (size_t i {}; !data->empty(); i++) {
            // std::cout<<+data->front()<<" ";
            
            buffer[index + i] = data->front();
            data->pop_front();
        }

        if constexpr(std::is_same<Device, Router>::value){
            for(auto &iface_: user_->ifaces){
                if(iface_.id == iface){
                    iface_.sendARPRequest(ip, iface);
                }
            }
        }

        // Increased the packet count
        ++count;

        // Increased the counting semaphore
        sema.release();

        // Notify waiting scheduler
        signal.notify_one(); 
        // signal.notify_one(); 
        spdlog::info("NEW ADDED");
    }

    // TICK: Need to test
    void sendPacket(uint32_t ip, const uint8_array_6 &mac, std::optional<uint8_t> iface = std::nullopt){
        //std::cout<<"Sending packet\n";

        if (hashmap.find(ip) == hashmap.end()) return;
        // std::cout<<"I\n";

        size_t index = hashmap.at(ip).first;
        if (is_empty()) {
            throw std::underflow_error("Queue is empty");
        }
        // std::cout<<"II\n";

		std::scoped_lock lock(muxQueue);
        uint16_t length = static_cast<uint16_t>(buffer[index] << 8 | buffer[index+1]);

        // std::vector<uint8_t> packet;
        std::deque<uint8_t> packet;
        // std::cout<<"Size: "<<+length<<"\n";
	    //std::cout<<"ECHO REQUEST!"<<"\n";
        // std::cout<<"II\n";

        // for(auto el : packet){
        //     std::cout<<+el<<" ";
        // }
            


        uint8_array_6 src_mac{};
        if constexpr(std::is_same<Device, Client>::value || std::is_same<Device, Dhcp>::value){
            for (uint16_t i{ PROTOCOL::internal_hdr_size }; i < length- PROTOCOL::internal_hdr_size; i++) {
                //std::cout<<+buffer[index + i]<<" ";
                packet.push_back(buffer[index + i]);
            }

            user_->iface.getMAC(src_mac);
            
            user_->addEthernetHeader(packet, src_mac, mac, PROTOCOL::ethertype_ip);

            user_->addInternalHeader(packet, 0);

            // std::cout<<"Size: "<<+packet.size()<<"\n";
            /* for(auto el:packet){
                 std::cout<<+el<<" ";
             }
            std::cout<<std::endl;*/

            user_->iface.putMessageInOutputIface(&packet);
    
        } else if constexpr(std::is_same<Device, Router>::value) {

            for (uint16_t i{ PROTOCOL::router_internal_hdr_size }; i < length - PROTOCOL::router_internal_hdr_size; i++) {
                //std::cout<<+buffer[index + i]<<" ";
                packet.push_back(buffer[index + i]);
            }
            PROTOCOL::ethertype ethertype{};
            switch ((uint16_t)(((uint16_t)(buffer[index + 9]) << 8) + ((uint16_t)buffer[index + 10]))) {
            case PROTOCOL::ethertype_arp:
                ethertype = PROTOCOL::ethertype_arp;
                break;
            case PROTOCOL::ethertype_ip:
                ethertype = PROTOCOL::ethertype_ip;
                break;
            case PROTOCOL::ethertype_ERROR:
            default:
                ethertype = PROTOCOL::ethertype_ERROR;
                break;
            }

            if (iface.has_value()) {
                for(auto &iface_: user_->ifaces){
                    if(iface.value() == iface_.id){

                        user_->addRouterInternalHeader(packet, iface.value(), mac, ethertype);

                        iface_.putMessageInOutputIface(&packet);
                        break;
                    }
                }
            }
        }

        hashmap.erase(ip);

        indexes.push_back(index);

        --count;
        //spdlog::critical("Decrement Count: {}", +count);
    }

    // Just check if number of packets in buffer is zero
    bool is_empty() const {
		std::scoped_lock lock(muxQueue);
		// Use std::atomic<size_t> for thread-safe atomic access to count
        std::atomic<size_t> current_count(count);
        // Acquire the latest value of count using memory_order_acquire
        return current_count.load(std::memory_order_acquire) == 0;
    }
    
    // Since the number of packets allowed is maximum as the number of
    // segments we can get just if count of packet equal to number of segmetns
    bool is_full() const {
		std::scoped_lock lock(muxQueue);
		// Use std::atomic<size_t> for thread-safe atomic access to count
        std::atomic<size_t> current_count(count);
        // Acquire the latest value of count using memory_order_acquire
        return current_count.load(std::memory_order_acquire) == Size / Max_Pkt_Size;
    }

    // TICK: Need to test
    std::size_t number_of_packets() const {
		  std::scoped_lock lock(muxQueue);
        return count;
    }

    // TICK: Need to test
    // Start the decrementing thread
    void start() {
    time_thread = std::thread([this]() {
        while (!stop_thread) {
            {
                // Decrease the time for each entry
                for (auto &entry : hashmap) {
                    --entry.second.second;
                }
                
                {   // Remove the entry 
                    std::lock_guard<std::mutex> lock(muxQueue);

                    auto i = hashmap.begin();
                    while (i != hashmap.end()) {
                        if (i->second.second <= 0) {
                          indexes.push_back(i->second.first);
                          std::cout << "Removed: " << (i->first) << std::endl;
                          i = hashmap.erase(i);
                        } else {
                            ++i;
                        }
                    }

                } // Release the lock when lock goes out of scope
            }
            
            // Sleep after processing inside the while loop
            std::this_thread::sleep_for(std::chrono::seconds(1));
        }
    });

    time_thread.detach();
}

    ~CircularPtrQueue(){
        stop_thread=true;
    }

    // Key: "Waiting ip" and Value: "Index of packet, Time(default 15sec)"
    std::unordered_map<uint32_t, std::pair<size_t, uint8_t>> hashmap;

private:
    std::unique_ptr<uint8_t[]> buffer;

    Device *user_;
    // Contains indexes which can be used for storing a packet
    // Initialised with indexes in the constructor
    std::vector<size_t> indexes{0};

    size_t count;
    std::counting_semaphore<10> &sema;
    std::condition_variable &signal;

protected:
    bool stop_thread = false;
    std::thread time_thread;

	mutable std::mutex muxQueue;
	std::condition_variable cvBlocking;
	mutable std::mutex muxBlocking;
};

} // END NAMESPACE BUFFER

#endif