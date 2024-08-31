#pragma once
#ifndef SWITCHIFACE_H
#define SWITCHIFACE_H
#include "interface.h"

template <typename QueueType>
class SwitchIface : public Iface {
public:
    SwitchIface(uint8_t id,
                std::atomic<bool> &flag,
                std::condition_variable &cond_var_copy,
                std::shared_ptr<QueueType> queue,
                std::shared_ptr<MacTable> table,
                std::string_view sv,
                std::shared_ptr<DeviceWindowBase> consoleWindow,
                pcapWriter *pcapFile
        )
            : id(id), 
                flag_(flag), 
                signal(cond_var_copy), 
                memory_(queue), 
                mac_table_(table), 
                Iface(sv.data(),consoleWindow),
                pcapFile_(pcapFile)
    {
        start();
    }

    void processInputPktRam(){
		std::unique_lock<std::mutex> lock(mtx);

        // TODO: Deserialize the pkt ethernet header
        size_t offset{};
        PROTOCOL::internal_hdr internal_hdr(ram,offset);
        // internal_hdr.display();

        /*std::ostringstream out;

        for (auto el : ram) {
            out << +el << " ";
        }
        std::cout << out.str() << std::endl;*/

        pcapFile_->write(ram, PROTOCOL::internal_hdr_size);

        PROTOCOL::ethernet_hdr ethernet_hdr(ram,offset);
        //ethernet_hdr.display();
    
        // Checking whether the destination mac is broadcast
        bool for_broadcast = check_uint8_array_6(ethernet_hdr.ether_dhost, PROTOCOL::BroadcastEtherAddr);

        bool for_control_plane = check_uint8_array_6(ethernet_hdr.ether_dhost, PROTOCOL::MulticastSTPEtherAddr);

        // The packet is not for control plane so not a BPDU so check the state of the port whether it can receive the normal traffic
        if (for_control_plane == false) { 
            if (state == NON_DESIGNATED || status == BLOCKING || status == LISTENING) {
                // The port can't receive normal traffic so drop packet
                ram.clear();
                return;
            }

        // if (!flag_.load(std::memory_order_acquire)) {
        //   flag_.store(true, std::memory_order_release);
        // }
        
            // Normal traffic not meant for control plane so we can learn mac address of it
            mac_table_->checkMacTable(ethernet_hdr.ether_shost,id);

            // The packet is not for control plane so not a BPDU and we checked whether it could receive normal traffic now checking whether it is in learning state as in learning state the mac address table can be used to learn ports and fill the mac address table
            if (state == LEARNING) {
                // The port can't receive normal traffic so drop packet
                ram.clear();
                return;
            }
        
        }


        if(for_broadcast) { 
            //Since broadcast so change the output port of internal header as not(~) of the id so the fabric won't put the packet again in this interface
            ram[2] = (uint8_t)~id;
            //logger->info("Broadcast Port: {}", (uint8_t)~id);
            //logger->info("Broadcast Port: {}", (uint8_t)~~id);
        }
        else if (for_control_plane) {
            // Since for control plane we add 100 and the port id so we can deduce the input port and fabric knows the packet is for control plane
            ram[2] = 100+id;
        }
        else {
            uint8_t port = mac_table_->getInterface(ethernet_hdr.ether_dhost);
            printMessage(CONSOLE_INFO, "Port: {}", port);
            //Couldn't find the destination mac in mac table so broadcast the packet
            if(port==0) { ram[2]= (uint8_t)~id; }
            //If found port in mac table then change the output port to port 
            else {
                ram[2]= port;
            }
        }

        printMessage(CONSOLE_INFO, "Switch Fabric memory");
        // Enqueue the packet with the output port specified in the switch memory from which the switch fabric will put it in the output interface
        memory_->enqueue(&ram);

        signal.notify_one();

        ram.clear();
    }

    iFaceState getState() const override{ return state; }
    void setState(iFaceState st) override { state = st; }

    void processOutputPktRam() {}

    void start() {
        time_thread = std::thread([this]() {
            while (!stop_thread) {
                // Check the time against expire time
                {
                    std::lock_guard<std::mutex> lock(muxTime);
                    // Checking whether in LISTENING or LEARNING and decrementing forward delay and if it becomes zero means the state can be changed to upper  state
                    if (status == LISTENING || status == LEARNING) {

                        forward_delay--;

                        if (forward_delay == 0) {
                            forward_delay = set_forward_delay_to;
                            if (status == LISTENING) status = LEARNING;
                            else if (status == LEARNING) {
                                status = FORWARDING;
                            }
                        }

                    }else forward_delay = set_forward_delay_to;

                } // Release the lock when lock goes out of scope

                  // Sleep after processing for 1 second
                std::this_thread::sleep_for(std::chrono::seconds(1));

                {
                    std::unique_lock<std::mutex> lk(cv_m);
                    cv.wait(lk, [] { return !paused; });
                }
            }
            });

        time_thread.detach();
    };

    void printStateStatus() {
        switch (status) {
        case BLOCKING: {

            switch (state) {
            case NON_DESIGNATED:
                printMessage(CONSOLE_INFO, "State: NON_DESIGNATED, Status: BLOCKING");
                return;
            default:
                printMessage(CONSOLE_WARN, "WRONG STATE AND STATUS");
                return;
            }
            return;
        }
        case LISTENING: {

            switch (state) {
            case DESIGNATED:
                printMessage(CONSOLE_INFO, "State: DESIGNATED, Status: LISTENING");
                logger->info("State: DESIGNATED, Status: LISTENING");
                return;
            case ROOT:
                printMessage(CONSOLE_INFO, "State: ROOT, Status: LISTENING");
                return;
            default:
                printMessage(CONSOLE_WARN, "WRONG STATE AND STATUS");
                return;
            }
            return;
        }
        case LEARNING: {

            switch (state) {
            case DESIGNATED:
                printMessage(CONSOLE_INFO, "State: DESIGNATED, Status: LEARNING");
                return;
            case ROOT:
                printMessage(CONSOLE_INFO, "State: ROOT, Status: LEARNING");
                return;
            default:
                printMessage(CONSOLE_WARN, "WRONG STATE AND STATUS");
                return;
            }
            return;
        }
        case FORWARDING: {

            switch (state) {
            case DESIGNATED:
                printMessage(CONSOLE_INFO, "State: DESIGNATED, Status: FORWARDING");
                return;
            case ROOT:
                printMessage(CONSOLE_INFO, "State: ROOT, Status: FORWARDING");
                return;
            default:
                printMessage(CONSOLE_WARN, "WRONG STATE AND STATUS");
                return;
            }
            return;
        }
        }
    }

    ~SwitchIface() { stop_thread = true; }

    uint8_t id;
    //  Buffer::CircularQueue<8192, 512>* memory_;
    std::shared_ptr<QueueType> memory_;
    std::shared_ptr<MacTable> mac_table_;
  
    std::atomic<bool> &flag_;    
    std::condition_variable &signal;
	mutable std::mutex mtx;

	std::shared_ptr<MacTable> shared_mac_table = std::make_shared<MacTable>();

    /* ==== For STP ==== */

    bool stop_thread = false;
    std::thread time_thread;
    std::mutex muxTime;

    uint16_t set_forward_delay_to = 15; // DEFAULT: 15
    uint16_t forward_delay = set_forward_delay_to;


    iFaceState state = DESIGNATED;

    iFaceStatus status = LISTENING;

    pcapWriter* pcapFile_ = nullptr;

    /* ====================== */

    void setForwardDelayIface(uint16_t number) {
        set_forward_delay_to = number;
    }
};

#endif