#pragma once
#ifndef INTERFACE_H
#define INTERFACE_H
//#include "..\enums.h"
#include "..\enums.h"
#include "..\cpu.h"
#include "..\common.h"
#include "..\logger.h"
#include "..\stopThread.h"
#include "..\deviceWindow.h"


enum iFaceState {
	DESIGNATED,		// Can be used to forward normal traffic
	ROOT,			// Can be used to forward normal traffic
	NON_DESIGNATED	// Cannot be used to forward normal traffic
};

enum iFaceStatus {
	BLOCKING,		// When in NON_DESIGNATED then in BLOCKING. All regular traffic received by this port is dropped. But can still receive BPDU but can't forward BPDU and can't learn mac addresses.
	LISTENING,		// When in DESIGNATED or ROOT then in LISTENING. Go from BLOCKING to LISTENING. All regular traffic received by this port is dropped & can't send regular traffic as well. But can still receive & forward BPDU. Can't learn mac addresses from regular traffic. Default is 15secs and determined by forward delay.
	LEARNING,		// When in DESIGNATED or ROOT then in LEARNING. Go from BLOCKING to LISTENING then to learning. All regular traffic received by this port is dropped & can't send regular traffic as well. But can still receive & forward BPDU. Only difference is it can learn mac addresses from regular traffic. Default is 15secs and determined by forward delay same as LISTENING state.
	FORWARDING,		// When in DESIGNATED or ROOT then in forwarding. Normal operation
	DISABLED		// Port is administratively down no operation can't receive any packets
};

class Iface: public Loggable
{
public:
	Iface(	std::string_view sv, 
			std::shared_ptr<DeviceWindowBase> consoleWindow) 
			: input_count(0), 
			output_count(0), 
			process_input(true), 
			Loggable::Loggable(sv.data()), 
			consoleWindow_(consoleWindow) {

		scheduler = nullptr;
		nic = nullptr;
		count6++;

		// Increasing the MAC assignment so that each interface created has different MAC address
		if (count6 == 255)
		{
			count6 = 0;
			count5++;
			if (count5 == 255)
			{
				count5 = 0;
				count4++;
				if (count4 == 255)
				{
					count4 = 0;
					count3++;
					if (count3 == 255)
					{
						count3 = 0;
						count2++;
						if (count2 == 255)
						{
							count2 = 0;
							count1++;
						}
					}
				}
			}
		}
		uint8_array_6 input_mac = { count1, count2, count3, count4, count5, count6 };

		for (size_t i{}; i < MAC_ADDR_LEN; ++i)
		{
			mac[i] = input_mac[i];
		}

		wait();
	}

	void wait() {
		scheduler = std::make_unique<std::thread>([&]() {
			printMessage(CONSOLE_INFO,"Scheduler Thread called");
			//logger->info("Scheduler Thread called: {}", macToString(mac));
			while (run) { // Never ending loop so thread runs the entire lifetime
				std::unique_lock<std::mutex> lock(mtx);

				printMessage(CONSOLE_INFO, "Locked called");
				// if(!ram.empty()){
				// 	std::cout<<"RAM has item"<<std::endl;
				// }	else {
				// 	std::cout<<"RAM empty"<<std::endl;
				// }

				// Try to see if counting semaphore has a value(meaning a packet was inserted)
				if (input_count.try_acquire()) {
					printMessage(CONSOLE_INFO, "Input acquired");

					//Tells the NIC to process it like an input packet
					process_input.store(true, std::memory_order_release);
					//Copy the packet in ram 
					input_buf->insert_copy_in_ram(ram, cond_var_ram);

					 //Wait till NIC raises an interrupt saying it has performed the checking on packet in RAM 
					cond_var_process.wait(lock);
					 //Drop the packet as NIC the processed the packet
					input_buf->drop_packet();

				}
				else if (output_count.try_acquire()) {
					printMessage(CONSOLE_INFO, "Output acquired");
					// Tells the NIC to process the packet in output_buf like an output packet so just send it along the link
					process_input.store(false, std::memory_order_release);

					output_buf->insert_copy_in_ram(ram, cond_var_ram);
					// for(auto el : ram){
					// 	std::cout<<+el<<" ";
					// }
					// std::cout<<"\n";
					// Wait till CPU raises an interrupt saying it has performed the changes on packet in RAM 
					cond_var_process.wait(lock);
					// Drop the packet as NIC has sent the packet
					output_buf->drop_packet();

				}
				else {
					// Case: No packet in input or output buffer so wait till interrupt raised
					printMessage(CONSOLE_INFO, "Blocked");
					cond_var_buffer.wait(lock);

					printMessage(CONSOLE_INFO, "Unblooock");
				}
				{
					std::unique_lock<std::mutex> lk(cv_m);
					cv.wait(lk, [] { return !paused; });
				}
			}
		});
		scheduler->detach();

		nic = std::make_unique<std::thread>([&]() {
			printMessage(CONSOLE_INFO, "NIC Thread called");
			while (run) { // Never ending loop so thread runs the entire lifetime
				std::unique_lock<std::mutex> lock(mtx);

				if (ram.empty()) {
					printMessage(CONSOLE_INFO, "NIC waiting!");
					// Waiting for a packet to be in RAM
					cond_var_ram.wait(lock);
					printMessage(CONSOLE_INFO, "NIC can run!");
					// TODO: do the processing in the ram
				}
				if (process_input.load(std::memory_order_acquire)) {
					// CRC verification 
					printMessage(CONSOLE_INFO, "Input process!");
					 /*for(auto el: ram){
					 	std::cout<<+el<<" ";
					 }
					 std::cout<<"\n";*/
					if (verify_crc32(ram) != true) {
						// Error in packet so silently drops the packet
						printMessage(CONSOLE_WARN, "CRC Error Packet Dropped!");

						ram.clear();
					}
					else {
						// Now do device specific processing meaning calling virtual processing function
						// For USER only check mac_dst and then send it to CPU
						printMessage(CONSOLE_INFO, "Processing Input");
						processInputPktRam();
						// ram.clear();

						// For Switch check mac_src and update mac_table & check mac_dst and route or flood accordingly

						// For Router check mac_dst(for router or broadcast only then proceed) and make changes to arp table then check ip header and process forward
					}
				}
				else {
					printMessage(CONSOLE_INFO, "Output process");
					// TODO: Made this so that the output packets have the source mac as the interface's mac but need to check this  

					processOutputPktRam();
					/*std::ostringstream out;

					for (auto el: ram) {
						out << +el << " ";
					}
					std::cout << out.str() << std::endl;*/

					if(link!=nullptr) link->input_buf->enqueue(&ram);

					ram.clear();
				}

				// Notifying the scheduler the processing is done on the RAM
				cond_var_process.notify_one();

				{
					std::unique_lock<std::mutex> lk(cv_m);
					cv.wait(lk, [] { return !paused; });
				}
			}

		});
		nic->detach();

	}

	virtual void processInputPktRam() {};

	virtual void processOutputPktRam() {};

	Iface& operator=(Iface&& other) noexcept {
		if (this != &other) {
			if (scheduler && scheduler->joinable()) {
				scheduler->join();
			}
			scheduler = std::move(other.scheduler);
		}
		if (this != &other) {
			if (nic && nic->joinable()) {
				nic->join();
			}
			nic = std::move(other.nic);
		}
		return *this;
	}

	template <typename... Args>
	void printMessage(consoleType level,const std::string& format, Args&&... args) {
		std::lock_guard<std::mutex> lock(consoleMutex);

		std::string message = format_string(format, std::forward<Args>(args)...);

		switch (level) {
		case CONSOLE_TRACE:
			logger->trace("{}", message);
			break;
		case CONSOLE_DEBUG:
			logger->debug("{}", message);
			break;
		case CONSOLE_INFO:
			logger->info("{}", message);
			break;
		case CONSOLE_WARN:
			logger->warn("{}", message);
			break;
		case CONSOLE_ERROR:
			logger->error("{}", message);
			break;
		case CONSOLE_CRITICAL:
			logger->critical("{}", message);
			break;
		}

		//std::string captured_log = get_captured_log();

		consoleWindow_->addData(get_captured_log());
		logger->flush();
	}

	void putMessageInOutputIface(std::deque<uint8_t>* data) {
		output_buf->enqueue(data);
	}

	void BufferPacketCount() {
		printMessage(CONSOLE_INFO, "Input Buf: {}, Output Buf: {}", input_buf->number_of_packets(), output_buf->number_of_packets());
	}

	virtual iFaceState getState() const = 0;
	virtual void setState(iFaceState st) = 0;

	virtual void getMAC(uint8_array_6& arr) const {
		for (size_t i = 0; i < MAC_ADDR_LEN; i++) {
			arr[i] = mac[i];
		}
	}

	~Iface() {
		run = false;
	}

	// Getter methods 
	virtual uint32_t getIPV4()		  const { return 0; }
	virtual uint32_t getSUBNET_MASK() const { return 0; }
	virtual uint32_t getGATEWAY()	  const { return 0; }
	virtual uint32_t getDNS()		  const { return 0; }

	// Setter methods 
	virtual void setIPV4(uint32_t ip) { }
	virtual void setSUBNET_MASK(uint32_t mask) { }
	virtual void setGATEWAY(uint32_t default_gateway) { }
	virtual void setDNS(uint32_t dns) { }


	/* == For Mac Address == */

	static uint8_t count1;
	static uint8_t count2;
	static uint8_t count3;
	static uint8_t count4;
	static uint8_t count5;
	static uint8_t count6;

	uint8_array_6  mac;

	/* ====================== */

	/* == For Thread Communication == */

	// The scheduler tells the nic according to this whether to process the packet as a input(true) or output(false) packet
	std::atomic<bool> process_input;

	// Interrupts to notify scheduler
	// Used in the ram to notify the scheduler that a packet has been processed by the nic
	std::condition_variable cond_var_process;

	/* ====================== */

	/* == For Scheduler Thread == */

	mutable std::mutex mtx;

	std::unique_ptr<std::thread> scheduler;

	/* ====================== */

	/* == For Nic Thread == */

	mutable std::mutex mtx2;

	std::unique_ptr<std::thread> nic;

	/* ====================== */

	/* ====== For Ram ====== */

	// Interrupt to notify nic
	// Used in the ram to notify the nic that a packet has been inserted in ram for processing by scheduler
	std::condition_variable cond_var_ram;

	std::vector<uint8_t> ram;

	/* ====================== */

	/* == For Interface == */

	bool layer2_up = true;
	bool layer3_up = true;

	uint16_t mtu{ 1500 };
	Iface* link{nullptr};

	// Whenever packet is enqueued the semaphore is increased
	std::counting_semaphore<10> input_count;
	std::counting_semaphore<10> output_count;

	// Interrupt to notify scheduler
	// Used in the buffers to notify the scheduler that a packet has been inserted in any of the input/output buffer
	std::condition_variable cond_var_buffer;

	// The input & output buffers
	/*Buffer::CircularQueue<4096, 512> input_buf{ cond_var_buffer, input_count };
	Buffer::CircularQueue<4096, 512> output_buf{ cond_var_buffer, output_count };*/
	std::unique_ptr<Buffer::CircularQueue<4096, 512>> input_buf = std::make_unique<Buffer::CircularQueue<4096, 512>>(cond_var_buffer, input_count);
	std::unique_ptr<Buffer::CircularQueue<4096, 512>> output_buf = std::make_unique<Buffer::CircularQueue<4096, 512>>(cond_var_buffer, output_count);

	/* ====================== */

	// Used in destructor to stop all threads 
	bool run = true;
	std::mutex consoleMutex;
	std::shared_ptr<DeviceWindowBase> consoleWindow_;

protected:
	std::mutex muxQueue;
	std::condition_variable cvBlocking;
	std::mutex muxBlocking;
};

#endif

