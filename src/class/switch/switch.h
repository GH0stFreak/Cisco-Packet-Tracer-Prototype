#pragma once
#ifndef SWITCH_H
#define SWITCH_H

#include "..\common.h"
#include "..\macTable\macTable.h"
#include "..\interface\switchIface.h"
#include "..\layer2\layer2.h"
#include "..\stopThread.h"
//#include "..\deviceWindow.h"
#include "..\pcapWriter.h"


//class Layer2;
template<class Device>
class DeviceWindow;

class Switch : public Layer2, public Loggable
{
public:
Switch() : count(0), control_plane_count(0), Loggable::Loggable("Switch "+ std::to_string(++counter)), hostname("Switch " + std::to_string(counter)), pcapFile("Switch" + std::to_string(counter)) {
	{
		// Initializing the variables here seems to work when we just initalized it outside the my_id was not being incorrectly
		priority = 0x8000;
		root_cost = 0;
		my_id = (static_cast<uint64_t>(priority + 1) << 48) | uint8_array_6ToUint64(ifaces[0].mac);
		root_id = my_id;
		bridge_id = root_id;
		port_id = priority;

		start();

		switchFabric = nullptr;
		controlPlane = nullptr;

		switchFabric = std::make_unique<std::thread>([&]() {
			printMessage(CONSOLE_INFO, "Switch Fabric Thread called");
			// Never ending loop so thread runs the entire lifetime
			while (true) {
				std::unique_lock<std::mutex> lock(fabric_mtx);

				// Checks the queue if empty wait for a packet to be inserted
				if (shared_memory->is_empty() == true) {
					printMessage(CONSOLE_INFO, "Switch Fabric waiting!");

					// Waiting for a packet to be in Memory
					cond_var_memory.wait(lock);
					printMessage(CONSOLE_INFO, "Switch Fabric unblock!");
				}

				if (count.try_acquire()) {

					// Get the packet from memory
					std::vector<uint8_t> packet;
					shared_memory->dequeue(&packet);

					// Get output port of packet
					uint8_t output_port = packet[2];

					
					/*if (output_port > 100 && output_port < (100 + id)) {
						logger->info("For Control Plane!");
					}
					else if (output_port > 15) {
						logger->info("BROADCAST!");
					}
					else {
						logger->info("UNICAST!");
					}
					logger->info("Switch Iface: {}", (uint8_t)output_port);
					logger->info("Switch Iface: {}", (uint8_t)~output_port);*/
					

					// Checking the output port value against the id of interface
					// If output interface > 100 and less then 100+no. of interfaces the packet is for control plane
					// If output interface <= 15 means there is a specific port
					// If output interface > 15 means it is broadcast and to only send to whose id is not equal to ~output_port as ~ of a port is meant to symbolise a broadcast packet received on this port
					// 100 < control plane packet <100+id means the packet is meant for the control plane
					if (output_port > 100 && output_port < (100+id)) {
						control_plane_memory->enqueue(&packet);
					}
					else {
						// Placing packet in accordingly in output buffers of repective interfaces
						for (auto& iface : ifaces) {
							if (iface.link == nullptr) continue;
							if (output_port > 15 && (uint8_t)(~output_port) != iface.id) {
								//logger->info("Placed Iface: {}", +iface.id);

								iface.output_buf->enqueue(&packet);
							}
							else if (output_port <= 15 && output_port == iface.id) {
								iface.output_buf->enqueue(&packet);
								break;
							}
						}
					}
				}
				{
					std::unique_lock<std::mutex> lk(cv_m);
					cv.wait(lk, [] { return !paused; });
				}

			}
			});

		switchFabric->detach();

		controlPlane = std::make_unique<std::thread>([&]() {
			printMessage(CONSOLE_INFO, "Switch Control Plane Thread called");
			// Never ending loop so thread runs the entire lifetime
			sendBPDUHello();
			while (true) {
				std::unique_lock<std::mutex> lock(fabric_mtx);
				//std::unique_lock<std::mutex> lock(control_plane_mtx);

				// Checks the queue if empty wait for a packet to be inserted
				if (control_plane_memory->is_empty() == true) {
					printMessage(CONSOLE_INFO, "Switch Control Plane waiting!");

					// Waiting for a packet to be in Memory
					cond_var_control_plane_memory.wait(lock);
					printMessage(CONSOLE_INFO, "Switch Control Plane unblock!");
				}

				if (control_plane_count.try_acquire()) {

					// Get the packet from memory
					std::vector<uint8_t> packet;
					control_plane_memory->dequeue(&packet);

					// Get input port of packet
					uint8_t input_port = packet[2];

					if (input_port < 100) {
						printMessage(CONSOLE_ERROR, "Packet Not for Control plane!");
					}
					else {
						// After subtracting 100 we get the input port of the packet 
						input_port -= 100;
						// Now processing packet
						processPacket(packet, input_port);
					}
					//logger->info("Switch Iface: {}", +input_port);

				}
				{
					std::unique_lock<std::mutex> lk(cv_m);
					cv.wait(lk, [] { return !paused; });
				}

			}
			});

		controlPlane->detach();
	}

  }
	
	void processPacket(std::vector<uint8_t>& packet, uint8_t input_port) {
		if (packet.empty())return;

		PROTOCOL::internal_hdr internal_hdr(packet);

		PROTOCOL::ethernet_hdr ethernet_hdr(packet);

		PROTOCOL::ethernet_trailer ethernet_trailer(packet);

		uint16_t length = ethernet_hdr.ether_type;

		PROTOCOL::ethertype ether_type = processEthernetHeader(this, ethernet_hdr);

		switch (ether_type)
		{
		case PROTOCOL::ethertype_llc: {
			PROTOCOL::llc_hdr llc_hdr(packet, length);

			PROTOCOL::llc_sap sap = processLlcHeader(this, llc_hdr);

			switch (sap) {
			case PROTOCOL::llc_sap_stp: {
				PROTOCOL::bpdu_hdr bpdu_hdr(packet, length);

				PROTOCOL::action next_action_bpdu = processBpduHeader(this, bpdu_hdr);

				switch (next_action_bpdu) {
				case PROTOCOL::RECEIVE_BPDU_CONFIGURATION: {
					processBpduConfiguration(this, bpdu_hdr, input_port);

					if (root_bridge == false) {
						forwardBpdu(input_port, bpdu_hdr.bpdu_message_age);
						// Reset max age as we received a BPDU from the root
						max_age = 20;
						
					}
					//printIfaceStateStatus();
					return;
				}
				case PROTOCOL::RECEIVE_BPDU_TOPOLOGY_CHANGE: {
					// TODO: Need to make a function to process topology BPDU
					return;
				}
				default:
					return;
				}
				return;
			}
			case PROTOCOL::llc_sap_ERROR: {
				printMessage(CONSOLE_WARN, "Error Dropped");
				return;
			}
			default: {
				printMessage(CONSOLE_WARN, "Dropped");
				return;
			}
			}
			return;
		}
		case PROTOCOL::ethertype_ERROR:
		default:
			printMessage(CONSOLE_WARN, "Error Not for Control Plane");
			return;
		}
	}

	void sendBPDUHello() {

		//uint8_array_6 root_mac = {};
		//ifaces[0].getMAC(root_mac);

		//uint64_t mac48 = uint8_array_6ToUint64(root_mac);

		//uint64_t root_id = static_cast<uint64_t>(priority) << 32 | mac48;
		for (auto &iface : ifaces) {
			if (iface.link == nullptr) continue;
			std::deque<uint8_t> packet;

			uint8_array_6 src_mac = {};
			iface.getMAC(src_mac);

			addBPDUHeader(packet, 0, 0, PROTOCOL::bpdu_configuration, 0, root_id, 0, my_id,(priority+iface.id),0);

			addLLCHeader(packet, PROTOCOL::llc_sap_stp, PROTOCOL::llc_sap_stp, PROTOCOL::llc_control_unnumbered);

			addEthernetHeader(packet,src_mac,PROTOCOL::MulticastSTPEtherAddr,0);

			addInternalHeader(packet, iface.id);

			//logger->info("Switch(BHCP Hello) Sent: {}", packet.size());

			shared_memory->enqueue(&packet);
		}
	}

	void forwardBpdu(uint8_t input_port, uint16_t message_age){
		for (auto& iface : ifaces) {
			if (iface.id == input_port || iface.link == nullptr) continue;

			std::deque<uint8_t> packet;

			uint8_array_6 src_mac = {};
			iface.getMAC(src_mac);

			addBPDUHeader(packet, 0, 0, PROTOCOL::bpdu_configuration, 0, root_id, root_cost, my_id, (priority+iface.id), message_age+1);

			addLLCHeader(packet, PROTOCOL::llc_sap_stp, PROTOCOL::llc_sap_stp, PROTOCOL::llc_control_unnumbered);

			addEthernetHeader(packet, src_mac, PROTOCOL::MulticastSTPEtherAddr, 0);

			addInternalHeader(packet, iface.id);

			printMessage(CONSOLE_INFO, "Switch(BHCP Forward) Sent: {}", packet.size());

			shared_memory->enqueue(&packet);
		}
	}

	inline void ShowPacketCount() {
		for (auto& iface : ifaces) {
			iface.BufferPacketCount();
		}
		std::cout <<"================================" << std::endl;
	}
	
	inline void printIfaceStateStatus() {
		for (auto& iface : ifaces) {
			if(iface.link != nullptr)
			iface.printStateStatus();
		}
	}

	// TODO: Make the change and correct it to standard protocol rules
	void processBpduConfiguration(Switch* sw, PROTOCOL::bpdu_hdr& bpdu_hdr, uint16_t input_port) {
		/*if (bpdu_hdr.bpdu_r_id < sw->root_id) {
			
			if (sw->root_bridge == true) {
				sw->root_bridge = false;
				for (auto& iface : sw->ifaces) {
					iface.state = NON_DESIGNATED;
					iface.status = BLOCKING;
				}
			}

			sw->root_id = bpdu_hdr.bpdu_r_id;
			sw->root_cost = bpdu_hdr.bpdu_r_cost + 4;
			sw->bridge_id = bpdu_hdr.bpdu_b_id;
			sw->port_id = bpdu_hdr.bpdu_port_id;
			for (auto& iface : sw->ifaces) {
				if (input_port != iface.id) {
					iface.state = NON_DESIGNATED;
				}
				else if (input_port == iface.id) {
					iface.state = ROOT;
					if (iface.status == BLOCKING) iface.status = LEARNING;
				}
				else if (iface.link->getState() == NON_DESIGNATED && iface.state == NON_DESIGNATED) {
					// This is wrong according to standard STP but to make it easier have done this 
					// otherwise the switch interface whose switch has the lowest root cost that side of interface should become DESIGNATED
					// if cost is same then the switch interface whose switch has the lowest bridge id that side of interface should become DESIGNATED
					iface.state = DESIGNATED;
				}
			}
			
			for (auto& iface : sw->ifaces) {
				if (input_port == iface.id) {
					if (iface.link->getState() == ROOT) iface.link->setState(DESIGNATED);
					
					iface.state = ROOT;

					if (iface.status == BLOCKING) iface.status = LEARNING;
				}
				else if (iface.link->getState() == NON_DESIGNATED && iface.state == NON_DESIGNATED) {
					// This is wrong according to standard STP but to make it easier have done this 
					// otherwise the switch interface whose switch has the lowest root cost that side of interface should become DESIGNATED
					// if cost is same then the switch interface whose switch has the lowest bridge id that side of interface should become DESIGNATED
					iface.state = DESIGNATED;
					if (iface.status == BLOCKING) iface.status = LEARNING;
				}
			}
		}
		else if (bpdu_hdr.bpdu_r_id == sw->root_id) {
			if ((bpdu_hdr.bpdu_r_cost + 4) < sw->root_cost) {
				sw->root_cost = bpdu_hdr.bpdu_r_cost + 4;
				sw->bridge_id = bpdu_hdr.bpdu_b_id;
				sw->port_id = bpdu_hdr.bpdu_port_id;
				for (auto& iface : sw->ifaces) {
					if (input_port == iface.id) {
						if (iface.link->getState() == ROOT) iface.link->setState(DESIGNATED);

						iface.state = ROOT;

						if (iface.status == BLOCKING) iface.status = LEARNING;
					}
					else if (iface.link->getState() == NON_DESIGNATED && iface.state == NON_DESIGNATED) {
						// This is wrong according to standard STP but to make it easier have done this 
						// otherwise the switch interface whose switch has the lowest root cost that side of interface should become DESIGNATED
						// if cost is same then the switch interface whose switch has the lowest bridge id that side of interface should become DESIGNATED
						iface.state = DESIGNATED;
						if (iface.status == BLOCKING) iface.status = LEARNING;
					}
				}
			}
			else if ((bpdu_hdr.bpdu_r_cost + 4) == sw->root_cost) {
				if (bpdu_hdr.bpdu_b_id < sw->bridge_id) {
					sw->bridge_id = bpdu_hdr.bpdu_b_id;
					sw->port_id = bpdu_hdr.bpdu_port_id;
					for (auto& iface : sw->ifaces) {
						if (input_port == iface.id) {
							if (iface.link->getState() == ROOT) iface.link->setState(DESIGNATED);

							iface.state = ROOT;

							if (iface.status == BLOCKING) iface.status = LEARNING;
						}
						else if (iface.link->getState() == NON_DESIGNATED && iface.state == NON_DESIGNATED) {
							// This is wrong according to standard STP but to make it easier have done this 
							// otherwise the switch interface whose switch has the lowest root cost that side of interface should become DESIGNATED
							// if cost is same then the switch interface whose switch has the lowest bridge id that side of interface should become DESIGNATED
							iface.state = DESIGNATED;
							if (iface.status == BLOCKING) iface.status = LEARNING;
						}
					}
				}
				else if (bpdu_hdr.bpdu_b_id == sw->bridge_id) {
					if (bpdu_hdr.bpdu_port_id < sw->port_id) {
						sw->port_id = bpdu_hdr.bpdu_port_id;
						for (auto& iface : sw->ifaces) {
							if (input_port == iface.id) {
								if (iface.link->getState() == ROOT) iface.link->setState(DESIGNATED);

								iface.state = ROOT;

								if (iface.status == BLOCKING) iface.status = LEARNING;
							}
							else if (iface.link->getState() == NON_DESIGNATED && iface.state == NON_DESIGNATED) {
								// This is wrong according to standard STP but to make it easier have done this
								// otherwise the switch interface whose switch has the lowest root cost that side of interface should become DESIGNATED
								// if cost is same then the switch interface whose switch has the lowest bridge id that side of interface should become DESIGNATED
								iface.state = DESIGNATED;
								if (iface.status == BLOCKING) iface.status = LEARNING;
							}
						}
					}
				}
			}
		}
		return PROTOCOL::PACKET_ERROR;
		*/
		// If switch is root bridge
		if (sw->root_bridge == true) {
			// If the root bridge & Getting Superior BPDU
			if (bpdu_hdr.bpdu_r_id < sw->root_id) {
				//logger->info("If the root bridge & Getting Superior BPDU");
				sw->root_bridge = false;
				for (auto& iface : sw->ifaces) {
					if (input_port == iface.id) {
						iface.state = ROOT;

						if (iface.status == BLOCKING) iface.status = LISTENING;
					}
				}
				sw->root_id = bpdu_hdr.bpdu_r_id;
				sw->root_cost = bpdu_hdr.bpdu_r_cost + 4;
				sw->bridge_id = bpdu_hdr.bpdu_b_id;
				sw->port_id = bpdu_hdr.bpdu_port_id;

			} 
			// If the root bridge & Getting Inferior BPDU do nothing
			
		} // If switch is not root bridge
		else { // If not the root bridge & Getting Superior BPDU
			if (bpdu_hdr.bpdu_r_id < sw->root_id) {
				//logger->info("If not the root bridge & Getting Superior BPDU");
				for (auto& iface : sw->ifaces) {
					if (input_port == iface.id) {
						iface.state = ROOT;
					}
					else {
						iface.state = DESIGNATED;
					}
					if (iface.status == BLOCKING) iface.status = LISTENING;
				}
				// This is when the root bridge is not selected so whenever this occurs need to reset all state and make input port as ROOT and other ports as DESIGNATED 
				sw->root_id = bpdu_hdr.bpdu_r_id;
				sw->root_cost = bpdu_hdr.bpdu_r_cost + 4;
				sw->bridge_id = bpdu_hdr.bpdu_b_id;
				sw->port_id = bpdu_hdr.bpdu_port_id;

			} // If not the root bridge & Getting Inferior BPDU
			else if (bpdu_hdr.bpdu_r_id > sw->root_id) {
				//logger->info("If not the root bridge & Getting Inferior BPDU");
				for (auto& iface : sw->ifaces) {
					if (input_port == iface.id) {
						iface.state = DESIGNATED;

						if (iface.status == BLOCKING) iface.status = LISTENING;
					}
				}

			} // If not the root bridge & Getting the same root bridge
			else if (bpdu_hdr.bpdu_r_id == sw->root_id) {
				// If not the root bridge, Getting the same root bridge & Root cost is lesser
				if ((bpdu_hdr.bpdu_r_cost + 4) < sw->root_cost) {
					//logger->info("If not the root bridge, Getting the same root bridge & Root cost is lesser");
					for (auto& iface : sw->ifaces) {
						if (input_port == iface.id) {
							iface.state = ROOT;
							if (iface.status == BLOCKING) iface.status = LISTENING;
						}
						else if (iface.state == ROOT) {
							if ((bpdu_hdr.bpdu_r_cost + 8) > sw->root_cost){
								iface.state = NON_DESIGNATED;
								iface.status = BLOCKING;
							}
							else {
								iface.state = DESIGNATED;
								if (iface.status == BLOCKING) iface.status = LISTENING;
							}
						}
						else {
							iface.state = DESIGNATED;
							if (iface.status == BLOCKING) iface.status = LISTENING;
						}
					}
					// This is probably the condition when the election is completed and ports are going all states and status
					sw->root_cost = bpdu_hdr.bpdu_r_cost + 4;
					sw->bridge_id = bpdu_hdr.bpdu_b_id;
					sw->port_id = bpdu_hdr.bpdu_port_id;

				} // If not the root bridge, Getting the same root bridge & Root cost is greater
				else if ((bpdu_hdr.bpdu_r_cost + 4) > sw->root_cost) {
					//logger->info("If not the root bridge, Getting the same root bridge & Root cost is greater");
					for (auto& iface : sw->ifaces) {
						if (input_port == iface.id) {
							iface.state = DESIGNATED;
							if (iface.status == BLOCKING) iface.status = LISTENING;
							if (bpdu_hdr.bpdu_b_id < sw->my_id) {
								printMessage(CONSOLE_INFO, "Packet root: {}, Switch root: {}", uint64ToHexString(bpdu_hdr.bpdu_b_id), uint64ToHexString(sw->my_id));
								iface.state = NON_DESIGNATED;
								iface.status = BLOCKING;
							}
						}
					}
				} // If not the root bridge, Getting the same root bridge & Root cost is equal
				else if ((bpdu_hdr.bpdu_r_cost + 4) == sw->root_cost) {
					// If not the root bridge, Getting the same root bridge, Root cost is equal & Lesser bridge id
					if (bpdu_hdr.bpdu_b_id < sw->bridge_id) {
						//logger->info("If not the root bridge, Getting the same root bridge, Root cost is equal & Lesser bridge id");
						for (auto& iface : sw->ifaces) {
							if (input_port == iface.id) {
								iface.state = ROOT;
								if (iface.status == BLOCKING) iface.status = LISTENING;
							}
							else if (iface.state == ROOT) {
								iface.state = NON_DESIGNATED;
								iface.status = BLOCKING;
							}
							else {
								iface.state = DESIGNATED;
								if (iface.status == BLOCKING) iface.status = LISTENING;
							}
						}
						sw->bridge_id = bpdu_hdr.bpdu_b_id;
						sw->port_id = bpdu_hdr.bpdu_port_id;

					} // If not the root bridge, Getting the same root bridge, Root cost is equal & Greater bridge id
					else if (bpdu_hdr.bpdu_b_id > sw->bridge_id) {
						//logger->info("If not the root bridge, Getting the same root bridge, Root cost is equal & Greater bridge id");
						for (auto& iface : sw->ifaces) {
							if (input_port == iface.id) {
								iface.state = NON_DESIGNATED;
								iface.status = BLOCKING;
							}
						}

					} // If not the root bridge, Getting the same root bridge, Root cost is equal & Equal bridge id
					else if (bpdu_hdr.bpdu_b_id == sw->bridge_id) {
						if (bpdu_hdr.bpdu_port_id < sw->port_id) {
							//logger->info("If not the root bridge, Getting the same root bridge, Root cost is equal & Equal bridge id");
							for (auto& iface : sw->ifaces) {
								if (input_port == iface.id) {
									iface.state = ROOT;
									if (iface.status == BLOCKING) iface.status = LISTENING;
								}
								else if (iface.state == ROOT) {
									iface.state = NON_DESIGNATED;
									iface.status = BLOCKING;
								}
								else {
									iface.state = DESIGNATED;
									if (iface.status == BLOCKING) iface.status = LISTENING;
								}
							}

							sw->port_id = bpdu_hdr.bpdu_port_id;
						}
						else if (bpdu_hdr.bpdu_port_id > sw->port_id) {
							//logger->info("If not the root bridge, Getting the same root bridge, Root cost is equal & Equal bridge id");
							for (auto& iface : sw->ifaces) {
								if (input_port == iface.id) {
									iface.state = NON_DESIGNATED;
									iface.status = BLOCKING;
								}
							}
						}
					}
				}
			}
		}
	}

	template <typename... Args>
	void printMessage(consoleType level, const std::string& format, Args&&... args) {
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

		wndClass->addData(get_captured_log());
		logger->flush();
	}

	void setHostname(std::string host_str) {
		hostname = host_str;
	}

	void setHelloTimer(uint16_t number) {
		set_hello_time_to = number;
	}

	void setForwardDelay(uint16_t number){
		for(auto &iface : ifaces){
			iface.setForwardDelayIface(number);
		}
	}

	void setMaxAge(uint16_t number) {
		set_max_age_to = number;
	}

	void start() {
		if (STP_BOOL == 0) {
			return;
		}
		else {
			time_thread = std::thread([this]() {
			
			while (!stop_thread) {
				// Check the time against expire time
				{
					std::lock_guard<std::mutex> lock(muxTime);
					// Root Switch so we countdown hello timer and send BPDU Hello
					if (root_bridge == true) {
						hello_time--;
						if (hello_time == 0) {
							hello_time = set_hello_time_to;
							sendBPDUHello();
						}
					}
					else { // Not root switch so we countdown max age and when is becomes 0 we make the switch back to default and consider itself as root bridge and send BPDU Hello
						// It becomes 0 when it doesn't receive BPDU packets from root
						max_age--;
						if (max_age == 0) {
							hello_time = set_hello_time_to;
							max_age = set_max_age_to;
							root_bridge = true;
							for (auto &iface : ifaces) {
								iface.state = DESIGNATED;
								iface.status = LISTENING;
								sendBPDUHello();
							}
						}
					}

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
		}
	};

	

	~Switch(){ stop_thread = true; }
	
	static uint8_t counter;

	std::string hostname;


	pcapWriter pcapFile;

// private: 
  // std::atomic<int> seconds;

	/* == For Device Control Window == */

	std::mutex consoleMutex;

	std::shared_ptr<DeviceWindow<Switch>> wndClass = std::make_shared<DeviceWindow<Switch>>(this, 2, switchWindowClass, SWITCH_CLASS_NAME);

	/* ====================== */
	
	/* == For Switch Fabric == */

	mutable std::mutex fabric_mtx;
	std::counting_semaphore<10> count;
	std::condition_variable cond_var_memory;

	std::shared_ptr<Buffer::CircularQueue<8192, 512>> shared_memory = std::make_shared<Buffer::CircularQueue<8192, 512>>(cond_var_memory, count);

	std::unique_ptr<std::thread> switchFabric;

	/* ====================== */

	/* == For Control Plane == */

	mutable std::mutex control_plane_mtx;
	std::counting_semaphore<10> control_plane_count;
	std::condition_variable cond_var_control_plane_memory;

	std::shared_ptr<Buffer::CircularQueue<8192, 512>> control_plane_memory = std::make_shared<Buffer::CircularQueue<8192, 512>>(cond_var_control_plane_memory, control_plane_count);

	std::unique_ptr<std::thread> controlPlane;
	

	/* ====================== */

	/* ==== For Mac Table ==== */

	std::shared_ptr<MacTable> shared_mac_table = std::make_shared<MacTable>();

	/* ====================== */

	/* ==== For STP ==== */

	bool root_bridge = true;
	uint16_t priority = 0x8000;
	uint32_t root_cost{ 0 };
	uint64_t my_id = (static_cast<uint64_t>(priority+1) << 48) | uint8_array_6ToUint64(ifaces[0].mac);
	uint64_t root_id = my_id;
	uint64_t bridge_id = root_id;
	uint16_t port_id = priority + id;

	// STP Timers

	uint16_t set_max_age_to = 20; // DEFAULT: 20
	uint16_t max_age = set_max_age_to;
	uint16_t set_hello_time_to = 2; // DEFAULT: 2
	uint16_t hello_time = 2;

	bool stop_thread = false;
	std::thread time_thread;
	std::mutex muxTime;

	/* ====================== */

	/* == For Switch Interfaces == */

	uint8_t id = 0;

	std::atomic<bool> flag;

	std::condition_variable cond_var_copy;

	SwitchIface<Buffer::CircularQueue<8192, 512>> ifaces[4] {
		SwitchIface<Buffer::CircularQueue<8192, 512>> {++id, flag, cond_var_copy, shared_memory, shared_mac_table, "Switch " + std::to_string(counter) + " Iface " + std::to_string(id),wndClass,&pcapFile},
		SwitchIface<Buffer::CircularQueue<8192, 512>> {++id, flag, cond_var_copy, shared_memory, shared_mac_table, "Switch " + std::to_string(counter) + " Iface " + std::to_string(id),wndClass,&pcapFile},
		SwitchIface<Buffer::CircularQueue<8192, 512>> {++id, flag, cond_var_copy, shared_memory, shared_mac_table, "Switch " + std::to_string(counter) + " Iface " + std::to_string(id),wndClass,&pcapFile},
		SwitchIface<Buffer::CircularQueue<8192, 512>> {++id, flag, cond_var_copy, shared_memory, shared_mac_table, "Switch " + std::to_string(counter) + " Iface " + std::to_string(id),wndClass,&pcapFile}
    };

};

#endif
