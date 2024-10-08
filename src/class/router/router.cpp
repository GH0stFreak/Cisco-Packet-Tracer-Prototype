//#include "router.h"
//
//
//Router::Router(std::vector<IpPool>& ifacesIp)
//	: count(0),
//	count2(0),
//	ifacesIp_(ifacesIp),
//	Loggable::Loggable("Router " + std::to_string(++counter)),
//	hostname("Router " + std::to_string(counter)),
//	pcapFile("Router" + std::to_string(counter)) {
//
//	this->start();
//
//	for (size_t i{}; (i < ifacesIp_.size()) && (i < 4); i++) {
//		ifaces[i].setPublicIPV4(ifacesIp_[i].ip);
//		ifaces[i].setSUBNET_MASK(ifacesIp_[i].option.mask);
//		ifaces[i].setGATEWAY(ifacesIp_[i].option.gateway);
//		ifaces[i].setDNS(ifacesIp_[i].option.dns);
//
//		uint8_array_6 mac{};
//		ifaces[i].getMAC(mac);
//		arp_table->addEntry(mac, ifacesIp_[i].ip, ifaces[i].id);
//
//		routing_table->InsertRoute({ {ifacesIp_[i].ip, countLeadingOnes(ifacesIp_[i].option.mask),ifaces[i].id, MANUAL} });
//	}
//
//	routerFabric = nullptr;
//
//	routerFabric = std::make_unique<std::thread>([&]() {
//		printMessage(CONSOLE_INFO, "Router Fabric Thread called");
//		// Never ending loop so thread runs the entire lifetime
//		while (true) {
//			std::unique_lock<std::mutex> lock(mtx);
//
//			// Checks the queue if empty wait for a packet to be inserted
//			if (shared_memory->is_empty() == true) {
//				printMessage(CONSOLE_INFO, "Router Fabric waiting!");
//
//				// Waiting for a packet to be in Memory
//				cond_var_memory.wait(lock);
//				printMessage(CONSOLE_INFO, "Router Fabric unblock!");
//			}
//
//			if (count.try_acquire()) {
//				// Get the packet from memory
//				std::vector<uint8_t> packet;
//				shared_memory->dequeue(&packet);
//
//				// Get output port of packet
//				uint8_t output_port = packet[2];
//				printMessage(CONSOLE_INFO, "Router Iface: {}", +output_port);
//
//				// Checking the output port value against the id of interface
//				for (auto& iface : ifaces) {
//					if (output_port <= 15 && output_port == iface.id) {
//						iface.output_buf->enqueue(&packet);
//						break;
//					}
//				}
//
//			}
//			{
//				std::unique_lock<std::mutex> lk(cv_m);
//				cv.wait(lk, [] { return !paused; });
//			}
//		}
//		});
//
//	routerFabric->detach();
//}
//
//void Router::IpConfig() {
//	for (size_t i{ 0 }; i < id; i++) {
//		printMessage(CONSOLE_INFO, "Iface {}", i + 1);
//		printMessage(CONSOLE_INFO, "IPV4: {}", ipToString(ifaces[i].getIPV4()));
//		printMessage(CONSOLE_INFO, "Subnet: {}", ipToString(ifaces[i].getSUBNET_MASK()));
//		printMessage(CONSOLE_INFO, "Gateway: {}", ipToString(ifaces[i].getGATEWAY()));
//		std::cout << std::endl;
//	}
//}
//
//void Router::setHostname(std::string host_str) {
//	hostname = host_str;
//}
//
//void Router::start() {
//	time_thread = std::thread([this]() {
//		while (!stop_thread) {
//			// Check the time against expire time
//			{
//				std::lock_guard<std::mutex> lock(muxTable);
//				clock++;
//
//			} // Release the lock when lock goes out of scope
//
//	  // Sleep after processing for 1 second
//			std::this_thread::sleep_for(std::chrono::seconds(1));
//		}
//		});
//
//	time_thread.detach();
//};
