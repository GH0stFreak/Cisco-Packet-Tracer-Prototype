#pragma once
#ifndef ROUTER_H
#define ROUTER_H
//#include "..\common.h"
#include "..\enums.h"
#include "..\interface\routerIface.h"
//#include "..\arpCache\arpCache.h"
#include "..\dhcpTable\dhcpTable.h"
#include "..\layer3\layer3.h"
#include "..\stopThread.h"
#include "..\pcapWriter.h"
//#include "..\deviceWindow.h"

template<class Device>
class DeviceWindow;

class Router : public Layer3, public Loggable
{
public:
	Router(std::vector<IpPool>& ifacesIp);

	void IpConfig();

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

	void setHostname(std::string host_str);

	void start();

	~Router(){stop_thread = true;}

	static uint8_t counter;

	std::string hostname;

	pcapWriter pcapFile;

// private: 
    bool stop_thread = false;
    std::thread time_thread;
	std::mutex muxTable;

	mutable std::mutex mtx;

	std::unique_ptr<std::thread> routerFabric;


	/* == For Device Control Window == */

	std::mutex consoleMutex;

	std::shared_ptr<DeviceWindow<Router>> wndClass = std::make_shared<DeviceWindow<Router>>(this, 3, routerWindowClass, ROUTER_CLASS_NAME);

	/* ====================== */

	/* == For ARP process == */

	std::counting_semaphore<10> count2;
	std::condition_variable cond_var_arp;

	std::shared_ptr<Buffer::CircularPtrQueue<8192, 512, Router>> shared_arp_memory = std::make_shared<Buffer::CircularPtrQueue<8192, 512, Router>>(cond_var_arp, count2, this);

	std::shared_ptr<ArpCache<ArpRouterEntry, Buffer::CircularPtrQueue<8192, 512, Router>>> arp_table = std::make_shared<ArpCache<ArpRouterEntry, Buffer::CircularPtrQueue<8192, 512, Router>>>(shared_arp_memory);

	/* ====================== */

	/* == For ICMP process == */

	uint32_t clock{ 0 };

	/* ====================== */

	/* == For processed packets == */

	std::counting_semaphore<10> count;
	std::condition_variable cond_var_memory;

	std::shared_ptr<Buffer::CircularQueue<8192, 512>> shared_memory = std::make_shared<Buffer::CircularQueue<8192, 512>>(cond_var_memory, count);

	/* ====================== */

	/* ==== For Routing Table ==== */

	std::shared_ptr<RoutingTable> routing_table = std::make_shared<RoutingTable>();

	/* ====================== */

	/* == For Router Interfaces == */

	std::vector<IpPool>& ifacesIp_;

	uint8_t id = 0;

    std::atomic<bool> flag;

	std::condition_variable cond_var_copy;

    RouterIface<Buffer::CircularQueue<8192, 512>,Buffer::CircularPtrQueue<8192, 512, Router>> ifaces[4] = {
        RouterIface<Buffer::CircularQueue<8192, 512>,Buffer::CircularPtrQueue<8192, 512, Router>>{++id, flag, cond_var_copy, shared_memory, routing_table, arp_table, shared_arp_memory, &clock, "Router " + std::to_string(counter) + " Iface " + std::to_string(id),wndClass,&pcapFile},
        RouterIface<Buffer::CircularQueue<8192, 512>,Buffer::CircularPtrQueue<8192, 512, Router>>{++id, flag, cond_var_copy, shared_memory, routing_table, arp_table, shared_arp_memory, &clock, "Router " + std::to_string(counter) + " Iface " + std::to_string(id),wndClass,&pcapFile},
        RouterIface<Buffer::CircularQueue<8192, 512>,Buffer::CircularPtrQueue<8192, 512, Router>>{++id, flag, cond_var_copy, shared_memory, routing_table, arp_table, shared_arp_memory, &clock, "Router " + std::to_string(counter) + " Iface " + std::to_string(id),wndClass,&pcapFile},
        RouterIface<Buffer::CircularQueue<8192, 512>,Buffer::CircularPtrQueue<8192, 512, Router>>{++id, flag, cond_var_copy, shared_memory, routing_table, arp_table, shared_arp_memory, &clock, "Router " + std::to_string(counter) + " Iface " + std::to_string(id),wndClass,&pcapFile},
    };

};


Router::Router(std::vector<IpPool>& ifacesIp)
	: count(0),
	count2(0),
	ifacesIp_(ifacesIp),
	Loggable::Loggable("Router " + std::to_string(++counter)),
	hostname("Router " + std::to_string(counter)),
	pcapFile("Router" + std::to_string(counter)) {

	this->start();

	for (size_t i{}; (i < ifacesIp_.size()) && (i < 4); i++) {
		ifaces[i].setPublicIPV4(ifacesIp_[i].ip);
		ifaces[i].setSUBNET_MASK(ifacesIp_[i].option.mask);
		ifaces[i].setGATEWAY(ifacesIp_[i].option.gateway);
		ifaces[i].setDNS(ifacesIp_[i].option.dns);

		uint8_array_6 mac{};
		ifaces[i].getMAC(mac);
		arp_table->addEntry(mac, ifacesIp_[i].ip, ifaces[i].id);

		routing_table->InsertRoute({ {ifacesIp_[i].ip, countLeadingOnes(ifacesIp_[i].option.mask),ifaces[i].id, MANUAL} });
	}

	routerFabric = nullptr;

	routerFabric = std::make_unique<std::thread>([&]() {
		printMessage(CONSOLE_INFO, "Router Fabric Thread called");
		// Never ending loop so thread runs the entire lifetime
		while (true) {
			std::unique_lock<std::mutex> lock(mtx);

			// Checks the queue if empty wait for a packet to be inserted
			if (shared_memory->is_empty() == true) {
				printMessage(CONSOLE_INFO, "Router Fabric waiting!");

				// Waiting for a packet to be in Memory
				cond_var_memory.wait(lock);
				printMessage(CONSOLE_INFO, "Router Fabric unblock!");
			}

			if (count.try_acquire()) {
				// Get the packet from memory
				std::vector<uint8_t> packet;
				shared_memory->dequeue(&packet);

				// Get output port of packet
				uint8_t output_port = packet[2];
				printMessage(CONSOLE_INFO, "Router Iface: {}", +output_port);

				// Checking the output port value against the id of interface
				for (auto& iface : ifaces) {
					if (output_port <= 15 && output_port == iface.id) {
						iface.output_buf->enqueue(&packet);
						break;
					}
				}

			}
			{
				std::unique_lock<std::mutex> lk(cv_m);
				cv.wait(lk, [] { return !paused; });
			}
		}
		});

	routerFabric->detach();
}

void Router::IpConfig() {
	for (size_t i{ 0 }; i < id; i++) {
		printMessage(CONSOLE_INFO, "Iface {}", i + 1);
		printMessage(CONSOLE_INFO, "IPV4: {}", ipToString(ifaces[i].getIPV4()));
		printMessage(CONSOLE_INFO, "Subnet: {}", ipToString(ifaces[i].getSUBNET_MASK()));
		printMessage(CONSOLE_INFO, "Gateway: {}", ipToString(ifaces[i].getGATEWAY()));
		std::cout << std::endl;
	}
}

void Router::setHostname(std::string host_str) {
	hostname = host_str;
}

void Router::start() {
	time_thread = std::thread([this]() {
		while (!stop_thread) {
			// Check the time against expire time
			{
				std::lock_guard<std::mutex> lock(muxTable);
				clock++;

			} // Release the lock when lock goes out of scope

	  // Sleep after processing for 1 second
			std::this_thread::sleep_for(std::chrono::seconds(1));
		}
		});

	time_thread.detach();
};


#endif
