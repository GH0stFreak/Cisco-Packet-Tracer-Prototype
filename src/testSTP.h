// #pragma once
//
//
// #include "class\common.h"
// #include "class\client\client.h"
// #include "class\switch\switch.h"
// #include "class\dhcp\dhcp.h"
// #include "class\router\router.h"
// #include "class\helper.h"
//
// uint8_t Iface::count1 = 0;
// uint8_t Iface::count2 = 0;
// uint8_t Iface::count3 = 0;
// uint8_t Iface::count4 = 0;
// uint8_t Iface::count5 = 0;
// uint8_t Iface::count6 = 0;
//
// uint8_t Client::counter = 0;
// uint8_t Switch::counter = 0;
// uint8_t Router::counter = 0;
// uint8_t Dhcp::counter = 0;
//
// std::shared_ptr<spdlog::sinks::stderr_color_sink_mt> Loggable::consoleSink = std::make_shared<spdlog::sinks::stderr_color_sink_mt>();
//
// int main()
//{
//	std::string command = "Karan";
//
//	// STP network 1
//
//	Switch s1; // 1,2,3,4
//	Switch s2; // 5,6,7,8
//	Switch s3; // 9,a,b,c
//	Switch s4; // d,e,f,10
//	std::vector<Switch*> allSwitches = { &s1, &s2, &s3, &s4 };
//
//
//
//	s1.ifaces[0].link = &s2.ifaces[0];
//	s1.ifaces[1].link = &s3.ifaces[0];
//	s1.ifaces[2].link = &s3.ifaces[1];
//
//	s2.ifaces[0].link = &s1.ifaces[0];
//	s2.ifaces[1].link = &s4.ifaces[0];
//
//	s3.ifaces[0].link = &s1.ifaces[1];
//	s3.ifaces[1].link = &s1.ifaces[2];
//	s3.ifaces[2].link = &s4.ifaces[1];
//
//	s4.ifaces[0].link = &s2.ifaces[1];
//	s4.ifaces[1].link = &s3.ifaces[2];
//
//
//	// STP network 2
//	/*
//	Switch s1; // 1,2,3,4
//	Switch s2; // 5,6,7,8
//	Switch s3; // 9,a,b,c
//	std::vector<Switch*> allSwitches = { &s1, &s2, &s3 };
//
//
//
//	s1.ifaces[0].link = &s2.ifaces[0];
//	s1.ifaces[1].link = &s3.ifaces[0];
//
//	s2.ifaces[0].link = &s1.ifaces[0];
//	s2.ifaces[1].link = &s3.ifaces[1];
//
//	s3.ifaces[0].link = &s1.ifaces[1];
//	s3.ifaces[1].link = &s2.ifaces[1];
//	*/
//
//	// STP network 3
//	/*
//	Switch s1; // 5,6,7,8
//	Switch s2; // 9,a,b,c
//	Switch s3; // 1,2,3,4
//	Switch s4; // d,e,f,10
//	std::vector<Switch*> allSwitches = { &s3, &s1, &s2, &s4 };
//
//	s1.ifaces[0].link = &s2.ifaces[2];
//	s1.ifaces[1].link = &s3.ifaces[0];
//	s1.ifaces[2].link = &s2.ifaces[1];
//
//	s2.ifaces[0].link = &s4.ifaces[1];
//	s2.ifaces[1].link = &s1.ifaces[2];
//	s2.ifaces[2].link = &s1.ifaces[0];
//
//	s3.ifaces[0].link = &s1.ifaces[1];
//	s3.ifaces[1].link = &s4.ifaces[0];
//
//	s4.ifaces[0].link = &s3.ifaces[1];
//	s4.ifaces[1].link = &s2.ifaces[0];
//	*/
//
//	std::this_thread::sleep_for(std::chrono::seconds(3));
//
//	std::cout << "Program ran for 3 second afterwards" << std::endl;
//
//	uint8_array_6 mac{};
//
//	for (size_t i{ 0 }; i < allSwitches.size(); i++) {
//		std::cout << "Switch " << (1 + i) << " " << allSwitches[i]->root_bridge << std::endl;
//		allSwitches[i]->printIfaceStateStatus();
//	}
//
//	std::this_thread::sleep_for(std::chrono::seconds(10));
//	for (size_t i{ 0 }; i < allSwitches.size(); i++) {
//		std::cout << "Switch " << (1 + i) << " " << allSwitches[i]->root_bridge << std::endl;
//		allSwitches[i]->printIfaceStateStatus();
//
//	}
//
//	return 0;
// }
