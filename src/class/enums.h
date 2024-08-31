#pragma once
#include "tscircularqueue.h"
#include "tscircularptrqueue.h"


enum consoleType {
	CONSOLE_TRACE,
	CONSOLE_DEBUG,
	CONSOLE_INFO,
	CONSOLE_WARN,
	CONSOLE_ERROR,
	CONSOLE_CRITICAL
};

/*enum return_ethertype {
	WRONG_MAC,
	IPV4,
	ARP,
	UNKNOWN
};


struct etherProcessStatus {
	bool error = false;
	PROTOCOL::ethertype type = PROTOCOL::ethertype_ip;
	bool forward = false;
	uint8_t out_port = 0;
	bool flood = false;
};

struct ipProcessStatus {
	bool error = false;
	size_t pkt_len = 0;
	bool options = false;
	size_t opt_len = 0;
	bool forward = false;
};*/