// https://infocenter.nokia.com/public/7705SAR234R1A/index.jsp?topic=%2Fcom.nokia.oam-guide%2Fpcap_file_forma-ai9o99jjsa.html
// https://www.ietf.org/archive/id/draft-gharris-opsawg-pcap-01.html


#pragma once
#include "common.h"

//#include "protocol.h"
#include "layer5\layer5.h"

template<typename T>
void pop_front(std::vector<T>& vec)
{
	assert(!vec.empty());
	vec.erase(vec.begin());
}

typedef struct pcap_hdr_s {
	uint32_t magic_number;   /* magic number */
	uint16_t version_major;  /* major version number */
	uint16_t version_minor;  /* minor version number */
	int32_t  thiszone;       /* GMT to local correction */
	uint32_t sigfigs;        /* accuracy of timestamps */
	uint32_t snaplen;        /* max length of captured packets, in octets */
	uint32_t network;        /* data link type */
} pcap_hdr_t;

typedef struct pcaprec_hdr_s {
	uint32_t ts_sec;         /* timestamp seconds */
	uint32_t ts_usec;        /* timestamp microseconds */
	uint32_t incl_len;       /* number of octets of packet saved in file */
	uint32_t orig_len;       /* actual length of packet */
} pcaprec_hdr_t;

static pcap_hdr_t pcapFileHeader{
	.magic_number = 0xa1b2c3d4, // Big-endian magic number for PCAP
	.version_major = 2,         // Major version 2
	.version_minor = 4,         // Minor version 4
	.thiszone = 0,              // GMT to local correction
	.sigfigs = 0,               // Accuracy of timestamps
	.snaplen = 65535,           // Max length of captured packets (in octets)
	.network = 1                // Ethernet (Datalink type)
};

class pcapWriter : public Layer5{

	FILE* pFile = nullptr;

public:

	pcapWriter(std::string str) {

		//std::string str = "example"; // Example string for file name
		std::string relativePath = "pcap/";
		std::string fileName = str + ".pcap";
		std::filesystem::path dirPath(relativePath);

		// Ensure the directory exists
		if (!std::filesystem::exists(dirPath)) {
			std::filesystem::create_directories(dirPath);
		}

		// Create the full path
		std::filesystem::path filePath = dirPath / fileName;

		// Convert to an absolute path
		if (filePath.is_relative()) {
			filePath = std::filesystem::absolute(filePath);
		}

		pFile = fopen(filePath.string().c_str(), "wb"); // open for writing in binary mode

		if (!pFile) {
			perror("File opening failed");
			return;
		}

		fwrite(&pcapFileHeader, 1, sizeof(pcap_hdr_t), pFile);
	}

	void write(std::vector<uint8_t> packet) {

		if (!pFile) {
			perror("File opening failed");
			return;
		}
		// Since we have considered premable and starting delimiter as part of ethernet header
		uint32_t captured_pkt_len = (uint32_t)packet.size() - 8;

		size_t offset{};
		PROTOCOL::ethernet_hdr ethernet_hdr(packet, offset);

		// Remove the ethernet trailer
		PROTOCOL::ethernet_trailer ethernet_trailer(packet);

		// Getting ethertype to know how much to write
		PROTOCOL::ethertype ether_type = processEthernetHeader(ethernet_hdr);

		switch (ether_type)
		{
		case PROTOCOL::ethertype_ip:
		{
			PROTOCOL::ipv4_hdr ipv4_hdr(packet,offset);

			//PROTOCOL::ip_protocol ip_type = processIPv4Header(&iface, ipv4_hdr);

			// Removes the padding of the packet
			auto actual_bytes_size = ipv4_hdr.ip_len - ((ipv4_hdr.ip_v_hl & IP_HL) << 2);
			auto start_it = packet.begin() + actual_bytes_size;
			if (start_it < packet.end())
				packet.erase(start_it, packet.end());

			// Since we have considered premable and starting delimiter as part of ethernet header
			uint32_t size = (uint32_t)packet.size()-8;
			
			uint8_t* packetArr = new uint8_t[size];

			for (size_t i{}; i<size;i++)
			{
				packetArr[i] = packet[i+8];
			}

			// Get the current time point
			auto now = std::chrono::system_clock::now();

			// Convert to time since epoch
			auto epoch = now.time_since_epoch();

			// Get seconds since epoch
			auto seconds = duration_cast<std::chrono::seconds>(epoch).count();

			// Get microseconds since the last second
			auto microseconds = duration_cast<std::chrono::microseconds>(epoch).count() % 1000000;

			pcaprec_hdr_t packetHdr{
				.ts_sec = static_cast<uint32_t>(seconds),
				.ts_usec = static_cast<uint32_t>(microseconds),
				.incl_len = size,
				.orig_len = captured_pkt_len
			};
			fwrite(&packetHdr, 1, sizeof(pcaprec_hdr_t), pFile);
			fwrite(packetArr, 1, size, pFile);

			delete[] packetArr;

			break;
		}

		case PROTOCOL::ethertype_arp:
		{
			// Since we have considered premable and starting delimiter as part of ethernet header 14 + 28
			uint32_t size = 42;

			uint8_t* packetArr = new uint8_t[size];

			for (size_t i{}; i < size; i++)
			{
				packetArr[i] = packet[i + 8];
			}


			// Get the current time point
			auto now = std::chrono::system_clock::now();

			// Convert to time since epoch
			auto epoch = now.time_since_epoch();

			// Get seconds since epoch
			auto seconds = duration_cast<std::chrono::seconds>(epoch).count();

			// Get microseconds since the last second
			auto microseconds = duration_cast<std::chrono::microseconds>(epoch).count() % 1000000;

			pcaprec_hdr_t packetHdr{
				.ts_sec = static_cast<uint32_t>(seconds),
				.ts_usec = static_cast<uint32_t>(microseconds),
				.incl_len = size,
				.orig_len = captured_pkt_len
			};
			fwrite(&packetHdr, 1, sizeof(pcaprec_hdr_t), pFile);
			fwrite(packetArr, 1, size, pFile);

			delete[] packetArr;

			break;
		}

		case PROTOCOL::ethertype_llc:{

			uint32_t size = ethernet_hdr.ether_type + 14;

			uint8_t* packetArr = new uint8_t[size];

			for (size_t i{}; i < size; i++)
			{
				packetArr[i] = packet[i + 8];
			}


			// Get the current time point
			auto now = std::chrono::system_clock::now();

			// Convert to time since epoch
			auto epoch = now.time_since_epoch();

			// Get seconds since epoch
			auto seconds = duration_cast<std::chrono::seconds>(epoch).count();

			// Get microseconds since the last second
			auto microseconds = duration_cast<std::chrono::microseconds>(epoch).count() % 1000000;

			pcaprec_hdr_t packetHdr{
				.ts_sec = static_cast<uint32_t>(seconds),
				.ts_usec = static_cast<uint32_t>(microseconds),
				.incl_len = size,
				.orig_len = captured_pkt_len
			};
			fwrite(&packetHdr, 1, sizeof(pcaprec_hdr_t), pFile);
			fwrite(packetArr, 1, size, pFile);

			delete[] packetArr;
			break;
		}

		case PROTOCOL::ethertype_ERROR:
		default:
			//printMessage(CONSOLE_WARN, "Dropped");
			break;
		}

	}

	void write(std::vector<uint8_t> packet, size_t offset) {

		if (!pFile) {
			perror("File opening failed");
			return;
		}

		while (offset > 0) {
			pop_front(packet);
			offset--;
		}
		// Since we have considered premable and starting delimiter as part of ethernet header
		uint32_t captured_pkt_len = (uint32_t)packet.size() - 8;

		//size_t offset{};
		PROTOCOL::ethernet_hdr ethernet_hdr(packet, offset);

		// Remove the ethernet trailer
		PROTOCOL::ethernet_trailer ethernet_trailer(packet);

		// Getting ethertype to know how much to write
		PROTOCOL::ethertype ether_type = processEthernetHeader(ethernet_hdr);

		switch (ether_type)
		{
		case PROTOCOL::ethertype_ip:
		{
			PROTOCOL::ipv4_hdr ipv4_hdr(packet, offset);

			//PROTOCOL::ip_protocol ip_type = processIPv4Header(&iface, ipv4_hdr);

			// Removes the padding of the packet
			auto actual_bytes_size = ipv4_hdr.ip_len - ((ipv4_hdr.ip_v_hl & IP_HL) << 2);
			auto start_it = packet.begin() + actual_bytes_size;
			if (start_it < packet.end())
				packet.erase(start_it, packet.end());

			// Since we have considered premable and starting delimiter as part of ethernet header
			uint32_t size = (uint32_t)packet.size() - 8;

			uint8_t* packetArr = new uint8_t[size];

			for (size_t i{}; i < size; i++)
			{
				packetArr[i] = packet[i + 8];
			}

			// Get the current time point
			auto now = std::chrono::system_clock::now();

			// Convert to time since epoch
			auto epoch = now.time_since_epoch();

			// Get seconds since epoch
			auto seconds = duration_cast<std::chrono::seconds>(epoch).count();

			// Get microseconds since the last second
			auto microseconds = duration_cast<std::chrono::microseconds>(epoch).count() % 1000000;

			pcaprec_hdr_t packetHdr{
				.ts_sec = static_cast<uint32_t>(seconds),
				.ts_usec = static_cast<uint32_t>(microseconds),
				.incl_len = size,
				.orig_len = captured_pkt_len
			};
			fwrite(&packetHdr, 1, sizeof(pcaprec_hdr_t), pFile);
			fwrite(packetArr, 1, size, pFile);

			delete[] packetArr;

			break;
		}

		case PROTOCOL::ethertype_arp:
		{
			// Since we have considered premable and starting delimiter as part of ethernet header 14 + 28
			uint32_t size = 42;

			uint8_t* packetArr = new uint8_t[size];

			for (size_t i{}; i < size; i++)
			{
				packetArr[i] = packet[i + 8];
			}


			// Get the current time point
			auto now = std::chrono::system_clock::now();

			// Convert to time since epoch
			auto epoch = now.time_since_epoch();

			// Get seconds since epoch
			auto seconds = duration_cast<std::chrono::seconds>(epoch).count();

			// Get microseconds since the last second
			auto microseconds = duration_cast<std::chrono::microseconds>(epoch).count() % 1000000;

			pcaprec_hdr_t packetHdr{
				.ts_sec = static_cast<uint32_t>(seconds),
				.ts_usec = static_cast<uint32_t>(microseconds),
				.incl_len = size,
				.orig_len = captured_pkt_len
			};
			fwrite(&packetHdr, 1, sizeof(pcaprec_hdr_t), pFile);
			fwrite(packetArr, 1, size, pFile);

			delete[] packetArr;

			break;
		}

		case PROTOCOL::ethertype_llc: {

			uint32_t size = ethernet_hdr.ether_type + 14;

			uint8_t* packetArr = new uint8_t[size];

			for (size_t i{}; i < size; i++)
			{
				packetArr[i] = packet[i + 8];
			}


			// Get the current time point
			auto now = std::chrono::system_clock::now();

			// Convert to time since epoch
			auto epoch = now.time_since_epoch();

			// Get seconds since epoch
			auto seconds = duration_cast<std::chrono::seconds>(epoch).count();

			// Get microseconds since the last second
			auto microseconds = duration_cast<std::chrono::microseconds>(epoch).count() % 1000000;

			pcaprec_hdr_t packetHdr{
				.ts_sec = static_cast<uint32_t>(seconds),
				.ts_usec = static_cast<uint32_t>(microseconds),
				.incl_len = size,
				.orig_len = captured_pkt_len
			};
			fwrite(&packetHdr, 1, sizeof(pcaprec_hdr_t), pFile);
			fwrite(packetArr, 1, size, pFile);

			delete[] packetArr;
			break;
		}

		case PROTOCOL::ethertype_ERROR:
		default:
			//printMessage(CONSOLE_WARN, "Dropped");
			break;
		}

	}


	~pcapWriter() {
		if(pFile) fclose(pFile);
	}
};
