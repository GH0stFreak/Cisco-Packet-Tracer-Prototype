 #pragma once
 #include "common.h"
// #include <iostream>
// #include <string>

// //Print function
// template <typename T>
// void print(const T& data) {
//     std::cout << data << std::endl;
// }
// template <typename T,typename S>
// void print(const T& data, const S& data1) {
//     std::cout << data << data1 << std::endl;
// }

// // Puts the packet in reverse order in the queue so that when poping the packet, we get it in correct order 
// // template <typename T>
// // void reverse_byte_add_into_queue (const T* hdr_struct_ptr, std::queue<uint8_t>& pkt, size_t size) {
// //     // size_t hdr_struct_size = sizeof(T);
// //     uint8_t* byte_ptr = reinterpret_cast<uint8_t*>(hdr_struct_ptr) + size - 1;

// //     // Loop through each byte of struct in reverse order
// //     for (size_t i = 0; i < size; ++i) 
// //     {
// //         // Access the current byte
// //         uint8_t byte = *byte_ptr;
// //         // Push the byte in the queue 
// //         pkt.push(byte);
// //         // Move to the previous byte
// //         byte_ptr--;
// //     }
// // }

// void showIpConfig(Client* client)
// {
//     print("IPV4 address: ", client->getIPV4());
//     // print("Subnet mask: ", client->getSUBNET_MASK());
//     // print("Gateway address: ", client->getGATEWAY());
// }

// void handleIpRelease(Client* client)
// {
//     // client->setIPV4(0);
//     // print("IP released");
// }

// // PROTOCOL::ethernet_hdr createEthernetHeader (uint8_array_6 dhost, uint8_array_6 shost, PROTOCOL::ethertype type) {
    
// //     PROTOCOL::ethernet_hdr hdr(dhost, shost, type);

// //     return hdr;
// // }

// // PROTOCOL::ipv4_hdr createIPv4Header (uint8_t hl, uint16_t len, uint8_t type, uint32_t src, uint32_t dst) {
    
// //     PROTOCOL::ipv4_hdr hdr(hl, len, type, src, dst);

// //     return hdr;
// // }

// // PROTOCOL::dhcp_hdr createDHCPHeaderDiscover (uint8_array_6 mac) {
    
// //     PROTOCOL::dhcp_hdr hdr;
// //     hdr.dhcp_discover(mac);

// //     return hdr;
// // }

// void handleIpRenew(Client* client){

//     // if(client->getIPV4() != 0)
//     // {
//     //     print("Already have IP");
//     //     return;
//     // }
//     // TODO: Send a Dhcp packet 
//     // TODO: Send the dhcp discover packet to the dhcp server
//     // client->accessIface("put", &dhcp_req_pkt, dhcp_req_pkt.size());
    
//     print("IP renewed");
// }

void getNumber(std::string device, size_t &number) {
    for (size_t i{ 1 }; i < device.length(); i++) {
        char c = device[i];
        if (std::isdigit(c)) {
            number = number * 10 + (c - '0');
        }
        else {
            spdlog::info("Incorrect device in command!!");
            number = 0;
            return;
        }
    }
}

std::vector<std::string> splitString(const std::string & str) {
    std::istringstream iss(str);
    std::vector<std::string> words;
    std::string word;

    while (iss >> word) {
        words.push_back(word);
    }

    return words;
}

enum Instruction {
    IPCONFIG,
    IPRENEW,
    IPRELEASE,
    PING,
    MESSAGE,
    SHOW_MAC_TABLE,
    SHOW_ROUTE_TABLE,
    SHOW_ARP_TABLE,
    SHOW_STP,
    ARP,
    HOSTNAME,
    BUFFER_COUNT,
    SET_HELLO_TIMER,
    SET_FORWARD_DELAY,
    SET_MAX_AGE,
    INSTRUCTION_ERROR
};

bool is_subvector_equal(const std::vector<std::string>& v1, size_t start, size_t end, const std::vector<std::string>& v2) {
    if (end - start != v2.size() || v1.size() < end) {
        return false; // Different sizes
    }

    std::vector<std::string> subvector(v1.begin() + start, v1.begin() + end);
    return subvector == v2;
}

Instruction checkCommand(const std::vector<std::string> splitCommand)
{
    std::string ipConfig{ "ipconfig" };
    std::vector<std::string> ipRelease{ "ipconfig", "/ release" };
    std::vector<std::string> ipRenew{ "ipconfig", "/renew" };
    std::string ping{ "ping" }; 
    std::string show = "show";
    std::vector<std::string> show_mac_table{ "show", "mac", "address-table" };
    std::vector<std::string> show_route_table{ "show", "ip", "route" };
    std::vector<std::string> show_arp_table{ "show", "ip", "arp" };
    std::vector<std::string> show_packet_count{ "show", "packet", "count" };
    std::vector<std::string> show_spanning_tree{ "show", "spanning-tree" };
    std::string arp = "arp";
    

    std::string command = splitCommand[1];

    if (command == ipConfig) {
        if(splitCommand.size() > 3) return INSTRUCTION_ERROR;
        else if (splitCommand.size() == 3) {
            if (is_subvector_equal(splitCommand, 1, 3, ipRelease)) {
                return IPRELEASE;
            }
            else if (is_subvector_equal(splitCommand, 1, 3, ipRenew)) {
                return IPRENEW;
            }
            else return INSTRUCTION_ERROR;
        }
        return IPCONFIG;
    }
    else if (command == ping) {
        return PING;
    }
    else if (command == show) {
        if (is_subvector_equal(splitCommand, 1, 4, show_mac_table)) {
            return SHOW_MAC_TABLE;
        }
        else if (is_subvector_equal(splitCommand, 1, 4, show_route_table)) {
            return SHOW_ROUTE_TABLE;
        }
        else if (is_subvector_equal(splitCommand, 1, 4, show_arp_table)) {
            return SHOW_ARP_TABLE;
        }
        else if (is_subvector_equal(splitCommand, 1, 4, show_packet_count)) {
            return BUFFER_COUNT;
        }
        else if (is_subvector_equal(splitCommand, 1, 3, show_spanning_tree)) {
            return SHOW_STP;
        }
    }
    else if(command == arp)
    {
        return ARP;
    }
    return INSTRUCTION_ERROR;
}

Instruction checkCommandWindow(const std::vector<std::string> splitCommand)
{
    std::string ipConfig{ "ipconfig" };
    std::vector<std::string> ipRelease{ "ipconfig", "/ release" };
    std::vector<std::string> ipRenew{ "ipconfig", "/renew" };
    std::string ping{ "ping" };
    std::string show = "show";
    std::vector<std::string> show_mac_table{ "show", "mac", "address-table" };
    std::vector<std::string> show_route_table{ "show", "ip", "route" };
    std::vector<std::string> show_arp_table{ "show", "ip", "arp" };
    std::vector<std::string> show_packet_count{ "show", "packet", "count" };
    std::vector<std::string> show_spanning_tree{ "show", "spanning-tree" };
    std::string hostname{ "hostname" };
    std::string stp{ "stp" };
    std::vector<std::string> set_hello_timer{ "stp" , "timer" , "forward-delay","time" };    
    std::vector<std::string> set_forward_delay{ "stp", "timer", "hello","time" };
    std::vector<std::string> set_max_age{ "stp", "timer", "max-age" , "time"};
    std::string arp = "arp";


    std::string command = splitCommand[0];

    if (command == ipConfig) {
        if (splitCommand.size() > 2) return INSTRUCTION_ERROR;
        else if (splitCommand.size() == 2) {
            if (is_subvector_equal(splitCommand, 0, 2, ipRelease)) {
                return IPRELEASE;
            }
            else if (is_subvector_equal(splitCommand, 0, 2, ipRenew)) {
                return IPRENEW;
            }
            else return INSTRUCTION_ERROR;
        }
        return IPCONFIG;
    }
    else if (command == ping) {
        return PING;
    }
    else if (command == show) {
        if (is_subvector_equal(splitCommand, 0, 3, show_mac_table)) {
            return SHOW_MAC_TABLE;
        }
        else if (is_subvector_equal(splitCommand, 0, 3, show_route_table)) {
            return SHOW_ROUTE_TABLE;
        }
        else if (is_subvector_equal(splitCommand, 0, 3, show_arp_table)) {
            return SHOW_ARP_TABLE;
        }
        else if (is_subvector_equal(splitCommand, 0, 3, show_packet_count)) {
            return BUFFER_COUNT;
        }
        else if (is_subvector_equal(splitCommand, 0, 2, show_spanning_tree)) {
            return SHOW_STP;
        }
    }
    else if (command == arp)
    {
        if (splitCommand.size() > 2) return INSTRUCTION_ERROR;
        return ARP;
    }
    else if (command == hostname) {
        return HOSTNAME;
    }
    else if (command == stp) {
        if (is_subvector_equal(splitCommand, 0, 4, set_hello_timer)) {
            return SET_HELLO_TIMER;
        }
        else if (is_subvector_equal(splitCommand, 0, 4, set_forward_delay)) {
            return SET_FORWARD_DELAY;
        }
        else if (is_subvector_equal(splitCommand, 0, 4, set_max_age)) {
            return SET_MAX_AGE;
        }
    }
    return INSTRUCTION_ERROR;
}

// Base case: No more arguments to process
void replace_placeholders(std::string& str, size_t start_pos) {
    // No operation needed
}

// Variadic template function to replace placeholders
template <typename T, typename... Args>
void replace_placeholders(std::string& str, size_t start_pos, T value, Args... args) {
    size_t pos = str.find("{}", start_pos);

    if (pos != std::string::npos) {
        std::stringstream ss;
        ss << value;
        str.replace(pos, 2, ss.str());

        // Recur to replace next placeholder
        replace_placeholders(str, pos + ss.str().length(), args...);
    }
}

// Function to replace placeholders in a string
template <typename... Args>
std::string format_string(const std::string& format, Args... args) {
    std::string result = format;
    replace_placeholders(result, 0, args...);
    return result;
}

// Wrapper function that calls format_string
template <typename... Args>
void log_message(const std::string& format, Args&&... args) {
    std::string message = format_string(format, std::forward<Args>(args)...);
    // You can now do something with the formatted message
    std::cout << message << std::endl;
}