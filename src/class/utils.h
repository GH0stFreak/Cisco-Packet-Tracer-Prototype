
#pragma once
#ifndef UTILS_H
#define UTILS_H
//#include "common.h"

#include <spdlog\spdlog.h>

#include <cstdint>
#include <vector>
#include <string>
#include <stdexcept>
#include <algorithm>
#include <iomanip>
#include <bitset>
#include <optional>
#include <random>
#include <queue>
#include <list>
#include <iostream>

#ifndef MAC_ADDR_LEN
#define MAC_ADDR_LEN 6
#endif

typedef uint8_t uint8_array_6[MAC_ADDR_LEN];

uint16_t stringToUint16(const std::string& str, uint16_t defaultValue = 10) {
    try {
        return static_cast<uint16_t>(std::stoi(str));
    }
    catch (const std::invalid_argument& e) {
        spdlog::critical("Invalid argument: {}",e.what());
        return defaultValue;
    }
    catch (const std::out_of_range& e) {
        spdlog::critical("Out of range: {}", e.what());
        return defaultValue;
    }
}

// trim from start(in place)
inline void ltrim(std::string & s) {
    s.erase(s.begin(), std::find_if(s.begin(), s.end(), [](unsigned char ch) {
        return !std::isspace(ch);
        }));
}

// trim from end (in place)
inline void rtrim(std::string& s) {
    s.erase(std::find_if(s.rbegin(), s.rend(), [](unsigned char ch) {
        return !std::isspace(ch);
        }).base(), s.end());
}

// trim from both sides (in place)
inline void trim(std::string& s) {
    ltrim(s);
    rtrim(s);
}
// Gives a 32 bit value with number of MSB as 1 for argument 
// Like for 8 will return FF000000 as value 
uint32_t 
setMSBToOne(int numBits) {
  // Check for invalid input (more bits than available)
  if (numBits > sizeof(uint32_t) * 8) {
    return (uint32_t)-1; // Or any other error handling mechanism
  }

  // Create a mask with all bits 1
  uint32_t mask = (uint32_t)-1;

  // Shift the mask to the left by the number of bits we want to set
  mask = mask << (sizeof(uint32_t) * 8 - numBits);

  return mask;
}

std::string
macToString(const uint8_array_6& macAddr)
{
    char s[18]; // 12 digits + 5 separators + null terminator
    char sep = ':';

    // - apparently gcc-4.6 does not support the 'hh' type modifier
    // - std::snprintf not found in some environments
    //   https://redmine.named-data.net/issues/2299 for more information
    snprintf(s, sizeof(s), "%02x%c%02x%c%02x%c%02x%c%02x%c%02x",
            macAddr[0], sep, macAddr[1], sep, macAddr[2], sep,
            macAddr[3], sep,macAddr[4], sep, macAddr[5]);

    return std::string(s);
}

std::string
ipToString(uint32_t ip)
{
    char s[16]; // 4 numbers (3 digits max) + 3 separators + null terminator

    snprintf(s, sizeof(s), "%u.%u.%u.%u",
             (ip >> 24) & 0xFF,  // Extract the first byte
             (ip >> 16) & 0xFF,  // Extract the second byte
             (ip >> 8) & 0xFF,   // Extract the third byte
             ip & 0xFF);         // Extract the fourth byte

    return std::string(s);
}

uint32_t ipToUint32(const std::string& ip_str) {
  // Split the string by "."
  std::istringstream iss(ip_str);
  std::string segment;
  uint32_t result = 0;
  int i = 0;  // Declare i outside the loop

  // Iterate over each segment (maximum 4)
  for (; std::getline(iss, segment, '.') && i < 4; ++i) {
    // Convert segment to integer and check range (0-255)
    int segment_value;
    try {
      segment_value = std::stoi(segment);
      if (segment_value < 0 || segment_value > 255) {
        throw std::invalid_argument("Invalid IP segment value");
      }
    } catch (const std::invalid_argument& e) {
      throw std::invalid_argument(std::string("Invalid IP format: ") + e.what());
    }

    // Shift existing result and add segment value
    result = (result << 8) | segment_value;
  }

  // Check for extra segments or missing segments
  if (iss.good() || i != 4) {
    throw std::invalid_argument("Invalid IP format");
  }

  return result;
}

uint64_t uint8_array_6ToUint64(const uint8_array_6 mac){
    uint64_t result = 0;
    for (size_t i{}; i < MAC_ADDR_LEN; i++) {
        result = result << 8;
        result = result + mac[i];
    }
    return result;
}

// Function to count the number of leading ones in the binary representation of a uint32_t number
uint8_t countLeadingOnes(uint32_t num) {
    std::bitset<32> binary(num);
    uint8_t count = 0;
    bool foundZero = false;

    for (int i = 31; i >= 0; --i) {
        if (binary[i] == 1) {
            if (foundZero) {
                // If we found a 0 before and now we find a 1, throw an error
                return 0;
                // throw std::invalid_argument("Invalid input: Change from 0 to 1 found.");
            }
            count++;
        } else {
            foundZero = true; // Mark that we have found a zero
        }
    }

    return count;
}

std::string uint64ToHexString(uint64_t value) {
    std::stringstream ss;
    ss << std::hex << std::setfill('0') << std::setw(16) << value;

    std::string hex_str = ss.str();
    hex_str.insert(14, ":");
    hex_str.insert(10, ":");
    hex_str.insert(6, ":");
    hex_str.insert(2, ":");

    return hex_str;
}

void assign_uint8_array_6(uint8_array_6& lhs, const uint8_array_6& rhs) {
    std::copy(std::begin(rhs), std::end(rhs), std::begin(lhs));
}

bool check_uint8_array_6(const uint8_array_6 lhs, const uint8_array_6 rhs) {
    for(size_t i{};i<MAC_ADDR_LEN;i++){
        if(lhs[i]!=rhs[i]) return false;
    }
    return true;
}

uint32_t generateRandomNumber(int bits, std::optional<uint32_t> min = std::nullopt) {
    // Ensure the number of bits is within a valid range
    if (bits <= 0 || bits > 32) {
        throw std::invalid_argument("Number of bits must be between 1 and 32");
    }

    // Calculate the maximum value for the specified number of bits
    uint32_t max_value = (1ULL << bits) - 1;

    // Create a random device to seed the random number generator
    std::random_device rd;

    // Initialize a random number generator with the random device
    std::mt19937 generator(rd());

    // Define a uniform distribution in the range [0, max_value] or [min, max_value]
    if (min.has_value()) {
        if (min.value() > max_value) {
            throw std::invalid_argument("Minimum value exceeds the maximum possible value for the specified number of bits");
        }
        std::uniform_int_distribution<uint32_t> distribution( min.value(), max_value);
        return distribution(generator);
    }

    std::uniform_int_distribution<uint32_t> distribution(0, max_value);
    return distribution(generator);
}

// Helper function to check if a type is a container
template<typename T>
struct is_container {
    template<typename U>
    static constexpr bool test(U*) { return false; }
    
    template<typename U>
    static constexpr bool test(std::vector<U>*) { return true; }

    static constexpr bool value = test(static_cast<T*>(nullptr));
};

// Add the property(variable) in queue of uint8_t
template<typename T>
// typename std::enable_if<std::is_fundamental<T>::value, void>::type 
inline void serializer (const T* variable, std::queue<uint8_t> &pkt, size_t size) {

    const uint8_t* bBytes = reinterpret_cast<const uint8_t*>(variable);

    for(size_t i{}; i < size; i++)
    pkt.push(bBytes[i]);
}

template<typename T>
// typename std::enable_if<std::is_fundamental<T>::value, void>::type 
inline void serializer (const T* variable, std::list<uint8_t> &pkt, size_t size) {
    const uint8_t* bBytes = reinterpret_cast<const uint8_t*>(variable);
    if(IS_LITTLE_ENDIAN) {
        for(size_t i = size; i > 0; i--) {
            pkt.push_back(bBytes[i - 1]);
        }
    } else {
        for(size_t i = 0; i < size; i++) {
            pkt.push_back(bBytes[i]);
        }
    }
}

inline void serializer(const std::string* variable, std::list<uint8_t>& pkt, size_t size) {
  const uint8_t* strBytes = reinterpret_cast<const uint8_t*>(variable->c_str());
    for (size_t i = 0; i < size; i++) {
        pkt.push_back(strBytes[i]);
    }
}

// Add the property(container) in queue of uint8_t
// typename std::enable_if<is_container<T>::value, void>::type
inline void serializer (std::vector<uint8_t>* container, std::queue<uint8_t> &pkt, size_t length) {
    for(size_t i{}; i < length; i++){
        pkt.push((*container)[i]);
    }
}
inline void serializer (std::vector<uint8_t>* container, std::list<uint8_t> &pkt, size_t length) {
    for(size_t i{}; i < length; i++){
        pkt.push_back((*container)[i]);
    }
}
// typename std::enable_if<is_container<T>::value, void>::type
inline void serializer (uint8_t* container, std::queue<uint8_t> &pkt, size_t length) {
    for(size_t i{}; i < length; i++){
        pkt.push(*(container+i));
    }
}
inline void serializer (uint8_t* container, std::list<uint8_t> &pkt, size_t length) {
    for(size_t i{}; i < length; i++){
        pkt.push_back(*(container+i));
    }
}

// Get the property(variable) from queue of uint8_t
template<typename T>
inline
typename std::enable_if<std::is_fundamental<T>::value, void>::type
deserializer (T* variable, std::queue<uint8_t> &pkt, size_t size) {

    uint8_t* bBytes = reinterpret_cast<uint8_t*>(variable);
    if(size==1) {
        *bBytes = pkt.front();
        pkt.pop();
        return;
    }
    for(size_t i{}; i < size; i++){
        bBytes[i] = pkt.front();
        pkt.pop();
    }
}
//TODO: Wrong
template<typename T>
inline
typename std::enable_if<std::is_fundamental<T>::value, void>::type
deserializer (T* variable, std::list<uint8_t> &pkt, size_t size) {

    uint8_t* bBytes = reinterpret_cast<uint8_t*>(variable);
    if(size==1) {
        *bBytes = pkt.front();
        pkt.pop_back();
        return;
    }
    for(size_t i{}; i < size; i++){
        bBytes[i] = pkt.front();
        pkt.pop_back();
    }
}

// Deserialize from vector packet
template<typename T>
inline
typename std::enable_if<std::is_fundamental<T>::value, void>::type
deserializer (T* variable, std::vector<uint8_t> &pkt, size_t size, size_t &offset) {

    uint8_t* bBytes = reinterpret_cast<uint8_t*>(variable);
    if(size==1) {
        *bBytes = pkt[offset++];
        return;
    }

    if(IS_LITTLE_ENDIAN) {
        for(size_t i = size; i > 0; i--) {
            bBytes[i - 1]=pkt[offset++];
        }
    } else {
        for(size_t i = 0; i < size; i++) {
            bBytes[i] = pkt[offset++];
        }
    }
}

template<typename T>
inline
typename std::enable_if<std::is_fundamental<T>::value, void>::type
deserializer (T* variable, std::vector<uint8_t> &pkt, size_t size) {

    uint8_t* bBytes = reinterpret_cast<uint8_t*>(variable);
    if(size==1) {
        if (!pkt.empty()) {
            *bBytes = pkt.front();
            pkt.erase(pkt.begin());
            return;
        }
    }

    if(IS_LITTLE_ENDIAN) {
        if (!pkt.empty()) {
            for(size_t i = size; i > 0; i--) {
                bBytes[i - 1] = pkt.front();
                pkt.erase(pkt.begin());
            }
        }
    } else {
        if (!pkt.empty()) {
            for(size_t i = 0; i < size; i++) {
                bBytes[i] = pkt.front();
                pkt.erase(pkt.begin());
            }
        }
    }
}

template<typename T>
inline
typename std::enable_if<std::is_fundamental<T>::value, void>::type
deserializer (T* variable, std::deque<uint8_t> &pkt, size_t size) {

    uint8_t* bBytes = reinterpret_cast<uint8_t*>(variable);
    if(size==1) {
        *bBytes = pkt.front();
        pkt.pop_front();
        return;
    }

    if(IS_LITTLE_ENDIAN) {
        for(size_t i = size; i > 0; i--) {
            bBytes[i - 1] = pkt.front();
            pkt.pop_front();
        }
    } else {
        for(size_t i = 0; i < size; i++) {
            bBytes[i] = pkt.front();
            pkt.pop_front();
        }
    }
}

template<typename T>
inline
typename std::enable_if<std::is_fundamental<T>::value, void>::type
deserializer (T* variable, std::deque<uint8_t> &pkt, size_t size, bool reverse) {
    if(reverse == false){
        return;
    }
    uint8_t* bBytes = reinterpret_cast<uint8_t*>(variable);

    if(IS_LITTLE_ENDIAN) {
        for(size_t i = 0; i < size; i++) {
            bBytes[i] = pkt.back();
            pkt.pop_back();
        }
        
    } else {
        for(size_t i = size; i > 0; i--) {
            bBytes[i - 1] = pkt.back();
            pkt.pop_back();
        }
    }
}

template<typename T>
inline
typename std::enable_if<std::is_fundamental<T>::value, void>::type
deserializer (T* variable, std::vector<uint8_t> &pkt, size_t size, bool reverse) {
    if(reverse == false){
        return;
    }
    uint8_t* bBytes = reinterpret_cast<uint8_t*>(variable);

    if(IS_LITTLE_ENDIAN) {
        for(size_t i = 0; i < size; i++) {
            if (!pkt.empty()) {
                bBytes[i] = pkt.back();
                pkt.pop_back();
                // pkt.erase(pkt.end()-1);
            }
        }
    } else {
        for(size_t i = size; i > 0; i--) {
            if (!pkt.empty()) {
                bBytes[i - 1] = pkt.back();
                pkt.pop_back();
                // pkt.erase(pkt.end()-1);
            }
        }
    }
}

// Get the property(container) from queue of uint8_t
inline void deserializer (std::vector<uint8_t>* container, std::queue<uint8_t> &pkt, size_t length) {

    for(size_t i{}; i < length; i++){
        (*container).push_back(pkt.front());
        pkt.pop();
    }
}
inline void deserializer (std::vector<uint8_t>* container, std::list<uint8_t> &pkt, size_t length) {

    for(size_t i{}; i < length; i++){
        (*container).push_back(pkt.front());
        pkt.pop_front();
    }
}
inline void deserializer (std::vector<uint8_t>* container, std::vector<uint8_t> &pkt, size_t length, size_t &offset) {

    for(size_t i{}; i < length; i++){
        (*container).push_back(pkt[offset++]);
    }
}
inline void deserializer (std::vector<uint8_t>* container, std::vector<uint8_t> &pkt, size_t length) {
    
    for(size_t i{}; i < length; i++){
        if (!pkt.empty()) {
            (*container).push_back(pkt.front());
            pkt.erase(pkt.begin());
        }
    }
}
inline void deserializer (std::vector<uint8_t>* container, std::deque<uint8_t> &pkt, size_t length) {

    for(size_t i{}; i < length; i++){
        (*container).push_back(pkt.front());
        pkt.pop_front();
    }
}

// Get the property(mac) from queue of uint8_t
inline void deserializer (uint8_array_6* container, std::queue<uint8_t> &pkt, size_t length) {

    for(size_t i{}; i < length; i++){
        (*container)[i]= (pkt.front());
        pkt.pop();
    }
}
inline void deserializer (uint8_array_6* container, std::list<uint8_t> &pkt, size_t length) {

    for(size_t i{}; i < length; i++){
        (*container)[i]= (pkt.front());
        pkt.pop_front();
    }
}
inline void deserializer (uint8_array_6* container, std::vector<uint8_t> &pkt, size_t length, size_t &offset) {

    for(size_t i{}; i < length; i++){
        (*container)[i]= (pkt[offset++]);
    }
}
inline void deserializer (uint8_array_6* container, std::vector<uint8_t> &pkt, size_t length) {

    for(size_t i{}; i < length; i++){
        if (!pkt.empty()) {
            (*container)[i]= (pkt.front());
            pkt.erase(pkt.begin());
        }
    }
}
inline void deserializer (uint8_array_6* container, std::deque<uint8_t> &pkt, size_t length) {

    for(size_t i{}; i < length; i++){
        (*container)[i]= (pkt.front());
        pkt.pop_front();
    }
}



/* ========= Header Error Calculation ========= */

// Complete CRC-32 table
const uint32_t crc_table[256] = {
    0x00000000, 0x77073096, 0xEE0E612C, 0x990951BA,
    0x076DC419, 0x706AF48F, 0xE963A535, 0x9E6495A3,
    0x0EDB8832, 0x79DCB8A4, 0xE0D5E91E, 0x97D2D988,
    0x09B64C2B, 0x7EB17CBD, 0xE7B82D07, 0x90BF1D91,
    0x1DB71064, 0x6AB020F2, 0xF3B97148, 0x84BE41DE,
    0x1ADAD47D, 0x6DDDE4EB, 0xF4D4B551, 0x83D385C7,
    0x136C9856, 0x646BA8C0, 0xFD62F97A, 0x8A65C9EC,
    0x14015C4F, 0x63066CD9, 0xFA0F3D63, 0x8D080DF5,
    0x3B6E20C8, 0x4C69105E, 0xD56041E4, 0xA2677172,
    0x3C03E4D1, 0x4B04D447, 0xD20D85FD, 0xA50AB56B,
    0x35B5A8FA, 0x42B2986C, 0xDBBBC9D6, 0xACBCF940,
    0x32D86CE3, 0x45DF5C75, 0xDCD60DCF, 0xABD13D59,
    0x26D930AC, 0x51DE003A, 0xC8D75180, 0xBFD06116,
    0x21B4F4B5, 0x56B3C423, 0xCFBA9599, 0xB8BDA50F,
    0x2802B89E, 0x5F058808, 0xC60CD9B2, 0xB10BE924,
    0x2F6F7C87, 0x58684C11, 0xC1611DAB, 0xB6662D3D,
    0x76DC4190, 0x01DB7106, 0x98D220BC, 0xEFD5102A,
    0x71B18589, 0x06B6B51F, 0x9FBFE4A5, 0xE8B8D433,
    0x7807C9A2, 0x0F00F934, 0x9609A88E, 0xE10E9818,
    0x7F6A0DBB, 0x086D3D2D, 0x91646C97, 0xE6635C01,
    0x6B6B51F4, 0x1C6C6162, 0x856530D8, 0xF262004E,
    0x6C0695ED, 0x1B01A57B, 0x8208F4C1, 0xF50FC457,
    0x65B0D9C6, 0x12B7E950, 0x8BBEB8EA, 0xFCB9887C,
    0x62DD1DDF, 0x15DA2D49, 0x8CD37CF3, 0xFBD44C65,
    0x4DB26158, 0x3AB551CE, 0xA3BC0074, 0xD4BB30E2,
    0x4ADFA541, 0x3DD895D7, 0xA4D1C46D, 0xD3D6F4FB,
    0x4369E96A, 0x346ED9FC, 0xAD678846, 0xDA60B8D0,
    0x44042D73, 0x33031DE5, 0xAA0A4C5F, 0xDD0D7CC9,
    0x5005713C, 0x270241AA, 0xBE0B1010, 0xC90C2086,
    0x5768B525, 0x206F85B3, 0xB966D409, 0xCE61E49F,
    0x5EDEF90E, 0x29D9C998, 0xB0D09822, 0xC7D7A8B4,
    0x59B33D17, 0x2EB40D81, 0xB7BD5C3B, 0xC0BA6CAD,
    0xEDB88320, 0x9ABFB3B6, 0x03B6E20C, 0x74B1D29A,
    0xEAD54739, 0x9DD277AF, 0x04DB2615, 0x73DC1683,
    0xE3630B12, 0x94643B84, 0x0D6D6A3E, 0x7A6A5AA8,
    0xE40ECF0B, 0x9309FF9D, 0x0A00AE27, 0x7D079EB1,
    0xF00F9344, 0x8708A3D2, 0x1E01F268, 0x6906C2FE,
    0xF762575D, 0x806567CB, 0x196C3671, 0x6E6B06E7,
    0xFED41B76, 0x89D32BE0, 0x10DA7A5A, 0x67DD4ACC,
    0xF9B9DF6F, 0x8EBEEFF9, 0x17B7BE43, 0x60B08ED5,
    0xD6D6A3E8, 0xA1D1937E, 0x38D8C2C4, 0x4FDFF252,
    0xD1BB67F1, 0xA6BC5767, 0x3FB506DD, 0x48B2364B,
    0xD80D2BDA, 0xAF0A1B4C, 0x36034AF6, 0x41047A60,
    0xDF60EFC3, 0xA867DF55, 0x316E8EEF, 0x4669BE79,
    0xCB61B38C, 0xBC66831A, 0x256FD2A0, 0x5268E236,
    0xCC0C7795, 0xBB0B4703, 0x220216B9, 0x5505262F,
    0xC5BA3BBE, 0xB2BD0B28, 0x2BB45A92, 0x5CB36A04,
    0xC2D7FFA7, 0xB5D0CF31, 0x2CD99E8B, 0x5BDEAE1D,
    0x9B64C2B0, 0xEC63F226, 0x756AA39C, 0x026D930A,
    0x9C0906A9, 0xEB0E363F, 0x72076785, 0x05005713,
    0x95BF4A82, 0xE2B87A14, 0x7BB12BAE, 0x0CB61B38,
    0x92D28E9B, 0xE5D5BE0D, 0x7CDCEFB7, 0x0BDBDF21,
    0x86D3D2D4, 0xF1D4E242, 0x68DDB3F8, 0x1FDA836E,
    0x81BE16CD, 0xF6B9265B, 0x6FB077E1, 0x18B74777,
    0x88085AE6, 0xFF0F6A70, 0x66063BCA, 0x11010B5C,
    0x8F659EFF, 0xF862AE69, 0x616BFFD3, 0x166CCF45,
    0xA00AE278, 0xD70DD2EE, 0x4E048354, 0x3903B3C2,
    0xA7672661, 0xD06016F7, 0x4969474D, 0x3E6E77DB,
    0xAED16A4A, 0xD9D65ADC, 0x40DF0B66, 0x37D83BF0,
    0xA9BCAE53, 0xDEBB9EC5, 0x47B2CF7F, 0x30B5FFE9,
    0xBDBDF21C, 0xCABAC28A, 0x53B39330, 0x24B4A3A6,
    0xBAD03605, 0xCDD70693, 0x54DE5729, 0x23D967BF,
    0xB3667A2E, 0xC4614AB8, 0x5D681B02, 0x2A6F2B94,
    0xB40BBE37, 0xC30C8EA1, 0x5A05DF1B, 0x2D02EF8D
};

// Function to compute CRC-32 
// Can check for correctness at https://crccalc.com/ 
uint32_t compute_crc32(const std::deque<uint8_t>& data) {
    uint32_t crc = 0xFFFFFFFF;

    // Computing CRC from the 8th byte as the first 8 bytes are premable and SFD which are not included in CRC computation
    for (size_t i = 8; i < data.size(); ++i) {
        uint8_t byte = data[i];
        crc = crc_table[(crc ^ byte) & 0xFF] ^ (crc >> 8);
    }

    return crc ^ 0xFFFFFFFF;
}
uint32_t compute_crc32(const std::vector<uint8_t>& data) {
    uint32_t crc = 0xFFFFFFFF;

    // Computing CRC from the 8th byte as the first 8 bytes are premable and SFD which are not included in CRC computation
    for (size_t i = 8; i < data.size(); ++i) {
        uint8_t byte = data[i];
        crc = crc_table[(crc ^ byte) & 0xFF] ^ (crc >> 8);
    }

    return crc ^ 0xFFFFFFFF;
}

bool verify_crc32(const std::vector<uint8_t>& data) {
    uint32_t crc = 0xFFFFFFFF;

    // Computing CRC from the 11th byte as the first 3 bytes are the internal header bytes and the next 8 bytes are premable and SFD which are not included in CRC computation and not taking the last 4 bytes as they are checksum bytes and we are verifying against those bytes
    size_t size =  data.size();
    for (size_t i = 11; i < size - 4; ++i) {
        // std::cout<<+data[i]<<" ";
        uint8_t byte = data[i];
        crc = crc_table[(crc ^ byte) & 0xFF] ^ (crc >> 8);
    }

    crc = crc ^ 0xFFFFFFFF;

    uint32_t computed_crc = (static_cast<uint32_t>(data[size-4]) << 24) |
                            (static_cast<uint32_t>(data[size-3]) << 16) |
                            (static_cast<uint32_t>(data[size-2]) << 8)  |
                            static_cast<uint32_t>(data[size-1]);

	// std::cout<<"CRC(verify against): "<< crc <<std::endl;
	// std::cout<<"CRC(computed crc): "<< computed_crc <<std::endl;

    return crc == computed_crc;
}

uint16_t calculateChecksum(const std::list<uint8_t>& header) {
    uint32_t sum = 0;
    size_t length = header.size();

    auto it = header.begin();

    // Sum all 16-bit words
    while (length >= 2) {
        sum += ((*it) << 8) + (*(std::next(it)));
        std::advance(it, 2);
        length -= 2;
    }

    // If length is odd, add the last byte (padded with zero)
    if (length > 0) {
        sum += ((*it) << 8);
    }

    // Fold carry bits
    while (sum >> 16) {
        sum = (sum & 0xFFFF) + (sum >> 16);
    }

    // Take one's complement
    return static_cast<uint16_t>(~sum);
}

uint16_t calculateChecksum(const std::list<uint8_t>& pseudo_hdr,const std::list<uint8_t>& layer4_hdr,const std::deque<uint8_t>& header) {
    uint32_t sum = 0;
    
    size_t pseudo_hdr_len = pseudo_hdr.size();

    auto it1 = pseudo_hdr.begin();

    // Sum all 16-bit words
    while (pseudo_hdr_len >= 2) {
        sum += ((*it1) << 8) + (*(std::next(it1)));
        std::advance(it1, 2);
        pseudo_hdr_len -= 2;
    }

    size_t layer4_hdr_len = layer4_hdr.size();

    auto it2 = layer4_hdr.begin();

    // Sum all 16-bit words
    while (layer4_hdr_len >= 2) {
        sum += ((*it2) << 8) + (*(std::next(it2)));
        std::advance(it2, 2);
        layer4_hdr_len -= 2;
    }

    size_t pkt_length = header.size();

    auto it3 = header.begin();

    // Sum all 16-bit words
    while (pkt_length >= 2) {
        sum += ((*it3) << 8) + (*(std::next(it3)));
        std::advance(it3, 2);
        pkt_length -= 2;
    }

    // If length is odd, add the last byte (padded with zero)
    if (pkt_length > 0) {
        sum += ((*it3) << 8);
    }

    // Fold carry bits
    while (sum >> 16) {
        sum = (sum & 0xFFFF) + (sum >> 16);
    }

    // Take one's complement
    return static_cast<uint16_t>(~sum);
}

bool verifyChecksum(std::list<uint8_t>& header) {
    // Check if header is at least 20 bytes (minimum IPv4 header length)
    if (header.size() < 20) {
        std::cerr << "Error: IPv4 header length is less than 20 bytes." << std::endl;
        return false;
    }

	// std::cout<<"Checksum\n";
    
    // for(auto el: header){
	// 	std::cout<<+el<<" ";
	// }
	// std::cout<<"\n";


    // Extract the checksum from the header (assuming it's at position 10 and 11 in the list)
    std::list<uint8_t>::iterator it = header.begin();
    std::advance(it, 10);
    uint16_t storedChecksum = static_cast<uint16_t>(*it << 8);
    std::advance(it, 1);
    storedChecksum += static_cast<uint16_t>(*it);


    // Calculate checksum for the header (excluding the checksum field itself)
    std::list<uint8_t> headerWithoutChecksum(header.begin(), std::next(header.begin(), 10));
    std::list<uint8_t> restOfHeader(std::next(header.begin(), 12), header.end());

    for (auto byte : restOfHeader) {
        headerWithoutChecksum.push_back(byte);
    }

    uint16_t calculatedChecksum = calculateChecksum(headerWithoutChecksum);
	// std::cout<<"HERE: "<<+calculatedChecksum<<std::endl;
	// std::cout<<"HERE: "<<+storedChecksum<<std::endl;

    // Compare calculated checksum with stored checksum
    return (calculatedChecksum == storedChecksum);
}

bool verifyChecksum(const std::list<uint8_t>& pseudo_hdr, const std::list<uint8_t>& layer4_hdr, const std::deque<uint8_t>& header) {
    if (layer4_hdr.size() != 8) {
        std::cerr << "Error: UDP header length is not 8 bytes." << std::endl;
        return false;
    }

    // Extract the checksum from the header (assuming it's at position 10 and 11 in the list)
    auto it = layer4_hdr.begin();
    std::advance(it, 6);
    uint16_t storedChecksum = static_cast<uint16_t>(*it << 8);
    std::advance(it, 1);
    storedChecksum += static_cast<uint16_t>(*it);

    // Calculate checksum for the header (excluding the checksum field itself)
    std::list<uint8_t> headerWithoutChecksum(layer4_hdr.begin(), std::next(layer4_hdr.begin(), 6));
    // for(auto i : headerWithoutChecksum){
    //     std::cout<<+i<<" ";
    // }
    // std::cout<<"\n";

    uint16_t calculatedChecksum = calculateChecksum(pseudo_hdr, headerWithoutChecksum, header);
    // std::cout<<"checksum"<<+calculatedChecksum<<" ";
    // std::cout<<"checksum"<<+storedChecksum<<" ";


// Compare calculated checksum with stored checksum
    return (calculatedChecksum == storedChecksum);
}


#endif