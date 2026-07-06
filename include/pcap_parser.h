#ifndef PCAP_PARSER_H
#define PCAP_PARSER_H

#include "pcap_reader.h";
#include <cstring>
#include <string>
#include <array>

namespace PacketAnalyzer
{

    // struct for Ethernet header
    struct EthernetHeader
    {

        std::array<uint8_t, 6> dest_mac; // destination MAC address
        std::array<uint8_t, 6> src_mac;  // source MAC address
        uint16_t ethertype;              // types of payload (0x0800 for IPv4, 0x0806 for ARP, etc.)
    };

    // struct for  IPv4Header
    struct IPV4Header
    {
        uint8_t version_ihl;     // Version (4 bits) + Header Length (4 bits)
        uint8_t tos;             // Type of Service
        uint16_t total_length;   // Total packet length
        uint16_t identification; // Fragment identification
        uint16_t flags_fragment; // Flags (3 bits) + Fragment Offset (13 bits)
        uint8_t ttl;             // Time To Live
        uint8_t protocol;        // Protocol (6=TCP, 17=UDP, 1=ICMP)
        uint16_t checksum;       // Header checksum
        uint32_t src_ip;         // Source IP address
        uint32_t dest_ip;        // Destination IP address
        // Options may follow if header length > 5
    };

    // struct for TCPHeader
    struct TCPHeader
    {
        uint16_t src_port;       // Source port
        uint16_t dest_port;      // Destination port
        uint32_t seq_num;        // Sequence number
        uint32_t ack_num;        // Acknowledgment number
        uint8_t data_offset;     // Data offset (4 bits) + Reserved (4 bits)
        uint8_t flags;           // Flags (6 bits) + Reserved (2 bits)
        uint16_t window_size;    // Window size
        uint16_t checksum;       // Checksum
        uint16_t urgent_pointer; // Urgent pointer
        // Options may follow if data offset > 5
    };
    // struct for UDPHeader
    struct UDPHeader
    {
        uint16_t src_port;  // Source port
        uint16_t dest_port; // Destination port
        uint16_t length;    // Length of UDP header and data
        uint16_t checksum;  // Checksum
    };
  
    // struct for parsedpacket
    struct ParsedPacket
    {
        // Timestamps
    uint32_t timestamp_sec;
    uint32_t timestamp_usec;
    
    // Ethernet layer
    std::string src_mac;
    std::string dest_mac;
    uint16_t ether_type;
    
    // IP layer (if present)
    bool has_ip = false;
    uint8_t ip_version;
    std::string src_ip;
    std::string dest_ip;
    uint8_t protocol;          // TCP=6, UDP=17, ICMP=1
    uint8_t ttl;
    
    // Transport layer (if present)
    bool has_tcp = false;
    bool has_udp = false;
    uint16_t src_port;
    uint16_t dest_port;
    
    // TCP-specific
    uint8_t tcp_flags;
    uint32_t seq_number;
    uint32_t ack_number;
    
    // Payload
    size_t payload_length;
    const uint8_t* payload_data = nullptr;  // Points into original packet
    };
};
#endif