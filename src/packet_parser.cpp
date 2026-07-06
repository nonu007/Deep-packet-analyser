#include "../include/packet_parser.h"
#include "../include/platfrom.h"
#include <sstream>
#include <iomanip>
#include <string>


// use portable byte order functions
using PortableNet :: netToHost16;
using PortableNet :: netToHost32;


// Wrapper macros for compatibility
#define ntohs(x) netToHost16(x)
#define ntohl(x) netToHost32(x)

namespace PacketAnalyzer{

bool PacketParser::parse(const RawPacket& raw , ParsedPacket& parsed){

    // initialise the parsed packet 
    parsed = ParsedPacket();
    parsed.timestamp_sec = raw.header.ts_sec;
    parsed.timestamp_usec = raw.header.ts_usec;

    const uint8_t* data = raw.data.data();
    size_t len = raw.data.size();
    size_t offset = 0;
    
    // Parse Ethernet layer
    
}

}