#include "types.h"
#include <sstream>   //tring stream ke liye (string ko stream ki tarah read/write karna, parsing ke kaam aata hai);
#include <iomanip>   // Formatting output in pattern
#include <algorithm> //STL algorithms (sort, find, transform, etc.)
#include <cctype>    //Character functions (toupper, tolower, isdigit, isalpha, etc.)

namespace DPI
{

    std::string FiveTuple::toString() const
    {                           //
        std::ostringstream oss; //  o = output, string = string mein store, stream = data flow
        // Normal string mein numbers directly nahi jod sakte, isliye ostringstream use rte h just like Cout  ( jo bhi likho print hojayga)

        // format IP address
        auto formatIP = [](uint32_t ip) { //=> // Lambda function — ek chhota helper function
            std::ostringstream s;
            s << ((ip >> 0) & 0xFF) << "."
              << ((ip >> 8) & 0xFF) << "."
              << ((ip >> 16) & 0xFF) << "."
              << ((ip >> 24) & 0xFF);
            return s.str();
        };
        oss << formatIP(src_ip) << ":" << src_port
            << " -> "
            << formatIP(dest_ip) << ":" << dest_port
            << " (" << (protocol == 6 ? "TCP" : protocol == 17 ? "UDP" : "?")
            << ")";

        return oss.str();
    }
    // format IP address output should like
    // IP: 192.168.1.105

    //          uint32_t mein (little-endian):
    //              [ 105 | 1 | 168 | 192 ]
    //                  ↑                ↑
    //             byte 0           byte 3

    // ip >> 0  = byte 0 = 105  → pehla number nikala
    // ip >> 8  = byte 1 = 1
    // ip >> 16 = byte 2 = 168
    // ip >> 24 = byte 3 = 192

    // & 0xFF = sirf last 8 bits rakho (baaki sab zero karo)

}