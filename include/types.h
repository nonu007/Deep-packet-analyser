#ifndef DPI_TYPES_H
#define DPI_TYPES_H

#include <cstdint>
#include <string>
#include<vector>
#include<functional>
#include<chrono>
#include<optional>
#include<atomic>


namespace DPI{

    //==========================================================================
    // FIve Tuple uniquly idenifies a connection / flow 
    //==========================================================================

    struct FiveTuple{
        uint32_t src_ip;
        uint32_t dst_ip;
        uint16_t src_port;
        uint16_t dst_port;
        uint8_t protocol;
    
    // equality check  => hashmap ke liye zaroori 
        bool operator == (const FiveTuple & tuple ) const {
             return 
             src_ip == tuple.src_ip &&
             src_port ==  tuple.src_port &&  
             dst_ip == tuple.dst_ip &&
             dst_port == tuple.dst_port &&
            protocol == tuple.protocol;
        }
  // creating reverse tuple ( for directional matching flow )
        FiveTuple reverse() const {
            //  return { dst_ip, src_ip, dst_port, src_port, protocol }/
              return { dst_ip,src_ip,dst_port,src_port, protocol };
        }
        std::string toString() const ;
    };

    // hash function for five tuple 
    // because c++ do not know about how to do hash of FiveTuple 
    struct FiveTupleHash{
        size_t operator() (const FiveTuple &tuple) const{
            
     // basically we create a struct who helps to C++ to uderstand how to calcultae hash of FiveTuple 
            size_t h =0;
            h^= std::hash<uint32_t>{}(tuple.src_ip) + 0x9e3779b9 + (h << 6) + (h >> 2);
            h^= std::hash<uint32_t>{}(tuple.dst_ip) + 0x9e3779b9 + (h << 6) + (h >> 2);
            h^= std::hash<uint16_t>{}(tuple.src_port) + 0x9e3779b9 + (h << 6) + (h >> 2);
            h^= std::hash<uint16_t>{}(tuple.dst_port) + 0x9e3779b9 + (h << 6) + (h >> 2);
            h^= std::hash<uint8_t>{}(tuple.protocol) + 0x9e3779b9 + (h << 6) + (h >> 2);
            return h;
        }
    };

    //==========================================================================
    // Application classifciation which ap i have to allow and blokc 

   enum class AppType {
    UNKNOWN = 0, HTTP,HTTPS,DNS,TLS,
    QUIC,GOOGLE,FACEBOOK,YOUTUBE,TWITTER,INSTAGRAM,NETFLIX,AMAZON,MICROSOFT,APPLE,WHATSAPP,
    TELEGRAM,TIKTOK,SPOTIFY,ZOOM,DISCORD,GITHUB,CLOUDFLARE,
    APP_COUNT,};

    std::string appTypetoString(AppType appType);
    AppType sniToAppType(const std::string &sni);

//============================================================================
// Connection State
// ============================================================================

enum class ConnectionState{
    NEW,
    ESTABLISHED,
    CLOSED,
    CLASSIFIED,
    BLOCKED
};

//============================================================================
// pACKET aCTION : WHAT TO DO NEXT WITH THIS PACKET 
// ============================================================================

enum class PacketAction{
    FORWARD,    // SEND TO INTERNET 
    DROP,       // BLOCK/DROP THE ACKET 
    INSPECT,       // NEEDS FURTHER INSPECTION ( FOR EXAMPLE DEEP PACKET INSPECTION )
    LOG_ONLY      // JUST LOG THE PACKET INFO WITHOUT TAKING ANY ACTION 
};

//============================================================================
// Connection Entry tracked per flow in DPI engine 
// ============================================================================

struct Connection {
    FiveTuple tuple;
    ConnectionState state = ConnectionState::NEW;
    AppType appType = UNKNOWN;
    std::string sni;

    uint64_t packet_in =0;
    uint64_t packet_out =0;
    uint64_t butes_in =0;
    uint64_t bytes_out =0;

    std::chrono::steady_clock::time_point first_seen;
    std::chrono::steady_clock::time_point last_seen; // for timeout and eviction

    PacketAction action =  PacketAction::FORWARD; // default action is to forward the packet

    // for the TCP state tracking 
    bool syn_seen = flase ;
    bool syn_ack_seen = false;
    bool fin_seen = flase;
};


//=========================================================
// Packet Wrapper for queue passing 
//==========================================================

struct PacketJob{
    uint32_t packet_id;
    FiveTuple tuple;
    std::vector<uint8_t> data; // packet data for deep inspection
    size_t eth_offset =0;  //Ethernet header ki starting position
    //eth_offset = 0  => (mostly hamesha 0 hi hota hai — start se)
    size_t ip_offset =0; // IP header ki starting position
    //ip_offset = 14  =>  (kyunki Ethernet header 14 bytes ka hota hai)
    size_t transport_offset =0;
    size_t payload_offset =0;
    size_t payload_length =0;
    uint8_t tcp_flags =0; // for TCP packet state tracking
    const uint8_t* payload_data = nullptr; // pointer to the payload data for direct access during inspection

    // timestamps
    uint32_t timestamp_sec;
    uint32_t timestamp_usec;

};

// ============================================================================
// Statistics - uses regular uint64_t, protected by mutex externally
// ============================================================================
struct DPIStats {
    std::atomic<uint64_t> total_packets{0};
    std::atomic<uint64_t> total_bytes{0};
    std::atomic<uint64_t> forwarded_packets{0};
    std::atomic<uint64_t> dropped_packets{0};
    std::atomic<uint64_t> tcp_packets{0};
    std::atomic<uint64_t> udp_packets{0};
    std::atomic<uint64_t> other_packets{0};
    std::atomic<uint64_t> active_connections{0};
    
    // Non-copyable due to atomics
    DPIStats() = default;
    DPIStats(const DPIStats&) = delete;
    DPIStats& operator=(const DPIStats&) = delete;
};

} // namespace DPI
#endif //DPI_TYPES_H