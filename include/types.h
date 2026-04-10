#ifndef DPI_TYPES_H
#define DPI_TYPES_H
#include <cstdint>
#include <chrono>
#include <string>
#include <vector>
#include <functional>
#include <atomic>
// #include <optional>
namespace DPI
{
    // ============================================================================
    // Five-Tuple: Uniquely identifies a connection/flow
    // ============================================================================

    // struct ka use hota hai multiple related data ko ek hi jagah group karne ke liye.
    struct FiveTuple
    {
        uint32_t src_ip;
        uint32_t dest_ip;
        uint16_t src_port;
        uint16_t dest_port;
        uint8_t protocol; // TCP = 6 , UDP = 17

        bool operator==(const FiveTuple &other) const
        { // flow identify
            return src_ip == other.src_ip &&
                   dest_ip == other.dest_ip &&
                   src_port == other.src_port &&
                   dest_port == other.dest_port &&
                   protocol == other.protocol;
        }
        // operator== ==> operator overloading
        // other = doosra object jisse compare karna hai
        // & = reference (copy nahi banegi → fast)
        // const = isko change nahi kar sakte

        // Create reverse tuple (for matching bidirectional flows)
        FiveTuple reverse() const
        {
            return {src_ip, src_port, dest_ip, dest_port, protocol};
        }

        std ::string toString() const; // object ko human readable string me convert karne wala function
    };

    // Hash function for FiveTuple (used for load balancing)
    struct FiveTupleHash
    {
        size_t operator()(const FiveTuple &tuple) const
        {
            // simple but combining all fields for hashing
            size_t h = 0; // for storing final hash
            h ^= std::hash<uint32_t>{}(tuple.src_ip) + 0x9e3779b9 + (h << 6) + (h >> 2);
            h ^= std::hash<uint32_t>{}(tuple.dest_ip) + 0x9e3779b9 + (h << 6) + (h >> 2);
            h ^= std::hash<uint16_t>{}(tuple.src_port) + 0x9e3779b9 + (h << 6) + (h >> 2);
            h ^= std::hash<uint16_t>{}(tuple.dest_port) + 0x9e3779b9 + (h << 6) + (h >> 2);
            h ^= std::hash<uint8_t>{}(tuple.protocol) + 0x9e3779b9 + (h << 6) + (h >> 2);

            //  h XOR= std::hash<fixed_size_variable_type>{}(tuple.filed_name) + unique + (leftshift*6) + (rightshift/2);
            // ex :- src_ip will be 1 after calculation hash and bfore hash it will be 1 then h^=1 will be  1^1 =0
            return h; // return the value of fivetuplehash
        }
    };

    // ============================================================================
    // Application Classification
    // ============================================================================
 
    // DPI ka brain hai — yahi decide karega packet kis app ka hai
    enum class AppType
    {
        UNKNOWN = 0,
        HTTP,
        HTTPS,
        DNS,
        TLS,
        QUIC,
        // Specific applications (detected via SNI)
        ACEBOOK,
        YOUTUBE,
        TWITTER,
        INSTAGRAM,
        NETFLIX,
        AMAZON,
        MICROSOFT,
        APPLE,
        WHATSAPP,
        TELEGRAM,
        TIKTOK,
        SPOTIFY,
        ZOOM,
        DISCORD,
        GITHUB,
        CLOUDFLARE,
        APP_COUNT // Keep this last for counting
    };
    std::string AppTypetostring(AppType type);  // ye function convert karega: AppType → string
    AppType sniAppType(const std::string &sni); // explanation 👇
    // AppType app = AppType::YOUTUBE;
    // std::string name = AppTypeToString(app);

    // ============================================================================
    // Connection State
    // ============================================================================

    //Enum ka use hota hai predefined named constants dene ke liye, taaki code readable, safe aur maintainable bane.
    enum class ConnectionState
    {
        NEW,
        ESTABLISHED,
        CLASSIFIED,
        CLOSED,
        BLOCKED,
    };

// ============================================================================
// Packet Action (what to do with the packet)
// ============================================================================

enum class PacketAction{
    FORWARD,
    DROP,
    INSPECT,
    LOG_ONLY
};

// ============================================================================
// Connection Entry (tracked per flow)
// ============================================================================

// Connection struct = ek poore network flow ka record hai
//👉 DPI ka core yahi hai — har connection ka data yaha store hota hai

struct Connection{
    FiveTuple tuple;
    ConnectionState state = ConnectionState::NEW;     // connection state => NEW, CONNECTED ETC.
    AppType app_type = AppType::UNKNOWN; // apptype value default is UNKNOWN =0 and increase according to the give list. 
    std::string sni; // Server Name Indification (if identified)

    // ek connection me kitna data aaya-gaya uska record   [ in	means internet → user    , out means	user → internet]
    uint64_t packet_in =0; 
    uint64_t packet_out =0;  // ========== in short : - connection me kitna traffic aaya-gaya uski ginti ========== 
    uint64_t bytes_in =0;
    uint64_t bytes_out =0;
    
    // connection kab start hua aur last packet kab aaya , ye sara time store krta hu 
    std::chrono::steady_clock::time_point first_seen; 
    std::chrono::steady_clock::time_point last_seen;
    // std::time_p measure::clock type ::timestamp object first_seen / last_seen

    PacketAction action = PacketAction::FORWARD;
    // means what we have to do by this packet 


    //for TCP state tracking  => Note :- TCP connection start hua, confirm hua, aur close hua ya nahi
    bool syn_seen = false;  //   ---------> client ne connection start kiya ya nahi  ( call dial ki  ) 
    bool syn_ack_seen = false; //      ---> server ne reply diya ya nahi  ( saamne wale ne uthaya  )
    bool fin_seen = false ; // -----------> connection close hone laga ya nahi  ( call cut ki  ) 
};

// ============================================================================
// Packet wrapper for queue passing
// ============================================================================

struct packetJob{
    uint32_t packet_id;
    FiveTuple tuple;
    std::vector<uint8_t>data;
    size_t eth_offset = 0;
    size_t ip_offset = 0;
    size_t transport_offset =0;
    size_t payload_offset =0;
    size_t payload_length =0;
    uint8_t tcp_flags =0;
    const uint8_t* payload_data = nullptr;

    //timestamps 
    uint32_t ts_sec;
    uint32_t ts_usec;

};

// ============================================================================
// Statistics - uses regular uint64_t, protected by mutex externally
// ============================================================================

// har packet ka overall count yahi track karega
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

} // namespace end

#endif // end of DPI_TYPES