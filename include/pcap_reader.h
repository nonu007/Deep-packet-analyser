#ifndef PCAP_READER_H
#define PCAP_READER_H

#include <cstdint>
#include <vector>
#include <string>
#include <fstream> // for file handling

using namespace packetAnalyzer
{

    // Global pcap header at the very begining  every pcap file.

    struct PcapGlobalHeader
    {

        uint32_t magic_number;     // for swap (for big endian)   , endianness => (matlab data seedha read karna hai ya reverse karke)
        uint16_t version_major     // PCAP file ka format version (usually 2.4)
            uint16_t version_minor // PCAP file ka format version (usually 2.4)
                int32_t thiszone;  // usulaly 0  (ignore)
        uint32_t sigfigs           // timestamps usually 0
            uint32_t snaplen       // max length of captured packet
                uint32_t network   // data link layer (1 means ethernet )
    };

    // PCAP header
    struct Pcap_packetHeader
    {
        uint32_t ts_sec;         // timestamp in seconds
        uint32_t ts_usec;        // timestamp in micro-seconds
        uint32_t incl_length     // number of bytes saved in a file
            uint32_t orig_length // actual length of packet
    };

    // represent a single captured packet
    struct RawPacket
    {
        Pcap_packetHeader header;
        std::vector<uint8_t> data; // actual packet bytes data
    };

    // class to read pcap files
    class pcapReader
    {
    public:
        pcapReader() = default;
        ~pcapReader();

        // open th file for reading
        bool open(const std::string &filename);

        // close the file after reading
        void close();

        // read the next packet , if no more packet found , return false
        bool readNextPacket(RawPacket &packet);

        // get the globaheader of the file
        const PcapGlobalHeader &getGlobalHeader() const { return global_header_; }

        // check is the file open
        bool isOpen() const { return file_.is_open(); }

        // check if we need to swap the byte order
        bool needsByteSwap const { return needs_bte_swap; }

    private:
        std::ifstream file_;
        PcapGlobalHeader global_header;
        bool need_byte_swap = false;

        // helper to say bytes if needed 
        uint32_t maybeswap32(uint32_t value);
        uint16_t maybeswap16 (uint16_t value);    
    };
}

#endif
