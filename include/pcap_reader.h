#ifndef PCAP_READER_H
#define PCAP_READER_H

#include <cstdint>
#include <vector>
#include <string>
#include <fstream>

namespace PacketAnalyzer
{
    // Pcap global header, starting 24 bytes of file
    // this isi the very beggining of the packet
    struct PcapGlobalHeader
    {

        uint32_t magic_number; // 0xa1b2c3d4
        uint16_t version_major;
        uint16_t version_minor;
        int32_t thiszone;
        uint32_t sigfigs; // timestamps
        uint32_t snaplen; // max lengeth of captured packet
        uint32_t network; // data link layer( ETherneet =1, Tls =2, TCP=3,.... etc)
    };
    // Each packet in the file starts from these listed header
    // pcap header 16 bytes
    struct PcapPacketHeader
    {
        uint32_t ts_sec;      // timestamps in seconds
        uint32_t ts_usec;     // timestamps in micro-seconds
        uint32_t inc_len;  // number of bytes saved in file
        uint32_t orig_len; // actual length of packet
    };

    // struct of a singlr capture  packet

    struct RawPacket
    {
        PcapPacketHeader header;
        std::vector<uint8_t> data;
    };
    class PcapReader
    {

    private:
        std::ifstream file_;
        PcapGlobalHeader global_header_;
        bool needs_byte_swap_ = false;

        // helper if need to swap byte
        uint16_t maybeSwap16(uint16_t value);
        uint32_t maybeSwap32(uint32_t value);

    public:
        PcapReader() = default;
        ~PcapReader();

        // open the fie for reading the packet
        bool open(const std::string &filename);

        // close the file
        void close();

        // read the next packet , retrn false if no more packets recieved
        bool ReadNextPacket(RawPacket &packet);

        // if recieved the packet , get the global header info
        const PcapGlobalHeader &getGlobalHeader() const
        {
            return global_header_;
        }

        // checking file is open
        bool isOpen() const
        {
            return file_.is_open();
        }

        // check if we need to swap byte
        bool needsByteSwap() const {
             return needs_byte_swap_;
        }
    };

} // end of namespace ppacketAnalyzer

#endif // end of pcap readere