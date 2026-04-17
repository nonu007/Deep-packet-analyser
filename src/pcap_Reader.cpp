#include "pcap_reader.h"
#include <cstring>
#include <iostream>

namespace packetAnalyzer
{
   // Magic numbers for PCAP files
   constexpr uint32_t PCAP_MAGIC_NATIVE = 0X1a2b3c4d;  // native byte order
   constexpr uint32_t PCAP_MAGIC_SWAPPED = 0X4d3c2b1a; // swapped byte order

   PcapReader::~PcapReader()
   {
      close();
   }
   bool PcapReader::open(const std::string &filename)
   {
      // close the file already opened
      close();
      // open in binary mode , crucial for reading raw bytes
      file_.open(filename, std::ios::binary);
      if (!file_.is_open())
      {
         std::cerr << "Error: Could not open file " << filename << std::endl;
         return false;
      }
      // read the global header (first 24 bytes of file )
      file_.read(reinterpret_cast<char *>(&global_header_), sizeof(PcapGlobalHeader));
      if (!file_.good())
      {
         std::cerr << "Error: Could not read PCAP global header from the file " << filename << std::endl;
         close();
         return false;
      }

      // check the magic number is determine byte order
      if (global_header_.magic_number == PCAP_MAGIC_NATIVE)
      {
         needs_byte_swap_ = false;
      }
      else if (global_header_.magic_number == PCAP_MAGIC_SWAPPED)
      {
         needs_byte_swap_ = true;

         // swap the global header fields to correct byte order
         global_header_.version_major = maybeswap16(global_header_.version_major);
         global_header_.version_minor = maybeswap16(global_header_.version_minor);
         // global_header_.thiszone = maybeswap32(global_header_.thiszone);
         // global_header_.sigfigs = maybeswap32(global_header_.sigfigs);
         global_header_.snaplen = maybeswap32(global_header_.snaplen);
         global_header_.network = maybeswap32(global_header_.network);
      }
      else
      {
         std::cerr << "Error: Invalid PCAP file " << filename << std::endl;
         close();
         return false;
      }

      std::cout << "Successfully opened PCAP file " << filename << std::endl;
      std::cout << "Version " << global_header_.version_major << "." << global_header_.version_minor << std::endl;
      std::cout << "Snaplen " << global_header_.snaplen << "bytes" << std::endl;
      std::cout << "Link-layer type " << global_header_.network << (global_header_.network == 1 ? "(Ethernet)" : "") << std::endl;

      return true;
   }

   // checking file is open if it is the close it and no need to swap
   void PcapReader::close()
   {
      if (file_.is_open())
      {
         file_.close();
      }
      needs_byte_swap_ = false;
   }

   bool PcapReader::readNextPacket(RawPacket &packet)
   {
      if (!file_.is_open())
      {
         std::cerr << "Error: No file is open for reading packets." << std::endl;
         return false;
      }

      // read the packet header (16 bytes)
      Pcap_packetHeader pkt_header;
      file_.read(reinterpret_cast<char *>(&pkt_header), sizeof(Pcap_packetHeader));
      if (!file_.good())
      {
         return false; // no more packets to read
      }

      // swap the packet header fields if needed
      if (needs_byte_swap_)
      {
         pkt_header.ts_sec = maybeswap32(pkt_header.ts_sec);
         pkt_header.ts_usec = maybeswap32(pkt_header.ts_usec);
         pkt_header.incl_length = maybeswap32(pkt_header.incl_length);
         pkt_header.orig_length = maybeswap32(pkt_header.orig_length);
      }

      // read the packet data based on incl_length
      packet.header = pkt_header;
      packet.data.resize(pkt_header.incl_length);
      file_.read(reinterpret_cast<char *>(packet.data.data()), pkt_header.incl_length);
      if (!file_.good())
      {
         std::cerr << "Error: Could not read complete packet data." << std::endl;
         return false;
      }

      return true; // successfully read a packet
   }
   // may be swap for 16 bit 
   uint16_t PcapReader::maybeswap16(uint16_t value)
   {
      if (needs_byte_swap_)
      {
         return (value >> 8) | (value << 8);
      }
      return value;
   }

      // may be swap for 32 bit
   uint32_t PcapReader::maybeswap32(uint32_t value)
   {
      if (needs_byte_swap_)
      {
         return ((value >> 24) & 0x000000FF) |
                ((value >> 8) & 0x0000FF00) |
                ((value << 8) & 0x00FF0000) |
                ((value << 24) & 0xFF000000);
      }
      return value;
   }

} // end of namespace PacketAnalyzer
