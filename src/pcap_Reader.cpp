#include "pcap_reader.h"
#include <cstring>
#include <iostream>

namespace PacketAnalyzer // same namespace as in pcapreader header file
{

   // magic numbers for pcap file
   // constexpr :- "Ye value compile time pe hi fix hai, kabhi nahi badlegi, memory waste mat karo"
   constexpr uint32_t PCAP_MAGIC_NATIVE = 0xa1b2c3d4;  // native byte order (withour swap)
   constexpr uint32_t PCAP_MAGIC_SWAPPED = 0xd4c3b2a1; // why swapped , bcoz Intel processor bytes ulte store karta hai

   PcapReader ::~PcapReader()
   {
      close();
   }
   // open the file and getting the header and adding it to create rawpacket
   bool PcapReader ::open(const std::string &filename)
   {
      // close file if previosuly opened
      close();

      // open file in binary mode
      file_.open(filename, std::ios::binary);
      if (!file_.is_open())
      {
         std::cerr << " Error: Could not open file " << filename << std::endl;
      }

      // read the globla header from the file
      file_.read(reinterpret_cast<char *>(&global_header_), sizeof(PcapGlobalHeader));
      // if file not good
      if (!file_.good())
      {
         std::cerr << " Error : Sorry Couldn't read Pcap global header  " << std::endl;
         close();
         return false;
      }
      // check the magic number to determine the byte order
      if (global_header_.magic_number == PCAP_MAGIC_NATIVE)
      {
         needs_byte_swap_ = false;
      }
      else if (global_header_.magic_number == PCAP_MAGIC_SWAPPED)
      {
         needs_byte_swap_ = true;
         // swap the header fields to the correct byte order
         global_header_.version_major = maybeSwap16(global_header_.version_major);
         global_header_.version_minor = maybeSwap16(global_header_.version_minor);
         global_header_.snaplen = maybeSwap32(global_header_.snaplen);
         global_header_.network = maybeSwap32(global_header_.network);
      }
      else
      {
         std::cerr << "Error : Invalid PCAP magic number : OK"
                   << std::hex << global_header_.magic_number << std::dec << std::endl;
         close();
         return false;
      }

      std::cout << "Opened PCAP file" << filename << std::endl;
      std::cout << "Version " << global_header_.version_major
                << "." << global_header_.version_minor << std::endl;
      std::cout << "Snap len" << global_header_.snaplen << " bytes" << std::endl;
      std::cout << "Link type " << global_header_.network << (global_header_.network == 1 ? " (Ethernet) " : "") << std::endl;

      return true;
   }

   // after create raw packet , close the file
   void PcapReader ::close()
   {
      if (file_.is_open())
      {
         file_.close();
      }
      needs_byte_swap_ = false;
   }

   bool PcapReader ::ReadNextPacket(RawPacket &packet)
   {
      if (!file_.is_open())
      {
         return false;
      }

      // read the header in (16 bytes)
      file_.read(reinterpret_cast<char *>(&packet.header), sizeof(PcapPacketHeader));
      if (!file_.good())
      {
         return false;
      }
      // swap bytes if needed
      if(needs_byte_swap_){
         packet.header.ts_sec = maybeSwap32(packet.header.ts_sec);
         packet.header.ts_usec = maybeSwap32(packet.header.ts_usec);
         packet.header.inc_len = maybeSwap32(packet.header.inc_len);
         packet.header.orig_len = maybeSwap32(packet.header.orig_len);
      }

      // sanity check on packet length
      if(packet.header.inc_len > global_header_.snaplen 
         ||packet.header.inc_len > 65535){
         std::cerr << " Error : invalid packet length "
         <<packet.header.inc_len <<std::endl;
      }
     
      // read the packet data 
      packet.data.resize(packet.header.inc_len);
      file_.read(reinterpret_cast<char*> (packet.data.data()),
      packet.header.inc_len);
      if(!file_.good()){
         std::cerr << "Error : Could not read packet data "<<std::endl;
         return false;
      }
      return true;

   }

   // swap into 16 bytes
   uint16_t PcapReader ::maybeSwap16(uint16_t value) {
      if(!needs_byte_swap_){
         return value;
      } return ((value & 0x00FF) <<8 ) | ((value & 0xFF00) >> 8);
   }

   // swap into 16 bytes
   uint32_t PcapReader ::maybeSwap32(uint32_t value) {
      if(!needs_byte_swap_){
         return value;
      } return ((value & 0x000000FF) << 24) |
                ((value & 0x0000FF00) << 8) |
                ((value & 0x00FF0000) >> 8) |
                ((value & 0xFF000000) >> 24);
   }
} // end of namespace PacketAnalyzer