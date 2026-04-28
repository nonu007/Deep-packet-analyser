#ifndef PLATFORM_H
#define PLATFORM_H

// Platform-specific definitions and includes
// this header provide portable byte-order conversion functions 

#include <cstdint> // for fixed-width integer types

// portable byte order conversion 
// works on any platform that do not need any system headers

namespace PortableNet{
    
    inline uint16_t swapbytes16(uint16_t val){
        return (val << 8) | (val >> 8);
    }

    inline uint32_t swapbytes32(uint32_t val){
        return ((val << 24) & 0xFF000000) |
               ((val << 8)  & 0x00FF0000) |
               ((val >> 8)  & 0x0000FF00) |
               ((val >> 24) & 0x000000FF);
    }

    // checking system ediannes at runtime
    inline bool isLittleEndian(){
        uint16_t test = 0x0001;
        return *(reinterpret_cast<uint8_t*>(&test)) == 0x01;
    }

    // network to host byte order 16 bit 
    // network  byte order is always big-endian 

    inline uint16_t netTohost16(uint16_t netvalue){
        if(isLittleEndian()){
            return swapbytes16(netvalue);
        }
        return netvalue; // already big-endian
    }

    //network to host byte order 32 bit
    inline uint32_t netTohost32(uint32_t netValue){
        if(isLittleEndian()){
            return swapbytes32(netValue);
        }
        return netValue; // already big-endian   ---------------------
    }

    // host to network byte order 16 bit
    inline uint16_t hosttonet16(uint16_t hostValue){
        if(isLittleEndian()){
            return netTohost16(hostValue);
        }
        return hostValue; // already big-endian
    }


    // host to network byte order 32 bit
    inline uint32_t hosttonet32(uint32_t hostValue){
        if(isLittleEndian()){
            return netTohost32(hostValue);
        }
        return hostValue; // already big-endian
    }

} // end if namespace PortableNet

#endif