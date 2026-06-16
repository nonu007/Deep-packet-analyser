#ifndef PLATFORM_H
#define PLATFORM_H
#include <cstdint> // for fixed-width integer types

// Platform-specific definitions and includes
// this header provide portable byte-order conversion functions 
// "Har computer bytes alag order mein store karta hai — ye file us problem ko solve karti hai.

//Network hamesha Big Endian bhejta hai —  ye standard hai. 
// hamara laptop/PC hamesha Little Endian hai. Toh jab packet aaya aur tumne seedha padha — number ulta nikla!

// Port 443 network mein aaya as: 0xBB01
// Little Endian machine ne padha:   0x01BB = 443 nahi, 443 hai!
// Seedha padha toh:                 0xBB01 = 47873 — GALAT! 

// portable byte order conversion 
// works on any platform that do not need any system headers

namespace PortableNet{
    
    
inline uint16_t swapBytes16(uint16_t val) {
    return (val & 0xFF00) >> 8 | (val & 0x00FF) << 8;
}

inline uint32_t swapBytes32(uint32_t val){
    return ((val & 0xFF000000)  >> 24) |
           ((val & 0x00FF0000) >> 8) | 
            ((val & 0x0000FF00) << 8) | 
            ((val & 0x000000FF) << 24);
}


// check system endians at runtime 
inline bool isLittleEndian(){
    uint16_t test = 0x0001;
    return *reinterpret_cast<uint8_t*>(&test) == 0x01;
}

// network to host byte order (16 bit)

inline uint16_t netToHost16(uint16_t netValue){
    if(isLittleEndian()){
        return swapBytes16(netValue);
    }
    return netValue; // big endian system pe koi conversion nahi chahiye
}

// network to host byte order (32 bit)

inline uint32_t netToHost32(uint32_t netValue){
    if(isLittleEndian()){
        return swapBytes32(netValue);
    }
    return netValue; // big endian system pe koi conversion nahi chahiye
}

// host to network (16 bit)
inline uint16_t hostToNet16(uint16_t hostValue){
        return netToHost16(hostValue); // big endian system pe koi conversion nahi chahiye
}

inline uint32_t hostToNet32(uint32_t hostValue){
        return netToHost32(hostValue); // big endian system pe koi conversion nahi chahiye
}


// end if namespace PortableNet
};
#endif