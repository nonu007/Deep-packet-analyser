#ifndef PLATFORM_H
#define PLATFORM_H
#include <cstdint>   // for use of fixed widh  integer types  ( ex , uint32_t,uint16_t....) 

// "Har computer bytes alag order mein store karta hai — ye file us problem ko solve karti hai.
namespace portableNet{

// agar alue recieved 16 bytes the this way me conversion hoga 
inline uint16_t swapBytes16(uint16_t value){
    return ((value & 0xFF00) >> 8) | ((value & 0x00FF) << 8);
}

// agar value recieved 16 bytes the this way me conversion hoga 
inline uint32_t swapBytes32(uint32_t value){
    return ((value & 0xFF000000) >> 24) |
            ((value & 0x00FF0000) >> 8) |
            ((value & 0x00FF0000) << 8) |
            ((value & 0x00FF0000) >> 24);
}

// checking system runtime endians , like what endian is accepted by system right now ( big endian or little endian) 
// reinterpret_cast tell us treat that 16 bit ( 2 byte number ) into 1 byte andthen search 1 byte m konsa number mila 
/// agar 00 mila means big endia and agar 01 mila to small endian
inline bool isLittleEndian(){
    uint16_t test  = 0x0001;
    return  *reinterpret_cast<uint8_t*>(&test) == 0x01;
}

// majorly saare modern system uses little endian , minorly use big endian
// net to host 16 byte
inline uint16_t netToHost16(uint16_t netValue){
    if(isLittleEndian()){
        return swapBytes16(netValue);
    }
    return netValue;
}

// for net to host 32 bytes
inline uint32_t netToHost32(uint32_t netValue){
    if(isLittleEndian()){
        return swapBytes32(netValue);
    }
    return netValue;
}

// host to net 16 byte
inline uint16_t hostToNet16(uint16_t hostValue){
    return netToHost16(hostValue);
}

// host to net 32 byte
inline uint32_t hostToNet32(uint32_t hostvalue){
    return netToHost32(hostvalue);
}

};
#endif  // end of platfrom 