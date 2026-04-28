# Deep-packet-analyser
Working on Deep Packet Inspection (DPI) systems that analyze internet data packets to validate, filter, and control traffic by allowing or blocking packets based on security and policy rules.



Platform.h role 
Network packets big-endian format mein aate hain, 
lekin PC little-endian hai — yeh file dono ke beech translator ka kaam karti hai.

Function                                      Kaam
swapBytes16/32                                Bytes ko physically ulta karta hai
isLittleEndian()                              Check karta hai — tera system little-endian hai ya nahi
netToHost16/32                                Network → tera PC (packet parse karte waqt)
hostToNet16/32                                PC → Network (packet bhejte waqt)


Kab use hoga?
packet_parser.cpp mein jab tu raw bytes se port/IP padhe: