# CPacketParser
A PacketParser based on PcapPlusPlus
Parses radius packets and outputs some information regarding each layer.

main.cpp no longer in use. User parser.cpp. Make is updated accordingly.

usage: ./parser <input> <packets> <repetitions>
  <input>       Either a pcap file or type N to listen via interface
  <packet>      Enter packet type. (radius, dns, udp etc)
  <repetitions> Enter number of times the program needs to run. (Benchmarking)
                Use 1 if not using a pcap file
  example usage: /parser Radius.pcap radius 5
