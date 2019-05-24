#include "in.h" //for ntohs() and htons()
#include "stdlib.h"
#include "stdio.h"
#include "Packet.h"
#include "EthLayer.h"
#include "IPv4Layer.h"
#include "TcpLayer.h"
#include "UdpLayer.h"
#include "HttpLayer.h"
#include "RadiusLayer.h"
#include "PcapFileDevice.h"

#include <string>
#include <iostream>
#include <chrono>
#include <vector>
#include <numeric>

size_t count = 0;             //total packet count
size_t totalRadiusPackets = 0;//total radius pacekets
size_t not_radius = 0;        //not radius packets
//Usage Help
void printHelp(char* argv[]){
  std::cout<<"\tusage: "<<*argv<<"<input> <packets> <repetitions>\n";
  std::cout<<"\t<input>      \tEither a pcap file or type N to listen via interface\n";
  std::cout<<"\t<packet>     \tEnter packet type. (radius, dns, udp etc)\n";
  std::cout<<"\t<repetitions>\tEnter number of times the program needs to run. (Benchmarking)\n";
  std::cout<<"\t\t\tUse 1 if not using a pcap file\n";
  std::cout<<"\texample usage: /parser Radius.pcap radius 5\n";
  exit(1);
}

struct PacketInfo{
    //src ip
    //dst ip
    //src mac
    //dst mac
    //src port
    //dst port
    //rad code
    //code message string
    //msisdn
};

//Handle Radius Packet
int handle_radius(pcpp::Packet& packet){
  count++;
  if(!packet.isPacketOfType(pcpp::Radius)){
    //std::cout << "not radius!\n"; 
    not_radius++;
    return 1;
  }
  pcpp::RadiusLayer* radiusLayer = packet.getLayerOfType<pcpp::RadiusLayer>();
  totalRadiusPackets++;
 if(radiusLayer==NULL){
  std::cout<<"Couldn't read radius Layer\n";
  return 1;
 }
 int attr_count = radiusLayer->getAttributeCount();
 int MessageID = radiusLayer->getRadiusHeader()->id;
 int code = radiusLayer->getRadiusHeader()->code;
 //std::cout<<"radius attr count: "<<attr_count<<"\n";
 //std::cout<<"radius message code: "<<MessageID<<"\n";
 //std::cout<<"radius header code: "<<code<<"\n";
 //std::cout<<"Attributes:--\n";
 pcpp::RadiusAttribute radiusAttribute = radiusLayer->getFirstAttribute();
  
 radiusAttribute = radiusLayer->getAttribute(40);
 int a_type= radiusAttribute.getType();
 int a_data_size= radiusAttribute.getDataSize();
 int a_total_size = radiusAttribute.getTotalSize();
 //std::string value(radiusAttribute.getValue());
 //std::cout<<"a_type: "<<a_type<<"\n";
 //std::cout<<"a_total_size: "<<a_total_size<<"\n";
 //std::cout<<"a_data_size :"<<a_data_size<<"\n";
 //std::cout<<"value: "<<value<<"\n";
 //std::cout<<"value: "<<radiusAttribute.getValue()<<"\n";
/* 
 // NAS-IO-Address (4)
 // Data Type: ipv4addr
 radiusAttribute = radiusLayer->getAttribute(4);
 std::cout<<"value(4): "<<radiusAttribute.getValue()<<"\n";
 
 // NAS-Port (5)
 // Data Type: integer
 radiusAttribute = radiusLayer->getAttribute(5);
 std::cout<<"value(5): "<<radiusAttribute.getValue()<<"\n";
 
 // Framed-IP-Address (8)
 // Data Type: ipv4addr
 radiusAttribute = radiusLayer->getAttribute(8);
 std::cout<<"value(8): "<<radiusAttribute.getValue()<<"\n";
 
 // Framed-IP-Netmask (9)
 // Data Type: ipv4addr
 radiusAttribute = radiusLayer->getAttribute(9);
 std::cout<<"value(9): "<<radiusAttribute.getValue()<<"\n";

 
 // Callback-Number (19)
 // Data Type: text
 radiusAttribute = radiusLayer->getAttribute(19);
 std::cout<<"value(19): "<<radiusAttribute.getValue()<<"\n";
 
 // Callback-ID (20)
 // Data Type: text
 radiusAttribute = radiusLayer->getAttribute(20);
 std::cout<<"value(20): "<<radiusAttribute.getValue()<<"\n";

 // Acct-Status-Type(40)
 // Data Type: enum
 radiusAttribute = radiusLayer->getAttribute(40);
 std::cout<<"value(40): "<<radiusAttribute.getValue()<<"\n";
*/
 //std::cout<<"---------\n";
 return 1; 
}


//For Future Use
int handle_packet(pcpp::Packet& packet){
  //
  //
  //Enter Your Code Here
  //
  //
  return 1;
}

int main(int argc, char* argv[]){
  if(argc!=4){
    printHelp(argv);
  }
  std::cout << "argv[1]: " << argv[1] << " argv2: " << argv[2] << " argv[3]: " << argv[3] << "\n";
  std::chrono::high_resolution_clock myclock;
  std::string input_type(argv[1]); //input_type
  std::string packet_type(argv[2]); //packet_type
  int total_reps = std::stoi(argv[3]); //total_reps
  size_t total_packets=0;
  std::vector<std::chrono::high_resolution_clock::duration> durations;
  if(input_type!="n"){

    // Display filename
    std::cout << "Using file: " << argv[1] << "\n";
    
    for(int i=0; i<total_reps; i++){
      //Reset variables for next iteration
      count = 0;
      totalRadiusPackets = 0;
      not_radius = 0;
      pcpp::IFileReaderDevice* reader = pcpp::IFileReaderDevice::getReader(argv[1]);

      //Check FileType -- Error 
      if(reader==NULL){
        std::cout << "Cannot determine file type:\n";
        exit(1);
      }
    
      //Cannot Open file
      if(!reader->open()){
        std::cout << "Cannot open file for reading.\n";
        exit(1);
      }

      reader->open();
      std::chrono::high_resolution_clock::time_point start;
      if(packet_type == "radius"){
        start = std::chrono::high_resolution_clock::now();
        pcpp::RawPacket raw_packet;
        while(reader->getNextPacket(raw_packet)){// && totalRadiusPackets<=5){
          pcpp::Packet packet(&raw_packet);
          handle_radius(packet);
        }
      }else{
          std::cout << "Not yet\n";
          start=std::chrono::high_resolution_clock::now();
          pcpp::RawPacket raw_packet;
          pcpp::Packet packet(&raw_packet);
          handle_packet(packet);
      }
      auto end = std::chrono::high_resolution_clock::now();
      durations.push_back( end-start );
      total_packets += count;
      reader->close();
    

    }
    auto total_time = std::accumulate(
        durations.begin(),
        durations.end(),
        std::chrono::high_resolution_clock::duration(0)
        );

    using std::chrono::duration_cast;
    using std::chrono::milliseconds;
    auto total_time_in_ms = duration_cast<milliseconds>(total_time).count();
    std::cout << "(total_packets:total_reps):\t\t " << totalRadiusPackets << "::" << total_reps << ":: \t" <<total_packets/total_reps<<"\n";
    std::cout << "(total_time_in_ms/durations.size()):\t " << total_time_in_ms << "/ " << durations.size() << ": \t" << (total_time_in_ms/durations.size())<<"\n";
    std::cout << "Other Packets:\t\t\t\t" << not_radius << "\n";
    std::cout << "Total Packets:\t\t\t\t" << count << "\n";
    std::cout << "Average Total Time(ms): \t\t" << total_time_in_ms/durations.size() << "\n";
    std::cout << "Average Time/Packet(ms): \t\t" <<(double)((double)(total_time_in_ms/durations.size())/count)<< "\n";

    
  }
}
