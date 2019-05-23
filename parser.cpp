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

size_t count=0; //total packet count
size_t totalRadiusPackets=0; //total radius pacekets

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

class PacketInfo{
  public:
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
bool handle_radius(pcpp::Packet& packet){
  count++;
  if(!packet.isPacketOfType(pcpp::Radius)){
    return true;
  }
  pcpp::RadiusLayer* radiusLayer = packet.getLayerOfType<pcpp::RadiusLayer>();
  totalRadiusPackets++;
 if(radiusLayer==NULL){
  std::cout<<"Couldn't read radius Layer\n";
  return true;
 }
 int attr_count = radiusLayer->getAttributeCount();
 int MessageID = radiusLayer->getRadiusHeader()->id;
 int code = radiusLayer->getRadiusHeader()->code;
 std::cout<<"radius attr count: "<<attr_count<<"\n";
 std::cout<<"radius message code: "<<MessageID<<"\n";
 std::cout<<"radius header code: "<<code<<"\n";
 std::cout<<"Attributes:--\n";
 pcpp::RadiusAttribute radiusAttribute = radiusLayer->getFirstAttribute();
 for(int i=0;i<10;i++){
   std::cout<<"\tAVP: "<<i<<"\n";
   int a_type= radiusAttribute.getType();
   int a_total_size= radiusAttribute.getTotalSize();
   int a_data_size= radiusAttribute.getDataSize();
   std::cout<<"\t\ta_type: "<<a_type<<"\n";
   std::cout<<"\t\ta_total_size: "<<a_total_size<<"\n";
   std::cout<<"\t\ta_data_size: "<<a_data_size<<"\n";
   radiusAttribute = radiusLayer->getNextAttribute(radiusAttribute);
 } 
 radiusAttribute = radiusLayer->getAttribute(40);
 int a_type= radiusAttribute.getType();
 int a_data_size= radiusAttribute.getDataSize();
 int a_total_size = radiusAttribute.getTotalSize();
 //std::string value(radiusAttribute.getValue());
 std::cout<<"a_type: "<<a_type<<"\n";
 std::cout<<"a_total_size: "<<a_total_size<<"\n";
 std::cout<<"a_data_size :"<<a_data_size<<"\n";
 //std::cout<<"value: "<<value<<"\n";
 std::cout<<"value: "<<radiusAttribute.getValue()<<"\n";

 std::cout<<"---------\n";
 return true; 
}


//For Future Use
bool handle_packet(pcpp::Packet& packet){
  //
  //
  //Enter Your Code Here
  //
  //
  return true;
}

int main(int argc, char* argv[]){
  if(argc!=4){
    printHelp(argv);
  }
  std::cout<<"argv[1]: "<<argv[1]<<" argv2: "<<argv[2]<<" argv[3]: "<<argv[3]<<"\n";
  std::chrono::high_resolution_clock myclock;
  std::string input_type(argv[1]); //input_type
  std::string packet_type(argv[2]); //packet_type
  int total_reps = std::stoi(argv[3]); //total_reps
  size_t total_packets=0;
  std::vector<std::chrono::high_resolution_clock::duration> durations;
  if(input_type!="n"){
    std::cout<<"PcapFILE\n";
    
    for(int i=0;i<total_reps;i++){
      //Reset variables for next iteration
      count = 0;
      totalRadiusPackets=0;
      pcpp::IFileReaderDevice* reader = pcpp::IFileReaderDevice::getReader(argv[1]);

      //Check FileType -- Error 
      if(reader==NULL){
        std::cout<<"Cannot determine file type:\n";
        exit(1);
      }
    
      //Cannot Open file
      if(!reader->open()){
        std::cout<<"Cannot open file for reading.\n";
        exit(1);
      }

      reader->open();
      std::chrono::high_resolution_clock::time_point start;
      if(packet_type=="radius"){
        start=std::chrono::high_resolution_clock::now();
        pcpp::RawPacket raw_packet;
        while(reader->getNextPacket(raw_packet) && totalRadiusPackets<=5){
          pcpp::Packet packet(&raw_packet);
          handle_radius(packet);
        }
      }else{
          std::cout<<"Not yet\n";
          start=std::chrono::high_resolution_clock::now();
          pcpp::RawPacket raw_packet;
          pcpp::Packet packet(&raw_packet);
          handle_packet(packet);
      }
      auto end = std::chrono::high_resolution_clock::now();
      durations.push_back(end-start);
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
    std::cout<<"(total_packets/total_reps) "<<total_packets/total_reps<<"\n";
    std::cout<<"(total_time_in_ms/durations.size()) "<< (total_time_in_ms/durations.size())<<"\n";
    
  }
}
