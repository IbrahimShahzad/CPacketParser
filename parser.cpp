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

struct Radius_Attribute{
  int code;
  int type;
  int dataSize;
  int totalSize;
  char value[20];
};

struct PacketInfo{
  //IPV4
  //src ip
  //dst ip
  char ipv4_src[16];
  char ipv4_dst[16];
  //Ethernet
  //src mac
  //dst mac
  char mac_src[20];
  char mac_dst[20];
  //src port
  //dst port
  int port_src;
  int port_dst;
  //Radius----------
  //rad_attr_count
  //rad_Code
  //rad_MessageID
  int rad_attrcount;
  int rad_code;
  int rad_msgID;
  //code message string
  //Attributes-------
  //msisdn
  //FramedIP
  // Framed-IP-Address (8)
  Radius_Attribute attr_framedIpv4;
  Radius_Attribute attr_framedIpv4Netmask;
  // Data Type: ipv4addr
  // Framed-IP-Netmask (9)
  // Data Type: ipv4addr
  // Callback-Number (19)
  Radius_Attribute attr_callBackNumber;
  // Data Type: text
  // Callback-ID (20)
  Radius_Attribute attr_callBackId;
  // Data Type: text
  // Acct-Status-Type(40)
  Radius_Attribute attr_accStatusType;
  // Data Type: enum
  //Acct-Status
  Radius_Attribute attr_callingStationId;
};

// Global
PacketInfo Rpack;

//initialize all values
void initialize_PacketInfo(){
  strcpy(Rpack.ipv4_src," ");
  strcpy(Rpack.ipv4_dst," ");
  strcpy(Rpack.mac_src," ");
  strcpy(Rpack.mac_dst," ");
  Rpack.port_src = 0;
  Rpack.port_dst = 0;
  Rpack.rad_attrcount = 0;
  Rpack.rad_code = 0;
  Rpack.rad_msgID = 0;

  Rpack.attr_accStatusType.code = 40;
  strcpy(Rpack.attr_accStatusType.value," ");
  Rpack.attr_accStatusType.type = -1;
  Rpack.attr_accStatusType.dataSize = -1;
  Rpack.attr_accStatusType.totalSize = -1;

  Rpack.attr_framedIpv4.code = 8;
  strcpy(Rpack.attr_framedIpv4.value," ");
  Rpack.attr_framedIpv4.type = -1;
  Rpack.attr_framedIpv4.dataSize = -1;
  Rpack.attr_framedIpv4.totalSize = -1;

  Rpack.attr_framedIpv4Netmask.code = 9;
  strcpy(Rpack.attr_framedIpv4Netmask.value," ");
  Rpack.attr_framedIpv4Netmask.type = -1;
  Rpack.attr_framedIpv4Netmask.dataSize = -1;
  Rpack.attr_framedIpv4Netmask.totalSize = -1;

  Rpack.attr_callBackNumber.code = 19;
  strcpy(Rpack.attr_callBackNumber.value," ");
  Rpack.attr_callBackNumber.type = -1;
  Rpack.attr_callBackNumber.dataSize = -1;
  Rpack.attr_callBackNumber.totalSize = -1;

  Rpack.attr_callBackId.code = 20;
  strcpy(Rpack.attr_callBackId.value," ");
  Rpack.attr_callBackId.type = -1;
  Rpack.attr_callBackId.dataSize = -1;
  Rpack.attr_callBackId.totalSize = -1;

  Rpack.attr_callingStationId.code = 31;
  strcpy(Rpack.attr_callingStationId.value," ");
  Rpack.attr_callingStationId.type = -1;
  Rpack.attr_callingStationId.dataSize = -1;
  Rpack.attr_callingStationId.totalSize = -1;
}

void DisplayPacketInfo(){
  std::cout << "\n";
  std::cout << "Ipv4_Src : Ipv4_Dst :: " << Rpack.ipv4_src << " : " << Rpack.ipv4_dst << "\n";
  std::cout << "MAC_Src  : MAC_Dst  :: " << Rpack.mac_src  << " : " << Rpack.mac_dst  << "\n";
  std::cout << "Port_Src : Port_Dst :: " << Rpack.port_src << " : " << Rpack.port_dst << "\n";
  std::cout << "Radius Attribute Count: " << Rpack.rad_attrcount << "\n";
  std::cout << "Radius Code           : " << Rpack.rad_code << "\n";
  std::cout << "Radius Message ID     : " << Rpack.rad_msgID << "\n";
  std::cout << "Radius Attributes:- \n";

  std::cout << "\tRadius Account Status\n";
  std::cout << "\t\t\t code:      " << Rpack.attr_accStatusType.code << "\n";
  std::cout << "\t\t\t Type:      " << Rpack.attr_accStatusType.type << "\n";
  std::cout << "\t\t\t DataSize:  " << Rpack.attr_accStatusType.dataSize << "\n";
  std::cout << "\t\t\t TotalSize: " << Rpack.attr_accStatusType.totalSize << "\n";
  std::cout << "\t\t\t Value:     " << Rpack.attr_accStatusType.totalSize << "\n";
  
  std::cout << "\tCalling Station ID\n";
  std::cout << "\t\t\t code:      " << Rpack.attr_callingStationId.code << "\n";
  std::cout << "\t\t\t Type:      " << Rpack.attr_callingStationId.type << "\n";
  std::cout << "\t\t\t DataSize:  " << Rpack.attr_callingStationId.dataSize << "\n";
  std::cout << "\t\t\t TotalSize: " << Rpack.attr_callingStationId.totalSize << "\n";
  std::cout << "\t\t\t Value:     " << Rpack.attr_callingStationId.value << "\n";

  std::cout << "\tCallBack ID\n";
  std::cout << "\t\t\t code:      " << Rpack.attr_callBackId.code << "\n";
  std::cout << "\t\t\t Type:      " << Rpack.attr_callBackId.type << "\n";
  std::cout << "\t\t\t DataSize:  " << Rpack.attr_callBackId.dataSize << "\n";
  std::cout << "\t\t\t TotalSize: " << Rpack.attr_callBackId.totalSize << "\n";
  std::cout << "\t\t\t Value:     " << Rpack.attr_callBackId.value << "\n";

  std::cout << "\tCallBack Number\n";
  std::cout << "\t\t\t code:      " << Rpack.attr_callBackNumber.code << "\n";
  std::cout << "\t\t\t Type:      " << Rpack.attr_callBackNumber.type << "\n";
  std::cout << "\t\t\t DataSize:  " << Rpack.attr_callBackNumber.dataSize << "\n";
  std::cout << "\t\t\t TotalSize: " << Rpack.attr_callBackNumber.totalSize << "\n";
  std::cout << "\t\t\t Value:     " << Rpack.attr_callBackNumber.value << "\n";

  std::cout << "\tFramed IPv4\n"; 
  std::cout << "\t\t\t code:      " << Rpack.attr_framedIpv4.code << "\n";
  std::cout << "\t\t\t Type:      " << Rpack.attr_framedIpv4.type << "\n";
  std::cout << "\t\t\t DataSize:  " << Rpack.attr_framedIpv4.dataSize << "\n";
  std::cout << "\t\t\t TotalSize: " << Rpack.attr_framedIpv4.totalSize << "\n";
  std::cout << "\t\t\t Value:     " << Rpack.attr_framedIpv4.value << "\n";

  std::cout << "\tFramed IPv4 Netmask\n"; 
  std::cout << "\t\t\t code:      " << Rpack.attr_framedIpv4Netmask.code << "\n";
  std::cout << "\t\t\t Type:      " << Rpack.attr_framedIpv4Netmask.type << "\n";
  std::cout << "\t\t\t DataSize:  " << Rpack.attr_framedIpv4Netmask.dataSize << "\n";
  std::cout << "\t\t\t TotalSize: " << Rpack.attr_framedIpv4Netmask.totalSize << "\n";
  std::cout << "\t\t\t Value:     " << Rpack.attr_framedIpv4Netmask.value << "\n";

}

int GetRadiusAttribute(pcpp::RadiusLayer* radiusLayer, int code){
  pcpp::RadiusAttribute radiusAttribute = radiusLayer->getAttribute(code);

   if(radiusAttribute.isNull()){
    return 0;
  }

  switch(code){
    case 40:
      //Account Status
      Rpack.attr_accStatusType.type = radiusAttribute.getType();
      Rpack.attr_accStatusType.dataSize = radiusAttribute.getDataSize();
      Rpack.attr_accStatusType.totalSize = radiusAttribute.getTotalSize();
      strncpy(Rpack.attr_accStatusType.value,(char*)radiusAttribute.getValue(),1);
      break;
/*      
    case 8:
      //Framed IP
      Rpack.attr_framedIpv4.type = radiusAttribute.getType();
      Rpack.attr_framedIpv4.dataSize = radiusAttribute.getDataSize();
      Rpack.attr_framedIpv4.totalSize = radiusAttribute.getTotalSize();
      Rpack.attr_framedIpv4.value.assign(radiusAttribute.getValue());
      break;

    case 9:
      //Framed Netmask
      Rpack.attr_framedIpv4Netmask.type = radiusAttribute.getType();
      Rpack.attr_framedIpv4Netmask.dataSize = radiusAttribute.getDataSize();
      Rpack.attr_framedIpv4Netmask.totalSize = radiusAttribute.getTotalSize();
      Rpack.attr_framedIpv4Netmask.value.assign(radiusAttribute.getValue());
      break;

    case 19:
      //CallBack number
      Rpack.attr_callBackNumber.type = radiusAttribute.getType();
      Rpack.attr_callBackNumber.dataSize = radiusAttribute.getDataSize();
      Rpack.attr_callBackNumber.totalSize = radiusAttribute.getTotalSize();
      Rpack.attr_callBackNumber.value.assign(radiusAttribute.getValue());
      break;

    case 20:
      //callBack code
      Rpack.attr_callBaclId.type = radiusAttribute.getType();
      Rpack.attr_callBaclId.dataSize = radiusAttribute.getDataSize();
      Rpack.attr_callBaclId.totalSize = radiusAttribute.getTotalSize();
      Rpack.attr_callBaclId.value.assign(radiusAttribute.getValue()); 
      break;
*/
    case 31:
      Rpack.attr_callingStationId.type = radiusAttribute.getType();
      Rpack.attr_callingStationId.dataSize = radiusAttribute.getDataSize();
      Rpack.attr_callingStationId.totalSize = radiusAttribute.getTotalSize();
      strncpy(Rpack.attr_callingStationId.value,(char*)radiusAttribute.getValue(),13);
      break;

     default:
      break;
  } 
  return 1;
}
 

int extract_ethernetLayerData(pcpp::EthLayer* ethernetLayer){
  //get ethernetProps
  if(ethernetLayer == NULL){
    return 0;
  }
  strcpy(Rpack.mac_src,(char*)ethernetLayer->getSourceMac().toString().c_str());
  strcpy(Rpack.mac_src,(char*)ethernetLayer->getDestMac().toString().c_str());
  return 1;
}

int extract_ipv4LayerData(pcpp::IPv4Layer* ipv4Layer){
  //get IP Props
  if(ipv4Layer == NULL){
    return 0;
  }  
  strcpy(Rpack.ipv4_src,(char*)ipv4Layer->getSrcIpAddress().toString().c_str());
  strcpy(Rpack.ipv4_dst,(char*)ipv4Layer->getDstIpAddress().toString().c_str());
  return 1;
}

int extract_udpLayerData(pcpp::UdpLayer* udpLayer){
  if(udpLayer == NULL){
    return 0;
  }
  Rpack.port_src = (int)ntohs(udpLayer->getUdpHeader()->portSrc);
  Rpack.port_dst = (int)ntohs(udpLayer->getUdpHeader()->portDst);
  return 1;
}

//Handle Radius Packet
int handle_radius(pcpp::Packet& packet){
  count++;

  //skip the packets that are not of type radius
  if(!packet.isPacketOfType(pcpp::Radius)){
    not_radius++;
    return 1;
  }

  extract_ethernetLayerData(packet.getLayerOfType<pcpp::EthLayer>());
  extract_ipv4LayerData(packet.getLayerOfType<pcpp::IPv4Layer>());
  extract_udpLayerData(packet.getLayerOfType<pcpp::UdpLayer>());

  pcpp::RadiusLayer* radiusLayer = packet.getLayerOfType<pcpp::RadiusLayer>();
  totalRadiusPackets++;
  
  if(radiusLayer==NULL){
    std::cout<<"Couldn't read radius Layer\n";
    return 1;
  }
  
  Rpack.rad_attrcount = radiusLayer->getAttributeCount();
  Rpack.rad_msgID = radiusLayer->getRadiusHeader()->id;
  Rpack.rad_code = radiusLayer->getRadiusHeader()->code;
  
  pcpp::RadiusAttribute radiusAttribute = radiusLayer->getFirstAttribute();

  GetRadiusAttribute(radiusLayer,Rpack.attr_accStatusType.code);
  GetRadiusAttribute(radiusLayer,Rpack.attr_framedIpv4.code);
  GetRadiusAttribute(radiusLayer,Rpack.attr_framedIpv4Netmask.code);
  GetRadiusAttribute(radiusLayer,Rpack.attr_callBackNumber.code);
  GetRadiusAttribute(radiusLayer,Rpack.attr_callBackId.code);
  GetRadiusAttribute(radiusLayer,Rpack.attr_callingStationId.code);

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
        
        while(reader->getNextPacket(raw_packet) && totalRadiusPackets<2){
          pcpp::Packet packet(&raw_packet);
          initialize_PacketInfo();
          handle_radius(packet);
          DisplayPacketInfo();
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
