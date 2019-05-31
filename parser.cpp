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

#define RADIUS_LENGTH_ID 2
#define RADIUS_IDENTIFIER_LENGTH 1
#define RADIUS_AUTHENTICATOR_LENGTH 16
#define ACCOUNT_STATUS_TYPE 40
#define FRAMED_IPV4 8
#define CALLING_STATION_ID 31
#define MAX_RADIUS_PACKET_LENGTH 4096

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

//uint8_t  Rad_Acct_Stat = 0;
int  Rad_Acct_Stat = 0;
// Framed IP set
//uint8_t FrIp4[4];
int  FrIp4[4];
//unsigned int IPv4_1 = 0;
//unsigned int IPv4_2 = 0;
//unsigned int IPv4_3 = 0;
//unsigned int IPv4_4 = 0;
//uint64_t number;
unsigned long number;

struct Radius_Attribute{
  int code;
  int type;
  int dataSize;
  int totalSize;
  char value[20];
};

struct PacketInfo{
  //char ipv4_src[16];
  //char ipv4_dst[16];
  //char mac_src[20];
  //char mac_dst[20];
  //int port_src;
  //int port_dst;
  //Radius----------
  int rad_attrcount;
  int rad_code;
  int rad_msgID;
  //code message string
  //Attributes-------
  Radius_Attribute attr_framedIpv4;
  Radius_Attribute attr_accStatusType;
  Radius_Attribute attr_callingStationId;
};

// Global
PacketInfo Rpack;

//initialize all values
void initialize_PacketInfo(){
  //strcpy(Rpack.ipv4_src," ");
  //strcpy(Rpack.ipv4_dst," ");
  //strcpy(Rpack.mac_src," ");
  //strcpy(Rpack.mac_dst," ");
  //Rpack.port_src = 0;
  //Rpack.port_dst = 0;
  Rpack.rad_attrcount = 0;
  Rpack.rad_code = 0;
  Rpack.rad_msgID = 0;

  Rpack.attr_accStatusType.code = ACCOUNT_STATUS_TYPE;
  strcpy(Rpack.attr_accStatusType.value," ");
  Rpack.attr_accStatusType.type = -1;
  Rpack.attr_accStatusType.dataSize = -1;
  Rpack.attr_accStatusType.totalSize = -1;

  Rpack.attr_framedIpv4.code = FRAMED_IPV4;
  strcpy(Rpack.attr_framedIpv4.value," ");
  Rpack.attr_framedIpv4.type = -1;
  Rpack.attr_framedIpv4.dataSize = -1;
  Rpack.attr_framedIpv4.totalSize = -1;

  Rpack.attr_callingStationId.code = CALLING_STATION_ID;
  strcpy(Rpack.attr_callingStationId.value," ");
  Rpack.attr_callingStationId.type = -1;
  Rpack.attr_callingStationId.dataSize = -1;
  Rpack.attr_callingStationId.totalSize = -1;
}

void DisplayAttributes(){
  std::cout << "\n";
  std::cout << std::dec << "ACCOUNT_STATUS_TYPE: " << Rad_Acct_Stat << "\n";
  std::cout << std::dec << "FRAMED_IPV4: " << FrIp4[0] << "." 
    << FrIp4[1] << "." 
    << FrIp4[2] << "." 
    << FrIp4[3] << "\n"; 
  std::cout<< std::dec << "CALLING_STATION_ID: " << number << "\n\n";
}

void DisplayPacketInfo(){
  std::cout << "\n";
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

  std::cout << "\tFramed IPv4\n"; 
  std::cout << "\t\t\t code:      " << Rpack.attr_framedIpv4.code << "\n";
  std::cout << "\t\t\t Type:      " << Rpack.attr_framedIpv4.type << "\n";
  std::cout << "\t\t\t DataSize:  " << Rpack.attr_framedIpv4.dataSize << "\n";
  std::cout << "\t\t\t TotalSize: " << Rpack.attr_framedIpv4.totalSize << "\n";
  std::cout << "\t\t\t Value:     " << Rpack.attr_framedIpv4.value << "\n";

}
// ----------------------------------------------------------------------------------
// Does not retrun proper attribute values when non ASCII values read (CAUTION!)
// ---------------------------------------------------------------------------------
int GetRadiusAttribute(pcpp::RadiusLayer* radiusLayer, int code){
  pcpp::RadiusAttribute radiusAttribute = radiusLayer->getAttribute(code);

   if(radiusAttribute.isNull()){
    return 0;
  }

  switch(code){
    case ACCOUNT_STATUS_TYPE:
      //Account Status
      Rpack.attr_accStatusType.type = radiusAttribute.getType();
      Rpack.attr_accStatusType.dataSize = radiusAttribute.getDataSize();
      Rpack.attr_accStatusType.totalSize = radiusAttribute.getTotalSize();
      strncpy(Rpack.attr_accStatusType.value,(char*)radiusAttribute.getValue(),1);
      break;
    case FRAMED_IPV4:
      //Framed IP
      Rpack.attr_framedIpv4.type = radiusAttribute.getType();
      Rpack.attr_framedIpv4.dataSize = radiusAttribute.getDataSize();
      Rpack.attr_framedIpv4.totalSize = radiusAttribute.getTotalSize();
      //Rpack.attr_framedIpv4.value.assign(radiusAttribute.getValue());
      break;

    case CALLING_STATION_ID:
      // MSISDN
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

// ---------------------------------------------------------------------------------
// -----------------------------------ETH-LAYER------------------------------------
//Not Used... Make sure to change PacketIfo if used
/*
int extract_ethernetLayerData(pcpp::EthLayer* ethernetLayer){
  //get ethernetProps
  if(ethernetLayer == NULL){
    return 0;
  }
  strcpy(Rpack.mac_src,(char*)ethernetLayer->getSourceMac().toString().c_str());
  strcpy(Rpack.mac_src,(char*)ethernetLayer->getDestMac().toString().c_str());
  return 1;
}
*/

// -----------------------------------IPv4-LAYER----------------------------------------

//Not Used... Make sure to change PacketIfo if used
/*
int extract_ipv4LayerData(pcpp::IPv4Layer* ipv4Layer){
  //get IP Props
  if(ipv4Layer == NULL){
    return 0;
  }  
  strcpy(Rpack.ipv4_src,(char*)ipv4Layer->getSrcIpAddress().toString().c_str());
  strcpy(Rpack.ipv4_dst,(char*)ipv4Layer->getDstIpAddress().toString().c_str());
  return 1;
}
*/

// -----------------------------------UDP-LAYER------------------------------------------

//Not Used... Make sure to change PacketIfo if used
/*
int extract_udpLayerData(pcpp::UdpLayer* udpLayer){
  if(udpLayer == NULL){
    return 0;
  }
  Rpack.port_src = (int)ntohs(udpLayer->getUdpHeader()->portSrc);
  Rpack.port_dst = (int)ntohs(udpLayer->getUdpHeader()->portDst);
  return 1;
}
*/

// ---------------------------------RADIUS-------------------------------------------------
// Reads Attributes byte by byte
// for example: --- 28 06 00 00 00 02 --- 
// 28 = dec(28) = 40 (Acct-Status-Type)
// 06 = total length
// 00 00 00 02 = value =  2 (stop)
// bytes for data (4) are calculated  [total:6] - [bytesforlength:1] - [bytesforcode:1] = 4
// In case of adding new attribute
// Please refer to proper documentation to get these values.
int readAttributebyBytes(pcpp::RadiusLayer* radiusLayer){
  int sum_check = 0;
  unsigned int length = radiusLayer->getHeaderLen();
  uint8_t bArray[MAX_RADIUS_PACKET_LENGTH];
  radiusLayer->copyData(bArray);
  int skip = RADIUS_AUTHENTICATOR_LENGTH + RADIUS_LENGTH_ID + RADIUS_IDENTIFIER_LENGTH +1;
  int counter = skip;
  //std::cout<< "skip "<< skip << "\n";
  while(counter < length -1){
    if(sum_check == 3){
      break;
    }
    int code = bArray[counter];
    int length = bArray[counter+1];
    //std::cout << " for code: " <<  code;
    //std::cout << " counter: " << counter;
    //std::cout << " sum= " << sum_check;
    unsigned long multiplier = 1;
    switch(code){

      case ACCOUNT_STATUS_TYPE:
        //std::cout << "\n\tAtt code: " << code << " ";
        //std::cout << "\n\tlength  : " << length << " ";
        Rad_Acct_Stat = (int)bArray[counter+5]; 
        //std::cout << "\n\tvalue   : " << Rad_Acct_Stat << "\n";
        sum_check++;
        break;

      case FRAMED_IPV4:
        //std::cout << "\n\tFr code: " << code << " ";
        //std::cout << "\n\tFr len :  " << length << " ";
        FrIp4[0] = bArray[counter + 2];
        FrIp4[1] = bArray[counter + 3];
        FrIp4[2] = bArray[counter + 4];
        FrIp4[3] = bArray[counter + 5];
        
        //std::cout << "\n\tFr IP:   " << FrIp4[0] << "." << FrIp4[1] << "." << FrIp4[2] << "." << FrIp4[3] << "\n";
        sum_check++;
        break;

      case CALLING_STATION_ID:
        //std::cout << "\n\tCall code: " << code << " ";
        //std::cout << "\n\tCall Leng: " << length << " ";
        multiplier = 1;
        number = 0;
        for(int i=length-1; i>1; i--){
          unsigned long temp;
          temp = (bArray[counter + i] - 48)  * multiplier;
          number = number + temp;
          multiplier = multiplier * 10;
        }
        //std::cout << "\n\tnumber   : " << number << " ";
        //std::cout << "\n";
        sum_check++;
        break;

      case 97:
        std::cout<< "THIS IS IPV6\n";
        break;

      default:
        //std::cout << " DEF ";
        break;
    } 
    //std::cout << "\n";
    if (length == 0){
      counter = counter + 1;
    }
    counter = counter + length;
    
  }
/*
  counter = skip; 
  while(counter < length ){
    unsigned int i= bArray[counter];
    std::cout << "bArray[ " << counter << "]" ;
    std::cout <<  bArray[counter] << " ";
    std::cout << " val2 " << i << "\n";
    counter++;
  }
*/
}

//Handle Radius Packet
int handle_radius(pcpp::Packet& packet){
  count++;

  //skip the packets that are not of type radius
  if(!packet.isPacketOfType(pcpp::Radius)){
    not_radius++;
    return 1;
  }

  //extract_ethernetLayerData(packet.getLayerOfType<pcpp::EthLayer>());
  //extract_ipv4LayerData(packet.getLayerOfType<pcpp::IPv4Layer>());
  //extract_udpLayerData(packet.getLayerOfType<pcpp::UdpLayer>());

  pcpp::RadiusLayer* radiusLayer = packet.getLayerOfType<pcpp::RadiusLayer>();
  totalRadiusPackets++;
  
  if(radiusLayer==NULL){
    std::cout<<"Couldn't read radius Layer\n";
    return 1;
  }
  
  Rpack.rad_attrcount = radiusLayer->getAttributeCount();
  Rpack.rad_msgID = radiusLayer->getRadiusHeader()->id;
  Rpack.rad_code = radiusLayer->getRadiusHeader()->code;
  //readAttributebyBytes(rawData,packet_length);
  readAttributebyBytes(radiusLayer);
  //pcpp::RadiusAttribute radiusAttribute = radiusLayer->getFirstAttribute();

  //GetRadiusAttribute(radiusLayer,Rpack.attr_accStatusType.code);
  //GetRadiusAttribute(radiusLayer,Rpack.attr_framedIpv4.code);
  //GetRadiusAttribute(radiusLayer,Rpack.attr_callingStationId.code);

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
        
        while(reader->getNextPacket(raw_packet) && totalRadiusPackets<99999){
          pcpp::Packet packet(&raw_packet);
          initialize_PacketInfo();
          handle_radius(packet);
        //  DisplayAttributes();
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
