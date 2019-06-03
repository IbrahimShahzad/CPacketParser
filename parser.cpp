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
#include <iomanip>
#include <chrono>
#include <vector>
#include <numeric>

#define RADIUS_LENGTH_ID 2
#define RADIUS_IDENTIFIER_LENGTH 1
#define RADIUS_AUTHENTICATOR_LENGTH 16
#define ACCOUNT_STATUS_TYPE 40
#define FRAMED_IPV4 8
#define CALLING_STATION_ID 31
#define IPV6_PREFIX_TYPE 97
#define MAX_RADIUS_PACKET_LENGTH 4096
#define IPV6_PREFIX_HEAD_LENGTH 2

size_t COUNT = 0;             //total packet COUNT
size_t TOTAL_RADIUS_PACKETS = 0;//total radius pacekets
size_t NOT_RADIUS = 0;        //not radius packets

void printHelp(char* argv[]){
  /*
   * prints out usage help
   */
  std::cout << "\n\n";
  std::cout << "\tusage: "<<*argv<<" <input> <packets> <repetitions>\n";
  std::cout << "\t<input>      \tEither a pcap file or type N to listen via interface\n";
  std::cout << "\t<packet>     \tEnter packet type. (radius, dns, udp etc)\n";
  std::cout << "\t<repetitions>\tEnter number of times the program needs to run. (Benchmarking)\n";
  std::cout << "\t\t\tUse 1 if not using a pcap file\n";
  std::cout << "\texample usage: /parser Radius.pcap radius 5\n";
  std::cout << "\n";
  exit(1);
}


// For a uniform data type for all radius attributes
// However length of value will need to be changed.
struct Radius_Attribute{
  int code;
  int type;
  int dataSize;
  int totalSize;
  char value[20];
};

struct PacketInfo{
  // Can be added.
  // Src/Dest IP
  // Src/Dest Mac
  // Src/Dest Port
  // Change the initializer respectively
  
  //Radius----------
  int rad_attrCOUNT;
  int rad_code;
  int rad_msgID;
  //code message string
  //Attributes-------
  uint8_t  Rad_Acct_Stat = 0;
  uint8_t FrIp4[4];
  uint64_t number;
  uint8_t FrIp6[20];
  uint8_t FrIp6Length;
  uint8_t FrIp6Type;

};

// Global
PacketInfo R_PACK;

void initialize_PacketInfo(){
  /*
   * Initialization of PacketInfo
   * 
   */
  R_PACK.rad_attrCOUNT = 0;
  R_PACK.rad_code = 0;
  R_PACK.rad_msgID = 0;
  
  //Attributes
  R_PACK.Rad_Acct_Stat = 0;
  R_PACK.number = 0;

  //FOR IPv4 and IPv6
  int temp1, temp2;
  temp1 = temp2 = 0;
  while (temp2 < 20){
    R_PACK.FrIp4[temp1]=0;
    R_PACK.FrIp6[temp2]=0;
    if(temp2%5==0){
      temp1++;
    }
    temp2++;
  }
  R_PACK.FrIp6Length = 0; //length of attribute in bytes
  R_PACK.FrIp6Type = 0; // 64

}

void DisplayAttributes(){
  std::cout << "\n";
  std::cout << std::dec << "ACCOUNT_STATUS_TYPE   : " << (int)R_PACK.Rad_Acct_Stat << "\n";
  std::cout << std::dec << "FRAMED_IPV4           : " 
    << (int)R_PACK.FrIp4[0] << "." 
    << (int)R_PACK.FrIp4[1] << "." 
    << (int)R_PACK.FrIp4[2] << "." 
    << (int)R_PACK.FrIp4[3] << "\n";

  std::cout << "FRAMED_IPV6_PREFIX    : ";
  for (int i=0; i<R_PACK.FrIp6Length-IPV6_PREFIX_HEAD_LENGTH; i++){
    std::cout << std::hex 
      << std::setw(2)
      << std::setfill('0')
      //<< std::setiosflags(ios::left)
      << (int) R_PACK.FrIp6[i]; 
  }
  std::cout<< std::dec << "\nCALLING_STATION_ID    : " << R_PACK.number << "\n\n";
}

void DisplayPacketInfo(){
  std::cout << "\n";
  std::cout<< "---------PACKET: " << COUNT << " ---------\n";
  std::cout << "Radius Attribute COUNT: " << R_PACK.rad_attrCOUNT << "\n";
  std::cout << "Radius Code           : " << R_PACK.rad_code << "\n";
  std::cout << "Radius Message ID     : " << R_PACK.rad_msgID << "\n";
  std::cout << "Radius Attributes:- \n";
  DisplayAttributes();
}
// ----------------------------------------------------------------------------------
// Does not retrun proper attribute values when non ASCII values read (CAUTION!)
// ---------------------------------------------------------------------------------
/*
int GetRadiusAttribute(pcpp::RadiusLayer* radiusLayer, int code){
  pcpp::RadiusAttribute radiusAttribute = radiusLayer->getAttribute(code);

   if(radiusAttribute.isNull()){
    return 0;
  }

  switch(code){
    case ACCOUNT_STATUS_TYPE:
      //AcCOUNT Status
      R_PACK.attr_accStatusType.type = radiusAttribute.getType();
      R_PACK.attr_accStatusType.dataSize = radiusAttribute.getDataSize();
      R_PACK.attr_accStatusType.totalSize = radiusAttribute.getTotalSize();
      strncpy(R_PACK.attr_accStatusType.value,(char*)radiusAttribute.getValue(),1);
      break;
    case FRAMED_IPV4:
      //Framed IP
      R_PACK.attr_framedIpv4.type = radiusAttribute.getType();
      R_PACK.attr_framedIpv4.dataSize = radiusAttribute.getDataSize();
      R_PACK.attr_framedIpv4.totalSize = radiusAttribute.getTotalSize();
      //R_PACK.attr_framedIpv4.value.assign(radiusAttribute.getValue());
      break;

    case CALLING_STATION_ID:
      // MSISDN
      R_PACK.attr_callingStationId.type = radiusAttribute.getType();
      R_PACK.attr_callingStationId.dataSize = radiusAttribute.getDataSize();
      R_PACK.attr_callingStationId.totalSize = radiusAttribute.getTotalSize();
      strncpy(R_PACK.attr_callingStationId.value,(char*)radiusAttribute.getValue(),13);
      break;

     default:
      break;
  } 
  return 1;
}
*/

// ---------------------------------------------------------------------------------
// -----------------------------------ETH-LAYER------------------------------------
//Not Used... Make sure to change PacketIfo if used
/*
int extract_ethernetLayerData(pcpp::EthLayer* ethernetLayer){
  //get ethernetProps
  if(ethernetLayer == NULL){
    return 0;
  }
  strcpy(R_PACK.mac_src,(char*)ethernetLayer->getSourceMac().toString().c_str());
  strcpy(R_PACK.mac_src,(char*)ethernetLayer->getDestMac().toString().c_str());
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
  strcpy(R_PACK.ipv4_src,(char*)ipv4Layer->getSrcIpAddress().toString().c_str());
  strcpy(R_PACK.ipv4_dst,(char*)ipv4Layer->getDstIpAddress().toString().c_str());
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
  R_PACK.port_src = (int)ntohs(udpLayer->getUdpHeader()->portSrc);
  R_PACK.port_dst = (int)ntohs(udpLayer->getUdpHeader()->portDst);
  return 1;
}
*/

// ---------------------------------RADIUS-------------------------------------------------
int readAttributebyBytes(pcpp::RadiusLayer* radiusLayer){
  /* Reads Attributes byte by byte 
   *  For example: --- 28 06 00 00 00 02 --- 
   *  28 = dec(28) = 40 (Acct-Status-Type) 
   *  06 = total length 
   *  00 00 00 02 = value =  2 (stop) 
   *  bytes for data (4) are calculated  [total:6] - [bytesforlength:1] - [bytesforcode:1] = 4 
   *
   * In case of adding new attribute 
   * Please refer to proper documentation to get these values.
   *
   * In this function the loop for reading bytes breaks when the sum_check equals zero.
   * Hence, only 4 attributes are read. In order to extract more attributes make sure to add
   * attribute type to switch_case and change the condition for sum_check.
   *
   * Attributes:
   *  Framed-IPv4,
   *  Acct-Status,
   *  IPv6-Prefix,
   *  MSISDN
   *
   * Attributes are read after skipping
   *  Radius Authenticator
   *  Radius Length indicator
   *  Radius ID
   *  
   * All of the above has been done to  keep this extraction as efficient as possible.
   */
  int sum_check = 0;
  unsigned int length = radiusLayer->getHeaderLen();
  uint8_t bArray[MAX_RADIUS_PACKET_LENGTH];
  radiusLayer->copyData(bArray);
  int skip = RADIUS_AUTHENTICATOR_LENGTH + RADIUS_LENGTH_ID + RADIUS_IDENTIFIER_LENGTH +1;
  int COUNTer = skip;
  while(COUNTer < length -1){
    if(sum_check == 4){
      break;
    }
    int code = bArray[COUNTer];
    int length = bArray[COUNTer+1];
    unsigned long multiplier = 1;
    switch(code){

      case ACCOUNT_STATUS_TYPE:
        R_PACK.Rad_Acct_Stat = (int)bArray[COUNTer+5]; 
        sum_check++;
        break;

      case FRAMED_IPV4:
        /*
         * saved as int array
         */
        R_PACK.FrIp4[0] = bArray[COUNTer + 2];
        R_PACK.FrIp4[1] = bArray[COUNTer + 3];
        R_PACK.FrIp4[2] = bArray[COUNTer + 4];
        R_PACK.FrIp4[3] = bArray[COUNTer + 5];
        sum_check++;
        break;

      case CALLING_STATION_ID:
        /*
         * MSISDN 
         * saved as unsigned int 64
         *
         */
        multiplier = 1;
        R_PACK.number = 0;
        for(int i=length-1; i>1; i--){
          unsigned long temp;
          temp = (bArray[COUNTer + i] - 48)  * multiplier;
          R_PACK.number = R_PACK.number + temp;
          multiplier = multiplier * 10;
        }
        sum_check++;
        break;

      case IPV6_PREFIX_TYPE:
        for(int i=IPV6_PREFIX_HEAD_LENGTH; i<=length-1; i++){
          R_PACK.FrIp6[i-IPV6_PREFIX_HEAD_LENGTH] = bArray[COUNTer+i];
        }
        R_PACK.FrIp6Length = length; 
        R_PACK.FrIp6Type = bArray[length];
        //DisplayPacketInfo();
        break;

      default:
        //un-needed attributes
        break;
    } 
    if (length == 0){
      COUNTer = COUNTer + 1;
    }
    COUNTer = COUNTer + length;
    
  }

}

int handle_radius(pcpp::Packet& packet){
  /* INPUT: PCPP::PACKET
   * Handles radius packets.
   * Further gets attributes by calling 
   * readAttributebyBytes function.
   */
  COUNT++;

  //skip the packets that are not of type radius
  if(!packet.isPacketOfType(pcpp::Radius)){
    NOT_RADIUS++;
    return 1;
  }

  //get Radius Layer
  pcpp::RadiusLayer* radiusLayer = packet.getLayerOfType<pcpp::RadiusLayer>();
  TOTAL_RADIUS_PACKETS++;
  
  if(radiusLayer==NULL){
    std::cout<<"Couldn't read radius Layer\n";
    return 1;
  }
  
  R_PACK.rad_attrCOUNT = radiusLayer->getAttributeCount();
  R_PACK.rad_msgID = radiusLayer->getRadiusHeader()->id;
  R_PACK.rad_code = radiusLayer->getRadiusHeader()->code;

  //Read radius attributes
  readAttributebyBytes(radiusLayer);

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
      COUNT = 0;
      TOTAL_RADIUS_PACKETS = 0;
      NOT_RADIUS = 0;
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
        
        while(reader->getNextPacket(raw_packet) && TOTAL_RADIUS_PACKETS<99999){
          initialize_PacketInfo();
          pcpp::Packet packet(&raw_packet);
          handle_radius(packet);
          /*
          if(COUNT==98){
            DisplayAttributes();
          }
          */  
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
      total_packets += COUNT;
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
    std::cout << "(total_packets:total_reps):\t\t " << TOTAL_RADIUS_PACKETS << "::" << total_reps << ":: \t" <<total_packets/total_reps<<"\n";
    std::cout << "(total_time_in_ms/durations.size()):\t " << total_time_in_ms << "/ " << durations.size() << ": \t" << (total_time_in_ms/durations.size())<<"\n";
    std::cout << "Other Packets:\t\t\t\t" << NOT_RADIUS << "\n";
    std::cout << "Total Packets:\t\t\t\t" << COUNT << "\n";
    std::cout << "Average Total Time(ms): \t\t" << total_time_in_ms/durations.size() << "\n";
    std::cout << "Average Time/Packet(ms): \t\t" <<(double)((double)(total_time_in_ms/durations.size())/COUNT)<< "\n";
}
