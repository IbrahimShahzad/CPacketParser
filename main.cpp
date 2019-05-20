// Last Edit 16-th May 2019
#include "in.h" 		//for ntohs() and htons()
#include "stdlib.h"
#include "Packet.h" 		// includes basic parsed packet structures	
#include "EthLayer.h" 
#include "IPv4Layer.h"
#include "TcpLayer.h"
#include "UdpLayer.h"
#include "HttpLayer.h"
#include "RadiusLayer.h"
#include "PcapFileDevice.h" 	//contains API fro reading pcap files
				//For printing protocol
#include "string.h"

std::string cleanString(char* s){

}

//Returns Protocol Type
std::string getProtocolTypeAsString(pcpp::ProtocolType protocolType){
	switch (protocolType){
		case pcpp::Ethernet:
			return "Ethernet";
		case pcpp::IPv4:
			return "IPv4";
		case pcpp::TCP:
			return "TCP";
		case pcpp::HTTPRequest:
		case pcpp::HTTPResponse:
			return "HTTP";
		case pcpp::Radius:
			return "Radius";
		case pcpp::UDP:
			return "UDP";
		default:
			return "Unkown";
	}
}

//Ethernet Details
int printEthernetProtocolDetailsAsString(pcpp::EthLayer* ethernetLayer){
	printf("\n\t\t------------Ehternet-Layer-Details---------------\n");
	if (ethernetLayer == NULL){
		printf("Something Wrong!");
		return 1;
	}
	printf("\t\tSrc  Address:\t\t%s\n", ethernetLayer->getSourceMac().toString().c_str());
	printf("\t\tDest Address:\t\t%s\n", ethernetLayer->getDestMac().toString().c_str());
	printf("\t\t-------------------------------------------------\n");
	return 0;
}

//IPv4 Details
int printIPv4ProtocolDetailsAsString(pcpp::IPv4Layer* ipLayer){
	printf("\n\t\t-------------IPv4-Layer-Details-----------------\n");
	if (ipLayer == NULL){
		printf("Something is wrong here boy\n");
		return 1;
	}
	printf("\t\tSource IP address:\t\t%s\t\n", ipLayer->getSrcIpAddress().toString().c_str());
	printf("\t\tDestination IP address:\t%s\t\n", ipLayer->getDstIpAddress().toString().c_str());
	printf("\t\tIP ID:\t\t\t\t0x%X\t\t\n",ntohs(ipLayer->getIPv4Header()->ipId));
	printf("\t\tTTL  :\t\t\t\t%d\t\t\n",ipLayer->getIPv4Header()->timeToLive);
	printf("\t\t------------------------------------------------\n");
}

//Radius Details
int printRadiusProtocolDetailsAsString(pcpp::RadiusLayer* radiusLayer){
	printf("\n\t\t-------------Radius-Layer-Details-----------------\n");
	if(radiusLayer == NULL){
		printf("Something Wrong");
		return 1;
	}
//	printf("\t\tFirst Attribute: %s \n", radiusLayer->getFirstAttribute());
	printf("\t\tAttribute Count:\t\t %d\t\t\n",radiusLayer->getAttributeCount());
	//printf("\t\t|Athencticator  : 0x%X \n",radiusLayer->getAuthenticatorValue());
	printf("\t\tMessage ID     :\t\t %d\t\t\n",radiusLayer->getRadiusHeader()->id);
	//printf("\t\t|Message Length :\t\t %s\t|\n",radiusLayer->getRadiusHeader()->length);
	printf("\t\tMessage Code   :\t\t %d\t\t\n",radiusLayer->getRadiusHeader()->code);
        if(!radiusLayer->getAttribute(1).isNull()){
          printf("\t\tAVP-Type 01    :\t\t %s\t\n",radiusLayer->getAttribute(1).getValue());
        }	
        char callingStationId[12]="";
        strncpy(callingStationId,(char*)radiusLayer->getAttribute(31).getValue(),11);
	//printf("\t\t|AVP-Type 30    :\t\t %s\t|\n",radiusLayer->getAttribute(30).getValue());
	printf("\t\tAVP-Type 31    :\t\t %s\t\n",callingStationId);
//	iprintf("\t\t|AVP-Type 01    :\t\t %s\t|\n",radiusLayer->
//	printf("\t\t|AVP-Type 40    :\t\t %s\t|\n",radiusLayer->getAttribute(40).getValue());
//	printf("\t\t|AVP-Type 02    :\t\t %s\t|\n",radiusLayer->getAttribute(2).getValue());
	printf("\t\t--------------------------------------------------\n");
}

//TCP Details
int printTCPProtocolDetailsAsString(pcpp::TcpLayer* tcpLayer){
	printf("\n\t\t-------------TCP-Layer-Details-----------------\n");
	if(tcpLayer==NULL){
		printf("Something Wrong");
		return 1;
	}
	printf("\t\tSource TCP port: %d\n",(int)ntohs(tcpLayer->getTcpHeader()->portSrc));
	printf("\t\tDestination TCP port: %d\n",(int)ntohs(tcpLayer->getTcpHeader()->portDst));
	printf("\t\tWindow Size: %d\n",(int)ntohs(tcpLayer->getTcpHeader()->windowSize));
//	printf("TCP Flags: %d\n",printTcpFlags(tcpLayer).c_str());
	printf("\n\t\t--------------------------------------------------\n");
}

//UDP Details
int printUDPProtocolDetailsAsString(pcpp::UdpLayer* udpLayer){
	printf("\n\t\t---------------UDP-Layer-Details-----------------\n");
	if(udpLayer==NULL){
		printf("Something Wrong");
		return 1;
	}
	printf("\t\tSource UDP port:\t\t%d\t\t\n",(int)ntohs(udpLayer->getUdpHeader()->portSrc));
	printf("\t\tDestination UDP port:\t\t%d\t\t\n",(int)ntohs(udpLayer->getUdpHeader()->portDst));
	printf("\t\t-------------------------------------------------\n");
}

int main(int argc, char* argv[]){

	//Write Code here
	printf("Hello\n");

	//for counting packets	
	unsigned long  packet_count=1; 


	//Use IFileReaderDevice to automatically indentify file type (pcap/pcap-ng)
	//and create an interface that both readers implement
	//make sure to change packet file!!
	pcpp::IFileReaderDevice* reader = pcpp::IFileReaderDevice::getReader("TEST_Radius.pcap");

	//Check Error File Type?
	if (reader == NULL){
		printf("Cannot determine reader for the file type\n");
		exit(1);
	}

	//Check can open file?
	if (!reader->open()){
		printf("Cannot open pcap file for reading\n");
		exit(1);
	}

	//Read first Raw packet from the file
	pcpp::RawPacket rawPacket;
        while (reader->getNextPacket(rawPacket)){ //&& packet_count<=86){
//	if(!reader->getNextPacket(rawPacket)){
  //          printf("couldnt read the packet in the file\n");
//	    return 1;
//	}
        if(packet_count<=23689){
          packet_count++;
          continue;
        }	
        //Parse Raw Packet into a parsed packet
	pcpp::Packet parsedPacket(&rawPacket);
	printf("\n*****************************************PACKET# %2d************************************************\n",packet_count);	

	for (pcpp::Layer* curLayer = parsedPacket.getFirstLayer(); curLayer != NULL; curLayer = curLayer->getNextLayer()){
		printf("------------------------------------------------------------------------------------------------------\n");	
		//getProcotol() - get enum of the protocol the layer represents
		//getHeaderLen() - get the size of the layers's bheader, meaning the size of the layer data
		//getLayerPayLoadSize() - get the size of the layer's payload, meaning the size of all the
		//layers that follow this layer
		//getDataLen() - get the total size fo the layer: header + payload
		printf("Layer type: %s; Total data %d [bytes]; Layer data: %d [bytes]; Layer payload: %d [bytes]\n",
			getProtocolTypeAsString(curLayer->getProtocol()).c_str(),
			(int)curLayer->getDataLen(),
			(int)curLayer->getHeaderLen(),
			(int)curLayer->getLayerPayloadSize());

/*		if(strcmp(getProtocolTypeAsString(curLayer->getProtocol()).c_str(),"Radius")==0){
			printf("\nTHIS IS RADIUS\n");
			if(curLayer == NULL){
				printf("Something went wrong\n");
				exit(1);
			}}*/
		pcpp::ProtocolType protocolType = curLayer->getProtocol();
		switch (curLayer->getProtocol()){
			case pcpp::Ethernet:
				{
                                printf("Ethernet");
				pcpp::EthLayer* ethernetLayer = parsedPacket.getLayerOfType<pcpp::EthLayer>();
				printEthernetProtocolDetailsAsString(ethernetLayer);
				}	
				break;
			case pcpp::IPv4:
				{
                                printf("IPv4");
				pcpp::IPv4Layer* ipLayer = parsedPacket.getLayerOfType<pcpp::IPv4Layer>();
				printIPv4ProtocolDetailsAsString(ipLayer);
				}
				break;
			case pcpp::TCP:
				{
                                printf("TCP");
				pcpp::TcpLayer* tcpLayer = parsedPacket.getLayerOfType<pcpp::TcpLayer>();
				printTCPProtocolDetailsAsString(tcpLayer);
				}
				break;
			case pcpp::Radius:
				{
                                printf("Radius");
                                
                                //printf("%s\n",getProtocolTypeAsString(curLayer->getProtocol()).c_str());
			    //    if((int)curLayer->getHeaderLen()<=20){
                              //    printf("packet # %d, Header Len %d",packet_count,curLayer->getHeaderLen());
                               // }
				pcpp::RadiusLayer* radiusLayer = parsedPacket.getLayerOfType<pcpp::RadiusLayer>();
                                if(radiusLayer->getHeaderLen()<=64){
                                  printf("Radius Header %d",radiusLayer->getHeaderLen());
                                  exit(1);
                                }
				printRadiusProtocolDetailsAsString(radiusLayer);
				}
				break;
			case pcpp::UDP:
				{
                                printf("UDP");
				pcpp::UdpLayer* udpLayer = parsedPacket.getLayerOfType<pcpp::UdpLayer>();
				printUDPProtocolDetailsAsString(udpLayer);
				}
				break;
			default:
				printf("Unknown");
		}
	
        }

        packet_count++;	
        
        }

	reader->close();
        return 0;
}	 
