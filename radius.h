/**
 * @file radius.h
 * @brief This file contains the radius class
 * @author ibrahim
 * @date 12 Sep 2020
 */

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
#include <string>
#include <iostream>
#include <iomanip>
#include <chrono>
#include <vector>
#include <numeric>
#include <fstream>


#define MAX_IPV4_LEN 12                     /**< MAX IPV4 LEN */
#define MAX_IPV6_LEN 18                     /**< MAX IPV6 LEN */
#define MAX_ATTRIBUTES_TO_EXTRACT 4         /**< NUMBER OF AVPs to extract (if) found */
#define MIN_VALID_AVP_LEN 3                 /**< MINIMUM VALID AVP LENGTH */
#define MIN_VALID_AVP_CODE 1                /**< MINIMUM VALID AVP CODE */
#define NOT_RADIUS_ERROR -1            /**< ERROR CODE -1 */
#define ATTRIBUTE_PARSE_ERROR -2            /**< ERROR CODE -2 */
#define RADIUS_AUTHENTICATION_PORT 1812     /**< Port Number associated with Authentication */
#define RADIUS_AUTHORIZATION_PORT 1813      /**< Port Number associated with Authorization  */
#define RADIUS_PACKET_MIN_LEN 230           /**< Minimum Packet Size set for a RADIUS Packet */
#define RADIUS_ACCOUTING_REQUEST 4

size_t g_sTotalPacketCount = 0;             /**< Total packet COUNT */
size_t g_sTotalRadiusPackets = 0;           /**< Total radius pacekets */
size_t g_sNotRadius = 0;                    /**< Total packets excluding RADIUS */

class Radius {
    public:
    int nRadiusAttributeCount;
    int nRadiusCode;
    int nRadiusMessageID;
    
    uint8_t  u8RadiusAccountingType;
    uint8_t  pu8FramedIPv4Address[MAX_IPV4_LEN];
    uint64_t u64CallingStationID;
    uint8_t  pu8FramedIPv6Address[MAX_IPV6_LEN];
    uint8_t  u8FramedIPv6Length;
    uint8_t  u8FramedIPv6Type;
    Radius(){
        nRadiusAttributeCount=-1;
        nRadiusCode=-1;
        nRadiusMessageID=-1;
        
        u8RadiusAccountingType = 0;
        for(int i=0; i<MAX_IPV4_LEN ;i++){
            pu8FramedIPv4Address[i]=0;
        }
        u64CallingStationID=0;
        for(int i=0; i<MAX_IPV6_LEN ;i++){
            pu8FramedIPv6Address[i]=0;
        }
        u8FramedIPv6Length=0;
        u8FramedIPv6Type=0;
    }
    int dumpToCsv(){
        std::ofstream fCSV;
        fCSV.open ("radiusAttributes.csv");
        fCSV << "nRadiusAttributeCount,nRadiusCode,nRadiusMessageID,u8RadiusAccountingType,u64CallingStationID,pu8FramedIPv4Address\n";
        fCSV << nRadiusAttributeCount << "," << nRadiusCode "," nRadiusMessageID << "," << u8RadiusAccountingType << "," << u64CallingStationID << "," << pu8FramedIPv4Address[0] << "." <<pu8FramedIPv4Address[1]<< "." << pu8FramedIPv4Address[2] << "." << pu8FramedIPv4Address[3] << "\n";
        fCSV.close();
    }
    /**
     * @brief 
     * 
     * @param packet PCPP:PACKET  
     * @return int returns negative in case of non RADIUS packets or error 
     */
    int parseRadiusHeader(pcpp::Packet& packet){ 
        g_sTotalPacketCount++;

        //skip the packets that are not of type radius
        if(!packet.isPacketOfType(pcpp::Radius)){
            g_sNotRadius++;
            return NOT_RADIUS_ERROR;
        }

        //get Radius Layer
        pcpp::RadiusLayer* radiusLayer = packet.getLayerOfType<pcpp::RadiusLayer>();
        g_sTotalRadiusPackets++;
        
        if(radiusLayer==NULL){
            std::cout<<"Couldn't read radius Layer\n";
            return NOT_RADIUS_ERROR;
        }
        
        nRadiusAttributeCount = radiusLayer->getAttributeCount();
        nRadiusMessageID = radiusLayer->getRadiusHeader()->id;
        nRadiusCode = radiusLayer->getRadiusHeader()->code;

        //Read radius attributes
        // readAttributebyBytes(radiusLayer);

        return 1; 
        }

    /**
     * @brief Reads Radius Attributes byte by byte 
     * 
     *  For example: --- 28 06 00 00 00 02 --- 
     *  28 = dec(28) = 40 (Acct-Status-Type) 
     *  06 = total length 
     *  00 00 00 02 = value =  2 (stop) 
     *  bytes for data (4) are calculated  [total:6] - [bytesforlength:1] - [bytesforcode:1] = 4 
     *
     * In case of adding new attribute 
     * Please refer to proper documentation to get these values.
     *
     * In this function the loop for reading bytes breaks when the nSumCheck equals zero.
     * Hence, only 4 attributes are read. In order to extract more attributes make sure to add
     * attribute type to switch_case and change the condition for nSumCheck.
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
     * @param radiusLayer 
     * @return int 0 on success, -1 on error
     */
    int readAttributebyBytes(pcpp::RadiusLayer* radiusLayer){
        int nSumCheck = 0;
        unsigned int nRadiusHeaderLength = radiusLayer->getHeaderLen();
        uint8_t u8ByteArray[MAX_RADIUS_PACKET_LENGTH];
        radiusLayer->copyData(u8ByteArray);
        int nSkip = RADIUS_AUTHENTICATOR_LENGTH + RADIUS_LENGTH_ID + RADIUS_IDENTIFIER_LENGTH + 1;
        int nIterator = nSkip;
        while(nIterator < (nRadiusHeaderLength - 1)){
            if(nSumCheck == MAX_ATTRIBUTES_TO_EXTRACT){
            break;
            }
            int nAvpCode = u8ByteArray[nIterator];
            int nAvpLength = u8ByteArray[nIterator+1];
            unsigned long ulMultiplier = 1;
            if (nAvpLength < MIN_VALID_AVP_LEN || nAvpCode < MIN_VALID_AVP_CODE){
                return ATTRIBUTE_PARSE_ERROR;
            }
            switch(nAvpCode){

            case ACCOUNT_STATUS_TYPE:
                u8RadiusAccountingType = (int)u8ByteArray[nIterator+5]; 
                nSumCheck++;
                break;

            case FRAMED_IPV4:
                /*
                * saved as int array
                */
                pu8FramedIPv4Address[0] = u8ByteArray[nIterator + 2];
                pu8FramedIPv4Address[1] = u8ByteArray[nIterator + 3];
                pu8FramedIPv4Address[2] = u8ByteArray[nIterator + 4];
                pu8FramedIPv4Address[3] = u8ByteArray[nIterator + 5];
                nSumCheck++;
                break;

            case CALLING_STATION_ID:
                /*
                * MSISDN 
                * saved as unsigned int 64
                *
                */
                ulMultiplier = 1;
                u64CallingStationID = 0;
                for(int i=nAvpLength-1; i>1; i--){
                unsigned long ulTemp;
                ulTemp = (u8ByteArray[nIterator + i] - 48)  * ulMultiplier;
                u64CallingStationID = R_PACK.number + ulTemp;
                ulMultiplier = ulMultiplier * 10;
                }
                nSumCheck++;
                break;

            case IPV6_PREFIX_TYPE:
                for(int i=IPV6_PREFIX_HEAD_LENGTH; i<=nAvpLength-1; i++){
                pu8FramedIPv6Address[i-IPV6_PREFIX_HEAD_LENGTH] = u8ByteArray[nIterator+i];
                }
                u8FramedIPv6Length = nAvpLength; 
                u8FramedIPv6Type = u8ByteArray[length];
                break;

            default:
                break;
            } 
            
            nIterator = nIterator + nAvpLength;
        }
        return 1;
    }
}