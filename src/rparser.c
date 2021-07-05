#include <stdio.h>
#include <stdlib.h>
#include <stdbool.h>
#include <signal.h>
#include <string.h>
#include <time.h>

#include <rte_eal.h>
#include <rte_common.h>
#include <rte_ethdev.h>
#include <rte_log.h>
#include <rte_mbuf.h>
#include <rte_ip.h>
#include <rte_ring.h>
#include <rte_malloc.h>

#include "rparser.h"
#include "config.h"
#include "arch.h"
#include "userSession.h"



#define RTE_LOGTYPE_RA  RTE_LOGTYPE_USER3 /**< RTE LOG TYPE*/
#define acl_log(format, ...)  RTE_LOG(ERR, RA, format, ##__VA_ARGS__)



// TEST/CONFIGURATION FLAGS ----------------------
uint8_t g_u8DTime = 0;                     /**< (unsigned int 8) used to calculate parse time per packet, (display flag in RP.cfg) */
uint8_t g_u8WriteToFile = 0;               /**< (unsigned int 8) write to file flag for testing (file flag in RP.cfg) */
uint8_t g_u8TxEnable = 0;                  /**< (unsigned int 8) tx flag for testing (display flag in RP.cfg) */
uint8_t g_u8UpdateEnabled = 0;             /**< (unsigned int 8) Update flag for turning update parsing on and off (update_enable flag in RP.cfg) */
uint8_t g_u8PortId;                        /**< (unsigned int 8) receive port for parser (set in config file) */
uint8_t g_u8ForwLcore;                     /**< (unsigned int 8) lcore running parser (set in config file) */
//------------------------------------------------

// NON-MODULE Variables --------------------------
struct rte_ring *g_pMessageQueue;      /**< (pData) Queue for pushing extracted info. Dequeued by Correlator, mem assigned by main */
// RADIUS INFO HOLDER ---------------------------
//-----------------------------------------------



struct RadiusStats{
    uint64_t u64RadiusStartPackets = 0;       /**< (unsigned int 64) Total Radius Start Packets */
    uint64_t u64RadiusStopPackets = 0;        /**< (unsigned int 64) Total Radius Stop Packets */
    uint64_t u64RadiusUpdatePackets = 0;      /**< (unsigned int 64) Total Radius Stop Packets */
    uint64_t u64TotalPackets = 0;             /**< (unsigned int 64) Total Packets */
    uint64_t u64RadiusPackets = 0;            /**< (unsigned int 64) Total Radius Packets */
    uint64_t u64InvalidPackets = 0;            /**< (unsigned int 64) Invalid Packets */
} sRadiusStats;

void printStats(void)
{
    struct rte_eth_stats sStats; 
    uint8_t u8NbPorts = rte_eth_dev_count_avail(); 
    uint8_t u8Port;
    for (u8Port = 0; u8Port < u8NbPorts; ++u8Port) {
        printf("\nStatistics for the Port %u\n", u8Port);
        rte_eth_stats_get(u8Port, &sStats);
        printf("RX:%11lu Tx:%11lu dropped:%11lu\n",
               sStats.ipackets, sStats.opackets, sStats.imissed);
    }
    printf("Total Packets: %llu\n",         sRadiusStats.u64TotalPackets);
    printf("InvalidPackets:%llu\n",         sRadiusStats.u64InvalidPackets);
    printf("RadiusPackets: %llu\n",         sRadiusStats.u64RadiusPackets);
    printf("RadiusStopPackets : %llu\n",    sRadiusStats.u64RadiusStopPackets);
    printf("RadiusStartPackets: %llu\n",    sRadiusStats.u64RadiusStartPackets);
    printf("RadiusUpdatePackets: %llu\n",   sRadiusStats.u64RadiusUpdatePackets);
}



/* CORE FUNCTION */
uint8_t getRadiusCode(char* pStartOfRadLayer)
{
    int nSkip = 0;
    uint8_t u8Code = *(pStartOfRadLayer + nSkip);
    return u8Code;
}


/* CORE FUNCTION */
uint8_t getRadiusIdentifier(char* pStartOfRadLayer)
{
    int nSkip = RADIUS_CODE_FIELD;
    uint8_t u8Identifier = *(pStartOfRadLayer + nSkip);
    return u8Identifier;
}


/* CORE FUNCTION */
uint16_t getRadiusLength(char* pStartOfRadLayer)
{
    int nSkip = RADIUS_CODE_FIELD + RADIUS_IDENTIFIER_FIELD_LENGTH;
    uint8_t temp1 = 0;
    uint8_t temp2 = 0;
    temp1 = *(pStartOfRadLayer + nSkip);
    temp2 = *(pStartOfRadLayer + nSkip + 1);
    uint16_t u16Length = (temp1 * 256) + temp2;
    return u16Length;
}

int logInvalidAvp(uint8_t u8AvpCodeField, uint8_t u8AvpLenField, uint32_t u32Loop)
{   
    /*
    printf("Pack: %d Error: Code %d u8RadiusAvpLen %d u32Loop %d\n",
        g_u64TotalPackets,
        u8AvpCodeField,
        u8AvpLenField,
        u32Loop);
        char temp_str2[50];
        sprintf(temp_str2, "Invalid - Code %d , len= %d, loop @ %d\n", u8AvpCodeField, u8AvpLenField, u32Loop);
        */
    ++sRadiusStats.u64InvalidPackets;
    RTE_LOG(INFO,RA,"Pack: %d Error: Code %d u8RadiusAvpLen %d u32Loop %d\n",
            sRadiusStats.u64InvalidPackets,
            u8AvpCodeField,
            u8AvpLenField,
            u32Loop);
    char temp_str2[50];
    sprintf(temp_str2, "Invalid - Code %d , len= %d, loop @ %d\n", u8AvpCodeField, u8AvpLenField, u32Loop);

    // initializePacketInfo();
    return -1;
}

int logInvalidAccountStatus(uint8_t u8AvpAccountStatusType)
{
    //sift_log("WARN", "RPARSER", "ACCT_STATUS_TYPE %u\n",userDetails.u8AccountStatusType);
    initializePacketInfo();
    return -1;
}

uint64_t extractMSISDN(uint8_t u8RadiusAvpLen, char* pFirstByteOfCallingStationId)
{
    uint64_t u64Multiplier = 1;
    uint64_t u64CallingStationId = 0;
    uint32_t u32Loop = 0;

    for (u32Loop = u8RadiusAvpLen - 1; u32Loop > 1; --u32Loop) {
        char cIterator = *(pFirstByteOfCallingStationId + u32Loop);
        u64CallingStationId += (cIterator - 48) * u64Multiplier;            // ASCII FOR NUMERICS START FROM 48
        u64Multiplier *= 10;
    }
    return u64CallingStationId;
}

/* CORE FUNCTION */
int
readRadiusAttributes(char* pcRadiusLayerPointer, uint16_t u16RadiusLength)
{
    struct UserSessionInfo userDetails;
    int nSessionIndicator = -1;
    userDetails.u64ValidAttributes =0;
    uint32_t u32Loop = RADIUS_CODE_FIELD + RADIUS_IDENTIFIER_FIELD_LENGTH + RADIUS_LENGTH_FIELD_LENGTH + RADIUS_AUTHENTICATOR_FIELD_LENGTH;
    uint8_t u32SecondLoop = 0;

    while (u32Loop < u16RadiusLength && userDetails.u64ValidAttributes <= NUMBER_OF_ATTRIBUTES_TO_EXTRACT) {
        uint8_t u8RadiusAvpCode = *(pcRadiusLayerPointer + u32Loop);
        uint8_t u8RadiusAvpLen = *(pcRadiusLayerPointer + u32Loop + 1);

        if (u8RadiusAvpCode == 0 || u8RadiusAvpLen <= 3)
            return logInvalidAvp(u8RadiusAvpCode,u8RadiusAvpLen,u32Loop);
        switch (u8RadiusAvpCode) {
            case ACCT_STATUS_TYPE:
                userDetails.u8AccountStatusType = *(pcRadiusLayerPointer + u32Loop + u8RadiusAvpLen - 1);
                switch (userDetails.u8AccountStatusType) {
                    case SESSION_START:
                        sessionStart(&userDetails);
                        ++sRadiusStats.u64RadiusStartPackets;
                        nSessionIndicator = SESSION_START;
                        break;
                    case SESSION_STOP:
                        sessionEnd();
                        nSessionIndicator = SESSION_STOP;
                        ++sRadiusStats.u64RadiusStopPackets
                        break;
                    case SESSION_UPDATE:
                        if(g_u8UpdateEnabled == 0)
                            return logInvalidAccountStatus(userDetails.u8AccountStatusType);
                        sessionEnd();
                        sessionStart();
                        ++sRadiusStats.u64RadiusUpdatePackets;
                        break;
                
                    default:
                        return logInvalidAccountStatus(userDetails.u8AccountStatusType);
                }
                
                ++userDetails.u64ValidAttributes;
            break;

            case NAS_IP_ADDRESS:
                for(u32SecondLoop = 0; u32SecondLoop <= 3; u32SecondLoop++){
                    userDetails.u8NasIpAddress[u32SecondLoop] = *(pcRadiusLayerPointer + u32Loop + u32SecondLoop + 2);
                }
                ++userDetails.u64ValidAttributes;
                break;

            case NAS_PORT:
                userDetails.u16NasPort = *(pcRadiusLayerPointer + u32Loop + u8RadiusAvpLen - 2);
                break;

            case SERVICE_TYPE:
                userDetails.u8ServiceType = *(pcRadiusLayerPointer + u32Loop + u8RadiusAvpLen - 1);
                break;

            case FRAMED_IP_ADDRESS:
                for(u32SecondLoop = 0; u32SecondLoop <= 3; u32SecondLoop++){
                    userDetails.u8FramedIpv4Address[u32SecondLoop] = *(pcRadiusLayerPointer + u32Loop + u32SecondLoop + 2);
                }
                ++userDetails.u64ValidAttributes;
                break;

            case FRAMED_IP_NETMASK:
                for(u32SecondLoop = 0; u32SecondLoop <= 3; u32SecondLoop++){
                    userDetails.u8FramedIpv4NetMask[u32SecondLoop] = *(pcRadiusLayerPointer + u32Loop + u32SecondLoop + 2);
                }
                ++userDetails.u64ValidAttributes;
                break;
            case FRAMED_IPV6_PREFIX:
                for (u32SecondLoop = IPV6_PREFIX_HEAD_LENGTH; u32SecondLoop <= u8RadiusAvpLen-1; ++u32SecondLoop){
                    userDetails.u8FramedIpv6Prefix[u32SecondLoop - IPV6_PREFIX_HEAD_LENGTH] = *(pcRadiusLayerPointer + u32Loop + u32SecondLoop);
                }
                ++userDetails.u64ValidAttributes;
                break;

            case CALLING_STATION_ID:
                userDetails.u64CallingStationId = 0;
                userDetails.u64CallingStationId = extractMSISDN(u8RadiusAvpLen,(pcRadiusLayerPointer + u32Loop));
                ++userDetails.u64ValidAttributes;
                break;

            case CALLED_STATION_ID:
                userDetails.u64CalledStationId = 0;
                userDetails.u64CalledStationId = extractMSISDN(u8RadiusAvpLen,(pcRadiusLayerPointer + u32Loop));
                ++userDetails.u64ValidAttributes;
                break;

            //TODO: handle Fall Throughs
            case USER_NAME:
            case USER_PASSWORD:
            case CHAP_PASSWORD:
            case FRAMED_PROTOCOL:
            case FRAMED_ROUTING:
            case FILTER_ID:
            case FRAMED_MTU:
            case FRAMED_COMPRESSION:
            case LOGIN_IP_HOST:
            case LOGIN_SERVICE:
            case LOGIN_TCP_PORT:
            default:
                break;
        } // END OF SWITCH
        u32Loop += u8RadiusAvpLen;
        ++userDetails.u64ValidAttributes;
    } // END OF WHILE LOOP
    return nSessionIndicator;
}

/* CORE FUNCTION */
uint16_t getUdpDstPort(char *pStartOfUdpLayer)
{
    int nSkip = UDP_SRC_PORT_FIELD;
    uint8_t u8FirstByte = 0;
    uint8_t u8SecondByte = 0;
    uint16_t u16UdpDestPort = 0;
    u8FirstByte  = *(pStartOfUdpLayer + nSkip);
    u8SecondByte = *(pStartOfUdpLayer + nSkip + 1);
    u16UdpDestPort = (u8FirstByte * 256) + u8SecondByte;
    return u16UdpDestPort;
}
int sessionStart(struct UserSessionInfo userDetails){
    setCurrentLocalTime(&userDetails.sSessionStartTime);
    return 0;
}
int sessionEnd(struct UserSessionInfo userDetails){
    setCurrentLocalTime(&userDetails.sSessionEndTime);
    return 0;
}




/* CORE FUNCTION */
static void parser(struct rte_mbuf **pPacketBurst, uint16_t u16NbPackets)
{
    struct timespec ts1, ts2;
    struct rte_mbuf *pPacket;
    struct ipv4_hdr *pIpv4Hdr;
    struct ether_hdr *pEthHdr;
    struct udp_hdr *pUdpHdr;
    FILE *fpDumpFile;
    uint16_t u16BufferIterator;
    for (u16BufferIterator = 0; u16BufferIterator < u16NbPackets; ++u16BufferIterator) {
        pPacket = pPacketBurst[u16BufferIterator];
        clock_gettime(CLOCK_REALTIME, &ts1);
        ++sRadiusStats.u64TotalPackets;
        while(rte_vlan_strip(pPacket)); // Vlan Check
        rte_prefetch0(rte_pktmbuf_mtod(pPacket, void*));
        if (pPacket->pkt_len < RADIUS_PACKET_MIN_LEN)
            continue;

        pEthHdr = rte_pktmbuf_mtod(pPacketBurst[u16BufferIterator], struct ether_hdr *);
        pIpv4Hdr = (struct ipv4_hdr*) (pEthHdr + 1);

        switch (pIpv4Hdr->next_proto_id) {
            case IPPROTO_UDP:
                pUdpHdr = (struct udp_hdr*) ((unsigned char *) pIpv4Hdr + sizeof (struct ipv4_hdr));
                void * pData = (void*) ((unsigned char*) pUdpHdr + 1);
                uint16_t u16UdpDstPort = getUdpDstPort(pData - 1);
                if (u16UdpDstPort == RADIUS_AUTHORIZATION_PORT || u16UdpDstPort == RADIUS_AUTHENTICATION_PORT) {
                    uint32_t u32HeaderOffset = UDP_HDR_LEN - 1;
                    /* Second check on radius code */
                    struct RadiusHeaderInfo sRadiusHeader;
                    sRadiusHeader.u8RadiusCode = getRadiusCode(pData + u32HeaderOffset);
                    if (sRadiusHeader.u8RadiusCode == ACCOUNTING_REQUEST) {
                        ++sRadiusStats.u64RadiusPackets;
                        sRadiusHeader.u16RadiusLength = getRadiusLength(pData + u32HeaderOffset);
                        sRadiusHeader.u8RadiusIdentifier = getRadiusIdentifier(pData + u32HeaderOffset);
                        //TODO: pass on the userData Struct
                        int nRet =readRadiusAttributes(pData + u32HeaderOffset, sRadiusHeader.u16RadiusLength);
                        if (nRet == ERROR) {
                            
                        }
                        switch(nRet){
                            case SESSION_START:
                                // TODO: malloc
                                // TODO: insert in hashtable
                                break;
                            case SESSION_STOP:
                                // TODO: search hashtable
                                // TODO: delete from hashtable
                                // TODO: insert in ring to be pass to Data Manager
                                break;
                            case SESSION_UPDATE:
                                // TODO: close previous session or
                                // TODO: update the info only for the same session in hash table
                                break;
                            case ERROR:
                                rte_pktmbuf_free(pPacketBurst[u16BufferIterator]);
                                continue;
                            case default:
                                break;
                        }

                        rte_pktmbuf_free(pPacketBurst[u16BufferIterator]);
                        clock_gettime(CLOCK_REALTIME, &ts2);
                        if (g_u8DTime == 1) {
                            printf("parser took about %9ld ns/pkt \n", (ts2.tv_nsec - ts1.tv_nsec));
                        }
                    }                 
                }
                break;

            default:
                break;
        }
    }// END OF FOR LOOP
}


/* CORE FUNCTION */
int
radiusParserWorkerThread(void *args) 
{
    unsigned int uLcoreId = rte_lcore_id();  
    const uint8_t u8NbPorts = rte_eth_dev_count_avail(); 
    int nOuterLoop = 0;
    int nInnerLoop = 0;
    int nFlag = 0;
    uint8_t u8DestPort;
    char cBuffer[100];
    for (nOuterLoop = 0; nOuterLoop <= g_u8NbModules; ++nOuterLoop) {
        sprintf(cBuffer, "packet_receiver%d", nOuterLoop);
        for (nInnerLoop = 0; nInnerLoop < g_u8NbModules; ++nInnerLoop) {
            if (strcmp(sModuleInstance[nInnerLoop].module_name, cBuffer) == 0) {
                g_u8PortId = sModuleInstance[nInnerLoop].port;
                g_u8ForwLcore = sModuleInstance[nInnerLoop].lcore;
                nFlag = 1;
                break;
            }
        }
        if(nFlag == 1) {
            break;
        }
    }
    RTE_LOG(INFO, RA, "Running RPARSER [lcore: %u port:%u] \n", uLcoreId, g_u8PortId);
    /* Run until RP-App is killed or quit */
    while (!bForceQuitFlag) {
        struct rte_mbuf * pPacketBurst[BURST_SIZE];
        uint16_t u16NbRxPackets = 0;
        uint16_t u16NbTxPackets = 0;
        uint16_t u16BufferIterator = 0;

        /* Get burst fo RX packets */
        u16NbRxPackets = rte_eth_rx_burst(g_u8PortId, 0, pPacketBurst, BURST_SIZE);

        // initializePacketInfo();
        parser(pPacketBurst, u16NbRxPackets);

        if (unlikely(u16NbRxPackets == 0))
            continue;
        
        u8DestPort = g_u8PortId ^ 1;

        if (g_u8TxEnable) {
            u16NbTxPackets = rte_eth_tx_burst(u8DestPort, 0, pPacketBurst, u16NbRxPackets);
        }

        /* Free any unsent packets. */
        if (unlikely(u16NbTxPackets < u16NbRxPackets)) {
            for (u16BufferIterator = 0; u16BufferIterator < u16NbRxPackets; ++u16BufferIterator) {
                rte_pktmbuf_free(pPacketBurst[u16BufferIterator]);
            }
        }
    }
    return 0;
}

/* NON MODULE FUNCTION */
/* THIS FUNCTION IS GOING TO REMOVED IN NEXT ITERATION */
/*
 * FUNCTION_NAME:
 *      port_init
 *
 * ARGS:
 *      @uint8_t port
 *      @struct mempool*
 *
 * DESCRIPTION:
 *      initialize ports
 */
int
port_init(uint8_t port, struct rte_mempool *mbuf_pool)
{
    struct rte_eth_conf port_conf = {
        .rxmode =
            { .max_rx_pkt_len = ETHER_MAX_LEN}
    };
    const uint16_t nb_rx_queues = 1;
    const uint16_t nb_tx_queues = 1;
    int ret;
    uint16_t q;

    /* configure the ethernet device */
    ret = rte_eth_dev_configure(port,
                                nb_rx_queues,
                                nb_tx_queues,
                                &port_conf);

    if (ret != 0)
        return ret;

    /* Allocate and setup 1 RX queue per Ethernet port */
    for (q = 0; q < nb_rx_queues; ++q) {
        ret = rte_eth_rx_queue_setup(port, q, RX_RING_SIZE,
                                     rte_eth_dev_socket_id(port),
                                     NULL, mbuf_pool);

        if (ret < 0)
            return ret;
    }

    /* Allocate and setup 1 TX queue per Ethernet port */
    for (q = 0; q < nb_tx_queues; ++q) {
        ret = rte_eth_tx_queue_setup(port, q, TX_RING_SIZE,
                                     rte_eth_dev_socket_id(port),
                                     NULL);

        if (ret < 0)
            return ret;
    }

    /* start the ethernet port */
    ret = rte_eth_dev_start(port);
    if (ret < 0)
        return ret;

    /* Enable RX in promiscuous mode for the Ethernet device */
    rte_eth_promiscuous_enable(port);

    return 0;
}

/* CORE FUNCTION */
int
rparserInit( uint8_t u8FileFlag, uint8_t u8TimeFlag, uint8_t u8TxFlag, uint8_t u8UpdateFlag, struct rte_ring *pRingQueue)
{
    // g_u8PortId       = port;
    g_u8WriteToFile     = u8FileFlag;
    g_u8DTime           = u8TimeFlag;
    g_u8TxEnable        = u8TxFlag;
    g_u8UpdateEnabled   = u8UpdateFlag;
    // g_u8ForwLcore    = lcore;
    g_pMessageQueue= pRingQueue;
    if (g_pMessageQueue == NULL){
        printf("ERROR: g_pMessageQueue not initialized");
        // may be exit here
    }
    RTE_LOG(INFO, RA, "RPARSER Initialized:\n\tWrite To File:\t\t\t%s\n\tDsp Time:\t\t\t%s\n\tTx:\t\t\t\t%s\n\tQUEUE:\t\t\t\t%d\n",
            (g_u8WriteToFile ? "\033[0;32mENABLE\033[0m" : "\033[0;31mDISABLE\033[0m"),
            (g_u8DTime ? "\033[0;32mENABLE\033[0m" : "\033[0;31mDISABLE\033[0m"),
            (g_u8TxEnable ? "\033[0;32mENABLE\033[0m" : "\033[0;31mDISABLE\033[0m"), pRingQueue);
    return 0;
}
