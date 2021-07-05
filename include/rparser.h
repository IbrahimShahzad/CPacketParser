/**
 * @file rparser.h
 * @brief rparser header file
 * @author IbrahimShahzad
 * @date 12 Sep 2019
 */
#include <stdio.h>
#include <stdlib.h>
#include <signal.h>
#include <stdbool.h>
#include <string.h>

#include <rte_eal.h>
#include <rte_common.h>
#include <rte_ethdev.h>
#include <rte_log.h>
#include <rte_mbuf.h>
#include <rte_ip.h>
#include <rte_malloc.h>
#include "radiusAttributesList.h"
#include "userSession.h"
#include <time.h>
#include <rte_ring.h>

#define NUM_MBUFS 8191                      /**< Total number of MBUFs that can be created */
#define MBUF_CACHE_SIZE 250                 /**< Not much to say its cache size */
#define BURST_SIZE 32                       /**< A packet burst receiver receives at a time */       
#define RX_RING_SIZE 128                    /**< Total Rx Queue Size */
#define TX_RING_SIZE 512                    /**< Total Tx Queue Size */

#define NUMBER_OF_ATTRIBUTES_TO_EXTRACT 4   /**< Total number of RADIUS AVPs that are to be extracted */
#define IPV6_PREFIX_HEAD_LENGTH 2           /**< Number of bytes containing IPV6 Prefix Length */
#define UDP_SRC_PORT_FIELD 2                /**< UDP Source port */
#define UDP_DST_PORT_FIELD 2                /**< UDP Destination port */
#define RADIUS_AUTHENTICATION_PORT 1812     /**< Port Number associated with Authentication */
#define RADIUS_AUTHORIZATION_PORT 1813      /**< Port Number associated with Authorization  */
#define RADIUS_PACKET_MIN_LEN 230           /**< Minimum Packet Size set for a RADIUS Packet */
#define UDP_HDR_LEN 8

#define ERROR -1                            /**< ERROR Code */
#define ACCOUNTING_REQUEST 4                /**< RADIUS ACCOUNTING REQUEST CODE */

#define RTE_LOGTYPE_RP  RTE_LOGTYPE_USER3 /**< RTE LOG TYPE*/
#define acl_log(format, ...)  RTE_LOG(ERR, RP, format, ##__VA_ARGS__)

/**
 * @brief print port statistics
 */
void printStats(void);


/**
 * @brief get Radius Code
 * @param *pStartOfRadiusLayer pointer to first byte of radius layer
 * @returns code value of radius
 */
uint8_t getRadiusCode(char* pStartOfRadiusLayer);

/**
 * @brief gets Radius Identifier
 *
 * SKIPS
 *          RADIUS_CODE_FIELD
 * 
 * @param *pStartOfRadiusLayer pointer to first byte of radius layer
 * @returns identifier value of radius
 */
uint8_t getRadiusIdentifier(char* pStartOfRadiusLayer);

/**
 * @brief get Radius Length
 *
 * SKIPS
 *     RADIUS_CODE_FIELD
 *     RADIUS_IDENTIFIER_FIELD_LENGTH
 * @param *pStartOfRadiusLayer pointer to first byte of radius layer
 * @returns length value of radius
 */
uint16_t getRadiusLength(char* pStartOfRadiusLayer);

/**
 * @brief read Radius Attributes
 *
 *      Reads Attributes byte by byte
 *      For example: --- 28 06 00 00 00 02 ---
 *      28 = dec(28) = 40 (Acct-Status-Type)
 *      06 = total length
 *      00 00 00 02 = value =  2 (stop)
 *      bytes for data (4) are calculated  [total:6] - [bytesforlength:1] - [bytesforcode:1] = 4
 *
 *      In case of adding new attribute
 *      Please refer to proper documentation to get these values.
 *
 *           ===================================================
 *               If attribute code or attribute length is 0
 *               Function will not parse rest of the packet
 *           ===================================================
 *
 *      All of the above has been done to  keep this extraction as efficient as possible.
 * @warn please make sure to benchmark if more attributes are extracted.
 * @param *radiusPointer pointer to first byte of radius layer
 * @param RadiusLength length of radius layer
 * @returns 0 for start stop packet -1 for any other
 * @see radiusAttributesList.h
 * @see userSession.h
 */
int readRadiusAttributes(char* pcRadiusLayerPointer,uint16_t u16RadiusLength);


/**
 * @brief get UDP destination port
 * @param *pStartOfUdpLayer Pointer to first byte of UDP Layer
 * @returns Returns UDP Destination Port
 */
uint16_t getUdpDstPort(char *pStartOfUdpLayer);

/**
 * @brief parses radius packet
 *
 *
 *      skips first 4 layers based on their length to get
 *      to starting of radius first byte.
 *
 *      For each packet in mbuf
 *          Strips vlan
 *          checks that the length of packet is greater than 230
 *          skips ether and ip
 *          gets to the UDP Layer
 *          checks that UDP port is either RADIUS_AUTHORIZATION_PORT or RADIUS_AUTHENTICATION_PORT
 *          makes sure that radius code is 4 (ACCOUNTING REQUEST)
 *          calls readRadiusAttributes to read attributes
 *      
 *      Starts A session on RADIUS START
 *      Closes the session on RADIUS STOP
 *      Forwards the data on session close to be dumped into the database
 *
 * @param **pPacketsBurst packet burst
 * @param u16NbPackets number of packets
 * @note static internal function
 */
static void parser(struct rte_mbuf **pPacketBurst, uint16_t u16NbPackets);


/**
 * @brief main rparser function called by main module
 *
 *
 *      receive on port X
 *      call parser function
 *      send on port 1,Only when Tx flag is enabled
 *
 *      ================================================
 *          Arguments can be determined by reading
 *          the conf file
 *      _______________________________________________
 *
 * @param port Port for receiver
 * @param forwarding_lcore Core for rparser
 * @returns 0
 */
int radiusParserWorkerThread(void *arg);

/* NON MODULE FUNCTION */
/**
 * @brief port initializer
 * @param port
 * @param mempool*
 * @returns value > 0 for success
 * @note un-used function - non-module function
 */
int port_init(uint8_t port,struct rte_mempool  *mbuf_pool);


/**
 * @brief initializes RADIUS parser module
 * 
 * @param u8FileFlag flag to enable file writing
 * @param u8TimeFlag for each packet processed
 * @param u8TxFlag  flag enable to transmit to adjacent port
 * @param u8UpdateFlag flag enable/disable RADIUS update packet parsing
 * @param pRingQueue Ring queue to send user session info on session close
 * @return int 0
 */
int rparserInit(uint8_t u8FileFlag,uint8_t  u8TimeFlag, uint8_t  u8TxFlag, uint8_t u8UpdateFlag, struct rte_ring *pRingQueue);
/**
 * @brief logs invalid AVP
 *
 * In case an invalid AVP Code or Len is read, this function
 * logs Code, Len and Loop number 
 * @param u8AvpCodeField AVP Code Field - 1 byte
 * @param u8AvpLenField  AVP Len Field  - 1 byte
 * @param u32Loop        Loop Number
 * @returns -1
 */
int logInvalidAvp(uint8_t  u8AvpCodeField, uint8_t  u8AvpLenField, uint32_t u32Loop);

/**
 * @brief logs invalid Account Status
 *
 * In case an invalid Account Status Code is read, this function
 * logs Code, Len and Loop number 
 * 
 * Invalid Account Status Other than 
 *      1 - Start
 *      2 - Stop
 *      3 - Update
 *
 * @param u8AvpCodeField AVP Code Field - 1 byte
 * @param u8AvpLenField  AVP Len Field  - 1 byte
 * @param u32Loop        Loop Number
 * @returns -1
 */
int logInvalidAccountStatus(uint8_t u8AvpAccountStatusType);


/**
 * @brief extracts MSISDN by reading bytes
 * Reads bytes, converts from ASCII to numeric and returns MSISDN
 * (CallingStationID Field in RADIUS AVPs)
 * @param u8RadiusAvpLen Avp Len Field - 1 byte
 * @param pFirstByteOfCallingStationId  First byte of AVP data field
 * @returns CallingStationID uint64_t
 */
uint64_t extractMSISDN(uint8_t u8RadiusAvpLen, char* pFirstByteOfCallingStationId);