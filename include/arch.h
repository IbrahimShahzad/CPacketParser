/**
 * @file arch.h
 * @author IbrahimShahzad
 * @brief holds map 
 * @version 0.1
 * @date 2021-03-05
 * 
 * @copyright Copyright (c) 2021
 * 
 */
#ifndef ARCH_H
#define ARCH_H

#include <rte_ring.h>
#include <rte_hash.h>
#include <rte_jhash.h>
#include <stdlib.h>
#include <stdbool.h>
#include <inttypes.h>

#define MAX_MODULES 8               /**< Number of Maximum Modules */
#define RING_SIZE 1048576           /**< Ring Buffer Size */
#define MSISDN_LEN  14              /**< Number of digits in an MSISDN no. (12 + 1) */
struct rte_hash *pUserHashTable;    /** To hold active sessions */

/**
 * @brief Map for Module
 * 
 * Map for Modules associated Lcore, Rx Port, Rx Queue and Instance Number.
 */
struct ArchMap {
    char pModuleName[50];
    uint8_t u8Lcore;                /**< logical core for module */
    uint8_t u8Port;                 /**< Receiving port for module */
    uint8_t u8Queue;                /**< Receiving queue for module */
    uint8_t u8Instance;             /**< module instance */
} sModuleInstance[MAX_MODULES] ;

uint8_t g_u8RadiusParserInstance;   /**< Radius Parser module instance */
uint8_t g_u8NbModules;              /**< number of modules */
volatile bool bForceQuitFlag;       /**< Gracefully shutdown all threads in the process. */

#endif
