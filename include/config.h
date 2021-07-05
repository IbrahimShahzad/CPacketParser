#ifndef CONFIG_H
#define CONFIG_H

#include <rte_cfgfile.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <rte_log.h>

#define CONFIG_FILE "/etc/RP/config.cfg"
#define DEFAULT_COMMENT_CHARACTER '#'

#define CFG_MAX_SECTIONS 20
#define CFG_MAX_SEC_NAME_LEN 32

#define MAXIMUM_NB_ENTRIES 20 /**< Maximum Number of Entries */
#define SECTION_DB "DB CRED"
#define SECTION_EAL "EAL PARAMS"
#define SECTION_APP "APP PARAMS"
#define SECTION_LOG "LOG PARAMS"
#define SECTION_MODULES "MODULES"
#define SECTION_PORT "PORT LCORE PARAMS"
#define SECTION_RECEIVER "RECEIVER PARAMS"
#define SECTION_PORT_CFG_DATAPATH "FORWARDING PORTS"

#define RTE_LOGTYPE_RP  RTE_LOGTYPE_USER3
#define acl_log(format, ...)  RTE_LOG(ERR, RP, format, ##__VA_ARGS__)

//struct rte_cfgfile * pConfigFile;
struct rte_cfgfile_entry MODULES[MAX_ENTRIES];
struct rte_cfgfile_entry DB_CRED[MAX_ENTRIES];
struct rte_cfgfile_entry EAL_PARAMS[MAX_ENTRIES];
struct rte_cfgfile_entry APP_PARAMS[MAX_ENTRIES];
struct rte_cfgfile_entry LOG_PARAMS[MAX_ENTRIES];
struct rte_cfgfile_entry PORT_LCORE_PARAMS[MAX_ENTRIES];
struct rte_cfgfile_entry RECEIVER_PARAMS[MAX_ENTRIES];
struct rte_cfgfile_entry DATAPATH_PARAMS[MAX_ENTRIES];
struct rte_cfgfile_entry CORRELATOR_PARAMS[MAX_ENTRIES];
struct rte_cfgfile_entry POLICY_ENFORCER_PARAMS[MAX_ENTRIES];
struct rte_cfgfile_entry PORT_CFG_DATAPATH[MAX_ENTRIES];

struct rte_cfgfile *g_pConfigFile; /**< global Config File pointer */
/**
 * @brief Loads config.cfg file from /etc/RP.
 * @param None
 * @returns int
 */
int loadConfigFile        (void);

/**
 * @brief unLoads config.cfg file from /etc/RP.
 * @param None
 * @returns int
 */
int unloadConfigFile      (void);

/**
 * @brief Checks if section exists in configuration file.
 * @param pSectionName (const char*) section name
 * @returns -ive in case of en error
 */
int sectionExists(const char *pSectionName);

/**
 * @brief Checks if entry exists in the given section in configuration file.
 * @param pSectionName (const char*) section name
 * @param pEntryName (const char*) entry name 
 * @returns -ive in case of en error
 */
int entryExists(const char *pSectionName, const char *pEntryName);

/**
 * @brief Stores name,value pairs in section structure.
 * @param pSectionName (const char*)             section name
 * @param pEntries (struct rte_cfgfile_entry *)  structure pointer to store name,value pairs in section.
 * @returns -ive in case of en error
 */
int getSectionEntries(const char *pSectionName, struct rte_cfgfile_entry *pEntries)

#define READ_FROM_FILE 2    /**< 0x1*                   */
#define READ_FROM_MODULE 0  /**< 0x0*     // default    */
#define WRITE_TO_MODULE 0   /**< 0x*0     // default    */
#define WRITE_TO_FILE 1     /**< 0x*1                   */

#endif  // CONFIG_H
