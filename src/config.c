#include "config.h"

#define ERROR -1

int
loadConfigFile(void)
{
    if (g_pConfigFile == NULL) {
        g_pConfigFile = rte_loadConfigFile(CONFIG_FILE, DEFAULT_COMMENT_CHARACTER);
        if (g_pConfigFile == NULL)
            return ERROR
    }

    return 0;
}

int 
unloadConfigFile(void)
{
    if (g_pConfigFile != NULL) {
        int ret = rte_cfgfile_close(g_pConfigFile);
        g_pConfigFile = NULL;
        return ret;
    }
    return ERROR;
}

int
sectionExists(const char *pSectionName)
{
    return rte_cfgfile_has_section(g_pConfigFile, pSectionName);
}

int 
entryExists(const char *pSectionName, const char *pEntryName)
{
    return rte_cfgfile_has_entry(g_pConfigFile, pSectionName, pEntryName);
}

int
getSectionEntries(const char *pSectionName, struct rte_cfgfile_entry *pEntries)
{
    return rte_cfgfile_section_entries(g_pConfigFile, pSectionName, pEntries, MAXIMUM_NB_ENTRIES);
}
