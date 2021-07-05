/**
 * @file userSession.h
 * @author IbrahimShahzad
 * @brief  User Session Functions
 * @version 0.1
 * @date 2021-03-05
 */
#ifndef USERSESSION_H
#define USERSESSION_H

#include <stdio.h>
#include <stdlib.h>
#include <time.h>

#define IPV6_PREFIX_MAX_LEN 18  /**< length of max ipv6 prefix including 2 bytes of dialing code */
#define SESSION_START 1         /**< Session start on RADIUS START message */
#define SESSION_STOP 2          /**< Session stop on RADIUS STOP message */
#define SESSION_UPDATE 3        /**< Session update on RADIUS UPDATE message */
#define IPV4_OCTETS 4           /**< Octets in IPv4 Address */



/**
 * @brief session Start
 * 
 * @param userDetails UserSessionInfo Struct
 * @return int 
 */
int sessionStart(struct UserSessionInfo userDetails);
/**
 * @brief session End
 * 
 * @param userDetails 
 * @return int 
 */
int sessionEnd(struct UserSessionInfo userDetails);


/**
 * @brief struct to hold user related info from the radius feed
 * 
 */
struct UserSessionInfo
{
    struct tm sSessionStartTime;
    struct tm sSessionEndTime;
    uint64_t u64ValidAttributes;
    char *pcUserName;                             /**< text [RFC2865] */
    char *pcUserPassword;                         /**< string [RFC2865]*/
    char *pcChapPassword;                         /**< string [RFC2865]*/
    uint8_t u8NasIpAddress[IPV4_OCTETS] = {0};          /**< ipv4addr [RFC2865]*/
    uint16_t u16NasPort;                           /**< integer [RFC2865]*/
    uint8_t u8ServiceType; /**< enum [RFC2865]*/       //TODO: enum
    int nFramedProtocol; /**< enum [RFC2865]*/    //TODO: enum
    uint8_t u8FramedIpv4Address[IPV4_OCTETS] = {0};     /**< ipv4addr [RFC2865]*/
    uint8_t u8FramedIpv4NetMask[IPV4_OCTETS] = {0};     /**< ipv4addr [RFC2865]*/
    int nFramedRouting; /**< enum [RFC2865]*/     //TODO: enum
    char *pcFilterId;                             /**< text [RFC2865]*/
    int nFramedMTU;                               /**< integer [RFC2865]*/
    int nFramedCompression; /**< enum [RFC2865]*/ //TODO: enum
    uint8_t u8LoginIpHost[IPV4_OCTETS] = {0};           /**< ipv4addr [RFC2865]*/
    int nLoginService; /**< enum [RFC2865]*/      //TODO: enum
    uint16_t u16LoginTcpPort;                     /**< integer [RFC2865]*/
    char *pcReplyMessage;                         /**< text [RFC2865]*/
    char *pcCallBackNumber;                       /**< text [RFC2865]*/
    char *pcCallBackId;                           /**< text [RFC2865]*/
    char *pcFramedRoute;                          /**< text [RFC2865]*/
    uint8_t u8FramedIpxNetwork[IPV4_OCTETS] = {0};      /**< ipv4addr [RFC2865]*/
    char *pcState;                                /**< string [RFC2865]*/
    char *pcClass;                                /**< string [RFC2865]*/
                                                  // VENDOR_SPECIFIC 26  /**< vsa [RFC2865]*/ //TODO: Vendor Specific
    int nSessionTimeout;                          /**< integer [RFC2865]*/
    int nIdleTimeout;                             /**< integer [RFC2865]*/
    int nTerminationAction; /**< enum [RFC2865]*/ //TODO: enum
    uint64_t u64CalledStationId;                  /**< text [RFC2865]*/
    uint64_t u64CallingStationId;                 /**< text [RFC2865]*/
    //TODO: All attributes
    //NAS_IDENTIFIER  32  /**< text [RFC2865]*/
    //PROXY_STATE 33  /**< string [RFC2865]*/
    //LOGIN_LAT_SERVICE   34  /**< text [RFC2865]*/
    //LOGIN_LAT_NODE  35  /**< text [RFC2865]*/
    //LOGIN_LAT_GROUP 36  /**< string [RFC2865]*/
    //FRAMED_APPLETALK_LINK   37  /**< integer [RFC2865]*/
    //FRAMED_APPLETALK_NETWORK    38  /**< integer [RFC2865]*/
    //FRAMED_APPLETALK_ZONE   39  /**< text [RFC2865]*/
    uint8_t u8AccountStatusType;  /**< enum [RFC2866]*/
    //ACCT_DELAY_TIME 41  /**< integer [RFC2866]*/
    //ACCT_INPUT_OCTETS   42  /**< integer [RFC2866]*/
    //ACCT_OUTPUT_OCTETS  43  /**< integer [RFC2866]*/
    //ACCT_SESSION_ID 44  /**< text [RFC2866]*/
    //ACCT_AUTHENTIC  45  /**< enum [RFC2866]*/
    //ACCT_SESSION_TIME   46  /**< integer [RFC2866]*/
    //ACCT_INPUT_PACKETS  47  /**< integer [RFC2866]*/
    //ACCT_OUTPUT_PACKETS 48  /**< integer [RFC2866]*/
    //ACCT_TERMINATE_CAUSE    49  /**< enum [RFC2866]*/
    //ACCT_MULTI_SESSION_ID   50  /**< text [RFC2866]*/
    //ACCT_LINK_COUNT 51  /**< integer [RFC2866]*/
    //ACCT_INPUT_GIGAWORDS    52  /**< integer [RFC2869]*/
    //ACCT_OUTPUT_GIGAWORDS   53  /**< integer [RFC2869]*/
    //EVENT_TIMESTAMP 55  /**< time [RFC2869]*/
    //EGRESS_VLANID   56  /**< integer [RFC4675]*/
    //INGRESS_FILTERS 57  /**< enum [RFC4675]*/
    //EGRESS_VLAN_NAME    58  /**< text [RFC4675]*/
    //USER_PRIORITY_TABLE 59  /**< string [RFC4675]*/
    //CHAP_CHALLENGE  60  /**< string [RFC2865]*/
    //NAS_PORT_TYPE   61  /**< enum [RFC2865]*/
    //PORT_LIMIT  62  /**< integer [RFC2865]*/
    //LOGIN_LAT_PORT  63  /**< text [RFC2865]*/
    //TUNNEL_TYPE 64  /**< enum [RFC2868]*/
    //TUNNEL_MEDIUM_TYPE  65  /**< enum [RFC2868]*/
    //TUNNEL_CLIENT_ENDPOINT  66  /**< text [RFC2868]*/
    //TUNNEL_SERVER_ENDPOINT  67  /**< text [RFC2868]*/
    //ACCT_TUNNEL_CONNECTION  68  /**< text [RFC2867]*/
    //TUNNEL_PASSWORD 69  /**< string [RFC2868]*/
    //ARAP_PASSWORD   70  /**< string [RFC2869]*/
    //ARAP_FEATURES   71  /**< string [RFC2869]*/
    //ARAP_ZONE_ACCESS    72  /**< enum [RFC2869]*/
    //ARAP_SECURITY   73  /**< integer [RFC2869]*/
    //ARAP_SECURITY_DATA  74  /**< text [RFC2869]*/
    //PASSWORD_RETRY  75  /**< integer [RFC2869]*/
    //PROMPT  76  /**< enum [RFC2869]*/
    //CONNECT_INFO    77  /**< text [RFC2869]*/
    //CONFIGURATION_TOKEN 78  /**< text [RFC2869]*/
    //EAP_MESSAGE 79  /**< concat [RFC2869]*/
    //MESSAGE_AUTHENTICATOR   80  /**< string [RFC2869]*/
    //TUNNEL_PRIVATE_GROUP_ID 81  /**< text [RFC2868]*/
    //TUNNEL_ASSIGNMENT_ID    82  /**< text [RFC2868]*/
    //TUNNEL_PREFERENCE   83  /**< integer [RFC2868]*/
    //ARAP_CHALLENGE_RESPONSE 84  /**< string [RFC2869]*/
    //ACCT_INTERIM_INTERVAL   85  /**< integer [RFC2869]*/
    //ACCT_TUNNEL_PACKETS_LOST    86  /**< integer [RFC2867]*/
    //NAS_PORT_ID 87  /**< text [RFC2869]*/
    //FRAMED_POOL 88  /**< text [RFC2869]*/
    //CUI 89  /**< string [RFC4372]*/
    //TUNNEL_CLIENT_AUTH_ID   90  /**< text [RFC2868]*/
    //TUNNEL_SERVER_AUTH_ID   91  /**< text [RFC2868]*/
    //NAS_FILTER_RULE 92  /**< text [RFC4849]*/
    //ORIGINATING_LINE_INFO   94  /**< string [RFC7155]*/
    //NAS_IPV6_ADDRESS    95  /**< ipv6addr [RFC3162]*/
    //FRAMED_INTERFACE_ID 96  /**< ifid [RFC3162]*/
    uint8_t u8FramedIpv6Prefix[IPV6_PREFIX_MAX_LEN] = {0}; /**< ipv6prefix [RFC3162]*/
    //LOGIN_IPV6_HOST 98  /**< ipv6addr [RFC3162]*/
    //FRAMED_IPV6_ROUTE   99  /**< text [RFC3162]*/
    //FRAMED_IPV6_POOL    100 /**< text [RFC3162]*/
    //ERROR_CAUSE ATTRIBUTE   101 /**< enum [RFC3576]*/
    //EAP_KEY_NAME    102 /**< string [RFC4072][RFC7268]*/
    //DIGEST_RESPONSE 103 /**< text [RFC5090]*/
    //DIGEST_REALM    104 /**< text [RFC5090]*/
    //DIGEST_NONCE    105 /**< text [RFC5090]*/
    //DIGEST_RESPONSE_AUTH    106 /**< text [RFC5090]*/
    //DIGEST_NEXTNONCE    107 /**< text [RFC5090]*/
    //DIGEST_METHOD   108 /**< text [RFC5090]*/
    //DIGEST_URI  109 /**< text [RFC5090]*/
    //DIGEST_QOP  110 /**< text [RFC5090]*/
    //DIGEST_ALGORITHM    111 /**< text [RFC5090]*/
    //DIGEST_ENTITY_BODY_HASH 112 /**< text [RFC5090]*/
    //DIGEST_CNONCE   113 /**< text [RFC5090]*/
    //DIGEST_NONCE_COUNT  114 /**< text [RFC5090]*/
    //DIGEST_USERNAME 115 /**< text [RFC5090]*/
    //DIGEST_OPAQUE   116 /**< text [RFC5090]*/
    //DIGEST_AUTH_PARAM   117 /**< text [RFC5090]*/
    //DIGEST_AKA_AUTS 118 /**< text [RFC5090]*/
    //DIGEST_DOMAIN   119 /**< text [RFC5090]*/
    //DIGEST_STALE    120 /**< text [RFC5090]*/
    //DIGEST_HA1  121 /**< text [RFC5090]*/
    //SIP_AOR 122 /**< text [RFC5090]*/
    //DELEGATED_IPV6_PREFIX   123 /**< ipv6prefix [RFC4818]*/
    //MIP6_FEATURE_VECTOR 124 /**< integer64 [RFC5447]*/
    //MIP6_HOME_LINK_PREFIX   125 /**< string [RFC5447]*/
    //OPERATOR_NAME   126 /**< text [RFC5580]*/
    //LOCATION_INFORMATION    127 /**< string [RFC5580]*/
    //LOCATION_DATA   128 /**< string [RFC5580]*/
    //BASIC_LOCATION_POLICY_RULES 129 /**< string [RFC5580]*/
    //EXTENDED_LOCATION_POLICY_RULES  130 /**< string [RFC5580]*/
    //LOCATION_CAPABLE    131 /**< enum [RFC5580]*/
    //REQUESTED_LOCATION_INFO 132 /**< enum [RFC5580]*/
    //FRAMED_MANAGEMENT_PROTOCOL  133 /**< enum [RFC5607]*/
    //MANAGEMENT_TRANSPORT_PROTECTION 134 /**< enum [RFC5607]*/
    //MANAGEMENT_POLICY_ID    135 /**< text [RFC5607]*/
    //MANAGEMENT_PRIVILEGE_LEVEL  136 /**< integer [RFC5607]*/
    //PKM_SS_CERT 137 /**< concat [RFC5904]*/
    //PKM_CA_CERT 138 /**< concat [RFC5904]*/
    //PKM_CONFIG_SETTINGS 139 /**< string [RFC5904]*/
    //PKM_CRYPTOSUITE_LIST    140 /**< string [RFC5904]*/
    //PKM_SAID    141 /**< text [RFC5904]*/
    //PKM_SA_DESCRIPTOR   142 /**< string [RFC5904]*/
    //PKM_AUTH_KEY    143 /**< string [RFC5904]*/
    //DS_LITE_TUNNEL_NAME 144 /**< text [RFC6519]*/
    //MOBILE_NODE_IDENTIFIER  145 /**< string [RFC6572]*/
    //SERVICE_SELECTION   146 /**< text [RFC6572]*/
    //PMIP6_HOME_LMA_IPV6_ADDRESS 147 /**< ipv6addr [RFC6572]*/
    //PMIP6_VISITED_LMA_IPV6_ADDRESS  148 /**< ipv6addr [RFC6572]*/
    //PMIP6_HOME_LMA_IPV4_ADDRESS 149 /**< ipv4addr [RFC6572]*/
    //PMIP6_VISITED_LMA_IPV4_ADDRESS  150 /**< ipv4addr [RFC6572]*/
    //PMIP6_HOME_HN_PREFIX    151 /**< ipv6prefix [RFC6572]*/
    //PMIP6_VISITED_HN_PREFIX 152 /**< ipv6prefix [RFC6572]*/
    //PMIP6_HOME_INTERFACE_ID 153 /**< ifid [RFC6572]*/
    //PMIP6_VISITED_INTERFACE_ID  154 /**< ifid [RFC6572]*/
    //PMIP6_HOME_IPV4_HOA 155 /**< ipv4prefix [RFC6572]*/
    //PMIP6_VISITED_IPV4_HOA  156 /**< ipv4prefix [RFC6572]*/
    //PMIP6_HOME_DHCP4_SERVER_ADDRESS 157 /**< ipv4addr [RFC6572]*/
    //PMIP6_VISITED_DHCP4_SERVER_ADDRESS  158 /**< ipv4addr [RFC6572]*/
    //PMIP6_HOME_DHCP6_SERVER_ADDRESS 159 /**< ipv6addr [RFC6572]*/
    //PMIP6_VISITED_DHCP6_SERVER_ADDRESS  160 /**< ipv6addr [RFC6572]*/
    //PMIP6_HOME_IPV4_GATEWAY 161 /**< ipv4addr [RFC6572]*/
    //PMIP6_VISITED_IPV4_GATEWAY  162 /**< ipv4addr [RFC6572]*/
    //EAP_LOWER_LAYER 163 /**< enum [RFC6677]*/
    //GSS_ACCEPTOR_SERVICE_NAME   164 /**< text [RFC7055]*/
    //GSS_ACCEPTOR_HOST_NAME  165 /**< text [RFC7055]*/
    //GSS_ACCEPTOR_SERVICE_SPECIFICS  166 /**< text [RFC7055]*/
    //GSS_ACCEPTOR_REALM_NAME 167 /**< text [RFC7055]*/
    //FRAMED_IPV6_ADDRESS 168 /**< ipv6addr [RFC6911]*/
    //DNS_SERVER_IPV6_ADDRESS 169 /**< ipv6addr [RFC6911]*/
    //ROUTE_IPV6_INFORMATION  170 /**< ipv6prefix [RFC6911]*/
    //DELEGATED_IPV6_PREFIX_POOL  171 /**< text [RFC6911]*/
    //STATEFUL_IPV6_ADDRESS_POOL  172 /**< text [RFC6911]*/
    //IPV6_6RD_CONFIGURATION  173 /**< tlv [RFC6930]*/
    //ALLOWED_CALLED_STATION_ID   174 /**< text [RFC7268]*/
    //EAP_PEER_ID 175 /**< string [RFC7268]*/
    //EAP_SERVER_ID   176 /**< string [RFC7268]*/
    //MOBILITY_DOMAIN_ID  177 /**< integer [RFC7268]*/
    //PREAUTH_TIMEOUT 178 /**< integer [RFC7268]*/
    //NETWORK_ID_NAME 179 /**< string [RFC7268]*/
    //EAPOL_ANNOUNCEMENT  180 /**< concat [RFC7268]*/
    //WLAN_HESSID 181 /**< text [RFC7268]*/
    //WLAN_VENUE_INFO 182 /**< integer [RFC7268]*/
    //WLAN_VENUE_LANGUAGE 183 /**< string [RFC7268]*/
    //WLAN_VENUE_NAME 184 /**< text [RFC7268]*/
    //WLAN_REASON_CODE    185 /**< integer [RFC7268]*/
    //WLAN_PAIRWISE_CIPHER    186 /**< integer [RFC7268]*/
    //WLAN_GROUP_CIPHER   187 /**< integer [RFC7268]*/
    //WLAN_AKM_SUITE  188 /**< integer [RFC7268]*/
    //WLAN_GROUP_MGMT_CIPHER  189 /**< integer [RFC7268]*/
    //WLAN_RF_BAND    190 /**< integer [RFC7268]*/
};

/**
 * @brief Initialise User Session Structure
 * 
 * @param sA Passed by address to be updated
 * @return 0
 */
int initUserSession(struct UserSessionInfo sA){
    sA.u64ValidAttributes=0;
    sA.pcUserName=NULL;
    sA.pcUserPassword=NULL;
    sA.pcChapPassword=NULL;
    sA.u16NasPort=0;
    sA.u8ServiceType=0;
    sA.nFramedProtocol=0;
    sA.nFramedRouting=0; 
    sA.pcFilterId=NULL;
    sA.nFramedMTU=0;
    sA.nFramedCompression=0;
    sA.nLoginService=0;
    sA.u16LoginTcpPort=0;
    sA.pcReplyMessage=NULL;
    sA.pcCallBackNumber=NULL;
    sA.pcCallBackId=NULL;
    sA.pcFramedRoute=NULL;
    sA.pcState=NULL;
    sA.pcClass=NULL;
    sA.nSessionTimeout=0;
    sA.nIdleTimeout=0;
    sA.nTerminationAction=0;
    sA.u64CalledStationId=0;
    sA.u64CallingStationId=0;
    return 0;
    //TODO Add rest
}
/**
 * @brief copy session info source to destination
 * 
 * @param sA destination
 * @param sB source
 * @return int number of elements not copied from source
 */
int userSessionEquate(struct UserSessionInfo sA, struct UserSessionInfo sB){
    int nI=0; //values not copied 
    sA.u64CallingStationId==0 ?  sA.u64CallingStationID = sB.u64CallingStationID : nI++;
    sA.u64CalledStationId==0 ?  sA.u64CalledStationId = sB.u64CalledStationId : nI++;
    rte_memcpy(&sA.sSessionEndTime,&sB.sSessionEndTime,sizeof(sA.sSessionEndTime));
    *sA.pcUserName==NULL ? rte_memcpy(sA.pcUserName,sB.pcUserName,sizeof(char)*strlen(sA.pcUserName)) :  nI++;
    *sA.pcUserPassword==NULL ? rte_memcpy(sA.pcUserPassword,sB.pcUserPassword,sizeof(char)*strlen(sA.pcUserPassword)) :  nI++;
    *sA.pcChapPassword==NULL ? rte_memcpy(sA.pcChapPassword,sB.pcChapPassword,sizeof(char)*strlen(sA.pcChapPassword)) :  nI++;
    sB.u8NasIpAddress[0] != 0 ? rte_memcpy(sA.u8NasIpAddress,sB.u8NasIpAddress,sizeof(uint8_t)*IPV4_OCTETS) : nI++;
    sB.u16NasPort !=0 ? sA.u16NasPort=sB.u16NasPort : nI++;
    sB.u8ServiceType !=0 ? sA.u8ServiceType=sB.u8ServiceType : nI++;
    sB.u8FramedIpv4Address[0] != 0 ? rte_memcpy(sA.u8FramedIpv4Address,sB.u8FramedIpv4Address,sizeof(uint8_t)*IPV4_OCTETS) : nI++;
    sB.u8FramedIpv4NetMask[0] != 0 ? rte_memcpy(sA.u8FramedIpv4NetMask,sB.u8FramedIpv4NetMask,sizeof(uint8_t)*IPV4_OCTETS) : nI++;
    return nI;
}

/**
 * @brief Set the Current Local Time object
 * 
 * @param sTime Time Object
 */
void setCurrentLocalTime(struct tm sTime){
    time_t t = time(NULL);
    sTime = *localtime(&t);
    //printf("now: %d-%02d-%02d %02d:%02d:%02d\n", tm.tm_year + 1900, tm.tm_mon + 1, tm.tm_mday, tm.tm_hour, tm.tm_min, tm.tm_sec);
}

#endif  
