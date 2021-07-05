/**
 * @file radiusAttributesList.h
 * @brief This file contains the radius attributes and associated code values in decimal
 * @author ibrahim,
 * @date 12 Sep 2020
 * @see https://www.iana.org/assignments/radius-types/radius-types.xhtml
 */
#define RADIUS_CODE_FIELD 1 /**< Number of bytes reserved for Code field */
#define RADIUS_LENGTH_FIELD_LENGTH 2/**< Number of bytes reserved for length field */
#define RADIUS_IDENTIFIER_FIELD_LENGTH 1/**< Number of bytes reserved for identifier field */
#define RADIUS_AUTHENTICATOR_FIELD_LENGTH 16/**< Number of bytes reserved for authenticator field */


#define USER_NAME   1           /**< text [RFC2865] */
#define USER_PASSWORD   2       /**< string [RFC2865]*/
#define CHAP_PASSWORD   3       /**< string [RFC2865]*/
#define NAS_IP_ADDRESS  4       /**< ipv4addr [RFC2865]*/
#define NAS_PORT    5           /**< integer [RFC2865]*/
#define SERVICE_TYPE    6       /**< enum [RFC2865]*/
#define FRAMED_PROTOCOL 7       /**< enum [RFC2865]*/
#define FRAMED_IP_ADDRESS   8   /**< ipv4addr [RFC2865]*/
#define FRAMED_IP_NETMASK   9   /**< ipv4addr [RFC2865]*/
#define FRAMED_ROUTING  10  /**< enum [RFC2865]*/
#define FILTER_ID   11  /**< text [RFC2865]*/
#define FRAMED_MTU  12  /**< integer [RFC2865]*/
#define FRAMED_COMPRESSION  13  /**< enum [RFC2865]*/
#define LOGIN_IP_HOST   14  /**< ipv4addr [RFC2865]*/
#define LOGIN_SERVICE   15  /**< enum [RFC2865]*/
#define LOGIN_TCP_PORT  16  /**< integer [RFC2865]*/
/* #define UNASSIGNED  17  */
#define REPLY_MESSAGE   18  /**< text [RFC2865]*/
#define CALLBACK_NUMBER 19  /**< text [RFC2865]*/
#define CALLBACK_ID 20  /**< text [RFC2865]*/
/* #define UNASSIGNED  21  */
#define FRAMED_ROUTE    22  /**< text [RFC2865]*/
#define FRAMED_IPX_NETWORK  23  /**< ipv4addr [RFC2865]*/
#define STATE   24  /**< string [RFC2865]*/
#define CLASS   25  /**< string [RFC2865]*/
#define VENDOR_SPECIFIC 26  /**< vsa [RFC2865]*/
#define SESSION_TIMEOUT 27  /**< integer [RFC2865]*/
#define IDLE_TIMEOUT    28  /**< integer [RFC2865]*/
#define TERMINATION_ACTION  29  /**< enum [RFC2865]*/
#define CALLED_STATION_ID   30  /**< text [RFC2865]*/
#define CALLING_STATION_ID  31  /**< text [RFC2865]*/
#define NAS_IDENTIFIER  32  /**< text [RFC2865]*/
#define PROXY_STATE 33  /**< string [RFC2865]*/
#define LOGIN_LAT_SERVICE   34  /**< text [RFC2865]*/
#define LOGIN_LAT_NODE  35  /**< text [RFC2865]*/
#define LOGIN_LAT_GROUP 36  /**< string [RFC2865]*/
#define FRAMED_APPLETALK_LINK   37  /**< integer [RFC2865]*/
#define FRAMED_APPLETALK_NETWORK    38  /**< integer [RFC2865]*/
#define FRAMED_APPLETALK_ZONE   39  /**< text [RFC2865]*/
#define ACCT_STATUS_TYPE    40  /**< enum [RFC2866]*/
#define ACCT_DELAY_TIME 41  /**< integer [RFC2866]*/
#define ACCT_INPUT_OCTETS   42  /**< integer [RFC2866]*/
#define ACCT_OUTPUT_OCTETS  43  /**< integer [RFC2866]*/
#define ACCT_SESSION_ID 44  /**< text [RFC2866]*/
#define ACCT_AUTHENTIC  45  /**< enum [RFC2866]*/
#define ACCT_SESSION_TIME   46  /**< integer [RFC2866]*/
#define ACCT_INPUT_PACKETS  47  /**< integer [RFC2866]*/
#define ACCT_OUTPUT_PACKETS 48  /**< integer [RFC2866]*/
#define ACCT_TERMINATE_CAUSE    49  /**< enum [RFC2866]*/
#define ACCT_MULTI_SESSION_ID   50  /**< text [RFC2866]*/
#define ACCT_LINK_COUNT 51  /**< integer [RFC2866]*/
#define ACCT_INPUT_GIGAWORDS    52  /**< integer [RFC2869]*/
#define ACCT_OUTPUT_GIGAWORDS   53  /**< integer [RFC2869]*/
/* #define UNASSIGNED  54  */
#define EVENT_TIMESTAMP 55  /**< time [RFC2869]*/
#define EGRESS_VLANID   56  /**< integer [RFC4675]*/
#define INGRESS_FILTERS 57  /**< enum [RFC4675]*/
#define EGRESS_VLAN_NAME    58  /**< text [RFC4675]*/
#define USER_PRIORITY_TABLE 59  /**< string [RFC4675]*/
#define CHAP_CHALLENGE  60  /**< string [RFC2865]*/
#define NAS_PORT_TYPE   61  /**< enum [RFC2865]*/
#define PORT_LIMIT  62  /**< integer [RFC2865]*/
#define LOGIN_LAT_PORT  63  /**< text [RFC2865]*/
#define TUNNEL_TYPE 64  /**< enum [RFC2868]*/
#define TUNNEL_MEDIUM_TYPE  65  /**< enum [RFC2868]*/
#define TUNNEL_CLIENT_ENDPOINT  66  /**< text [RFC2868]*/
#define TUNNEL_SERVER_ENDPOINT  67  /**< text [RFC2868]*/
#define ACCT_TUNNEL_CONNECTION  68  /**< text [RFC2867]*/
#define TUNNEL_PASSWORD 69  /**< string [RFC2868]*/
#define ARAP_PASSWORD   70  /**< string [RFC2869]*/
#define ARAP_FEATURES   71  /**< string [RFC2869]*/
#define ARAP_ZONE_ACCESS    72  /**< enum [RFC2869]*/
#define ARAP_SECURITY   73  /**< integer [RFC2869]*/
#define ARAP_SECURITY_DATA  74  /**< text [RFC2869]*/
#define PASSWORD_RETRY  75  /**< integer [RFC2869]*/
#define PROMPT  76  /**< enum [RFC2869]*/
#define CONNECT_INFO    77  /**< text [RFC2869]*/
#define CONFIGURATION_TOKEN 78  /**< text [RFC2869]*/
#define EAP_MESSAGE 79  /**< concat [RFC2869]*/
#define MESSAGE_AUTHENTICATOR   80  /**< string [RFC2869]*/
#define TUNNEL_PRIVATE_GROUP_ID 81  /**< text [RFC2868]*/
#define TUNNEL_ASSIGNMENT_ID    82  /**< text [RFC2868]*/
#define TUNNEL_PREFERENCE   83  /**< integer [RFC2868]*/
#define ARAP_CHALLENGE_RESPONSE 84  /**< string [RFC2869]*/
#define ACCT_INTERIM_INTERVAL   85  /**< integer [RFC2869]*/
#define ACCT_TUNNEL_PACKETS_LOST    86  /**< integer [RFC2867]*/
#define NAS_PORT_ID 87  /**< text [RFC2869]*/
#define FRAMED_POOL 88  /**< text [RFC2869]*/
#define CUI 89  /**< string [RFC4372]*/
#define TUNNEL_CLIENT_AUTH_ID   90  /**< text [RFC2868]*/
#define TUNNEL_SERVER_AUTH_ID   91  /**< text [RFC2868]*/
#define NAS_FILTER_RULE 92  /**< text [RFC4849]*/
/* #define UNASSIGNED  93  */
#define ORIGINATING_LINE_INFO   94  /**< string [RFC7155]*/
#define NAS_IPV6_ADDRESS    95  /**< ipv6addr [RFC3162]*/
#define FRAMED_INTERFACE_ID 96  /**< ifid [RFC3162]*/
#define FRAMED_IPV6_PREFIX  97  /**< ipv6prefix [RFC3162]*/
#define LOGIN_IPV6_HOST 98  /**< ipv6addr [RFC3162]*/
#define FRAMED_IPV6_ROUTE   99  /**< text [RFC3162]*/
#define FRAMED_IPV6_POOL    100 /**< text [RFC3162]*/
#define ERROR_CAUSE ATTRIBUTE   101 /**< enum [RFC3576]*/
#define EAP_KEY_NAME    102 /**< string [RFC4072][RFC7268]*/
#define DIGEST_RESPONSE 103 /**< text [RFC5090]*/
#define DIGEST_REALM    104 /**< text [RFC5090]*/
#define DIGEST_NONCE    105 /**< text [RFC5090]*/
#define DIGEST_RESPONSE_AUTH    106 /**< text [RFC5090]*/
#define DIGEST_NEXTNONCE    107 /**< text [RFC5090]*/
#define DIGEST_METHOD   108 /**< text [RFC5090]*/
#define DIGEST_URI  109 /**< text [RFC5090]*/
#define DIGEST_QOP  110 /**< text [RFC5090]*/
#define DIGEST_ALGORITHM    111 /**< text [RFC5090]*/
#define DIGEST_ENTITY_BODY_HASH 112 /**< text [RFC5090]*/
#define DIGEST_CNONCE   113 /**< text [RFC5090]*/
#define DIGEST_NONCE_COUNT  114 /**< text [RFC5090]*/
#define DIGEST_USERNAME 115 /**< text [RFC5090]*/
#define DIGEST_OPAQUE   116 /**< text [RFC5090]*/
#define DIGEST_AUTH_PARAM   117 /**< text [RFC5090]*/
#define DIGEST_AKA_AUTS 118 /**< text [RFC5090]*/
#define DIGEST_DOMAIN   119 /**< text [RFC5090]*/
#define DIGEST_STALE    120 /**< text [RFC5090]*/
#define DIGEST_HA1  121 /**< text [RFC5090]*/
#define SIP_AOR 122 /**< text [RFC5090]*/
#define DELEGATED_IPV6_PREFIX   123 /**< ipv6prefix [RFC4818]*/
#define MIP6_FEATURE_VECTOR 124 /**< integer64 [RFC5447]*/
#define MIP6_HOME_LINK_PREFIX   125 /**< string [RFC5447]*/
#define OPERATOR_NAME   126 /**< text [RFC5580]*/
#define LOCATION_INFORMATION    127 /**< string [RFC5580]*/
#define LOCATION_DATA   128 /**< string [RFC5580]*/
#define BASIC_LOCATION_POLICY_RULES 129 /**< string [RFC5580]*/
#define EXTENDED_LOCATION_POLICY_RULES  130 /**< string [RFC5580]*/
#define LOCATION_CAPABLE    131 /**< enum [RFC5580]*/
#define REQUESTED_LOCATION_INFO 132 /**< enum [RFC5580]*/
#define FRAMED_MANAGEMENT_PROTOCOL  133 /**< enum [RFC5607]*/
#define MANAGEMENT_TRANSPORT_PROTECTION 134 /**< enum [RFC5607]*/
#define MANAGEMENT_POLICY_ID    135 /**< text [RFC5607]*/
#define MANAGEMENT_PRIVILEGE_LEVEL  136 /**< integer [RFC5607]*/
#define PKM_SS_CERT 137 /**< concat [RFC5904]*/
#define PKM_CA_CERT 138 /**< concat [RFC5904]*/
#define PKM_CONFIG_SETTINGS 139 /**< string [RFC5904]*/
#define PKM_CRYPTOSUITE_LIST    140 /**< string [RFC5904]*/
#define PKM_SAID    141 /**< text [RFC5904]*/
#define PKM_SA_DESCRIPTOR   142 /**< string [RFC5904]*/
#define PKM_AUTH_KEY    143 /**< string [RFC5904]*/
#define DS_LITE_TUNNEL_NAME 144 /**< text [RFC6519]*/
#define MOBILE_NODE_IDENTIFIER  145 /**< string [RFC6572]*/
#define SERVICE_SELECTION   146 /**< text [RFC6572]*/
#define PMIP6_HOME_LMA_IPV6_ADDRESS 147 /**< ipv6addr [RFC6572]*/
#define PMIP6_VISITED_LMA_IPV6_ADDRESS  148 /**< ipv6addr [RFC6572]*/
#define PMIP6_HOME_LMA_IPV4_ADDRESS 149 /**< ipv4addr [RFC6572]*/
#define PMIP6_VISITED_LMA_IPV4_ADDRESS  150 /**< ipv4addr [RFC6572]*/
#define PMIP6_HOME_HN_PREFIX    151 /**< ipv6prefix [RFC6572]*/
#define PMIP6_VISITED_HN_PREFIX 152 /**< ipv6prefix [RFC6572]*/
#define PMIP6_HOME_INTERFACE_ID 153 /**< ifid [RFC6572]*/
#define PMIP6_VISITED_INTERFACE_ID  154 /**< ifid [RFC6572]*/
#define PMIP6_HOME_IPV4_HOA 155 /**< ipv4prefix [RFC6572]*/
#define PMIP6_VISITED_IPV4_HOA  156 /**< ipv4prefix [RFC6572]*/
#define PMIP6_HOME_DHCP4_SERVER_ADDRESS 157 /**< ipv4addr [RFC6572]*/
#define PMIP6_VISITED_DHCP4_SERVER_ADDRESS  158 /**< ipv4addr [RFC6572]*/
#define PMIP6_HOME_DHCP6_SERVER_ADDRESS 159 /**< ipv6addr [RFC6572]*/
#define PMIP6_VISITED_DHCP6_SERVER_ADDRESS  160 /**< ipv6addr [RFC6572]*/
#define PMIP6_HOME_IPV4_GATEWAY 161 /**< ipv4addr [RFC6572]*/
#define PMIP6_VISITED_IPV4_GATEWAY  162 /**< ipv4addr [RFC6572]*/
#define EAP_LOWER_LAYER 163 /**< enum [RFC6677]*/
#define GSS_ACCEPTOR_SERVICE_NAME   164 /**< text [RFC7055]*/
#define GSS_ACCEPTOR_HOST_NAME  165 /**< text [RFC7055]*/
#define GSS_ACCEPTOR_SERVICE_SPECIFICS  166 /**< text [RFC7055]*/
#define GSS_ACCEPTOR_REALM_NAME 167 /**< text [RFC7055]*/
#define FRAMED_IPV6_ADDRESS 168 /**< ipv6addr [RFC6911]*/
#define DNS_SERVER_IPV6_ADDRESS 169 /**< ipv6addr [RFC6911]*/
#define ROUTE_IPV6_INFORMATION  170 /**< ipv6prefix [RFC6911]*/
#define DELEGATED_IPV6_PREFIX_POOL  171 /**< text [RFC6911]*/
#define STATEFUL_IPV6_ADDRESS_POOL  172 /**< text [RFC6911]*/
#define IPV6_6RD_CONFIGURATION  173 /**< tlv [RFC6930]*/
#define ALLOWED_CALLED_STATION_ID   174 /**< text [RFC7268]*/
#define EAP_PEER_ID 175 /**< string [RFC7268]*/
#define EAP_SERVER_ID   176 /**< string [RFC7268]*/
#define MOBILITY_DOMAIN_ID  177 /**< integer [RFC7268]*/
#define PREAUTH_TIMEOUT 178 /**< integer [RFC7268]*/
#define NETWORK_ID_NAME 179 /**< string [RFC7268]*/
#define EAPOL_ANNOUNCEMENT  180 /**< concat [RFC7268]*/
#define WLAN_HESSID 181 /**< text [RFC7268]*/
#define WLAN_VENUE_INFO 182 /**< integer [RFC7268]*/
#define WLAN_VENUE_LANGUAGE 183 /**< string [RFC7268]*/
#define WLAN_VENUE_NAME 184 /**< text [RFC7268]*/
#define WLAN_REASON_CODE    185 /**< integer [RFC7268]*/
#define WLAN_PAIRWISE_CIPHER    186 /**< integer [RFC7268]*/
#define WLAN_GROUP_CIPHER   187 /**< integer [RFC7268]*/
#define WLAN_AKM_SUITE  188 /**< integer [RFC7268]*/
#define WLAN_GROUP_MGMT_CIPHER  189 /**< integer [RFC7268]*/
#define WLAN_RF_BAND    190 /**< integer [RFC7268]*/
/* #define UNASSIGNED  191 */
/*
#define EXPERIMENTAL USE    192-223 ///[RFC3575] //
#define IMPLEMENTATION SPECIFIC 224-240 ///  [RFC3575]//
#define EXTENDED_ATTRIBUTE_1    241 /// extended [RFC6929]//
#define FRAG_STATUS 241.1   /// integer [RFC7499]//
#define PROXY_STATE_LENGTH  241.2   /// integer [RFC7499]//
#define RESPONSE_LENGTH 241.3   /// integer [RFC7930]//
#define ORIGINAL_PACKET_CODE    241.4   /// integer [RFC7930]//
#define IP_PORT_LIMIT_INFO  241.5   /// tlv [RFC8045, Section 3.1.1]//
#define IP_PORT_RANGE   241.6   /// tlv [RFC8045, Section 3.1.2]//
#define IP_PORT_FORWARDING_MAP  241.7   /// tlv [RFC8045, Section 3.1.3]//
#define OPERATOR_NAS_IDENTIFIER 241.8   /// string [RFC8559]//
#define SOFTWIRE46_CONFIGURATION    241.9   /// tlv [RFC-ietf-softwire-map-radius-26, Section 3.1]//
#define SOFTWIRE46_PRIORITY 241.1   /// tlv [RFC-ietf-softwire-map-radius-26, Section 3.2]//
#define SOFTWIRE46_MULTICAST    241.11  /// tlv [RFC-ietf-softwire-map-radius-26, Section 3.3]//
#define UNASSIGNED  241.{12-25} /////
#define EXTENDED_VENDOR_SPECIFIC_1  241.26  /// evs [RFC6929]//
#define UNASSIGNED  241.{27-240}    /////
#define RESERVED    241.{241-255}   ///  [RFC6929]//
#define EXTENDED_ATTRIBUTE_2    242 /// extended [RFC6929]//
#define UNASSIGNED  242.{1-25}  /////
#define EXTENDED_VENDOR_SPECIFIC_2  242.26  /// evs [RFC6929]//
#define UNASSIGNED  242.{27-240}    /////
#define RESERVED    242.{241-255}   ///  [RFC6929]//
#define EXTENDED_ATTRIBUTE_3    243 /// extended [RFC6929]//
#define UNASSIGNED  243.{1-25}  /////
#define EXTENDED_VENDOR_SPECIFIC_3  243.26  /// evs [RFC6929]//
#define UNASSIGNED  243.{27-240}    /////
#define RESERVED    243.{241-255}   ///  [RFC6929]//
#define EXTENDED_ATTRIBUTE_4    244 /// extended [RFC6929]//
#define UNASSIGNED  244.{1-25}  /////
#define EXTENDED_VENDOR_SPECIFIC_4  244.26  /// evs [RFC6929]//
#define UNASSIGNED  244.{27-240}    /////
#define RESERVED    244.{241-255}   ///  [RFC6929]//
#define EXTENDED_ATTRIBUTE_5    245 /// long-extended [RFC6929]//
#define SAML_ASSERTION  245.1   /// text [RFC7833]//
#define SAML_PROTOCOL   245.2   /// text [RFC7833]//
#define UNASSIGNED  245.{3-25}  /////
#define EXTENDED_VENDOR_SPECIFIC_5  245.26  /// evs [RFC6929]//
#define UNASSIGNED  245.{27-240}    /////
#define RESERVED    245.{241-255}   ///  [RFC6929]//
#define EXTENDED_ATTRIBUTE_6    246 /// long-extended [RFC6929]//
#define UNASSIGNED  246.{1-25}  /////
#define EXTENDED_VENDOR_SPECIFIC_6  246.26  /// evs [RFC6929]//
#define UNASSIGNED  246.{27-240}    /////
#define RESERVED    246.{241-255}   ///  [RFC6929]//
#define RESERVED    247-255 ///  [RFC3575]//
*/
