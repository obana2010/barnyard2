/*
 * spo_alert_cu_kt.h
 *
 *  Created on: 2012/11/09
 *      Author: obana
 */

#ifndef SPO_ALERT_CU_KT_H_
#define SPO_ALERT_CU_KT_H_

// message
#define CU_MESSAGE_SOURCEIP  "sourceip"
#define CU_MESSAGE_NODEIP    "nodeip"
#define CU_MESSAGE_NODEPORT  "nodeport"
#define CU_MESSAGE_DOMAINID  "domainid"
#define CU_MESSAGE_DOMAINIDS "domainids"
#define CU_MESSAGE_TIMESLOT  "timeslot"
#define CU_MESSAGE_COUNT     "count"

#define CU_METHOD_JOIN_DOMAIN           "join_domain"
#define CU_METHOD_STORE_GLOBAL_ALERT    "store_global_alert"
#define CU_METHOD_GET_DOMAIN_NODE_LIST  "get_domain_node_list"
#define CU_METHOD_SHARE_BLACKLIST       "share_blacklist"
#define CU_METHOD_CU_STATUS             "cu_status"

#define CU_METHOD_GET_BLACKLIST         "get_blacklist"

#endif /* SPO_ALERT_CU_KT_H_ */
