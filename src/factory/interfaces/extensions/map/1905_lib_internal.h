/************* COPYRIGHT AND CONFIDENTIALITY INFORMATION NOTICE *************
** Copyright (c) [2019] – [Technicolor Delivery Technologies, SAS]          *
** All Rights Reserved                                                      *
** The source code form of this Open Source Project components              *
** is subject to the terms of the BSD-2-Clause-Patent.                      *
** You can redistribute it and/or modify it under the terms of              *
** the BSD-2-Clause-Patent. (https://opensource.org/licenses/BSDplusPatent) *
** See COPYING file/LICENSE file for more details.                          *
****************************************************************************/

#include "1905_lib_common.h"

#ifdef __cplusplus
extern "C" {
#endif

#ifndef __1905_LIB_INTERNAL_H
#define __1905_LIB_INTERNAL_H

#define MAX_1905_MESSAGE 19
#define MAX_MULTIAP_MESSAGE 27


#define LIB1905_REGISTER_MSGTYPE	(0x01)
#define LIB1905_NOTIFY_MSGTYPE		(0x02)

/**
 * library internal data structure, handle is a pointer to this data structure
 */
typedef struct {
    uint8_t socketfd;
    single_message_filter_t lib1905_messages[MAX_1905_MESSAGE];
    single_message_filter_t multiap_messages[MAX_MULTIAP_MESSAGE];
}lib1905_struct_t;

/**
 * CMDU header data structure
 */
typedef struct {
    uint8_t mac_addr[6];
    uint16_t length;
} CMDU_header_t; 

typedef struct {
	int msg_type;
	void *data;
}lib1905_msg;

/**
 * internal data structure for regiter_data
 */
typedef struct {
    uint8_t interest_set;
    uint8_t ack_required;
} message_interest_t; 

/** 
 * data structure to be shared with the 1905 extension
 */
typedef struct {
    message_interest_t lib1905_messages[MAX_1905_MESSAGE];
    message_interest_t multiap_messages[MAX_MULTIAP_MESSAGE];
} register_data_t;

/**
 * internal data structure server running in 1905 extension
 */
typedef struct {
    int8_t socketfd;
    register_data_t reg_data;
} map_server_struct_t;

typedef struct {    
    char interface_name[MAX_IFACE_NAME_LEN];
    int8_t event;
} lib1905_event_notification;

#endif

#ifdef __cplusplus
}
#endif
