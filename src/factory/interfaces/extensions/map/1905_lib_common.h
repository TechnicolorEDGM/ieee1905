/************* COPYRIGHT AND CONFIDENTIALITY INFORMATION NOTICE *************
** Copyright (c) [2019] – [Technicolor Delivery Technologies, SAS]          *
** All Rights Reserved                                                      *
** The source code form of this Open Source Project components              *
** is subject to the terms of the BSD-2-Clause-Patent.                      *
** You can redistribute it and/or modify it under the terms of              *
** the BSD-2-Clause-Patent. (https://opensource.org/licenses/BSDplusPatent) *
** See COPYING file/LICENSE file for more details.                          *
****************************************************************************/

#ifdef __cplusplus
extern "C" {
#endif

#ifndef __1905_LIB_COMMON_H
#define __1905_LIB_COMMON_H

#include <stdbool.h>
#include <syslog.h>

#include "1905_cmdus.h"

/**
@file
@brief This file defines the data structures used in the interface to the 1905 library
*/

/**
 * Data structure for every single message filter
 *
 * @param message_type   : message type that is of interest
 * @param ack_required   : for some of the messages,
 *                    Ack needs to be sent within a second.
 *                    This flag is to indicate if an ACK needs to be sent on
 *                    behalf of the Agent for 1905 messages
 *                    This flag is not implemented as of now.
 * @param lib1905_cb     : Callback function to call when a 1905/MultiAP message is received,
 *                    Parameters are source MAC address, CMDU and context
 * @param context        : Context to be saved and used while calling the call back
 */
typedef struct {
    uint16_t message_type;
    bool ack_required;
    int (*lib1905_cb)(uint8_t *mac,struct CMDU*,void* context);
    void * context;
} single_message_filter_t;

#endif

#ifdef __cplusplus
}
#endif
