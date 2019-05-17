/************* COPYRIGHT AND CONFIDENTIALITY INFORMATION NOTICE *************
** Copyright (c) [2019] – [Technicolor Delivery Technologies, SAS]          *
** All Rights Reserved                                                      *
** The source code form of this Open Source Project components              *
** is subject to the terms of the BSD-2-Clause-Patent.                      *
** You can redistribute it and/or modify it under the terms of              *
** the BSD-2-Clause-Patent. (https://opensource.org/licenses/BSDplusPatent) *
** See COPYING file/LICENSE file for more details.                          *
****************************************************************************/
/*
 *  Broadband Forum BUS (Broadband User Services) Work Area
 *  
 *  Copyright (c) 2017, Broadband Forum
 *  Copyright (c) 2017, MaxLinear, Inc. and its affiliates
 *  
 *  Redistribution and use in source and binary forms, with or
 *  without modification, are permitted provided that the following
 *  conditions are met:
 *  
 *  1. Redistributions of source code must retain the above copyright
 *     notice, this list of conditions and the following disclaimer.
 *  
 *  2. Redistributions in binary form must reproduce the above
 *     copyright notice, this list of conditions and the following
 *     disclaimer in the documentation and/or other materials
 *     provided with the distribution.
 *  
 *  3. Neither the name of the copyright holder nor the names of its
 *     contributors may be used to endorse or promote products
 *     derived from this software without specific prior written
 *     permission.
 *  
 *  THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND
 *  CONTRIBUTORS "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES,
 *  INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES OF
 *  MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE
 *  DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR
 *  CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL,
 *  SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT
 *  NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES;
 *  LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER
 *  CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT,
 *  STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE)
 *  ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF
 *  ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 *  
 *  The above license is used as a license under copyright only.
 *  Please reference the Forum IPR Policy for patent licensing terms
 *  <https://www.broadband-forum.org/ipr-policy>.
 *  
 *  Any moral rights which are necessary to exercise under the above
 *  license grant are also deemed granted under this license.
 */

/* Few lines in the below code are modified by Technicolor Connected Home SAS */

#include <pthread.h>
#include "platform.h"
#include "platform_crypto.h"
#include "1905_cmdus.h"
#include "al_datamodel.h"

static pthread_mutex_t check_duplicate_mutex = PTHREAD_MUTEX_INITIALIZER;

////////////////////////////////////////////////////////////////////////////////
// Public functions (exported only to files in this same folder)
////////////////////////////////////////////////////////////////////////////////

INT16U getNextMid(void)
{
    static INT16U mid       = 0;
    static INT8U first_time = 1;

    if (1 == first_time)
    {
        // Start with a random MID. The standard is not clear about this, but
        // I think a random number is better than simply choosing zero, to
        // avoid start up problems (ex: one node boots and after a short time
        // it is reset and starts making use of the same MIDs all over again,
        // which will probably be ignored by other nodes, thinking they have
        // already processed these messages in the past)
        //
        first_time = 0;
        PLATFORM_GET_RANDOM_BYTES((INT8U*)&mid, sizeof(INT16U));
    }
    else
    {
        mid++;
    }

    return mid;
}

INT8U checkDuplicates(INT8U *src_mac_address, struct CMDU *c)
{
    #define MAX_DUPLICATES_LOG_ENTRIES 10

    static INT8U  mac_addresses[MAX_DUPLICATES_LOG_ENTRIES][6];
    static INT16U message_ids  [MAX_DUPLICATES_LOG_ENTRIES];
    static INT16U message_type  [MAX_DUPLICATES_LOG_ENTRIES];

    static INT8U start = 0;
    static INT8U total = 0;

    INT8U mac_address[6];

    INT8U i;

    if(
        CMDU_TYPE_TOPOLOGY_RESPONSE               == c->message_type ||
        CMDU_TYPE_LINK_METRIC_RESPONSE            == c->message_type ||
        CMDU_TYPE_AP_AUTOCONFIGURATION_RESPONSE   == c->message_type ||
        CMDU_TYPE_HIGHER_LAYER_RESPONSE           == c->message_type ||
        CMDU_TYPE_INTERFACE_POWER_CHANGE_RESPONSE == c->message_type ||
        CMDU_TYPE_GENERIC_PHY_RESPONSE            == c->message_type ||
        CMDU_TYPE_AP_AUTOCONFIGURATION_WSC        == c->message_type
      )
    {
        // This is a "hack" until a better way to handle MIDs is found.
        //
        // Let me explain.
        //
        // According to the standard, each AL entity generates its monotonically
        // increasing MIDs every time a new packet is sent.
        // The only exception to this rule is when generating a "response". In
        // these cases the same MID contained in the original query must be
        // used.
        //
        // Imagine we have two ALs that are started in different moments:
        //
        //        AL 1               AL 2
        //        ====               ====
        //   t=0  --- MID=1 -->
        //   t=1  --- MID=2 -->
        //   t=2  --- MID=3 -->      <-- MID=1 --
        //   t=3  --- MID=4 -->      <-- MID=2 --
        //   t=4  --- MID=5 -->      <-- MID=3 --
        //
        // In "t=2", "AL 2" learns that, in the future, messages from "AL 1" with
        // a "MID=3" should be discarded.
        //
        // Now, imagine in "t=4" the message "AL 2" sends (with "MID=3") is a
        // query that triggers a response from "AL 1" (which *must* have the
        // same MID, ie., "MID=3").
        //
        // HOWEVER, because of what "AL 2" learnt in "t=2", this response will
        // be discarded!
        //
        // In oder words... until the standard clarifies how MIDs should be
        // generated to avoid this problem, we will just accept (and process)
        // all response messages... even if they are duplicates.
        //
#ifndef MULTIAP
        return 0; //TODO Make use of Message types also to reduce probable problem space
#endif
    }

    // For relayed CMDUs, use the AL MAC, otherwise use the ethernet src MAC.
    //
    PLATFORM_MEMCPY(mac_address, src_mac_address, 6);
    if (1 == c->relay_indicator)
    {
        INT8U i;
        INT8U *p;

        i = 0;
        while (NULL != (p = c->list_of_TLVs[i]))
        {
            if (TLV_TYPE_AL_MAC_ADDRESS_TYPE == *p)
            {
                struct alMacAddressTypeTLV *t = (struct alMacAddressTypeTLV *)p;

                PLATFORM_MEMCPY(mac_address, t->al_mac_address, 6);
                break;
            }
            i++;
        }
    }

	// Agent and controller may run in the same device but with different al mac, 
	// hence discard CMDUs whose AL MAC is our own (that means someone
    // is retrasnmitting us back a message we originally created)
    if (0 == PLATFORM_MEMCMP(mac_address, DMalMacGet(), 6))
    {
        PLATFORM_PRINTF_DEBUG_DETAIL("Packet with src MAC as AL MAC is detected! drop the pkt!!\n");
		return 1;
    }

    pthread_mutex_lock(&check_duplicate_mutex);

    // Find if the ("mac_address", "message_id") tuple is already present in the
    // database
    //
    for (i=0; i<total; i++)
    {
        INT8U index;

        index = (start + i) % MAX_DUPLICATES_LOG_ENTRIES;

        if (
             0 == PLATFORM_MEMCMP(mac_addresses[index],    mac_address, 6) &&
                                  message_ids[index]    == c->message_id &&
                                  message_type[index]   == c->message_type 
           )
        {
            pthread_mutex_unlock(&check_duplicate_mutex);
            // The entry already exists!
            //
            if ( c->message_type == CMDU_TYPE_AP_AUTOCONFIGURATION_WSC )
                return 0; // by pass WSC messages
            return 1;
        }
    }

    // This is a new entry, insert it into the cache and return "0"
    //
    if (total < MAX_DUPLICATES_LOG_ENTRIES)
    {
        // There is space for new entries
        //
        INT8U index;

        index = (start + total) % MAX_DUPLICATES_LOG_ENTRIES;

        PLATFORM_MEMCPY(mac_addresses[index], mac_address, 6);
        message_ids[index] = c->message_id;
        message_type[index] = c->message_type;

        total++;
    }
    else
    {
        // We need to replace the oldest entry
        //
        PLATFORM_MEMCPY(mac_addresses[start], mac_address, 6);
        message_ids[start] = c->message_id;
        message_type[start] = c->message_type;

        start++;

        start = start % MAX_DUPLICATES_LOG_ENTRIES;
    }

    pthread_mutex_unlock(&check_duplicate_mutex);

    return 0;
}



