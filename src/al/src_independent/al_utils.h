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

#ifndef _AL_UTILS_H_
#define _AL_UTILS_H_

#include "1905_cmdus.h"

// "MIDs" are "message IDs" used inside 1905 protocol messages. They must be
// monotonically increased as explained in "Section 7.8"
//
INT16U getNextMid(void);

// Returns '1' if the packet has already been processed in the past and thus,
// should be discarded (to avoid network storms). '0' otherwise.
//
// According to what is explained in "Sections 7.5, 7.6 and 7.7" if a
// defragmented packet whose "AL MAC address TLV" and "message id" match one
// that has already been received in the past, then it should be discarded.
//
// I *personally* think the standard is "slightly" wrong here because *not* all
// CMDUs contain an "AL MAC address TLV".
// We could use the ethernet source address instead, however this would only
// work for those messages that are *not* relayed (one same duplicated relayed
// message can arrive at our local node with two different ethernet source
// addresses).
// Fortunately for us, all relayed CMDUs *do* contain an "AL MAC address TLV",
// thus this is what we are going to do:
//
//   1. If the CMDU is a relayed one, check against the "AL MAC" contained in
//      the "AL MAC address TLV"
//
//   2. If the CMDU is *not* a relayed one, check against the ethernet source
//      address
//
// This function keeps track of the latest MAX_DUPLICATES_LOG_ENTRIES tuples
// of ("mac_address", "message_id") and:
//
//   1. If the provided tuple matches an already existing one, this function
//      returns '1'
//
//   2. Otherwise, the entry is added (discarding, if needed, the oldest entry)
//      and this function returns '0'
//
INT8U checkDuplicates(INT8U *src_mac_address, struct CMDU *c);

#endif

