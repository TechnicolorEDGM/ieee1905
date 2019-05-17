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

#ifndef _PLATFORM_INTERFACES_WRT1900ACX_PRIV_H_
#define _PLATFORM_INTERFACES_WRT1900ACX_PRIV_H_

// Get al-mac address from UCI
//
INT8U linksys_wrt1900acx_get_al_mac_address(INT8U *al_mac);

// Get list of 1905 interfaces
//
void linksys_wrt1900acx_get_list_of_1905_interfaces(char** if_list);


// Fill the "interfaceInfo" structure (associated to the provided
// "interface_name") by obtaining information from the OpenWRT UCI subsystem.
//
//
INT8U linksys_wrt1900acx_get_interface_info(char *interface_name, struct interfaceInfo *m);

// Modify the current Wifi configuration according to the values passed as
// parameters. Modifications take effect immediately.
//
#ifdef MULTIAP
INT8U linksys_wrt1900acx_apply_80211_configuration(char *interface_name, INT8U *ssid, INT8U *network_key, char *auth_type_str, INT8U map_extension);
#else
INT8U linksys_wrt1900acx_apply_80211_configuration(char *interface_name, INT8U *ssid, INT8U *network_key);
#endif

#endif
