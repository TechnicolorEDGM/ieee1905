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

#ifndef _PLATFORM_INTERFACES_H_
#define _PLATFORM_INTERFACES_H_

#include "media_specific_blobs.h"  // struct genericInterfaceType

// Return a list of strings (each one representing an "interface name", such
// as "eth0", "eth1", etc...).
//
// The length of the list is returned in the 'nr' output argument.
//
// If something goes wrong, return NULL and set the contents of 'nr' to '0'
//
// Each element of the list represents an interface on the localhost that will
// participate in the 1905 network.
//
// The 'name' field is a platform-specific NULL terminated string that will
// later be used in other functions to refer to this particular interface.
//
// The returned list must not be modified by the caller.
//
// When the returned list is no longer needed, it can be freed by calling
// "PLATFORM_FREE_LIST_OF_1905_INTERFACES()"
//
// [PLATFORM PORTING NOTE]
//   Typically you want to return as many entries as physical interfaces there
//   are in the platform. However, if for some reason you want to make one or
//   more interfaces "invisible" to 1905 (maybe because they are "debug"
//   interfaces, such as a "management" ethernet port) you can return a reduced
//   list of interfaces.
//
char **PLATFORM_GET_LIST_OF_1905_INTERFACES(INT8U *nr);

// Used to free the pointer returned by a previous call to
// "PLATFORM_GET_LIST_OF_1905_INTERFACES()"
//
// 'nr' is the same one returned by "PLATFORM_GET_LIST_OF_1905_INTERFACES()"
//
void PLATFORM_FREE_LIST_OF_1905_INTERFACES(char **x, INT8U nr);

// Return a "struct interfaceInfo" structure containing all kinds of information
// associated to the provided 'interface_name'
//
// If something goes wrong, return NULL.
//
// 'interface_name' is one of the names previously returned in a call to
// "PLATFORM_GET_LIST_OF_1905_INTERFACES()"
//
// The documentation of the "struct interfaceInfo" structure explain what each
// field of this structure should contain.
//
// Once the caller is done with the returned structure, hw must call
// "PLATFORM_FREE_1905_STRUCTURE()" to dispose it
//
struct interfaceInfo *PLATFORM_GET_1905_INTERFACE_INFO(char *interface_name);

// Free the memory used by a "struct interfaceInfo" structure previously
// obtained by calling "PLATFORM_GET_1905_INTERFACE_INFO()"
//
void PLATFORM_FREE_1905_INTERFACE_INFO(struct interfaceInfo *i);


////////////////////////////////////////////////////////////////////////////////
// Link metrics
////////////////////////////////////////////////////////////////////////////////

struct linkMetrics
{
    INT8U   local_interface_address[6];     // A MAC address belonging to one of
                                            // the local interfaces.
                                            // Let's call this MAC "A"
                                             
    INT8U   neighbor_interface_address[6];  // A MAC address belonging to a
                                            // neighbor interface that is
                                            // directly reachable from "A".
                                            // Let's call this MAC "B".

    INT32U  measures_window;   // Time in seconds representing how far back in
                               // time statistics have been being recorded for
                               // this interface.
                               // For example, if this value is set to "5" and
                               // 'tx_packet_ok' is set to "7", it means that
                               // in the last 5 seconds 7 packets have been 
                               // transmitted OK between "A" and "B".
                               //
                               // [PLATFORM PORTING NOTE]
                               //   This is typically the amount of time
                               //   ellapsed since the interface was brought
                               //   up.

    INT32U  tx_packet_ok;      // Estimated number of transmitted packets from
                               // "A" to "B" in the last 'measures_window'
                               // seconds.
    
    INT32U  tx_packet_errors;  // Estimated number of packets with errors
                               // transmitted from "A" to "B" in the last
                               // 'measures_window' seconds.

    INT16U  tx_max_xput;       // Extimated maximum MAC throughput from "A" to
                               // "B" in Mbits/s.

    INT16U  tx_phy_rate;       // Extimated PHY rate from "A" to "B" in Mbits/s.

    INT16U  tx_link_availability;
                               // Estimated average percentage of time that the
                               // link is available to transmit data from "A"
                               // to "B" in the last 'measures_window' seconds.

    INT32U  rx_packet_ok;      // Estimated number of transmitted packets from
                               // "B" to "A" in the last 'measures_window'
                               // seconds.
    
    INT32U  rx_packet_errors;  // Estimated number of packets with errors
                               // transmitted from "B" to "A" i nthe last
                               // 'measures_window' seconds.

    INT8U   rx_rssi;           // Estimated RSSI when receiving data from "B" to
                               // "A" in dB.
};

// Return a "struct linkMetrics" structure containing all kinds of information
// associated to the link that exists between the provided local interface and
// neighbor's interface whose MAC address is 'neighbor_interface_address'.
//
// If something goes wrong, return NULL.
//
// 'local_interface_name' is one of the names previously returned in a call to
// "PLATFORM_GET_LIST_OF_1905_INTERFACES()"
//
// 'neighbor_interface_address' is the MAC address at the other end of the link.
// (This MAC address belong to a neighbor's interface)
//
// The documentation of the "struct linkMetrics" structure explain what each
// field of this structure should contain.
//
// Once the caller is done with the returned structure, hw must call
// "PLATFORM_FREE_LINK_METRICS()" to dispose it
//
// [PLATFORM PORTING NOTE]
//   You will notice how each 'struct linkMetrics' is associated to a LINK and
//   not to an interface.
//   In some cases, the platform might not be able to keep PER LINK stats.
//   For example, in Linux is easy to check how many packets were received by
//   "eth0" *in total*, but it is not trivial to find out how many packets were
//   received by "eth0" *from each neighbor*.
//   In these cases there are two solutions:
//     1. Add new platform code to make this PER LINK reporting possible (for
//        example, in Linux you would have to create iptables rules among other
//        things)
//     2. Just report the overwall PER INTERFACE stats (thus ignoring the
//        'neighbor_interface_address' parameter).
//        This is better than reporting nothing at all.
//
struct linkMetrics *PLATFORM_GET_LINK_METRICS(char *local_interface_name, INT8U *neighbor_interface_address);

// Free the memory used by a "struct linkMetrics" structure previously
// obtained by calling "PLATFORM_GET_LINK_METRICS()"
//
void PLATFORM_FREE_LINK_METRICS(struct linkMetrics *l);

// Return a list of "bridge" structures. Each of them represents a set of
// local interfaces that have been "bridged" together.
//
// The length of the list is returned in the 'nr' output argument.
//
// When the returned list is no longer needed, it can be freed by calling
// "PLATFORM_FREE_LIST_OF_BRIDGES()"
//
struct bridge *PLATFORM_GET_LIST_OF_BRIDGES(INT8U *nr);

// Used to free the pointer returned by a previous call to
// "PLATFORM_GET_LIST_OF_BRIDGES()"
//
// 'nr' is the same one returned by "PLATFORM_GET_LIST_OF_BRIDGES()"
//
void PLATFORM_FREE_LIST_OF_BRIDGES(struct bridge *x, INT8U nr);


////////////////////////////////////////////////////////////////////////////////
// RAW packet generation
////////////////////////////////////////////////////////////////////////////////

// Send a RAW ethernet frame on interface 'name_interface' with:
//
//   - The "destination MAC address" field set to 'dst_mac'
//   - The "source MAC address" field set to 'src_mac'
//   - The "ethernet type" field set to 'eth_type'
//   - The payload os the ethernet frame set to the first 'payload_len' bytes
//     pointed by 'payload'
//
// If there is a problem and the packet cannot be sent, this function returns
// "0", otherwise it returns "1"
//
INT8U PLATFORM_SEND_RAW_PACKET(char *interface_name, INT8U *dst_mac, INT8U *src_mac, INT16U eth_type, INT8U *payload, INT16U payload_len);


////////////////////////////////////////////////////////////////////////////////
/// Push button configuration
////////////////////////////////////////////////////////////////////////////////

// Start the technology-specific "push button" configuration process on the
// provided interface.
//
// 'queue_id' is a value previously returned by a call to
// "PLATFORM_CREATE_QUEUE()"
//
// 'al_mac_address' is the AL MAC address contained in the "push button event
// notification" message that caused this function to be called. This value
// will later be reported back to the AL entity in the
// "PLATFORM_QUEUE_EVENT_AUTHENTICATED_LINK" message.
//
// 'mid' is the "message id" of the "push button event notification" message
// that caused this function to be called. This value will later be reported
// back to the AL entity in the "PLATFORM_QUEUE_EVENT_AUTHENTICATED_LINK"
// message.
//
//   NOTE:
//     When this function is called as a result of the user pressing a button
//     in the local device (versus receiving a remote "push button event
//     notification message" from another node) then 'al_mac_address' and 'mid'
//     contain the values that go inside the "push button event notification"
//     message that this local node is going to send to the others.
//
// Before calling this function, the "PLATFORM_QUEUE_EVENT_AUTHENTICATED_LINK"
// event must have been registered with "PLATFORM_REGISTER_QUEUE_EVENT()"
//
// This "push button" configuration process is used to add new devices to the
// network:
//
//   - For 802.11 interface this is usually the WPS mechanism.
//   - For G.hn interfaces we use the "pairing" mechanism.
//
// The function does not wait for the process to complete, instead it returns
// immediately and the configuration process is ran in background. Eventually,
// either:
//
//   A) The "push button" configuration process is stopped (because no one
//      answered at the other end of the link or because something failed)
//      after some technology-specific time.
//
//   B) The "push button" configuration is stopped because a new device has been
//      added. When this happens, a new message of type
//      "PLATFORM_QUEUE_EVENT_AUTHENTICATED_LINK" is posted to the system
//      queue.
//
// If there is a problem and the process cannot be started, this function
// returns "0", otherwise it returns "1"
//
// [PLATFORM PORTING NOTE]
//   If "interface_name" does not support the "push button" configuration
//   mechanism, this function should immediatley return "1".
//   Ie. a "PLATFORM_QUEUE_EVENT_AUTHENTICATED_LINK" message must *not* be
//   posted to the AL queue.
//
// [PLATFORM PORTING NOTE]
//   Note that once the process is started and until it finishes, if someone
//   calls "PLATFORM_GET_1905_INTERFACE_INFO()" on this interface, the field
//   'push_button_on_going' must return a value of "1".
//
INT8U PLATFORM_START_PUSH_BUTTON_CONFIGURATION(char *interface_name, INT8U queue_id, INT8U *al_mac, INT16U mid);


////////////////////////////////////////////////////////////////////////////////
/// Power control
////////////////////////////////////////////////////////////////////////////////

// Change the power mode of the provided interface.
//
// 'power_mode' can take any of the "INTERFACE_POWER_STATE_*" values
//
// The returned value can take any of the following values:
//   INTERFACE_POWER_RESULT_EXPECTED
//     The power mode has been applied as expected (ie. the new "power mode" is
//     the specified in the call)
//   INTERFACE_POWER_RESULT_NO_CHANGE   
//     There was no need to apply anything, because the interface *already* was
//     in the requested mode
//   INTERFACE_POWER_RESULT_ALTERNATIVE 
//     The interface power mode has changed as a result for this call, however
//     the new state is *not* the given one.  Example: You said
//     "INTERFACE_POWER_STATE_OFF", but the interface, due to maybe platform
//     limitations, ends up in "INTERFACE_POWER_STATE_SAVE"
//   INTERFACE_POWER_RESULT_KO
//     There was some problem trying to apply the given power mode
//
#define INTERFACE_POWER_RESULT_EXPECTED     (0x00)
#define INTERFACE_POWER_RESULT_NO_CHANGE    (0x01)
#define INTERFACE_POWER_RESULT_ALTERNATIVE  (0x02)
#define INTERFACE_POWER_RESULT_KO           (0x03)
INT8U PLATFORM_SET_INTERFACE_POWER_MODE(char *interface_name, INT8U power_mode);

////////////////////////////////////////////////////////////////////////////////
/// Security configuration
////////////////////////////////////////////////////////////////////////////////

// Configure an 80211 AP interface.
//
// 'interface_name' is one of the names previously returned in a call to
// "PLATFORM_GET_LIST_OF_1905_INTERFACES()".
// It must be an 802.11 interface with the role of "AP".
//
// 'ssid' is a NULL terminated string containing the "friendly" name of the
// network that the AP is going to create.
//
// 'bssid' is a 6 bytes long ID containing the MAC address of the "main" AP
// (typically the registrar) on "extended" networks (where several APs share the
// same security settings to make it easier for devices to "roam" between them).
//
// 'auth_mode' is the "authentication mode" the AP is going to use. It must take
// one of the values from "IEEE80211_AUTH_MODE_*"
//
// 'encryption_mode' is "encryption mode" the AP is going to use. It must take
// one of the values from "IEEE80211_ENCRYPTION_MODE_*"
//
// 'network_key' is a NULL terminated string representing the "network key" the
// AP is going to use.
// 
#ifdef MULTIAP
INT8U PLATFORM_CONFIGURE_80211_AP(char *interface_name, INT8U *ssid, INT8U *bssid, INT16U auth_mode, INT16U encryption_mode, INT8U *network_key, char *auth_type_str, uint8_t map_extension);
#else

INT8U PLATFORM_CONFIGURE_80211_AP(char *interface_name, INT8U *ssid, INT8U *bssid, INT16U auth_mode, INT16U encryption_mode, INT8U *network_key, char *auth_type_str);
#endif
// Get mac address from UCI
void PLATFORM_GET_MAC_ADDRESS(INT8U * mac);

// Set mac address to UCI
void PLATFORM_SET_MAC_ADDRESS(INT8U * mac);

#endif
