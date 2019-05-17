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

#ifndef __1905_LIB_H
#define __1905_LIB_H

#include <stdint.h>
#include "platform_map.h"

/**
@file
@brief This file defines the interface to the 1905 library
*/
#include <1905_tlvs.h>
#include "1905_lib_common.h"

//TODO To replace 40 with (CMDU_TYPE_MAP_LAST_MESSAGE - CMDU_TYPE_MAP_FIRST_MESSAGE
// + CMDU_TYPE_1905_LAST_MESSAGE )
#define MAX_MESSAGES 40

/**
 * Message Filters are used to indicate the list of messages that are of
 * interest. The messages that are set are forwarded by the 1905 library
 * Data structure containing all the message filters
 *
 * @param length: length of single message filter table
 * @param error_cb: error call back ( Currently unused )
 * @param mf[]: Array of message filters
 */
typedef struct {
    int length;
    int (*error_cb)(char* message, int last_message_type);
    single_message_filter_t mf[MAX_MESSAGES];
} message_filter_t;

/**
 * This data structure is used as a parameter while constructing or extracting
 * WSC M1/M2 messages using lib1905_get/lib1905_set
 *
 * @param[in] m2_config   : Controller Configuration info required to build M2.
 * @param[in] wd          : Agent Configuration required to process M2.
 * @param[in,out] wsc_key : The key that is generated during M1 construction is
 *                           provided back to the caller as an out parameter.
 *                           The returned key needs to be sent back while processing
 *                           the received M2 as an input parameter.
 * @param[out] m1         : Pointer to M1 returned for GET_1905_WSCM1TLV
 * @param[out] m2         : Pointer to M2 returned for GET_1905_WSCM2TLV
 */

typedef struct {
   struct wscKey          *wsc_key;
   struct wscTLV          m1;
   struct wscTLV          m2;
   wsc_m2_data            wd;
   config_credential_t    *m2_config;
} lib1905_wscTLV_t;

/**
 * This data structure is used as a parameter while constructing Frequency Band
 * TLV required for Auto-config response message.
 *
 * @param[in] freq_band               : The supported frequency band
 * @param[out] supported_freq_band_tlv: The supported frequency band TLV
 */
typedef struct {
   uint8_t freq_band;
   struct supportedFreqBandTLV *supported_freq_band_tlv;
} supported_freq_band_tlv_t;

/**
 * This enumeration is used as a parameter while connecting to AL entity
 *
 * @param MULTIAP_DEFAULT_MODE: Default mode of operation of AL entity, In this mode
 *                         the full functionality of AL entity is exercised,
 *                         Following are the functionalities that are exercised 
 *                         in default mode only
 *                         1. ALME server thread is launced
 *                         2. Topology monitor thread is launched
 *                         3. Push button monitor thread is launched
 *                         4. Garbage collection of old 1905 nodes is performed
 *
 * @param MULTIAP_OTHER_MODE: This mode of operation is used for test purposes
 */
typedef enum {
    MULTIAP_DEFAULT_MODE=0,
    MULTIAP_AGENT_MODE=10,
    MULTIAP_CONTROLLER_MODE=11,
    OTHER_MODE=12
}lib1905_mode_t;

/**
 * This enumeration is used as a parameter while getting/setting TLV/CMDU
 * from 1905 AL Entity
 * Multi-AP has extended some of the 1905 messages, this API is used to retrieve
 * or set the 1905 TLVs from/to AL entity
 * 
 * @param GET_1905_SEARCHEDROLETLV: Used to retrieve SearchedRole TLV
 * @param GET_1905_ALMACTLV: Used to retrieve ALMAC TLV
 * @param GET_1905_FREQUENCYBANDTLV: Used to retrieve Frequency Band TLV
 * @param GET_1905_WSCM1TLV: Used to retrieve WSC M1 TLV
 * @param GET_1905_SUPPORTEDROLETLV: Used to retrieve supported Role TLV
 * @param GET_1905_SUPPORTEDFREQBANDTLV: Used to retrieve supported Frequency Band TLV
 * @param GET_1905_WSCM2TLV: Used to retrieve WSC M2 TLV
 * @param SET_1905_WSCM2TLV: Used to set WSC M2 TLV to 1905 AL entity
 * @param GET_1905_TOPOLOGY_RESPONSE_CMDU: Used to get Topology Response CMDU
 *           with all the 1905 TLVs constructed
 * @param SET_1905_TOPOLOGY_RESPONSE_CMDU: Used to set Topology Response CMDU
 *           with all the 1905 TLVs constructed
 */
typedef enum {
    GET_1905_SEARCHEDROLETLV,
    GET_1905_ALMACTLV,
    GET_1905_FREQUENCYBANDTLV,
    GET_1905_WSCM1TLV,
    GET_1905_SUPPORTEDROLETLV,
    GET_1905_SUPPORTEDFREQBANDTLV,
    GET_1905_WSCM2TLV,
    SET_1905_WSCM2TLV,
    GET_1905_TOPOLOGY_RESPONSE_CMDU,
    SET_1905_TOPOLOGY_RESPONSE_CMDU,
    GET_1905_DEVICE_INFO_TLV,
}lib1905_param_t;


/**
 * Creates the socket and connects to communicate with 1905 Agent
 * This also launches an AL thread in the specified mode. 
 *
 * When this API is called with MULTIAP_AGENT_MODE as a parameter,
 * following are the functionalities that are performed
 * 1. Launches AL thread which
 *    Retrieves the list of interfaces from uci and starts pcap threads to
 *    listen on all the listed interfaces
 * 2. It also maintains a mapping of interface to Mac address
 * 3. Listens on 1905/MultiAP messages from launched pcap threads
 * 4. Sends Topology discovery messages on all interfaces which are powered on
 *    every 60 seconds 
 * 5. Sends 1905 Topology/Link Metrics/Higher layer query  periodically
 * 6. Processes Responses for Topology/Link Metrics and Higher layer messages
 *
 * When this API is called with MULTIAP_CONTROLLER_MODE as a parameter, all
 * of the above functionalities are exercised, except for 4.
 * Note: The registrar functionality of 1905 is not exercised using this API
 * 1905 is launched to maintain only the topology of the neighbor nodes.
 * Neighbor of neighbor nodes are not maintained
 * ie map_whole_network_flag is set to off
 *
 * @param[out] handle        : Returns the handle to the library
 * @param[out] fd            : Returns fd of the socket
 * @param[in] mode           : Mode in which the AL entity needs to be launched 
 *
 * @retval 0 For successful library initialization
 * @retval -EINVAL If the input is invalid
 */
int lib1905_connect(int* handle, int *fd, lib1905_mode_t mode);

/**
 * Gets information from 1905 Agent
 *
 * @param[in] handle  : handle to the library
 * @param[in] param: 1905 parameter Enumeration
 * @param[out] valueptr : Parameter that is obtained from 1905 Agent
 * @param[out] length : Length of the valueptr structure
 * @param[in] interface : Interface corresponding to the parameter 
 *
 * @retval  0 For successful get operation
 * @retval -EINVAL If the input parameters are invalid
 */
int lib1905_get(int handle, lib1905_param_t param,int* length, void *valueptr, char * interface);

/**
 * Sets information to 1905 Agent
 *
 * @param[in] handle  : handle to the library
 * @param[in] param: 1905 parameter Enumeration
 * @param[in] valueptr : Parameter value that is set to 1905 Agent
 * @param[in] length : Length of the valueptr structure
 *
 * @retval 0 For successful set operation
 * @retval -EINVAL If the input parameters are invalid
 */
int lib1905_set(int handle, lib1905_param_t param, int length, void * valueptr);

/**
 * Sends 1905 CMDU to the specified destination address
 * 
 * @param[in] handle   : handle to the library
 * @param[in,out] mid  : Pointer to message id, if the message id is set to 0,
 *                  it is generated and returned back by the 1905 library
 *                  if the message id is non-zero, the specified mid would
 *                  be used while sending the message
 *
 * @param[in] destination_mac_address : MAC address of the destination 1905.1 device
 * @param[in] data_message            : payload of the message that needs to be sent
 * 
 * @retval 0 For successful set operation
 * @retval -EINVAL If the input parameters are invalid
 */
int lib1905_send(int handle, uint16_t *mid, uint8_t *destination_mac_address, struct CMDU * data_message);

/**
 * Registers message types of interest. Also associates a callback
 * that can be called when a message of interest is received.
 * 
 * @param[in] handle  : handle to the library
 * @param[in] filter : Filter settings to receive 1905 messages
 * 
 * @retval 0 For successful register operation
 * @retval -EINVAL If the input parameters are invalid
 */
int lib1905_register(int handle, message_filter_t * filter);

/**
 * Unregisters message types already registered.
 *
 * @param[in] handle     : handle to the library
 * @param[in] message_type     : Array of message types to unregister
 * @param[in] count      : Count of message types to unregister
 *
 * @retval 0  For successful register operation
 * @retval -EINVAL If the input parameters are invalid
 */
int lib1905_unregister(int handle, uint8_t count, uint16_t * message_type);

/**
 * Polls for messages, if there are pending messages
 * 
 * @param[in] handle  : handle to the library
 * @param[in] timeout : specifies the number of milliseconds
 * 
 * @retval positive integer  Indicating number of events
 * @retval 0  Indicates timeout
 * @retval -1 If there is a disconnection
 * @retval -EINVAL If the input parameters are invalid
 */
int lib1905_poll(int handle,int timeout);

/**
 * Reads the registered 1905 and Multi-AP messages from AL entity and calls
 * the registered callback.
 * This function is a non-blocking call and returns -1 if there are no
 * messages pending to be read
 * 
 * @param[in] handle  : handle to the library
 * 
 * @retval 0  For successful read operation
 * @retval -EINVAL  if the input parameters are invalid
 * @retval -ENOMSG  if the message of interest is not available
 * @retval -EAGAIN  if there are no messages available, try again
 */
int lib1905_read(int handle);

/**
 * Closes the socket to communicate with AL Entity
 * 
 * @param[in] handle : handle to the library
 * 
 * @retval 0 On successful library shutdown
 * @retval -EINVAL If the input handle is not known
 * Note:
 * Memory for the handle is freed.
 */
int lib1905_shutdown(int* handle);

/**
 * Frees the CMDU that is passed to the function
 * This API also performs a deep free of all the TLVs present in the CMDU
 *
 * @param[in] cmdu : CMDU to be freed
 * 
 * @return void
 */
void lib1905_cmdu_cleanup(struct CMDU * cmdu);

/**
 * Notifies 1905 thread of new intrerface added
 * @param[in] handle : handle to the library
 *
 * @param[in] ifname : interface being added
 * 
 * @retval 0 On success
 * @retval -1 On failure
 */
int lib1905_notify_event(int handle,char* ifname, INT8U ifevent);


#endif

#ifdef __cplusplus
}
#endif
