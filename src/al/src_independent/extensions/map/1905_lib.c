/************* COPYRIGHT AND CONFIDENTIALITY INFORMATION NOTICE *************
** Copyright (c) [2019] – [Technicolor Delivery Technologies, SAS]          *
** All Rights Reserved                                                      *
** The source code form of this Open Source Project components              *
** is subject to the terms of the BSD-2-Clause-Patent.                      *
** You can redistribute it and/or modify it under the terms of              *
** the BSD-2-Clause-Patent. (https://opensource.org/licenses/BSDplusPatent) *
** See COPYING file/LICENSE file for more details.                          *
****************************************************************************/

#include <stdio.h>
#include <unistd.h>
#include <fcntl.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <stdlib.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <string.h>
#include <poll.h>
#include <errno.h>
#include <time.h>
#include <pthread.h>
#include <sys/ioctl.h>

#include "1905_lib_internal.h"
#include "1905_lib.h"
#include "map_server.h"

#include "al_send.h"
#include "al_recv.h"
#include "al.h"
#include "al_utils.h"
#include "al_wsc.h"
#include "1905_tlvs.h"
#include "al_datamodel.h"
#include "platform_interfaces.h"
#include "platform.h"
#include "platform_map.h"
#include "al_datamodel.h"



#ifdef PLATFORM_ABSTRACTION
#include "platform_map.h"
#endif

#define MSG_PROCESS_COUNT 4

void addInterface(char *long_interface_name);
/**
 * Check if the given FD is valid or not
 *
 *  Returns : 1 if valid
 *          : 0 if invalid
 */
#define is_valid_fd(fd) (fcntl(fd, F_GETFL) != 0 || errno != EBADF)

static int g_init_flag = 0;
static int g_thread_flag = 0;


void* start1905Thread(void* arg)
{
    start1905AL(DMalMacGet(),0,NULL);
    return NULL;
}

int lib1905_connect(int * handle, int *fd,lib1905_mode_t mode) {

    lib1905_struct_t * lib_struct;
    int sockfd = 0;
    struct sockaddr_un client;

    if (1 == g_init_flag) {
        PLATFORM_PRINTF_DEBUG_ERROR("Multiple INIT try");
        return -1;
    }

    if (fd == NULL) {
        PLATFORM_PRINTF_DEBUG_ERROR("FILE DESCRIPTOR IS NULL");
        return -1;
    }
    map_set_mode(mode);

    *fd = -1;
    if (!g_thread_flag)
    {
       pthread_t alThread;
       pthread_create(&alThread, NULL,start1905Thread,NULL);
       g_thread_flag = 1;
    } 

    if (-1 == (sockfd = socket(AF_UNIX, SOCK_SEQPACKET, 0))) {
        PLATFORM_PRINTF_DEBUG_ERROR("Socket creation error");
        return -1;
    }

    memset(&client, 0, sizeof(struct sockaddr_un));

    client.sun_family = AF_UNIX;
    char mode_str[MAX_MODE_LEN];
    memset(client.sun_path,0,MAX_SOCK_PATH);
    strncpy(client.sun_path + 1, SOCK_PATH, MAX_SOCK_PATH);
    snprintf(mode_str, MAX_MODE_LEN,"%d",map_get_mode());
    strncat(client.sun_path + 1, mode_str, MAX_SOCK_PATH);
    PLATFORM_PRINTF_DEBUG_DETAIL("Client socket path:%s",client.sun_path + 1);


    PLATFORM_PRINTF_DEBUG_DETAIL("Client Socket Path:%s",client.sun_path);

    if(-1 == (connect (sockfd, (const struct sockaddr *) &client,sizeof(struct sockaddr_un)))) {
        PLATFORM_PRINTF_DEBUG_ERROR("Socket connect failed, server is down");
        return -1;
    }

    // Set non-blocking state
    fcntl(sockfd, F_SETFL, (O_NONBLOCK | O_CLOEXEC));


    // Memory allocation for internal library structure
    lib_struct = (lib1905_struct_t *) calloc(1, sizeof(lib1905_struct_t));

    if (NULL == lib_struct) {
        PLATFORM_PRINTF_DEBUG_ERROR("Memory allocation error!");
        return -1;
    }

    // Point handle to the internal library structure
    lib_struct->socketfd = sockfd;
    *handle = (uintptr_t)lib_struct;

    g_init_flag = 1;
    *fd = sockfd;

    return 0;
}

int lib1905_poll(int handle,int timeout) {

    struct pollfd poll_fd;
    unsigned int n = 1;
    int nread = 0;
    int retval;
    lib1905_struct_t * lib_struct;

    // Initialise poll data
    if (NULL == (lib_struct = (lib1905_struct_t *)((uintptr_t)handle)))
       return -EINVAL;

    poll_fd.fd = lib_struct->socketfd;        
    poll_fd.events = POLLIN | POLLPRI;

    if (!is_valid_fd(lib_struct->socketfd)) 
        return -EINVAL;

    retval = poll(&poll_fd,n,timeout);
    if(retval)
    {
        // Check to see if server wants to close connection
        ioctl(poll_fd.fd, FIONREAD, &nread);

        if (0 == nread) 
            return -1;
    }
    return retval;
}

int lib1905_register(int handle, message_filter_t * filter) {

    uint8_t i;
    uint16_t msg_type;
    uint16_t message_type;
    lib1905_struct_t * lib_struct;
    register_data_t reg_data;
    message_interest_t msg_interest;
	INT8U message[sizeof(reg_data)+1];

    if (NULL == (lib_struct = (lib1905_struct_t *)((uintptr_t)handle)))
        return -1;

    memset(&reg_data, 0, sizeof(register_data_t));

    if (!is_valid_fd(lib_struct->socketfd)) 
        return -1;

    // iterate through to get all the message filters
    for (i = 0; i < filter->length; i++) {

        message_type = filter->mf[i].message_type;
        msg_interest.interest_set = 1;
        msg_interest.ack_required = filter->mf[i].ack_required;

        // Handle multi-ap messages
        if (filter->mf[i].message_type >= CMDU_TYPE_MAP_FIRST_MESSAGE && filter->mf[i].message_type <= CMDU_TYPE_MAP_LAST_MESSAGE) {
            msg_type = message_type - CMDU_TYPE_MAP_FIRST_MESSAGE;
            memcpy(&lib_struct->multiap_messages[msg_type], &filter->mf[i], sizeof(single_message_filter_t));
            reg_data.multiap_messages[msg_type] = msg_interest;
        }

        // Handle 1905 messages
        else if (filter->mf[i].message_type >= CMDU_TYPE_1905_FIRST_MESSAGE && filter->mf[i].message_type <= CMDU_TYPE_1905_LAST_MESSAGE){
            memcpy(&lib_struct->lib1905_messages[message_type], &filter->mf[i], sizeof(single_message_filter_t));
            reg_data.lib1905_messages[message_type] = msg_interest;
        }
    }

	message[0] = LIB1905_REGISTER_MSGTYPE;
	memcpy(&message[1],&reg_data,sizeof(register_data_t));
    // Send the registered messages to the 1905 extension
    if (-1 == send(lib_struct->socketfd, (INT8U *)&message, (sizeof(register_data_t)+1),0))
       return -1;

    return 0;
}

int lib1905_notify_event(int handle,char* ifname, INT8U ifevent)
{
    lib1905_struct_t * lib_struct;
    lib1905_event_notification event_msg = {0};
	struct interfaceInfo *if_info;
    INT8U message[sizeof(lib1905_event_notification)+1];

    PLATFORM_PRINTF_DEBUG_DETAIL("Entering lib1905_notify_event for %s\n",ifname);
    if (NULL == (lib_struct = (lib1905_struct_t *)((uintptr_t)handle)))
        return -1;
    
    if (!is_valid_fd(lib_struct->socketfd)) 
        return -1;

	/* NOTE this handling to be removed once 1905 datamodel dependency is removed 
	update 1905 datamodel with mac address of wds interface */
	if(LIB_1905_NEW_IF_CREATED_EVENT == ifevent) {
		if_info = PLATFORM_GET_1905_INTERFACE_INFO(ifname);
		if((if_info!= NULL) && ('\0' != ifname[0])) {
			DMinsertInterface(ifname, if_info->mac_address);
		}
		PLATFORM_FREE_1905_INTERFACE_INFO(if_info);
	}
	
    message[0] = LIB1905_NOTIFY_MSGTYPE;
    event_msg.event = ifevent;          
    memcpy(event_msg.interface_name, ifname, MAX_IFACE_NAME_LEN);
    memcpy(&message[1], &event_msg,sizeof(event_msg));

    // Send the notification message to the 1905 extension
    if (-1 == send(lib_struct->socketfd, &message, sizeof(message), 0))
    {
        PLATFORM_PRINTF_DEBUG_ERROR("lib1905_notify_event send message failed\n");
        return -1;
    }
    
    return 0;
}


int lib1905_tlv_cleanup(lib1905_param_t param, void *valueptr)
{

    if ( param == GET_1905_WSCM1TLV)
      {
          struct wscTLV   *wsc_tlv = (struct wscTLV*)valueptr;
          free(wsc_tlv->wsc_frame);
      }
    return 0;

}

int lib1905_get(int handle, lib1905_param_t param,int* length, void *valueptr, char * interface)
{
    lib1905_struct_t * lib_struct;

    // Initialise poll data
    if (NULL == (lib_struct = (lib1905_struct_t *)((uintptr_t)handle)))
       return -EINVAL;
    if ( NULL == valueptr )
       return -EINVAL;

    if (-1 == obtainTLVFrom1905(param,valueptr,interface)) {
        PLATFORM_PRINTF_DEBUG_ERROR("Tlv get from 1905 failed");
        return -EINVAL;
    }

    return 0;

}

int lib1905_set(int handle, lib1905_param_t param, int length, void * valueptr)
{

    lib1905_struct_t * lib_struct;

    // Initialise poll data
    if (NULL == (lib_struct = (lib1905_struct_t *)((uintptr_t)handle)))
       return -EINVAL;
    if ( 0 == length )
       return -EINVAL;
    if ( NULL == valueptr )
       return -EINVAL;

    if ( param == SET_1905_WSCM2TLV)
         {
             INT8U   *wsc_m2_frame;
             INT16U  wsc_m2_size;
             INT8U   *wsc_m1_frame;
             INT16U  wsc_m1_size;
             INT8U   wsc_type;

             lib1905_wscTLV_t* wsc_data =  (lib1905_wscTLV_t*)valueptr; 

             wsc_m2_frame  = wsc_data->m2.wsc_frame;
             wsc_m2_size   = wsc_data->m2.wsc_frame_size;
             wsc_m1_frame  = wsc_data->m1.wsc_frame;
             wsc_m1_size   = wsc_data->m1.wsc_frame_size;
             wsc_type      = wscGetType(wsc_m2_frame, wsc_m2_size);

             if (WSC_TYPE_M2 == wsc_type)
             {
                // Process it and apply the configuration to the corresponding
                // interface.
                //
                if(wscProcessM2(wsc_data->wsc_key, wsc_m1_frame, wsc_m1_size, wsc_m2_frame, wsc_m2_size, &wsc_data->wd) == 0)
                    return -EINVAL;

             }
         }
    else if ( param == SET_1905_TOPOLOGY_RESPONSE_CMDU )
         {
            struct CMDU* cmdu = (struct CMDU*) valueptr;
            process1905Cmdu(cmdu,(INT8U*)cmdu->interface_name, cmdu->cmdu_stream.src_mac_addr,0);
         }

   return 0;
}

int lib1905_unregister(int handle, uint8_t count, uint16_t * message_type) {

    lib1905_struct_t * lib_struct;
    register_data_t reg_data;
    message_interest_t msg_interest;
    uint8_t i;
    uint16_t msg_type;

    if (NULL == (lib_struct = (lib1905_struct_t *)((uintptr_t)handle)))
        return -1;

    memset(&reg_data, 0, sizeof(register_data_t));
    memset(&msg_interest, 0, sizeof(msg_interest));

    if (!is_valid_fd(lib_struct->socketfd))
        return -1;
    
    // Update Library datastructure
    for(i = 0; i < count; i++) {

        if (message_type[i] >= CMDU_TYPE_MAP_FIRST_MESSAGE && message_type[i] <= CMDU_TYPE_MAP_LAST_MESSAGE) {
            msg_type = message_type[i] - CMDU_TYPE_MAP_FIRST_MESSAGE;
            lib_struct->multiap_messages[msg_type].message_type = 0;
            lib_struct->multiap_messages[msg_type].lib1905_cb = NULL;
        }

        else if (message_type[i] >= CMDU_TYPE_1905_FIRST_MESSAGE && message_type[i] <= CMDU_TYPE_1905_LAST_MESSAGE) {
            lib_struct->lib1905_messages[message_type[i]].message_type = 0;
            lib_struct->lib1905_messages[message_type[i]].lib1905_cb = NULL;
        }
    }

    // Create register data structure for 1905 agent

    for (i = 0; i < MAX_1905_MESSAGE; i++) { 

        if (lib_struct->lib1905_messages[i].message_type > CMDU_TYPE_1905_FIRST_MESSAGE && lib_struct->lib1905_messages[i].message_type <= CMDU_TYPE_1905_LAST_MESSAGE && lib_struct->lib1905_messages[i].lib1905_cb != NULL) {
            msg_interest.interest_set = 1;
            msg_interest.ack_required = lib_struct->lib1905_messages[i].ack_required;
            reg_data.lib1905_messages[i] = msg_interest;
        }
    }

    for (i = 0; i < MAX_MULTIAP_MESSAGE; i++) {

        if (lib_struct->multiap_messages[i].message_type >= CMDU_TYPE_MAP_FIRST_MESSAGE && lib_struct->multiap_messages[i].message_type <= CMDU_TYPE_MAP_LAST_MESSAGE && lib_struct->multiap_messages[i].lib1905_cb != NULL) {
            msg_interest.interest_set = 1;
            msg_interest.ack_required = lib_struct->multiap_messages[i].ack_required;
            reg_data.multiap_messages[i] = msg_interest;
        }
    }

    // Send the registered messages to the 1905 extension
    if (-1 == send(lib_struct->socketfd, (register_data_t *)&reg_data,sizeof(register_data_t),0))
        return -1;

    return 0;
}

int lib1905_send(int handle, uint16_t *mid, uint8_t *destination_mac_address, struct CMDU * data_message) {

    lib1905_struct_t * lib_struct;
    char **if_list;
    uint8_t if_count = 0;
    uint8_t i;
    uint8_t iface_mac_addr[MAC_ADDR_LEN];

    if (NULL == (lib_struct = (lib1905_struct_t *)((uintptr_t)handle)))
        return -1;

    if (!is_valid_fd(lib_struct->socketfd))
        return -1;

    if ( mid && *mid != 0 ) {
       data_message->message_id = *mid;
    } else {
       data_message->message_id = getNextMid();
       if (mid != NULL)
           *mid = data_message->message_id;
    }
    PLATFORM_PRINTF_DEBUG_DETAIL("Interface Name in Send:%s \n",data_message->interface_name);

    if (strncmp(data_message->interface_name, "all", sizeof(data_message->interface_name)) == 0) {

        //TODO:get interfaces from UCI
        if_list = PLATFORM_GET_LIST_OF_1905_INTERFACES(&if_count);
 
        for (i = 0; i < if_count; i++) {
            INT8U authenticated;
            INT8U power_state;

            struct interfaceInfo *x;

            x = PLATFORM_GET_1905_INTERFACE_INFO(if_list[i]);
            if (NULL == x)
            {
                PLATFORM_PRINTF_DEBUG_WARNING("Could not retrieve info of interface %s\n", if_list[i]);
                authenticated = 0;
                power_state   = INTERFACE_POWER_STATE_OFF;
            }
            else
            {
                authenticated = x->is_secured;
                power_state   = x->power_state;
                memcpy(iface_mac_addr,x->mac_address,MAC_ADDR_LEN);
                PLATFORM_FREE_1905_INTERFACE_INFO(x);
            }

            PLATFORM_PRINTF_DEBUG_DETAIL("Interface Name:%s, authen %d, powersave %s\n", if_list[i], authenticated, power_state == INTERFACE_POWER_STATE_ON ?"INTERFACE_POWER_STATE_ON" : "INTERFACE_POWER_STATE_SAVE");
            if ( (strcmp(if_list[i],"lo") != 0) &&
                 ((0 == authenticated ) ||
                 ((power_state != INTERFACE_POWER_STATE_ON) && (power_state!= INTERFACE_POWER_STATE_SAVE)))
               )
            {
                // Do not send the message on this interface
                continue;
            }

            if ( 0 == send1905RawPacket(if_list[i], data_message->message_id, destination_mac_address, data_message))
                return -1;
        }
    } else {

        //Validate the CMDU->interface_name
        if_list = PLATFORM_GET_LIST_OF_1905_INTERFACES(&if_count);
 
        for (i = 0; i < if_count; i++) {
            if(strncmp(data_message->interface_name, if_list[i], sizeof(data_message->interface_name)) == 0)
                break;
        }
 
        if(i>=if_count) {
            //send Interface name didn't match with any of the available interface name
            return -1;
        }
 
        if ( 0 == send1905RawPacket( data_message->interface_name, data_message->message_id, destination_mac_address, data_message))
            return -1;
    }
    return 0;
}


int lib1905_read(int handle) {

    lib1905_struct_t * lib_struct;
    struct CMDU * message= NULL;
    int msg_type;

    if (NULL == (lib_struct = (lib1905_struct_t *)((uintptr_t)handle)))
        return -EINVAL;

    if (!is_valid_fd(lib_struct->socketfd))
        return -EINVAL;

    map_message_t map_msg;

    if (recv(lib_struct->socketfd, (map_message_t*)&map_msg, sizeof(map_message_t),0) == -1)
    {
        return -EAGAIN;
    }

    if ( !map_msg.message )
    {
        return -ENOMSG;
    }

    switch ( map_msg.type )
    {
       case MAP_CMDU_PAYLOAD:
         message = map_msg.message;
         break;

       default:
         // do not process any other messages now
         return -ENOMSG;
    }

    // Trigger callback
    if (message && message->message_type >= CMDU_TYPE_MAP_FIRST_MESSAGE && message->message_type <= CMDU_TYPE_MAP_LAST_MESSAGE) {

         msg_type = message->message_type - CMDU_TYPE_MAP_FIRST_MESSAGE;

         if (lib_struct->multiap_messages[msg_type].message_type == message->message_type) {

            if(lib_struct->multiap_messages[msg_type].lib1905_cb != NULL)
                 lib_struct->multiap_messages[msg_type].lib1905_cb(message->cmdu_stream.src_mac_addr, message, lib_struct->multiap_messages[msg_type].context);
        }
    }
    else if (message && message->message_type >= CMDU_TYPE_1905_FIRST_MESSAGE && message->message_type <= CMDU_TYPE_1905_LAST_MESSAGE) {

        if(lib_struct->lib1905_messages[message->message_type].lib1905_cb != NULL)
             lib_struct->lib1905_messages[message->message_type].lib1905_cb(message->cmdu_stream.src_mac_addr, message, lib_struct->lib1905_messages[message->message_type].context);
    }

    return 0;
}

int lib1905_shutdown(int* handle) {

    lib1905_struct_t * lib_struct;

    if (NULL == handle || *handle <= 0) {
        PLATFORM_PRINTF_DEBUG_WARNING("Trying to free empty handle");
        return -1;
    }

    lib_struct = (lib1905_struct_t *)((uintptr_t)(*handle));

    if (!is_valid_fd(lib_struct->socketfd))
        return -1;

    close(lib_struct->socketfd);
    free(lib_struct);
    *handle = -1;
    g_init_flag = 0;

    return 0;
}

void lib1905_cmdu_cleanup(struct CMDU * cmdu) {
    PLATFORM_PRINTF_DEBUG_DETAIL("Freeing cmdu type:%d Address:0x%p", cmdu->message_type,cmdu);
    free_1905_CMDU_structure(cmdu);
}

