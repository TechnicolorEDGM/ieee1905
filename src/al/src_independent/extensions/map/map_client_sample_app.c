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
#include <stdlib.h>
#include <sys/socket.h>
#include "1905_tlvs.h"
#include "1905_cmdus.h"
#include "1905_lib.h"
#include "1905_lib_internal.h"
#include <errno.h>

// 1905 multicast address ("01:80:C2:00:00:13")
#define MCAST_1905_B0 (0x01)
#define MCAST_1905_B1 (0x80)
#define MCAST_1905_B2 (0xC2)
#define MCAST_1905_B3 (0x00)
#define MCAST_1905_B4 (0x00)
#define MCAST_1905_B5 (0x15)
#define MCAST_1905  {MCAST_1905_B0, MCAST_1905_B1, MCAST_1905_B2, MCAST_1905_B3, MCAST_1905_B4, MCAST_1905_B5}

int callback_fn(uint8_t *mac, struct CMDU * cmdu, void * context) {
    int i;

    printf(" RECEIVED MAC ADDRESS: \n");
    for (i = 0; i < 6; i++)
        printf("%x:",mac[i]);
    printf("\n MESSAGE VERSION : %d\n MESSAGE_TYPE : %d\n MESSAGE ID : %d\n RELAY INDICATOR : %d\n TLV BYTES",cmdu->message_version,cmdu->message_type,cmdu->message_id,cmdu->relay_indicator);
    return 0;
}

int error_callback(char *message, int code) {
    return 0;
}

message_filter_t msg_filter[] = {
            {6, error_callback,  {{CMDU_TYPE_TOPOLOGY_DISCOVERY,1 , callback_fn, NULL},{CMDU_TYPE_HIGHER_LAYER_QUERY,1 , callback_fn, NULL},{CMDU_TYPE_TOPOLOGY_RESPONSE,1 , callback_fn, NULL},{CMDU_TYPE_LINK_METRIC_QUERY, 1, callback_fn, NULL}, {CMDU_TYPE_MAP_CLIENT_STEERING_REQUEST, 1, callback_fn, NULL},{CMDU_TYPE_LINK_METRIC_RESPONSE,1,callback_fn,NULL}}} ,
            {1, error_callback,{{CMDU_TYPE_AP_AUTOCONFIGURATION_WSC, 0, callback_fn, NULL}}} 
};


int main(){
    int handle = 0,rvalue,option;

    while(1) {
        printf("Choose the test to be done\n1 : INIT TEST\n2 : REGISTER TEST\n3 : POLL TEST\n4 : RAW SEND TEST\n5 : READ TEST\n6 : READ TEST WITH WAIT ON POLL\n7 : UNREGISTER TEST\n8 : SHUTDOWN TEST\n9 : QUIT\n");
        scanf("%d",&option);

        switch(option) {
            case 1: {
                // INIT TEST 
                int fd = 0;
                rvalue = lib1905_connect(&handle,&fd,OTHER_MODE);
                if(rvalue == 0)
                    syslog (LOG_INFO,"INIT SUCCESS");
                else if(rvalue == -1)
                    syslog (LOG_ERR,"INIT FAILED");
                break;
            }
            case 2: {
                // REGISTER TEST
                rvalue = lib1905_register(handle, &msg_filter[0]);
                if(rvalue == 0)
                    syslog (LOG_INFO,"REGISTRATION SUCCESS");
                else if (rvalue == -1)
                    syslog (LOG_ERR,"REGISTRATION FAILED");
                break;
            }   
            case 3: {
                // POLL TEST
                rvalue = lib1905_poll(handle,0);
                if(rvalue == 0)
                    syslog (LOG_INFO, "NO DATA IN SOCKET");
                else if (rvalue == 1)
                    syslog (LOG_INFO, "DATA PRESENT IN SOCKET");
                else if (rvalue == EINVAL)
                    syslog (LOG_ERR, "INVALID ARGUMENTS FOR POLL");
                break;
            }
            case 4: {
                // SEND TEST
                uint16_t mid;
                struct CMDU discovery_message;
                struct alMacAddressTypeTLV al_mac_addr_tlv;
                struct macAddressTypeTLV   mac_addr_tlv;
                uint8_t mcast_address[] = MCAST_1905;
                al_mac_addr_tlv.tlv_type          = TLV_TYPE_AL_MAC_ADDRESS_TYPE;
                al_mac_addr_tlv.al_mac_address[0] = 0xE0;
                al_mac_addr_tlv.al_mac_address[1] = 0xB9;
                al_mac_addr_tlv.al_mac_address[2] = 0xE5;
                al_mac_addr_tlv.al_mac_address[3] = 0xB2;
                al_mac_addr_tlv.al_mac_address[4] = 0x7B;
                al_mac_addr_tlv.al_mac_address[5] = 0x96;
                mac_addr_tlv.tlv_type             = TLV_TYPE_MAC_ADDRESS_TYPE;
                mac_addr_tlv.mac_address[0]       = 0xE0;
                mac_addr_tlv.mac_address[1]       = 0xB9;
                mac_addr_tlv.mac_address[2]       = 0xE5;
                mac_addr_tlv.mac_address[3]       = 0xB2;
                mac_addr_tlv.mac_address[4]       = 0x7B;
                mac_addr_tlv.mac_address[5]       = 0x96;
                discovery_message.message_version = 0;
                discovery_message.message_type    = CMDU_TYPE_TOPOLOGY_DISCOVERY;
                discovery_message.relay_indicator = 0;
                discovery_message.list_of_TLVs    = (uint8_t **)malloc(sizeof(uint8_t *)*3);
                discovery_message.list_of_TLVs[0] = (uint8_t *)&al_mac_addr_tlv;
                discovery_message.list_of_TLVs[1] = (uint8_t *)&mac_addr_tlv;
                discovery_message.list_of_TLVs[2] = NULL;
                if (0 == lib1905_send(handle,&mid, mcast_address, &discovery_message)) 
                    syslog (LOG_INFO,"SEND SUCCESS");
                break;
            }
            case 5: {
                // READ TEST
                rvalue = lib1905_read(handle);
                if(rvalue == -1)
                    syslog (LOG_ERR,"READ FAILED");
                else if(rvalue == 0)
                    syslog (LOG_INFO,"READ SUCCESS");
                else if(rvalue == EINVAL)
                    syslog (LOG_ERR, "INVALID ARGUMENTS FOR READ");
                break;
            }
            case 6: { 
                // READ TEST WITH WAIT ON POLL
                while(1){
                    rvalue = lib1905_poll(handle,1000);
                    if (rvalue == 1) {
                        syslog (LOG_INFO,"DATA PRESENT IN SOCKET");
                        rvalue = lib1905_read(handle);
                        if(rvalue == -1)
                            syslog (LOG_ERR,"READ FAILED");
                    }
                }
                break;
            }
            case 7: {
                // UNREGISTER TEST
                uint16_t m_types[40];
                uint8_t count;
                m_types[0] = CMDU_TYPE_AP_AUTOCONFIGURATION_WSC;
                m_types[1] = CMDU_TYPE_TOPOLOGY_DISCOVERY;
                count = 1;
                rvalue = lib1905_unregister(handle,count, m_types);
                if(rvalue == 0)
                    syslog (LOG_INFO,"UNREGISTRATION SUCCESS");
                else if (rvalue == -1)
                    syslog (LOG_ERR,"UNREGISTRATION FAILED");
                break;
            }
            case 8: {
                // SHUTDOWN TEST
                rvalue = lib1905_shutdown(&handle);
                if (rvalue == 0)
                    syslog (LOG_INFO,"SHUTDOWN SUCCESS");
                else if(rvalue == -1)
                    syslog (LOG_ERR,"SHUTDOWN FAILURE");
                break;
            }
            case 9: {
                // QUIT APP
                return 0;
            }
            default: {
                break;
            }
        }
    }
    return 0;
}
