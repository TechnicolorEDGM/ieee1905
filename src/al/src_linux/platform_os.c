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

#include "platform.h"
#include "platform_os.h"
#include "platform_os_priv.h"
#include "platform_interfaces.h"
#include "platform_alme_server_priv.h"
#include "1905_l2.h"
#include "platform_interfaces_priv.h"


#ifdef MULTIAP
#include "map_server.h"
#endif

#include <stdlib.h>      // free(), malloc(), ...
#include <string.h>      // memcpy(), memcmp(), ...
#include <pthread.h>     // threads and mutex functions
#include <sys/fcntl.h>

#ifdef PLATFORM_ABSTRACTION
#include "queueutil.h"
#else
#include <mqueue.h>      // mq_*() functions
#endif

#include <pcap/pcap.h>   // pcap_*() functions
#include <errno.h>       // errno
#include <poll.h>        // poll()
#include <signal.h>
#include <sys/inotify.h> // inotify_*()
#include <time.h>
#include <unistd.h>      // read(), sleep()
#include <sys/socket.h>
#include <sys/types.h>
#include <arpa/inet.h>
#include <linux/if_ether.h>
#include <linux/if_packet.h>
#include <net/ethernet.h> /* the L2 protocols */
#include <sys/ioctl.h>
#include <net/if.h>
#include <sys/timerfd.h>

////////////////////////////////////////////////////////////////////////////////
// Private functions, structures and macros
////////////////////////////////////////////////////////////////////////////////

// *********** IPC stuff *******************************************************

// Queue related function in the PLATFORM API return queue IDs that are INT8U
// elements.
// However, in POSIX all queue related functions deal with a 'mqd_t' type.
// The following global arrays are used to store the association between a
// "PLATFORM INT8U ID" and a "POSIX mqd_t ID"

#define MAX_QUEUE_IDS  256  // Number of values that fit in an INT8U
#define IFACE_NAME_LEN 16
#define MAX(a,b) \
   ({ __typeof__ (a) _a = (a); \
       __typeof__ (b) _b = (b); \
     _a > _b ? _a : _b; })

#ifdef PLATFORM_ABSTRACTION
static tQueue*           queues_id[MAX_QUEUE_IDS] = {[ 0 ... MAX_QUEUE_IDS-1 ] = NULL};
#else
static mqd_t           queues_id[MAX_QUEUE_IDS] = {[ 0 ... MAX_QUEUE_IDS-1 ] = (mqd_t) -1};
#endif

static pthread_mutex_t queues_id_mutex          = PTHREAD_MUTEX_INITIALIZER;

#ifdef USE_RAW_SOCK
static int sock_list_count = 0;
unsigned char IEEE1905_MULTICAST_MAC[6] = {0x01, 0x80, 0xC2, 0x00, 0x00, 0x13};
unsigned char LLDP_MULTICAST_MAC[6] = {0x01, 0x80, 0xC2, 0x00, 0x00, 0x0E};
#endif


static int ifaceSocketRemove(char* ifname);
static void ifaceRemoveSockListItem(iface1905Socket *current_item);
static iface1905Socket* ifaceGetSockListItem(char* ifname, int socktype);


// *********** Packet capture stuff ********************************************

// We use 'libpcap' to capture 1905 packets on all interfaces.
// It works like this:
//
//   - When the PLATFORM API user calls "PLATFORM_REGISTER_QUEUE_EVENT()" with
//     'PLATFORM_QUEUE_EVENT_NEW_1905_PACKET', 'libpcap' is used to set the
//     corresponding interface into monitor mode.
//
//   - In addition, a new thread is created ('_pcapLoopThread()') which runs
//     forever and, everytime a new packet is received on the corresponding
//     interface, that thread calls '_pcapProcessPacket()'
//
//   - '_pcapProcessPacket()' simply post the whole contents of the received
//     packet to a queue so that the user can later obtain it with a call to
//     "PLATFORM_QUEUE_READ()"

static pthread_mutex_t pcap_filters_mutex = PTHREAD_MUTEX_INITIALIZER;
static pthread_cond_t  pcap_filters_cond  = PTHREAD_COND_INITIALIZER;
static int             pcap_filters_flag  = 0;

struct _pcapCaptureThreadData
{
    INT8U     queue_id;
    char     *interface_name;
    INT8U     interface_mac_address[6];
    INT8U     al_mac_address[6];
};

struct _timerHandlerThreadData
{
    INT8U    queue_id;
    INT32U   token;
    INT8U    periodic;
    timer_t  timer_id;
};


#if defined USE_RAW_SOCK

void process_timer(u_char *arg)
 {
 	struct _timerHandlerThreadData *aux;

    INT8U   message[3+4];
    INT16U  packet_len;
    INT8U   packet_len_msb;
    INT8U   packet_len_lsb;
    INT8U   token_msb;
    INT8U   token_2nd_msb;
    INT8U   token_3rd_msb;
    INT8U   token_lsb;

	aux = (struct _timerHandlerThreadData *)arg;
    // In order to build the message that will be inserted into the queue, we
    // need to follow the "message format" defines in the documentation of
    // function 'PLATFORM_REGISTER_QUEUE_EVENT()'
    //
    packet_len = 4;

#if _HOST_IS_LITTLE_ENDIAN_ == 1
    packet_len_msb = *(((INT8U *)&packet_len)+1);
    packet_len_lsb = *(((INT8U *)&packet_len)+0);

    token_msb      = *(((INT8U *)&aux->token)+3);
    token_2nd_msb  = *(((INT8U *)&aux->token)+2);
    token_3rd_msb  = *(((INT8U *)&aux->token)+1);
    token_lsb      = *(((INT8U *)&aux->token)+0);
#else
    packet_len_msb = *(((INT8U *)&packet_len)+0);
    packet_len_lsb = *(((INT8U *)&packet_len)+1);

    token_msb     = *(((INT8U *)&aux->token)+0);
    token_2nd_msb = *(((INT8U *)&aux->token)+1);
    token_3rd_msb = *(((INT8U *)&aux->token)+2);
    token_lsb     = *(((INT8U *)&aux->token)+3);
#endif

    message[0] = 1 == aux->periodic ? PLATFORM_QUEUE_EVENT_TIMEOUT_PERIODIC : PLATFORM_QUEUE_EVENT_TIMEOUT;
    message[1] = packet_len_msb;
    message[2] = packet_len_lsb;
    message[3] = token_msb;
    message[4] = token_2nd_msb;
    message[5] = token_3rd_msb;
    message[6] = token_lsb;

    PLATFORM_PRINTF_DEBUG_DETAIL("[PLATFORM] *Timer handler* Sending %d bytes to queue (%02x, %02x, %02x, ...)\n", 3+packet_len, message[0], message[1], message[2]);

	if(is_reg_complete == 1)
	{
	    if (0 == sendMessageToAlQueue(aux->queue_id, message, 3+packet_len))
	    {
	        PLATFORM_PRINTF_DEBUG_ERROR("[PLATFORM] *Timer handler* Error sending message to queue from _timerHandler()\n");
	    }
	}
	else
	{
		PLATFORM_PRINTF_DEBUG_ERROR("Reg not complete\n");
		return;
	}

    
        
    

    return;
 }

static void rawSockProcessPacket(u_char *arg, int pkt_len, char *packet)
{
	// This function is executed (on a dedicated thread) every
    // time a new 1905 packet arrives

	struct _pcapCaptureThreadData *aux;

	INT8U   message[3+MAX_NETWORK_SEGMENT_SIZE+16];
	INT16U  message_len;
	INT8U   message_len_msb;
	INT8U   message_len_lsb;

	if (NULL == arg)
	{
		// Invalid argument

		PLATFORM_PRINTF_DEBUG_ERROR("[PLATFORM] *Pcap thread* Invalid arguments in rawSockProcessPacket()\n");
		free(packet);
		return;
	}

	aux = (struct _pcapCaptureThreadData *)arg;

	if (pkt_len > MAX_NETWORK_SEGMENT_SIZE)
	{
		// This should never happen
		PLATFORM_PRINTF_DEBUG_ERROR("[PLATFORM] *Pcap thread* Captured packet too big\n");
		free(packet);
		return;
	}

	// In order to build the message that will be inserted into the queue, we
	// need to follow the "message format" defines in the documentation of
	// function 'PLATFORM_REGISTER_QUEUE_EVENT()'
	message_len = (INT16U)pkt_len + 16;

#if _HOST_IS_LITTLE_ENDIAN_ == 1
	message_len_msb = *(((INT8U *)&message_len)+1);
	message_len_lsb = *(((INT8U *)&message_len)+0);
#else
	message_len_msb = *(((INT8U *)&message_len)+0);
	message_len_lsb = *(((INT8U *)&message_len)+1);
#endif

	message[0] = PLATFORM_QUEUE_EVENT_NEW_1905_PACKET;
	message[1] = message_len_msb;
	message[2] = message_len_lsb;

/*
	* We need to pass interface name to packet processing thread, instead of mac address
	* Since mac address
*/
	strncpy((char*)&message[3], aux->interface_name, 16);

	memcpy(&message[19], packet,pkt_len);

	// Now simply send the message.

	PLATFORM_PRINTF_DEBUG_DETAIL("[PLATFORM] *Pcap thread* Sending %d bytes to queue (0x%02x, 0x%02x, 0x%02x, ...) - interface %s\n", 3+message_len, message[0], message[1], message[2], &message[3]);

	if (0 == sendMessageToAlQueue(aux->queue_id, message, 3 + message_len))
	{
		PLATFORM_PRINTF_DEBUG_ERROR("[PLATFORM] *Pcap thread* Error sending message to queue from rawSockProcessPacket()\n");
		free(packet);
		return;
	}

	free(packet);
	return;

}
#endif

static void _pcapProcessPacket(u_char *arg, const struct pcap_pkthdr *pkthdr, const u_char *packet)
{
    // This function is executed (on a dedicated thread) every
    // time a new 1905 packet arrives
  
    struct _pcapCaptureThreadData *aux;

    INT8U   message[3+MAX_NETWORK_SEGMENT_SIZE+16];
    INT16U  message_len;
    INT8U   message_len_msb;
    INT8U   message_len_lsb;
    
    if (NULL == arg)
    {
        // Invalid argument
        //
        PLATFORM_PRINTF_DEBUG_ERROR("[PLATFORM] *Pcap thread* Invalid arguments in _pcapProcessPacket()\n");
        return;
    }
   
    aux = (struct _pcapCaptureThreadData *)arg;

    if (pkthdr->len > MAX_NETWORK_SEGMENT_SIZE)
    {
        // This should never happen
        //
        PLATFORM_PRINTF_DEBUG_ERROR("[PLATFORM] *Pcap thread* Captured packet too big\n");
        return;
    }

    // In order to build the message that will be inserted into the queue, we
    // need to follow the "message format" defines in the documentation of
    // function 'PLATFORM_REGISTER_QUEUE_EVENT()'
    //
    message_len = (INT16U)pkthdr->len + 16;
#if _HOST_IS_LITTLE_ENDIAN_ == 1
    message_len_msb = *(((INT8U *)&message_len)+1);
    message_len_lsb = *(((INT8U *)&message_len)+0);
#else
    message_len_msb = *(((INT8U *)&message_len)+0);
    message_len_lsb = *(((INT8U *)&message_len)+1);
#endif

    message[0] = PLATFORM_QUEUE_EVENT_NEW_1905_PACKET;
    message[1] = message_len_msb;
    message[2] = message_len_lsb;

    /*
     * We need to pass interface name to packet processing thread, instead of mac address
     * Since mac address
     */
    strncpy((char*)&message[3], aux->interface_name, 16);
    memcpy(&message[19], packet, pkthdr->len);

    // Now simply send the message.
    //
    PLATFORM_PRINTF_DEBUG_DETAIL("[PLATFORM] *Pcap thread* Sending %d bytes to queue (0x%02x, 0x%02x, 0x%02x, ...) - interface %s\n", 3+message_len, message[0], message[1], message[2], &message[3]);

    if (0 == sendMessageToAlQueue(aux->queue_id, message, 3 + message_len))
    {
        PLATFORM_PRINTF_DEBUG_ERROR("[PLATFORM] *Pcap thread* Error sending message to queue from _pcapProcessPacket()\n");
        return;
    }

    return;
}

#ifdef USE_RAW_SOCK
int getInterfaceIndex(char *ifname)
{
	struct ifreq ifr;
	int sockfd;
	int ifindex;

	if ((sockfd = socket(AF_INET, SOCK_STREAM, 0)) == -1) {
		return -1;
	}

	strncpy(ifr.ifr_name, ifname, IFACE_NAME_LEN);
	ifr.ifr_name[IFACE_NAME_LEN] = '\0';
	if (ioctl(sockfd, SIOCGIFINDEX, &ifr) == -1) {
	close(sockfd);
	return -1;
	}

	ifindex = ifr.ifr_ifindex;

	close(sockfd);
	return ifindex;
}


int addSocketList(int sock_fd, int ifaceIndex, char* ifname, INT8U* iface_macaddress, int type)
{
	iface1905Socket *new_sock = (iface1905Socket*) calloc(1, sizeof(iface1905Socket));
	iface1905Socket *next_sock;

	if(new_sock == NULL)
	{
		PLATFORM_PRINTF_DEBUG_ERROR("[PLATFORM] * Socket Creation failed\n");
		return -1;
	} 

	if(type == SOCKTYPE_1905 || type == SOCKTYPE_LLDP)
	{
		PLATFORM_MEMCPY(new_sock->interface_mac_address,iface_macaddress,6);
		new_sock->iface_index = ifaceIndex;
		new_sock->interface_name = strdup(ifname);	
	}
		
	new_sock->sock_fd = sock_fd;
	new_sock->sock_in_use = 1;
	new_sock->type = type;
	new_sock->next = NULL;
	
	if ( raw_sock_list == NULL )
	{
		raw_sock_list = new_sock;
	}
	else
	{	
		next_sock = raw_sock_list;
		while(next_sock != NULL)
		{
			if(next_sock->next == NULL)
			{
				next_sock->next = new_sock;
				break;
			}
			next_sock = next_sock->next;
		}
	}

	PLATFORM_PRINTF_DEBUG_DETAIL("Added socket to list!! Count = %d\n",sock_list_count);
	sock_list_count++;
	return 0;
	
}


int ifaceSocketSet(int fd, int ifaceIndex, int protocol, unsigned char* multicast_address)
{
	int flags;
	struct sockaddr_ll sa;
	struct packet_mreq mr;

	flags = fcntl(fd, F_GETFL, 0);
	if(flags < 0) {
		PLATFORM_PRINTF_DEBUG_DETAIL("[PLATFORM] *Pcap thread* cannot retrieve socket flags. errno=%d", errno);
	}

	if ( fcntl(fd, F_SETFL, flags | O_NONBLOCK) < 0 ) {
		PLATFORM_PRINTF_DEBUG_DETAIL("[PLATFORM] *Pcap thread* cannot set socket to non-blocking. errno=%d", errno);
	}

	sa.sll_family   = PF_PACKET;
	sa.sll_protocol = htons(protocol);
	sa.sll_halen    = ETH_ALEN;
	sa.sll_ifindex  = ifaceIndex;

	if((bind(fd, (struct sockaddr *)&sa, sizeof(struct sockaddr_ll)))== -1) {
		PLATFORM_PRINTF_DEBUG_ERROR("[PLATFORM] *Pcap thread* could not bind socket to %d interface\n", ifaceIndex);
		close(fd);
		return -1;
	}

	//Set Socket to multicast promiscuous mode
	memset(&mr,0,sizeof(mr));
	mr.mr_ifindex = sa.sll_ifindex;
	mr.mr_type = PACKET_MR_MULTICAST;
	mr.mr_alen = ETH_ALEN;
	memcpy(mr.mr_address,multicast_address, ETH_ALEN);
	if(setsockopt(fd, SOL_PACKET, PACKET_ADD_MEMBERSHIP, &mr, sizeof(mr)) < 0)
	{
		PLATFORM_PRINTF_DEBUG_DETAIL("[PLATFORM] *Pcap thread* %s: setsockopt error (%s)\n", __func__, strerror(errno));
		close(fd);
		return -1;
	}

	return 0;
}


int ifaceSocketCreate(int ifaceIndex, char* ifname, INT8U* iface_macaddress )
{
	int sock_fd;
	int lldp_sock_fd;
	
	//Create sock for capturing 1905 packets
	sock_fd =  socket(AF_PACKET,SOCK_RAW,htons(ETHERTYPE_1905));
	if( sock_fd  < 0 )
	{
		//Could not open raw socket to capture 1905 packets
		PLATFORM_PRINTF_DEBUG_ERROR("[PLATFORM] *Pcap thread* Error opening socket for interface %s\n", ifname);
		return -1;
	}
	if (ifaceSocketSet(sock_fd, ifaceIndex, ETHERTYPE_1905, IEEE1905_MULTICAST_MAC) < 0)
	{
		PLATFORM_PRINTF_DEBUG_ERROR("[PLATFORM] * 1905 Socket Creation failed\n");
		close(sock_fd);
		return -1;
	}

	//Create sock for capturing LLDP packets
	lldp_sock_fd = socket(AF_PACKET,SOCK_RAW,htons(ETHERTYPE_LLDP));
	if(lldp_sock_fd < 0 )
	{
		//Could not open raw socket to capture 1905 packets
		PLATFORM_PRINTF_DEBUG_ERROR("[PLATFORM] *Pcap thread* Error opening LLDP socket for interface %s\n", ifname);
		close(sock_fd);
		return -1;
	}

	if( ifaceSocketSet(lldp_sock_fd,ifaceIndex, ETHERTYPE_LLDP, LLDP_MULTICAST_MAC) < 0)
	{
		PLATFORM_PRINTF_DEBUG_ERROR("[PLATFORM] * LLDP Socket Creation failed\n");
		close(sock_fd);
		close(lldp_sock_fd);
		return -1;
	}

	if(addSocketList(sock_fd, ifaceIndex,ifname,iface_macaddress,SOCKTYPE_1905) < 0 )
	{
		PLATFORM_PRINTF_DEBUG_ERROR("[PLATFORM] * 1905 Socket List Creation failed\n");
		close(sock_fd);
		close(lldp_sock_fd);
		return -1;
	}

	if(addSocketList(lldp_sock_fd, ifaceIndex,ifname,iface_macaddress,SOCKTYPE_LLDP) < 0 )
	{
		PLATFORM_PRINTF_DEBUG_ERROR("[PLATFORM] * Socket List Creation failed\n");
		close(sock_fd);
		close(lldp_sock_fd);
		return -1;
	}

	return 0;
		
}

static iface1905Socket* ifaceGetSockListItem(char* ifname, int socktype)
{
    iface1905Socket *current_item = NULL;
    iface1905Socket *prev_item = NULL;

    if ( raw_sock_list != NULL )
    {
        current_item = raw_sock_list;
        do
        {
            if(current_item->type == socktype) {
                if(!strcmp(current_item->interface_name , ifname)) {
                    /* links updated, element not freed here */
                    if(prev_item == NULL) {
                        raw_sock_list = current_item->next;
                    } else {
                        prev_item->next = current_item->next;
                    }
                    PLATFORM_PRINTF_DEBUG_DETAIL("[PLATFORM] %s found socket entry for interface %s\n", __FUNCTION__, current_item->interface_name);
                    break;
                }
            }            
            prev_item = current_item;
            current_item = current_item->next;
        } while(current_item != NULL);      
    } else {
        PLATFORM_PRINTF_DEBUG_ERROR("[PLATFORM] %s 1905 Socket List Empty\n", __FUNCTION__);
    }

    return current_item;
}

static void ifaceRemoveSockListItem(iface1905Socket *current_item)
{
    if(current_item != NULL) {
        /* free satellite memory */
        if(current_item->interface_name != NULL) {
            free(current_item->interface_name);
        }
        
        memset(current_item, 0, sizeof(iface1905Socket));
        free(current_item);
        sock_list_count--;
    }   
}

static int ifaceSocketRemove(char* ifname)
{
    int status = 0;
    iface1905Socket *current_sock = NULL;

    /* get current if 1905 socket data*/
    current_sock = ifaceGetSockListItem(ifname, SOCKTYPE_1905);
    if(current_sock != NULL) {
        /* close socket */
        close(current_sock->sock_fd);
        PLATFORM_PRINTF_DEBUG_DETAIL("[PLATFORM] %s closed socket type %d for %s", __FUNCTION__, current_sock->type,current_sock->interface_name);

        /*Remove socket info from list */
        ifaceRemoveSockListItem(current_sock);
    } else {
        status = -1;
        return status;
    }
    
    current_sock = NULL;
    /* get current if lldp sock data */ 
    current_sock = ifaceGetSockListItem(ifname, SOCKTYPE_LLDP);
    if(current_sock != NULL) {
        /* close socket */
        close(current_sock->sock_fd);
        PLATFORM_PRINTF_DEBUG_DETAIL("[PLATFORM] %s closed socket type %d for %s", __FUNCTION__, current_sock->type,current_sock->interface_name);

        /*Remove socket info from list */
        ifaceRemoveSockListItem(current_sock);
    } else {
        status = -1;
    }

    return status;      
}


void create1905Sockets()
{	
	INT8U interfaces_nr = 0;
	int ifaceIndex;
	char **interfaces_names;
	struct interfaceInfo *ifaceInfo;
	
	INT8U i;

	interfaces_names = PLATFORM_GET_LIST_OF_1905_INTERFACES(&interfaces_nr);
	if (NULL == interfaces_names)
	{
		PLATFORM_PRINTF_DEBUG_ERROR("No interfaces detected\n");
		return;
	}

	//Each Interface has 2 raw sockets each for 1905 and LLDP packet filtering repectively
	for (i=0; i<interfaces_nr; i++)
	{

		ifaceInfo = PLATFORM_GET_1905_INTERFACE_INFO(interfaces_names[i]);
                if (NULL == ifaceInfo)
                {
                    PLATFORM_PRINTF_DEBUG_ERROR("Could not retrieve interface info for %s\n", interfaces_names[i]);
                    continue;
                }

		if(ifaceInfo->power_state == INTERFACE_POWER_STATE_OFF)
		{
			PLATFORM_PRINTF_DEBUG_DETAIL("Iface %s is in power down state\n",interfaces_names[i]);
                        PLATFORM_FREE_1905_INTERFACE_INFO(ifaceInfo);
			continue;
		}

		ifaceIndex = getInterfaceIndex(interfaces_names[i]);

		PLATFORM_PRINTF_DEBUG_DETAIL("  Iface Index for - %s  is %d --> OK\n",interfaces_names[i],ifaceIndex );

		if (ifaceSocketCreate(ifaceIndex, interfaces_names[i], ifaceInfo->mac_address) < 0)
		{
			PLATFORM_PRINTF_DEBUG_ERROR("[PLATFORM] * Socket Creation failed\n");
                        PLATFORM_FREE_1905_INTERFACE_INFO(ifaceInfo);
                        PLATFORM_FREE_LIST_OF_1905_INTERFACES(interfaces_names, interfaces_nr);
			return;
		}
	
		PLATFORM_PRINTF_DEBUG_DETAIL("    - %s --> OK\n", interfaces_names[i]);
		PLATFORM_FREE_1905_INTERFACE_INFO(ifaceInfo);
	}

	PLATFORM_FREE_LIST_OF_1905_INTERFACES(interfaces_names, interfaces_nr);

}

void update1905RawSockets(char* ifname)
{
	INT8U interfaces_nr = 0;
	int is_sock_new     = 1;
	char **interfaces_names         = NULL;
	struct interfaceInfo *ifaceInfo = NULL;
	iface1905Socket      *sock      = NULL;
        INT8U iface_mac[MAC_ADDR_LEN]   = {0};
	int power_state;
	int ifaceIndex;
	INT8U i;
	
	interfaces_names = PLATFORM_GET_LIST_OF_1905_INTERFACES(&interfaces_nr);
	if (NULL == interfaces_names)
	{
		PLATFORM_PRINTF_DEBUG_ERROR("No interfaces detected\n");
		return;
	}
	
	//Each Interface has 2 raw sockets each for 1905 and LLDP packet filtering repectively
	for (i=0; i<interfaces_nr; i++)
	{
		if(strcmp(ifname,interfaces_names[i]) != 0)
		{
			continue;
		}

		else
		{
			PLATFORM_PRINTF_DEBUG_DETAIL("Iface name is in the list %s\n",interfaces_names[i]);
			ifaceInfo = PLATFORM_GET_1905_INTERFACE_INFO(interfaces_names[i]);
			if (NULL == ifaceInfo)
			{
				PLATFORM_PRINTF_DEBUG_ERROR("Could not retrieve interface info for %s\n", interfaces_names[i]);
				PLATFORM_FREE_LIST_OF_1905_INTERFACES(interfaces_names,interfaces_nr);
				return;
			}

			power_state = ifaceInfo->power_state;
			PLATFORM_PRINTF_DEBUG_DETAIL("Iface Power state is %d\n",power_state);

                        memcpy(iface_mac, ifaceInfo->mac_address, MAC_ADDR_LEN);
                        PLATFORM_FREE_1905_INTERFACE_INFO(ifaceInfo);
			break;
			
		}
	}

        PLATFORM_FREE_LIST_OF_1905_INTERFACES(interfaces_names,interfaces_nr);

	sock = raw_sock_list;
	while(sock != NULL)
	{
		if((sock->type == SOCKTYPE_1905) || (sock->type == SOCKTYPE_LLDP))
		{
			if(strcmp(ifname,sock->interface_name) != 0)
			{
				PLATFORM_PRINTF_DEBUG_DETAIL("Not in sock %s\n",sock->interface_name);
				
			}
			else
			{
				PLATFORM_PRINTF_DEBUG_DETAIL("Present in sock %s\n",sock->interface_name);
				if(sock->sock_in_use && (power_state == INTERFACE_POWER_STATE_OFF))
				{
					PLATFORM_PRINTF_DEBUG_DETAIL("Disable sock %s type %d\n",sock->interface_name,sock->type);
					sock->sock_in_use = 0;
				}
				
				is_sock_new = 0;
			}
		}
		sock = sock->next;
	}

	//Add new socket to the list
	if(is_sock_new)
	{
		PLATFORM_PRINTF_DEBUG_DETAIL("Adding new socket\n");
		if(power_state != INTERFACE_POWER_STATE_OFF)
		{
			ifaceIndex = getInterfaceIndex(ifname);

			PLATFORM_PRINTF_DEBUG_DETAIL("  Iface Index for - %s  is %d --> OK\n",ifname,ifaceIndex );

			if (ifaceSocketCreate(ifaceIndex, ifname, iface_mac) < 0)
			{
				PLATFORM_PRINTF_DEBUG_ERROR("[PLATFORM] * Socket Creation failed\n");
				return;
			}
		}
	}
}

void create_server_socket() 
{
	int sock_fd;
	sock_fd = get_server_socket();
	if(sock_fd < 0)
	{
		PLATFORM_PRINTF_DEBUG_ERROR("Server Socket creation failed!!\n");
		return;
	}
	else
	{
		addSocketList(sock_fd,0,NULL,NULL,SOCKTYPE_SERVER);
	}
	
}
void create_timer_fd(int interval, int periodic, int sock_type,int arm_interval)
{
	int tfd;
	struct itimerspec ts;
	
	tfd = timerfd_create(CLOCK_MONOTONIC, 0);
	if (tfd == -1) {
		PLATFORM_PRINTF_DEBUG_ERROR("timerfd_create() failed: errno=%d\n", errno);
		return;
	}

	PLATFORM_PRINTF_DEBUG_DETAIL("created timerfd %d\n", tfd);
	
	if(periodic)
	{
		ts.it_interval.tv_sec = interval / 1000;
		ts.it_interval.tv_nsec = (interval % 1000) * 1000000;
		
	}
	else
	{	
		ts.it_interval.tv_sec = 0;
		ts.it_interval.tv_nsec = 0;
	}

	
	if(arm_interval > 0)
	{
		ts.it_value.tv_sec = arm_interval / 1000;
		ts.it_value.tv_nsec = (arm_interval % 1000) * 1000000;
	}
	else
	{
		ts.it_value.tv_sec = interval / 1000;
		ts.it_value.tv_nsec = (interval % 1000) * 1000000;
	}

	 if (timerfd_settime(tfd, 0, &ts, NULL) < 0) {
		PLATFORM_PRINTF_DEBUG_ERROR("timerfd_settime() failed: errno=%d\n", errno);
		close(tfd);
		return;
	}

	PLATFORM_PRINTF_DEBUG_DETAIL("set timerfd time\n");
	addSocketList(tfd,0,NULL,NULL,sock_type);
	
	
}

static void *rawSockPcapLoop(void *queue_id)
{
	struct _pcapCaptureThreadData data;
	struct _timerHandlerThreadData timer_data;
	struct sockaddr_ll recv_addr;
	socklen_t addr_len;
	struct pollfd *fds = NULL;
	
	uint64_t timer_exp = 0;
	char *pkt_data = NULL;
	int fd_index = 0;
	int ret_poll;
	int ret;
	int client_socket = 0;
	static int is_sock_list_changed = 1 ;
	int current_fd_count =0 ;
	int nread     = 0;
	INT8U *server_msg;
	
	int q_id = *((int *)queue_id);
	free(queue_id);
	
	iface1905Socket *sock;

	// Signal the main thread so that it can continue its work
	pthread_mutex_lock(&pcap_filters_mutex);
	pcap_filters_flag = 1;
	pthread_cond_signal(&pcap_filters_cond);
	pthread_mutex_unlock(&pcap_filters_mutex);

	do{

		if(is_sock_list_changed)
		{
			//Create 2 poll fds per interface one for polling the 1905 socket and the other
			//for polling the LLDP socket respectively
			fds = (struct pollfd*) PLATFORM_REALLOC(fds, (sizeof(struct pollfd) * (sock_list_count)));
			if( fds == NULL)
			{
				PLATFORM_PRINTF_DEBUG_ERROR("[PLATFORM] * Poll descriptors Creation failed, Exiting!!\n");
				return NULL;
			}
			
			fd_index = 0;
			sock = raw_sock_list;
			while(sock != NULL)
			{
				if(sock->sock_in_use)
				{
					fds[fd_index].fd = sock->sock_fd;
					fds[fd_index].events = POLLIN;
					fds[fd_index].revents = 0;
					PLATFORM_PRINTF_DEBUG_DETAIL("[PLATFORM] Pcap Desc:0x%x fd:%d index:%d Interface:%s\n", sock->sock_fd, fds[fd_index].fd,fd_index,sock->interface_name);
					fd_index++;
				}
		
				sock = sock->next;
				
			}
			is_sock_list_changed = 0;
			current_fd_count = fd_index;
		}

		
		ret_poll = poll(fds, current_fd_count,-1 );
		if(ret_poll == -1)
		{
			PLATFORM_PRINTF_DEBUG_ERROR("poll returned an error %d, %s\n", errno, strerror(errno));
		}
		else if (ret_poll > 0)
		{
		
			for (fd_index = 0; fd_index < current_fd_count; fd_index++)
			{
				// Check which fd returned
				if (fds[fd_index].revents & (POLLIN | POLLERR | POLLHUP))
				{
					PLATFORM_PRINTF_DEBUG_DETAIL("[PLATFORM] * Recvd POLL on fd %d index %d\n",fds[fd_index].fd,fd_index);
					sock = raw_sock_list;
					while(sock != NULL)
					{
						if(sock->sock_fd == fds[fd_index].fd) 						
						{
							PLATFORM_PRINTF_DEBUG_DETAIL("Poll in on fd:0x%x\n",sock->sock_fd);
							break;
						}
						sock = sock->next;
					}

					if(sock)
					{
						switch(sock->type)
						{
							case SOCKTYPE_1905:
							case SOCKTYPE_LLDP:
							{
								data.interface_name = sock->interface_name;
								data.queue_id = q_id;

								pkt_data = (char *) PLATFORM_MALLOC(ETH_FRAME_LEN);
								addr_len = sizeof(recv_addr);
								ret = recvfrom(sock->sock_fd, pkt_data,ETH_FRAME_LEN,0,(struct sockaddr*)&recv_addr,&addr_len);

								/*A 1905 packet is processed only when
								1.Valid data is received in POLLIN
								2.The packet is not an outgoing packet from my interface
								3.Registration for CMDUs is complete*/
								if( (ret > 0) && (fds[fd_index].revents & POLLIN) && (recv_addr.sll_pkttype != PACKET_OUTGOING) && (is_reg_complete == 1))
								{
									rawSockProcessPacket((u_char*) &data,ret,pkt_data);
								}
								else
								{
									PLATFORM_PRINTF_DEBUG_ERROR("[PLATFORM] Drop packet as conditons for processing were not met\n");
									free(pkt_data);
								}
								break;
							}
							case SOCKTYPE_DISCOVERY_TIMER:
							{
								if(read(sock->sock_fd,&timer_exp,sizeof(uint64_t)) > 0)
								{
									PLATFORM_PRINTF_DEBUG_DETAIL("[PLATFORM] read and clear Discovery timer=%llu\n",timer_exp);
									if(fds[fd_index].revents & POLLIN)
									{
										timer_data.queue_id = q_id;
										timer_data.timer_id = 0;
										timer_data.token = TIMER_TOKEN_DISCOVERY;
										timer_data.periodic = PLATFORM_QUEUE_EVENT_TIMEOUT_PERIODIC;
										process_timer((u_char*)&timer_data);
									}
									else
										PLATFORM_PRINTF_DEBUG_ERROR("[PLATFORM] POLL ERR on fd:%d\n",fds[fd_index].fd);
								}
								
								break;
							}
							case SOCKTYPE_GARBAGE_COLLECT_TIMER:
							{
								if(read(sock->sock_fd,&timer_exp,sizeof(uint64_t)) > 0)
								{
									PLATFORM_PRINTF_DEBUG_DETAIL("[PLATFORM] read and clear garbage collect timer=%llu\n",timer_exp);
									if(fds[fd_index].revents & POLLIN)
									{
										timer_data.queue_id = q_id;
										timer_data.timer_id = 0;
										timer_data.token = TIMER_TOKEN_GARBAGE_COLLECTOR;
										timer_data.periodic = PLATFORM_QUEUE_EVENT_TIMEOUT_PERIODIC;
										process_timer((u_char*)&timer_data);
									}
									else
										PLATFORM_PRINTF_DEBUG_ERROR("[PLATFORM] POLL ERR on fd:%d\n",fds[fd_index].fd);
								}		
								break;
							}
							case SOCKTYPE_SERVER:
							{
						
								PLATFORM_PRINTF_DEBUG_DETAIL("[PLATFORM] recvd msg from server socket!!\n");

								client_socket = handleNewClientConnection(fds[fd_index].fd);
								if(client_socket >= 0)
								{
									addSocketList(client_socket,0,NULL,NULL,SOCKTYPE_SERVER);
									is_sock_list_changed = 1;
									
								}
								else
								{
									// Check to see if client wants to close connection
									ioctl(fds[fd_index].fd, FIONREAD, &nread);
									PLATFORM_PRINTF_DEBUG_DETAIL("%s ioctl nread %d \n", __FUNCTION__,nread);
									if (0 == nread) 
									{
										shutdown(fds[fd_index].fd,SHUT_RDWR);
										close(fds[fd_index].fd);
										fds[fd_index].events = 0;
										fds[fd_index].fd = -1;
										sock->sock_in_use = 0;
										handleCloseServerConnection(fds[fd_index].fd,fd_index);
										is_sock_list_changed =1;
									}
									else
									{
										register_data_t reg_data;
										lib1905_event_notification event;

										server_msg = (INT8U*)calloc(1,MAX(sizeof(register_data_t)+1, sizeof(event)+1));

										ret = recv(fds[fd_index].fd ,server_msg,(sizeof(register_data_t)+1),0); 										
										if ( (ret > 0) && (fds[fd_index].revents & POLLIN))
										{
											if(server_msg[0] == LIB1905_REGISTER_MSGTYPE)
											{
												PLATFORM_MEMCPY(&reg_data,&server_msg[1],sizeof(reg_data));
												handleServerMessage(fds[fd_index].fd,reg_data);
												PLATFORM_PRINTF_DEBUG_DETAIL("MAP message registration complete\n");
												is_reg_complete = 1;
												int64_t topo_dis_interval = ((atoi(al_entity_topology_discovery_env_interval)) * 1000);
												create_timer_fd(topo_dis_interval,1,SOCKTYPE_DISCOVERY_TIMER,100);
												is_sock_list_changed = 1;
											}
											else if(server_msg[0] == LIB1905_NOTIFY_MSGTYPE)
											{												
												PLATFORM_PRINTF_DEBUG_DETAIL("Received 1905 notification");
												PLATFORM_MEMCPY(&event,&server_msg[1],sizeof(event));												
												PLATFORM_PRINTF_DEBUG_DETAIL("for iface %s, event %d \n",event.interface_name, event.event);
												/* It's a new interface, update 1905 datamodel with new interface details */
												if(LIB_1905_NEW_IF_CREATED_EVENT == event.event) {												
													PLATFORM_PRINTF_DEBUG_DETAIL("New interface %s created\n",event.interface_name);													
												} else if (LIB_1905_IF_UP_EVENT == event.event) {
													/* interface up event, create socket on the interface for 1905 messages */
													update1905RawSockets(event.interface_name);
													is_sock_list_changed = 1;
												} else if (LIB_1905_IF_DOWN_EVENT == event.event) {
													/* interface down event, close and remove socket on the interface */
													if(ifaceSocketRemove(event.interface_name)) {
														PLATFORM_PRINTF_DEBUG_ERROR("Failed to close and remove socket for %s \n", event.interface_name);
													}
													is_sock_list_changed = 1;
											    }
											}
										}
										free(server_msg);
									}
								}
								break;
							}
						}
					}
					else 
					{
						PLATFORM_PRINTF_DEBUG_ERROR("POLL returned from an unkown fd:%d\n",fds[fd_index].fd);
						int i =0;
						for(i=0;i<current_fd_count;i++)
						{
							PLATFORM_PRINTF_DEBUG_DETAIL("[PLATFORM] Pcap Desc:0x%x fd:%d index:%d \n", fds[i].fd, fds[i].fd,i);
						}
						continue;
					}
				}
			}
		}
	}while (1);
	PLATFORM_PRINTF_DEBUG_ERROR("[PLATFORM] *Pcap thread* Exiting thread, Error!!\n");
	return NULL;
}

#endif

static void *_pcapLoopThread(void *p)
{
    // This function will loop forever in the "pcap_loop()" function, which
    // generates a callback to "_pcapProcessPacket()" every time a new 1905
    // packet arrives

    char errbuf[PCAP_ERRBUF_SIZE];
    pcap_t *pcap_descriptor;

    struct _pcapCaptureThreadData *aux;

    char pcap_filter_expression[255] = "";
    struct bpf_program fcode;

    if (NULL == p)
    {
        // 'p' must point to a valid 'struct _pcapCaptureThreadData'
        //
        PLATFORM_PRINTF_DEBUG_ERROR("[PLATFORM] *Pcap thread* Invalid arguments in _pcapLoopThread()\n");

        pthread_mutex_lock(&pcap_filters_mutex);
        pcap_filters_flag = 1;
        pthread_cond_signal(&pcap_filters_cond);
        pthread_mutex_unlock(&pcap_filters_mutex);

        return NULL;
    }

    aux = (struct _pcapCaptureThreadData *)p;

    // Open the interface in pcap.
    // The third argument of 'pcap_open_live()' is set to '1' so that the
    // interface is configured in 'monitor mode'. This is needed because we are
    // not only interested in receiving packets addressed to the interface
    // MAC address (or broadcast), but also those packets addressed to the
    // "non-existent" (virtual?) AL MAC address of the AL entity (contained in
    // 'aux->al_mac_address')
    //
    pcap_descriptor = pcap_open_live(aux->interface_name, MAX_NETWORK_SEGMENT_SIZE, 1, 512, errbuf);
    if (NULL == pcap_descriptor)
    {
        // Could not configure interface to capture 1905 packets
        //
        PLATFORM_PRINTF_DEBUG_ERROR("[PLATFORM] *Pcap thread* Error opening interface %s\n", aux->interface_name);

        pthread_mutex_lock(&pcap_filters_mutex);
        pcap_filters_flag = 1;
        pthread_cond_signal(&pcap_filters_cond);
        pthread_mutex_unlock(&pcap_filters_mutex);

        return NULL;
    }

    // If we started capturing now, we would receive *all* packets. This means
    // *all* packets (even those that have nothing to do with 1905) would be
    // copied from kernel space into user space (which is a very costly
    // operation).
    //
    // To mitigate this effect (which takes place when enabling 'monitor mode'
    // on an interface), 'pcap' let's us define "filtering rules" that take
    // place in kernel space, thus limiting the amount of copies that need to
    // be done to user space.
    //
    // Here we are going to configure a filter that only lets certain types of
    // packets to get through. In particular those that meet any of these
    // requirements:
    //
    //   1. Have ethertype == ETHERTYPE_1905 *and* are addressed to either the
    //      interface MAC address, the AL MAC address or the broadcast AL MAC
    //      address
    //
    //   2. Have ethertype == ETHERTYPE_LLDP *and* are addressed to the special
    //      LLDP nearest bridge multicast MAC address 
    //      
    snprintf(
              pcap_filter_expression,
              sizeof(pcap_filter_expression),
//              "not ether src %02x:%02x:%02x:%02x:%02x:%02x "
//              " and "
//              "not ether src %02x:%02x:%02x:%02x:%02x:%02x "
//              " and "
              "((ether proto 0x%04x and (ether dst %02x:%02x:%02x:%02x:%02x:%02x or ether dst %02x:%02x:%02x:%02x:%02x:%02x or ether dst %02x:%02x:%02x:%02x:%02x:%02x))"
              " or "
              "(ether proto 0x%04x and ether dst %02x:%02x:%02x:%02x:%02x:%02x))",
//              aux->interface_mac_address[0], aux->interface_mac_address[1], aux->interface_mac_address[2], aux->interface_mac_address[3], aux->interface_mac_address[4], aux->interface_mac_address[5],
//              aux->al_mac_address[0],        aux->al_mac_address[1],        aux->al_mac_address[2],        aux->al_mac_address[3],        aux->al_mac_address[4],        aux->al_mac_address[5],
              ETHERTYPE_1905,
              aux->interface_mac_address[0], aux->interface_mac_address[1], aux->interface_mac_address[2], aux->interface_mac_address[3], aux->interface_mac_address[4], aux->interface_mac_address[5],
              MCAST_1905_B0,                 MCAST_1905_B1,                 MCAST_1905_B2,                 MCAST_1905_B3,                 MCAST_1905_B4,                 MCAST_1905_B5,
              aux->al_mac_address[0],        aux->al_mac_address[1],        aux->al_mac_address[2],        aux->al_mac_address[3],        aux->al_mac_address[4],        aux->al_mac_address[5],
              ETHERTYPE_LLDP,
              MCAST_LLDP_B0,                 MCAST_LLDP_B1,                 MCAST_LLDP_B2,                 MCAST_LLDP_B3,                 MCAST_LLDP_B4,                 MCAST_LLDP_B5
            );

    PLATFORM_PRINTF_DEBUG_DETAIL("[PLATFORM] *Pcap thread* SETTING DIRECTION pcap_setdirection %s \n", aux->interface_name);
    if (pcap_setdirection(pcap_descriptor, PCAP_D_IN)) {
        PLATFORM_PRINTF_DEBUG_ERROR("[PLATFORM] *Pcap thread* DIRECTION pcap_setdirection failed %s \n", aux->interface_name);
    }


    if (pcap_compile(pcap_descriptor, &fcode, pcap_filter_expression, 1, 0xffffff) < 0)
    {
        PLATFORM_PRINTF_DEBUG_ERROR("[PLATFORM] *Pcap thread* Cannot compile pcap filter (interface %s)\n", aux->interface_name);

        pthread_mutex_lock(&pcap_filters_mutex);
        pcap_filters_flag = 1;
        pthread_cond_signal(&pcap_filters_cond);
        pthread_mutex_unlock(&pcap_filters_mutex);

        return NULL;
    }

    PLATFORM_PRINTF_DEBUG_DETAIL("[PLATFORM] *Pcap thread* Installing pcap filter on interface %s: %s\n", aux->interface_name, pcap_filter_expression);
    if (pcap_setfilter(pcap_descriptor, &fcode) < 0)
    {
        PLATFORM_PRINTF_DEBUG_ERROR("[PLATFORM] *Pcap thread* Cannot attach pcap filter to interface %s\n", aux->interface_name);

        pthread_mutex_lock(&pcap_filters_mutex);
        pcap_filters_flag = 1;
        pthread_cond_signal(&pcap_filters_cond);
        pthread_mutex_unlock(&pcap_filters_mutex);

        return NULL;
    }

    // Signal the main thread so that it can continue its work
    //
    pthread_mutex_lock(&pcap_filters_mutex);
    pcap_filters_flag = 1;
    pthread_cond_signal(&pcap_filters_cond);
    pthread_mutex_unlock(&pcap_filters_mutex);

    // Start the pcap loop. This goes on forever...
    // Everytime a new packet (that meets the filtering rules defined above)
    // arrives, the '_pcapProcessPacket()' callback is executed
    //
    pcap_loop(pcap_descriptor, -1, _pcapProcessPacket, (u_char *)aux);

    // This point should never be reached
    //
    PLATFORM_PRINTF_DEBUG_ERROR("[PLATFORM] *Pcap thread* Exiting thread (interface %s)\n", aux->interface_name);
    free(aux);
    return NULL;
}


// *********** Timers stuff ****************************************************

// We use the POSIX timers API to implement PLATFORM timers
// It works like this:
//
//   - When the PLATFORM API user calls "PLATFORM_REGISTER_QUEUE_EVENT()" with
//     'PLATFORM_QUEUE_EVENT_TIMEOUT*', a new POSIX timer is created.
//
//   - When the timer expires, the POSIX API creates a thread for us and makes
//     it run function '_timerHandler()'
//
//   - '_timerHandler()' simply deletes (or reprograms, depending on the type
//     of timer) the timer and sends a message to a queue so that the user can
//     later be aware of the timer expiration with a call to
//     "PLATFORM_QUEUE_READ()"



static void _timerHandler(union sigval s)
{
    struct _timerHandlerThreadData *aux;

    INT8U   message[3+4];
    INT16U  packet_len;
    INT8U   packet_len_msb;
    INT8U   packet_len_lsb;
    INT8U   token_msb;
    INT8U   token_2nd_msb;
    INT8U   token_3rd_msb;
    INT8U   token_lsb;

    aux = (struct _timerHandlerThreadData *)s.sival_ptr;

    // In order to build the message that will be inserted into the queue, we
    // need to follow the "message format" defines in the documentation of
    // function 'PLATFORM_REGISTER_QUEUE_EVENT()'
    //
    packet_len = 4;

#if _HOST_IS_LITTLE_ENDIAN_ == 1
    packet_len_msb = *(((INT8U *)&packet_len)+1);
    packet_len_lsb = *(((INT8U *)&packet_len)+0);

    token_msb      = *(((INT8U *)&aux->token)+3);
    token_2nd_msb  = *(((INT8U *)&aux->token)+2);
    token_3rd_msb  = *(((INT8U *)&aux->token)+1);
    token_lsb      = *(((INT8U *)&aux->token)+0);
#else
    packet_len_msb = *(((INT8U *)&packet_len)+0);
    packet_len_lsb = *(((INT8U *)&packet_len)+1);

    token_msb     = *(((INT8U *)&aux->token)+0);
    token_2nd_msb = *(((INT8U *)&aux->token)+1);
    token_3rd_msb = *(((INT8U *)&aux->token)+2);
    token_lsb     = *(((INT8U *)&aux->token)+3);
#endif

    message[0] = 1 == aux->periodic ? PLATFORM_QUEUE_EVENT_TIMEOUT_PERIODIC : PLATFORM_QUEUE_EVENT_TIMEOUT;
    message[1] = packet_len_msb;
    message[2] = packet_len_lsb;
    message[3] = token_msb;
    message[4] = token_2nd_msb;
    message[5] = token_3rd_msb;
    message[6] = token_lsb;

    PLATFORM_PRINTF_DEBUG_DETAIL("[PLATFORM] *Timer handler* Sending %d bytes to queue (%02x, %02x, %02x, ...)\n", 3+packet_len, message[0], message[1], message[2]);

#ifdef MULTIAP	
	if(is_reg_complete == 1)
	{
#endif
	    if (0 == sendMessageToAlQueue(aux->queue_id, message, 3+packet_len))
	    {
	        PLATFORM_PRINTF_DEBUG_ERROR("[PLATFORM] *Timer handler* Error sending message to queue from _timerHandler()\n");
	    }
#ifdef MULTIAP
	}
	else
	{
		PLATFORM_PRINTF_DEBUG_ERROR("Reg not complete\n");
		free(aux);
		return;
	}
#endif

    if (1 == aux->periodic)
    {
        // Periodic timer are automatically re-armed. We don't need to do
        // anything
    }
    else
    {
        // Delete the asociater timer
        //
        timer_delete(aux->timer_id);

        // Free 'struct _timerHandlerThreadData', as we don't need it any more
        //
        free(aux);
    }

    return;
}
 

// *********** Push button stuff ***********************************************

// Pressing the button can be simulated by "touching" (ie. updating the
// timestamp) the following tmp file
//
#define PUSH_BUTTON_VIRTUAL_FILENAME  "/tmp/virtual_push_button"

// For those platforms with a physical buttons attached to a GPIO, we need to
// know the actual GPIO number (as seen by the Linux kernel) to use.
//
//     NOTE: "PUSH_BUTTON_GPIO_NUMBER" is a string, not a number. It will later
//     be used in a string context, thus the "" are needed.
//     It can take the string representation of a number (ex: "26") or the
//     special value "disable", meaning we don't have GPIO support.
//
#define PUSH_BUTTON_GPIO_NUMBER              "disable" //"26"

#define PUSH_BUTTON_GPIO_EXPORT_FILENAME     "/sys/class/gpio/export"
#define PUSH_BUTTON_GPIO_DIRECTION_FILENAME  "/sys/class/gpio/gpio"PUSH_BUTTON_GPIO_NUMBER"/direction"
#define PUSH_BUTTON_GPIO_VALUE_FILENAME      "/sys/class/gpio/gpio"PUSH_BUTTON_GPIO_NUMBER"/direction"

// The only information that needs to be sent to the new thread is the "queue
// id" to later post messages to the queue.
//
struct _pushButtonThreadData
{
    INT8U     queue_id;
};

static void *_pushButtonThread(void *p)
{
    // In this implementation we will send the "push button" configuration
    // event message to the queue when either:
    //
    //   a) The user presses a physical button associated to a GPIO whose number
    //      is "PUSH_BUTTON_GPIO_NUMBER" (ie. it is exported by the linux kernel
    //      in "/sys/class/gpio/gpioXXX", where "XXX" is
    //      "PUSH_BUTTON_GPIO_NUMBER")
    //
    //   b) The user updates the timestamp of a tmp file called
    //      "PUSH_BUTTON_VIRTUAL_FILENAME".
    //      This is useful for debugging and for supporting the "push button"
    //      mechanism in those platforms without a physical button.
    //
    // This thread will simply wait for activity on any of those two file
    // descriptors and then send the "push button" configuration event to the
    // AL queue.
    // How is this done?
    //
    //   1. Configure the GPIO as input.
    //   2. Create an "inotify" watch on the tmp file.
    //   3. Use "poll()" to wait for either changes in the value of the GPIO or
    //      timestamp updates in the tmp file.

    int    gpio_enabled;

    FILE  *fd_gpio;
    FILE  *fd_tmp;

    int  fdraw_gpio;
    int  fdraw_tmp;

    struct pollfd fdset[2];

    INT8U queue_id;

    queue_id = ((struct _pushButtonThreadData *)p)->queue_id;;

    if (0 != strcmp(PUSH_BUTTON_GPIO_NUMBER, "disable"))
    {
        gpio_enabled = 1;
    }
    else
    {
        gpio_enabled = 0;
    }

    // First of all, prepare the GPIO kernel descriptor for "reading"...
    //
    if (gpio_enabled)
    {

        // 1. Write the number of the GPIO where the physical button is
        //    connected to file "/sys/class/gpio/export".
        //    This will instruct the Linux kernel to create a folder named
        //    "/sys/class/gpio/gpioXXX" that we can later use to read the GPIO
        //    level.
        //
        if (NULL == (fd_gpio = fopen(PUSH_BUTTON_GPIO_EXPORT_FILENAME, "w")))
        {
            PLATFORM_PRINTF_DEBUG_ERROR("[PLATFORM] *Push button thread* Error opening GPIO fd %s\n", PUSH_BUTTON_GPIO_EXPORT_FILENAME);
            return NULL;
        }
        if (0 == fwrite(PUSH_BUTTON_GPIO_NUMBER, 1, strlen(PUSH_BUTTON_GPIO_NUMBER), fd_gpio))
        {
            PLATFORM_PRINTF_DEBUG_ERROR("[PLATFORM] *Push button thread* Error writing '"PUSH_BUTTON_GPIO_NUMBER"' to %s\n", PUSH_BUTTON_GPIO_EXPORT_FILENAME);
            fclose(fd_gpio);
            return NULL;
        }
        fclose(fd_gpio);

        // 2. Write "in" to file "/sys/class/gpio/gpioXXX/direction" to tell the
        //    kernel that this is an "input" GPIO (ie. we are only going to
        //    read -and not write- its value).

        if (NULL == (fd_gpio = fopen(PUSH_BUTTON_GPIO_DIRECTION_FILENAME, "w")))
        {
            PLATFORM_PRINTF_DEBUG_ERROR("[PLATFORM] *Push button thread* Error opening GPIO fd %s\n", PUSH_BUTTON_GPIO_DIRECTION_FILENAME);
            return NULL;
        }
        if (0 == fwrite("in", 1, strlen("in"), fd_gpio))
        {
            PLATFORM_PRINTF_DEBUG_ERROR("[PLATFORM] *Push button thread* Error writing 'in' to %s\n", PUSH_BUTTON_GPIO_DIRECTION_FILENAME);
            fclose(fd_gpio);
            return NULL;
        }
        fclose(fd_gpio);
    }
    
    // ... and then re-open the GPIO file descriptors for reading in "raw"
    // (ie "open" instead of "fopen") mode.
    //
    if (gpio_enabled)
    {
        if (-1  == (fdraw_gpio = open(PUSH_BUTTON_GPIO_VALUE_FILENAME, O_RDONLY | O_NONBLOCK)))
        {
            PLATFORM_PRINTF_DEBUG_ERROR("[PLATFORM] *Push button thread* Error opening GPIO fd %s\n", PUSH_BUTTON_GPIO_VALUE_FILENAME);
        }
    }

    // Next, regarding the "virtual" button, first create the "tmp" file in
    // case it does not already exist...
    //
    if (NULL == (fd_tmp = fopen(PUSH_BUTTON_VIRTUAL_FILENAME, "w+")))
    {
        PLATFORM_PRINTF_DEBUG_ERROR("[PLATFORM] *Push button thread* Could not create tmp file %s\n", PUSH_BUTTON_VIRTUAL_FILENAME);
        return NULL;
    }
    fclose(fd_tmp);

    // ...and then add a "watch" that triggers when its timestamp changes (ie.
    // when someone does a "touch" of the file or writes to it, for example).
    //
    if (-1 == (fdraw_tmp = inotify_init()))
    {
        PLATFORM_PRINTF_DEBUG_ERROR("[PLATFORM] *Push button thread* inotify_init() returned with errno=%d (%s)\n", errno, strerror(errno));
        return NULL;
    }
    if (-1 == inotify_add_watch(fdraw_tmp, PUSH_BUTTON_VIRTUAL_FILENAME, IN_ATTRIB))
    {
        PLATFORM_PRINTF_DEBUG_ERROR("[PLATFORM] *Push button thread* inotify_add_watch() returned with errno=%d (%s)\n", errno, strerror(errno));
        return NULL;
    }

    // At this point we have two file descriptors ("fdraw_gpio" and "fdraw_tmp")
    // that we can monitor with a call to "poll()"
    //
    while(1)
    {
        int   nfds;
        INT8U button_pressed;

        memset((void*)fdset, 0, sizeof(fdset));

        fdset[0].fd     = fdraw_tmp;
        fdset[0].events = POLLIN;
        nfds            = 1;

        if (gpio_enabled)
        {
            fdset[1].fd     = fdraw_gpio;
            fdset[1].events = POLLPRI;
            nfds            = 2;
        }

        // The thread will block here (forever, timeout = -1), until there is
        // a change in one of the two file descriptors ("changes" in the "tmp"
        // file fd are cause by "attribute" changes -such as the timestamp-,
        // while "changes" in the GPIO fd are caused by a value change in the
        // GPIO value).
        //
        if (0 > poll(fdset, nfds, -1))
        {
            PLATFORM_PRINTF_DEBUG_ERROR("[PLATFORM] *Push button thread* poll() returned with errno=%d (%s)\n", errno, strerror(errno));
            break;
        }

        button_pressed = 0;

        if (fdset[0].revents & POLLIN)
        {
            struct inotify_event event;

            PLATFORM_PRINTF_DEBUG_DETAIL("[PLATFORM] *Push button thread* Virtual button has been pressed!\n");
            button_pressed = 1;

            // We must "read()" from the "tmp" fd to "consume" the event, or
            // else the next call to "poll() won't block.
            //
            read(fdraw_tmp, &event, sizeof(event));
        }
        else if (gpio_enabled && (fdset[1].revents & POLLPRI))
        {
            char buf[3];

            if (-1 == read(fdset[1].fd, buf, 3))
            {
                PLATFORM_PRINTF_DEBUG_ERROR("[PLATFORM] *Push button thread* read() returned with errno=%d (%s)\n", errno, strerror(errno));
                continue;
            }

            if (buf[0] == '1')
            {
                PLATFORM_PRINTF_DEBUG_DETAIL("[PLATFORM] *Push button thread* Physical button has been pressed!\n");
                button_pressed = 1;
            }
        }

        if (1 == button_pressed)
        {
            INT8U   message[3];

            message[0] = PLATFORM_QUEUE_EVENT_PUSH_BUTTON;
            message[1] = 0x0;
            message[2] = 0x0;

            PLATFORM_PRINTF_DEBUG_DETAIL("[PLATFORM] *Push button thread* Sending 3 bytes to queue (0x%02x, 0x%02x, 0x%02x)\n", message[0], message[1], message[2]);

            if (0 == sendMessageToAlQueue(queue_id, message, 3))
            {
                PLATFORM_PRINTF_DEBUG_ERROR("[PLATFORM] *Push button thread* Error sending message to queue from _pushButtonThread()\n");
            }
        }
    }

    // Close file descriptors and exit
    //
    if (gpio_enabled)
    {
        fclose(fd_gpio);
    }

    PLATFORM_PRINTF_DEBUG_DETAIL("[PLATFORM] *Push button thread* Exiting...\n");

    free(p);
    return NULL;
}

// *********** Topology change notification stuff ******************************

// The platform notifies the 1905 that a topology change has just took place
// by "touching" the following tmp file
//
#define TOPOLOGY_CHANGE_NOTIFICATION_FILENAME  "/tmp/topology_change"

// The only information that needs to be sent to the new thread is the "queue
// id" to later post messages to the queue.
//
struct _topologyMonitorThreadData
{
    INT8U     queue_id;
};

static void *_topologyMonitorThread(void *p)
{
    FILE  *fd_tmp;

    int  fdraw_tmp;

    struct pollfd fdset[2];

    INT8U  queue_id;

    queue_id = ((struct _topologyMonitorThreadData *)p)->queue_id;

    // Regarding the "virtual" notification system, first create the "tmp" file
    // in case it does not already exist...
    //
    if (NULL == (fd_tmp = fopen(TOPOLOGY_CHANGE_NOTIFICATION_FILENAME, "w+")))
    {
        PLATFORM_PRINTF_DEBUG_ERROR("[PLATFORM] *Topology change monitor thread* Could not create tmp file %s\n", TOPOLOGY_CHANGE_NOTIFICATION_FILENAME);
        return NULL;
    }
    fclose(fd_tmp);

    // ...and then add a "watch" that triggers when its timestamp changes (ie.
    // when someone does a "touch" of the file or writes to it, for example).
    //
    if (-1 == (fdraw_tmp = inotify_init()))
    {
        PLATFORM_PRINTF_DEBUG_ERROR("[PLATFORM] *Push button thread* inotify_init() returned with errno=%d (%s)\n", errno, strerror(errno));
        return NULL;
    }
    if (-1 == inotify_add_watch(fdraw_tmp, TOPOLOGY_CHANGE_NOTIFICATION_FILENAME, IN_ATTRIB))
    {
        PLATFORM_PRINTF_DEBUG_ERROR("[PLATFORM] *Push button thread* inotify_add_watch() returned with errno=%d (%s)\n", errno, strerror(errno));
        return NULL;
    }
    
    while (1)
    {
        int   nfds;
        INT8U notification_activated;

        memset((void*)fdset, 0, sizeof(fdset));

        fdset[0].fd     = fdraw_tmp;
        fdset[0].events = POLLIN;
        nfds            = 1;

        // TODO: Other fd's to detect topoly changes would be initialized here.
        // One good idea would be to use a NETLINK socket that is notified by
        // the Linux kernel when network "stuff" (routes, IPs, ...) change.
        //
        //fdset[0].fd     = ...;
        //fdset[0].events = POLLIN;
        //nfds            = 2;

        // The thread will block here (forever, timeout = -1), until there is
        // a change in one of the previous file descriptors .
        //
        if (0 > poll(fdset, nfds, -1))
        {
            PLATFORM_PRINTF_DEBUG_ERROR("[PLATFORM] *Topology change monitor thread* poll() returned with errno=%d (%s)\n", errno, strerror(errno));
            break;
        }

        notification_activated = 0;

        if (fdset[0].revents & POLLIN)
        {
            struct inotify_event event;

            PLATFORM_PRINTF_DEBUG_DETAIL("[PLATFORM] *Topology change monitor thread* Virtual notification has been activated!\n");
            notification_activated = 1;

            // We must "read()" from the "tmp" fd to "consume" the event, or
            // else the next call to "poll() won't block.
            //
            read(fdraw_tmp, &event, sizeof(event));
        }

        if (1 == notification_activated)
        {
            INT8U  message[3];

            message[0] = PLATFORM_QUEUE_EVENT_TOPOLOGY_CHANGE_NOTIFICATION;
            message[1] = 0x0;
            message[2] = 0x0;

            PLATFORM_PRINTF_DEBUG_DETAIL("[PLATFORM] *Topology change monitor thread* Sending 3 bytes to queue (0x%02x, 0x%02x, 0x%02x)\n", message[0], message[1], message[2]);

            if (0 == sendMessageToAlQueue(queue_id, message, 3))
            {
                PLATFORM_PRINTF_DEBUG_ERROR("[PLATFORM] *Topology change monitor thread* Error sending message to queue from _pushButtonThread()\n");
            }
        }
    }

    PLATFORM_PRINTF_DEBUG_DETAIL("[PLATFORM] *Topology change monitor thread* Exiting...\n");

    free(p);
    return NULL;
}


////////////////////////////////////////////////////////////////////////////////
// Internal API: to be used by other platform-specific files (functions
// declaration is found in "./platform_os_priv.h")
////////////////////////////////////////////////////////////////////////////////

INT8U sendMessageToAlQueue(INT8U queue_id, INT8U *message, INT16U message_len)
{
#ifdef PLATFORM_ABSTRACTION
    int retVal = kCpe_NoErr;
    tQueueEvent *pEvent = NULL;
    retVal = queue_EventCreate ( &pEvent ,message_len) ;

    if ( retVal != kCpe_NoErr || !pEvent )
       return 0;

    PLATFORM_MEMCPY(pEvent->data,message,message_len);

    retVal = queue_AddEvent(queues_id[queue_id],pEvent);

    if ( retVal != kCpe_NoErr )
    {
       queue_EventDestroy(pEvent);
       return 0;
    }
    return 1;
#else
    mqd_t   mqdes;

    mqdes = queues_id[queue_id];
    if ((mqd_t) -1 == mqdes)
    {
        PLATFORM_PRINTF_DEBUG_ERROR("[PLATFORM] Invalid queue ID\n");
        return 0;
    }

    if (NULL == message)
    {
        PLATFORM_PRINTF_DEBUG_ERROR("[PLATFORM] Invalid message\n");
        return 0;
    }

    if (0 !=  mq_send(mqdes, (const char *)message, message_len, 0))
    {
        PLATFORM_PRINTF_DEBUG_ERROR("[PLATFORM] mq_send('%d') returned with errno=%d (%s)\n", queue_id, errno, strerror(errno));
        return 0;
    }

    return 1;
#endif
}


////////////////////////////////////////////////////////////////////////////////
// Platform API: Device information functions to be used by platform-independent
// files (functions declarations are  found in "../interfaces/platform_os.h)
////////////////////////////////////////////////////////////////////////////////

struct deviceInfo *PLATFORM_GET_DEVICE_INFO(void)
{
    // TODO: Retrieve real data from OS

    static struct deviceInfo x = 
    {
        .friendly_name      = "Kitchen ice cream dispatcher",
        .manufacturer_name  = "Megacorp S.A.",
        .manufacturer_model = "Ice cream dispatcher X-2000",

        .control_url        = "http://192.168.10.44",
    };

    return &x;
}


////////////////////////////////////////////////////////////////////////////////
// Platform API: IPC related functions to be used by platform-independent
// files (functions declarations are  found in "../interfaces/platform_os.h)
////////////////////////////////////////////////////////////////////////////////

INT8U PLATFORM_CREATE_QUEUE(const char *name)
{
#ifdef PLATFORM_ABSTRACTION
    tQueue* q = NULL;
    int retVal = kCpe_NoErr;
    int i;
    if ( !name )
        return 0;

    pthread_mutex_lock(&queues_id_mutex);
    for (i=1; i<MAX_QUEUE_IDS; i++)  // Note: "0" is not a valid "queue_id"
    {                                // according to the documentation of
        if (NULL == queues_id[i])      // "PLATFORM_CREATE_QUEUE()". That's why we
        {                            // skip it
            // Empty slot found.
            //
            break;
        }
    }
    if (MAX_QUEUE_IDS == i)
    {
        // No more queue id slots available
        //
        pthread_mutex_unlock(&queues_id_mutex);
        return 0;
    }

    retVal = queue_Create(&q,name);
    if ( (retVal == kCpe_NoErr) && q  )
    {
        queues_id[i] = q;
    }

    pthread_mutex_unlock(&queues_id_mutex);

    return i;

#else
    mqd_t          mqdes;
    struct mq_attr attr;
    int            i;
    char           name_tmp[20];

    pthread_mutex_lock(&queues_id_mutex);

    for (i=1; i<MAX_QUEUE_IDS; i++)  // Note: "0" is not a valid "queue_id"
    {                                // according to the documentation of
        if (-1 == queues_id[i])      // "PLATFORM_CREATE_QUEUE()". That's why we
        {                            // skip it
            // Empty slot found.
            //
            break;
        }
    }
    if (MAX_QUEUE_IDS == i)
    {
        // No more queue id slots available
        //
        pthread_mutex_unlock(&queues_id_mutex);
        return 0;
    }

    if (!name)
    {
        name_tmp[0] = 0x0;
        sprintf(name_tmp, "/queue_%03d", i);
        name = name_tmp;
    }
    else if (name[0] != '/')
    {
        snprintf(name_tmp, 20, "/%s", name);
        name = name_tmp;
    }

    // If a queue with this name already existed (maybe from a previous
    // session), destroy and re-create it
    //
    mq_unlink(name);
       
    attr.mq_flags   = 0;  
    attr.mq_maxmsg  = 100;  
    attr.mq_curmsgs = 0; 
    attr.mq_msgsize = MAX_NETWORK_SEGMENT_SIZE+3;
      //
      // NOTE: The biggest value in the queue is going to be a message from the
      // "pcap" event, which is MAX_NETWORK_SEGMENT_SIZE+3 bytes long.
      // The "PLATFORM_CREATE_QUEUE()" documentation mentions 
      
    if ((mqd_t) -1 == (mqdes = mq_open(name, O_RDWR | O_CREAT, 0666, &attr)))
    {
        // Could not create queue
        //
        pthread_mutex_unlock(&queues_id_mutex);
        PLATFORM_PRINTF_DEBUG_ERROR("[PLATFORM] mq_open('%s') returned with errno=%d (%s)\n", name, errno, strerror(errno));
        return 0;
    }

    queues_id[i] = mqdes;

    pthread_mutex_unlock(&queues_id_mutex);
    return i;
#endif
}

INT8U PLATFORM_REGISTER_QUEUE_EVENT(INT8U queue_id, INT8U event_type, void *data)
{
    switch (event_type)
    {
#ifdef USE_RAW_SOCK
			case PLATFORM_QUEUE_EVENT_NEW_1905_PACKET_ALL_IFACE:
			{
				pthread_t thread;
				int *q_id = malloc(sizeof(*q_id));

				pthread_mutex_lock(&pcap_filters_mutex);
				pcap_filters_flag = 0;
				pthread_mutex_unlock(&pcap_filters_mutex);

				create1905Sockets();
				create_server_socket();
				
				*q_id = queue_id;
				pthread_create(&thread, NULL, rawSockPcapLoop, q_id);

				pthread_mutex_lock(&pcap_filters_mutex);
				while (0 == pcap_filters_flag)
				{
					pthread_cond_wait(&pcap_filters_cond, &pcap_filters_mutex);
				}
				pthread_mutex_unlock(&pcap_filters_mutex);

				break;
			}
#endif
        case PLATFORM_QUEUE_EVENT_NEW_1905_PACKET:
        {
            pthread_t                         thread;
            struct event1905Packet           *p1;
            struct _pcapCaptureThreadData    *p2;

            if (NULL == data)
            {
                // 'data' must contain a pointer to a 'struct event1905Packet'
                //
                return 0;
            }

            p1 = (struct event1905Packet *)data;

            p2 = (struct _pcapCaptureThreadData *)malloc(sizeof(struct _pcapCaptureThreadData));
            if (NULL == p2)
            {
                // Out of memory
                //
                return 0;
            }

                   p2->queue_id              = queue_id;
                   p2->interface_name        = strdup(p1->interface_name);
            memcpy(p2->interface_mac_address,         p1->interface_mac_address, 6);
            memcpy(p2->al_mac_address,                p1->al_mac_address,        6);

            pthread_mutex_lock(&pcap_filters_mutex);
            pcap_filters_flag = 0;
            pthread_mutex_unlock(&pcap_filters_mutex);

            pthread_create(&thread, NULL, _pcapLoopThread, (void *)p2);

            // While it is not strictly needed, we will now wait until the PCAP
            // thread registers the needed capture filters.
            //
            pthread_mutex_lock(&pcap_filters_mutex);
            while (0 == pcap_filters_flag)
            {
                pthread_cond_wait(&pcap_filters_cond, &pcap_filters_mutex);
            }
            pthread_mutex_unlock(&pcap_filters_mutex);

            // NOTE:
            //   The memory allocated by "p2" will be lost forever at this
            //   point (well... until the application exits, that is).
            //   This is considered acceptable.

            break;
        }

        case PLATFORM_QUEUE_EVENT_NEW_ALME_MESSAGE:
        {
            // The AL entity is telling us that it is capable of processing ALME
            // messages and that it wants to receive ALME messages on the
            // provided queue.
            // 
            // In our platform-dependent implementation, we have decided that
            // ALME messages are going to be received on a dedicated thread
            // that runs a TCP server.
            //
            // What we are going to do now is:
            //
            //   1) Create that thread
            //
            //   2) Tell it that everytime a new packet containing ALME
            //      commands arrives on its socket it should forward the
            //      payload to this queue.
            //
            pthread_t                thread;
            struct almeServerThreadData  *p;

            p = (struct almeServerThreadData *)malloc(sizeof(struct almeServerThreadData));
            if (NULL == p)
            {
                // Out of memory
                //
                return 0;
            }
            p->queue_id = queue_id;

            pthread_create(&thread, NULL, almeServerThread, (void *)p);

            break;
        }

        case PLATFORM_QUEUE_EVENT_TIMEOUT:
        case PLATFORM_QUEUE_EVENT_TIMEOUT_PERIODIC:
        {
            struct eventTimeOut             *p1;
            struct _timerHandlerThreadData  *p2;

            struct sigevent      se;
            struct itimerspec    its;
            timer_t              timer_id;

            p1 = (struct eventTimeOut *)data;

            if (p1->token > MAX_TIMER_TOKEN)
            {
                // Invalid arguments
                //
                return 0;
            }

            p2 = (struct _timerHandlerThreadData *)malloc(sizeof(struct _timerHandlerThreadData));
            if (NULL == p2)
            {
                // Out of memory
                //
                return 0;
            }
            
            p2->queue_id = queue_id;
            p2->token    = p1->token;
            p2->periodic = PLATFORM_QUEUE_EVENT_TIMEOUT_PERIODIC == event_type ? 1 : 0;

            // Next, create the timer. Note that it will be automatically
            // destroyed (by us) in the callback function
            //
            memset(&se, 0, sizeof(se));
            se.sigev_notify          = SIGEV_THREAD;
            se.sigev_notify_function = _timerHandler;
            se.sigev_value.sival_ptr = (void *)p2;
            
            if (-1 == timer_create(CLOCK_REALTIME, &se, &timer_id))
            {
                // Failed to create a new timer
                //
                free(p2);
                return 0;
            }
            p2->timer_id = timer_id;

            // Finally, arm/start the timer
            //
            its.it_value.tv_sec     = p1->timeout_ms / 1000;
            its.it_value.tv_nsec    = (p1->timeout_ms % 1000) * 1000000;
            its.it_interval.tv_sec  = PLATFORM_QUEUE_EVENT_TIMEOUT_PERIODIC == event_type ? its.it_value.tv_sec  : 0;
            its.it_interval.tv_nsec = PLATFORM_QUEUE_EVENT_TIMEOUT_PERIODIC == event_type ? its.it_value.tv_nsec : 0;

            if (0 != timer_settime(timer_id, 0, &its, NULL))
            {
                // Problems arming the timer
                //
                free(p2);
                timer_delete(timer_id);
                return 0;
            }

            break;
        }

        case PLATFORM_QUEUE_EVENT_PUSH_BUTTON:
        {
            // The AL entity is telling us that it is capable of processing
            // "push button" configuration events.
            //
            // Create the thread in charge of generating these events.
            //
            pthread_t                      thread;
            struct _pushButtonThreadData  *p;

            p = (struct _pushButtonThreadData *)malloc(sizeof(struct _pushButtonThreadData));
            if (NULL == p)
            {
                // Out of memory
                //
                return 0;
            }

            p->queue_id = queue_id;
            pthread_create(&thread, NULL, _pushButtonThread, (void *)p);

            break;
        }

        case PLATFORM_QUEUE_EVENT_AUTHENTICATED_LINK:
        {
            // The AL entity is telling us that it is capable of processing
            // "authenticated link" events.
            //
            // We don't really need to do anything here. The interface specific
            // thread will be created when the AL entity calls the
            // "PLATFORM_START_PUSH_BUTTON_CONFIGURATION()" function.

            break;
        }

        case PLATFORM_QUEUE_EVENT_TOPOLOGY_CHANGE_NOTIFICATION:
        {
            // The AL entity is telling us that it is capable of processing
            // "topology change" events.
            //
            // We will create a new thread in charge of monitoring the local
            // topology to generate these events.
            //
            pthread_t                           thread;
            struct _topologyMonitorThreadData  *p;
 
            p = (struct _topologyMonitorThreadData *)malloc(sizeof(struct _topologyMonitorThreadData));
            if (NULL == p)
            {
                // Out of memory
                //
                return 0;
            }

            p->queue_id = queue_id;

            pthread_create(&thread, NULL, _topologyMonitorThread, (void *)p);

            break;
        }

        default:
        {
            // Unknown event type!!
            //
            return 0;
        }
    }

    return 1;
}

INT8U PLATFORM_READ_QUEUE(INT8U queue_id, INT8U *message_buffer)
{
#ifdef PLATFORM_ABSTRACTION
    tQueueEvent *nextEvent = NULL ;
    struct timespec forever ;
    int err = kCpe_NoErr;
    forever.tv_sec = kQUitil_Forever ;
    forever.tv_nsec = kQUitil_Forever ;
    err =  queue_RemoveEvent(queues_id[queue_id],forever,&nextEvent);
    PLATFORM_PRINTF_DEBUG_DETAIL("[PLATFORM] Read Message of length:%d \n", nextEvent->length);
    if ( err == kCpe_NoErr && nextEvent )
    {
       PLATFORM_MEMCPY(message_buffer,nextEvent->data,nextEvent->length);
       queue_EventDestroy(nextEvent);
    }

    if ( err == kCpe_NoErr )
        return 1;
    return 0;

#else
    mqd_t    mqdes;
    ssize_t  len;

    mqdes = queues_id[queue_id];
    if ((mqd_t) -1 == mqdes)
    {
        // Invalid ID
        return 1;
    }

    len = mq_receive(mqdes, (char *)message_buffer, MAX_NETWORK_SEGMENT_SIZE+3, NULL);

    if (-1 == len)
    {
        PLATFORM_PRINTF_DEBUG_ERROR("[PLATFORM] mq_receive() returned with errno=%d (%s)\n", errno, strerror(errno));
        return 0;
    }

    // All messages are TLVs where the second and third bytes indicate the
    // total length of the payload. This value *must* match "len-3"
    //
    if ( len < 0 )
    {
        PLATFORM_PRINTF_DEBUG_ERROR("[PLATFORM] mq_receive() returned than 3 bytes (minimum TLV size)\n");
        return 0;
    }
    else
    {
        INT16U payload_len;

        PLATFORM_PRINTF_DEBUG_DETAIL("[PLATFORM] Receiving %d bytes from queue (%02x, %02x, %02x, ...)\n", len, message_buffer[0], message_buffer[1], message_buffer[2]);

        payload_len = *(((INT8U *)message_buffer)+1) * 256 + *(((INT8U *)message_buffer)+2);

        if (payload_len != len-3)
        {
            PLATFORM_PRINTF_DEBUG_ERROR("[PLATFORM] mq_receive() returned %d bytes, but the TLV is %d bytes\n", len, payload_len+3);
            return 0;
        }
    }

    return 1;
#endif
}


