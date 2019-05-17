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

#ifndef __1905_MAP_SERVER_H
#define __1905_MAP_SERVER_H

#include <stdio.h>
#include <unistd.h>
#include <stdint.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <stdlib.h>
#include <netinet/in.h>
#include <string.h>
#include <poll.h>
#include <sys/ioctl.h>
#include <pthread.h>
#include <fcntl.h>
#include <errno.h>
#include "1905_lib_internal.h"
#include "1905_cmdus.h"

#define MAX_CLIENTS 1

#define MAX_SOCK_PATH 32
#define MAX_MODE_LEN 4
#define SOCK_PATH "map_path_"

typedef enum  {
   MAP_CMDU_PAYLOAD,
   MAP_OTHER
} map_message_type;

typedef struct map_message {
   map_message_type type;
   void* message;
} map_message_t;

void map_set_mode(int mode);

int map_get_mode();

/* Checks if a message type has been registered by the given client
 * server_struct [in]   server struct containing the messages types registered by a client
 * message_type  [in]   message type to be checked if present in the registered messages
 * Returns 1  if present
 *         0  if not present
 *     -1 if invalid client
*/
bool is_registered(map_server_struct_t serv_struct, uint16_t message_type);

/* Checks if a message type has been registered by ANY of the client
 * message_type  [in]   message type to be checked if present in the registered messages
 * Returns 1 if registered
 *         0 if not registered
*/
bool map_ext_registered(uint16_t message_type);

/* Send the message to all the clients registered for the message
   message  [in]  		message to be sent to the registered clients
   Returns 0 for successful send
      -1 for sending failed
*/
int server_publish(map_message_t * message);

/** Server initialisation
 */
void * server_init(void * arg);

/** Server shutdown
 */
int server_shutdown();

/*Used to create the MAP server socket*/
int get_server_socket();

/*Used to handle messages send to the MAP server socket
Returns 0 if its a new client connection request*/
int handleServerMessage(int fd,register_data_t reg_data);

void handleCloseServerConnection(int fd,int fd_index);

int handleNewClientConnection(int fd);


#endif

#ifdef __cplusplus
}
#endif
