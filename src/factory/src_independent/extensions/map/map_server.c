/************* COPYRIGHT AND CONFIDENTIALITY INFORMATION NOTICE *************
** Copyright (c) [2019] – [Technicolor Delivery Technologies, SAS]          *
** All Rights Reserved                                                      *
** The source code form of this Open Source Project components              *
** is subject to the terms of the BSD-2-Clause-Patent.                      *
** You can redistribute it and/or modify it under the terms of              *
** the BSD-2-Clause-Patent. (https://opensource.org/licenses/BSDplusPatent) *
** See COPYING file/LICENSE file for more details.                          *
****************************************************************************/

#include "map_server.h"
#include "1905_lib_internal.h"
#include "platform_map.h"
#include "platform.h"

static pthread_mutex_t map_server_mutex = PTHREAD_MUTEX_INITIALIZER;
map_server_struct_t * g_server_struct;
int g_server_fd;
static int gMode = 0;

/**
 * Check if the given FD is valid or not
 *
 *  Returns : 1 if valid
 *          : 0 if invalid
 */
#define is_valid_fd(fd) (fcntl(fd, F_GETFL) != 0 || errno != EBADF)

void map_set_mode(int mode)
{
   gMode = mode;
}

int map_get_mode()
{
   return gMode;
}

bool is_registered(map_server_struct_t serv_struct, uint16_t message_type) {

    if (serv_struct.socketfd < 0) 
        return 0;

    if (message_type  >= CMDU_TYPE_MAP_FIRST_MESSAGE && message_type  <= CMDU_TYPE_MAP_LAST_MESSAGE) {
        uint16_t msg_type = message_type - CMDU_TYPE_MAP_FIRST_MESSAGE;
        return serv_struct.reg_data.multiap_messages[msg_type].interest_set;
    }

    else if (message_type  >= CMDU_TYPE_1905_FIRST_MESSAGE && message_type  <= CMDU_TYPE_1905_LAST_MESSAGE) {
        return serv_struct.reg_data.lib1905_messages[message_type].interest_set;
    }
    return 0;
}

bool map_ext_registered(uint16_t message_type) {

    int i;

    if (NULL == g_server_struct)
        return 0;
    pthread_mutex_lock(&map_server_mutex); 
    for (i = 0; i < MAX_CLIENTS; i++) {
        if (g_server_struct[i].socketfd > 0) {
            if(is_registered(g_server_struct[i],message_type)) {
                pthread_mutex_unlock(&map_server_mutex); 
                return 1;
            }
        }
    }
    pthread_mutex_unlock(&map_server_mutex);
    return 0;
}

int server_publish(map_message_t *map_message) {

    int i;
    int ret = -1;
    uint16_t length;
    struct CMDU* message = NULL;

    if ( map_message == NULL )
        return ret;

    switch ( map_message->type )
    {
       case MAP_CMDU_PAYLOAD:
         message = map_message->message;
         break;

       default:
         // do not process any other messages now
         return ret;
    }

    uint16_t message_type = message->message_type;

    if ( NULL == g_server_struct){
        return ret;
    }

    length = sizeof(map_message_t);

    for (i = 0; i < MAX_CLIENTS; i++) {

        if(g_server_struct[i].socketfd > 0) {

            if (is_registered(g_server_struct[i], message_type)) {

                ret = 1; // registered by the upper layer
                if (-1 == send(g_server_struct[i].socketfd, (map_message_t*)map_message, length, 0)) {
                    PLATFORM_PRINTF_DEBUG_ERROR("Sending data failed for socket %d, but length sent, so exiting",g_server_struct[i].socketfd);
                    break;
                }
            }
        }
    } 

    return ret;
}

void * server_init(void * arg) {

    int client_socket = 0;
    int i         = 0;
    int fd_index  = 0;
    int nread     = 0;
    int rider     = 0;
    static int num_fds   = 0;
    int flag      = 0;
    struct sockaddr_un server;
    struct pollfd poll_fd[MAX_CLIENTS+1];

    g_server_struct = (map_server_struct_t *) calloc (MAX_CLIENTS, sizeof(map_server_struct_t));

    if (-1 == (g_server_fd = socket(AF_UNIX, SOCK_SEQPACKET, 0))) {
        PLATFORM_PRINTF_DEBUG_ERROR("Server socket creation failed");
        return NULL;
    }

    memset(&server, 0, sizeof(struct sockaddr_un));

    /* Bind socket to socket name. */

    server.sun_family = AF_UNIX;

    char mode_str[MAX_MODE_LEN];
    memset(server.sun_path,0,MAX_SOCK_PATH);
    strncpy(server.sun_path + 1, SOCK_PATH, MAX_SOCK_PATH);
    snprintf(mode_str, MAX_MODE_LEN,"%d",gMode);
    strncat(server.sun_path + 1, mode_str, MAX_SOCK_PATH);
    PLATFORM_PRINTF_DEBUG_DETAIL("Server socket path:%s",server.sun_path + 1);


    if (-1 ==  bind(g_server_fd, (const struct sockaddr *) &server,sizeof(struct sockaddr_un))) {
        PLATFORM_PRINTF_DEBUG_ERROR("Server socket bind failed %d",errno);
        return NULL;
    }

    // Socket listen
    if (listen(g_server_fd, MAX_CLIENTS) < 0) {
        PLATFORM_PRINTF_DEBUG_ERROR("Listen failed");
        return NULL;
    }

    // Initialise poll parameter with server socket id
    poll_fd[0].fd = g_server_fd;
    poll_fd[0].events = POLLIN;
    num_fds++;

    while(1) {
        if (poll(poll_fd, num_fds, -1) == -1) {
        PLATFORM_PRINTF_DEBUG_ERROR("Map Server Poll failed %d",errno);
        return NULL;
    }

        for (fd_index = 0; fd_index < num_fds ; fd_index++) {

            // Check which fd returned POLLIN
            if (poll_fd[fd_index].revents & POLLIN) {

                // If server fd returned POLLIN, then new connection from a client
                if (poll_fd[fd_index].fd == g_server_fd) {

                    if (-1 == (client_socket = accept(g_server_fd, NULL,NULL)))
                        PLATFORM_PRINTF_DEBUG_ERROR("Accept failed");

                    // Close the newly connected socket	if number of clients exceeded the maximum count
                    if (num_fds >= MAX_CLIENTS+1) {
                        shutdown(client_socket,SHUT_RDWR);
                        close(client_socket);
                    }

                    else {

                        for (rider = 1; rider < MAX_CLIENTS+1 ; rider++) {

                            // handle unfilled in-between elements in array
                            if (-1 == poll_fd[rider].fd) {
                                flag = 1;
                                break;
                            }

                            else 
                                flag = 0;
                        }

                        if (1 == flag) {
                            g_server_struct[rider - 1].socketfd = client_socket;
                            poll_fd[rider].fd = client_socket;
                            poll_fd[rider].events = POLLIN;
                        }

                        else {
                            g_server_struct[num_fds - 1].socketfd = client_socket;
                            poll_fd[num_fds].fd = client_socket;
                            poll_fd[num_fds].events = POLLIN;
                            num_fds++;
                        }
                    }
                }

                // Otherwise, its an IO event from an existing client
                else {
                    // Check to see if client wants to close connection
                    ioctl(poll_fd[fd_index].fd, FIONREAD, &nread);

                    if (0 == nread) {
                        pthread_mutex_lock(&map_server_mutex);
                        shutdown(poll_fd[fd_index].fd,SHUT_RDWR);
                        close(poll_fd[fd_index].fd);
                        poll_fd[fd_index].events = 0;
                        poll_fd[fd_index].fd = -1;
                        g_server_struct[fd_index - 1].socketfd = -1;
                        pthread_mutex_unlock(&map_server_mutex);
                    }

                    // 1905 extension code to register messages
                    else {
                        register_data_t reg_data;

                        if (recv(poll_fd[fd_index].fd , (register_data_t *)&reg_data,sizeof(register_data_t),0) < 0) {
                            PLATFORM_PRINTF_DEBUG_ERROR("Registration receive failed for client with fd %d", poll_fd[fd_index].fd);
                            break;
                        }

                        PLATFORM_PRINTF_DEBUG_DETAIL("Registration received for client with fd %d", poll_fd[fd_index].fd);

                        pthread_mutex_lock(&map_server_mutex);
                        for (i = 0; i < MAX_CLIENTS; i++) {

                            if (poll_fd[fd_index].fd == g_server_struct[i].socketfd){
                                g_server_struct[i].reg_data = reg_data;
#ifdef MULTIAP
								is_reg_complete = 1;
#endif
                                break;
                            }
                        }
                        pthread_mutex_unlock(&map_server_mutex); 
                    }
                }
            }
        }
    }
    return arg;
}

int server_shutdown() {
    if(!is_valid_fd(g_server_fd))
        return -1;
    close(g_server_fd);
    free(g_server_struct);

    return 0;
}


#ifdef USE_RAW_SOCK
int get_server_socket() {

    struct sockaddr_un server;
    	
    g_server_struct = (map_server_struct_t *) calloc (MAX_CLIENTS, sizeof(map_server_struct_t));

    if (-1 == (g_server_fd = socket(AF_UNIX, SOCK_SEQPACKET, 0))) {
        PLATFORM_PRINTF_DEBUG_ERROR("Server socket creation failed");
        return -1;
    }

    memset(&server, 0, sizeof(struct sockaddr_un));

    /* Bind socket to socket name. */

    server.sun_family = AF_UNIX;

    char mode_str[MAX_MODE_LEN];
    memset(server.sun_path,0,MAX_SOCK_PATH);
    strncpy(server.sun_path + 1, SOCK_PATH, MAX_SOCK_PATH);
    snprintf(mode_str, MAX_MODE_LEN,"%d",gMode);
    strncat(server.sun_path + 1, mode_str, MAX_SOCK_PATH);
    PLATFORM_PRINTF_DEBUG_DETAIL("Server socket path:%s\n",server.sun_path + 1);


    if (-1 ==  bind(g_server_fd, (const struct sockaddr *) &server,sizeof(struct sockaddr_un))) {
        PLATFORM_PRINTF_DEBUG_ERROR("Server socket bind failed %d",errno);
        return -1;
    }

    // Socket listen
    if (listen(g_server_fd, MAX_CLIENTS) < 0) {
        PLATFORM_PRINTF_DEBUG_ERROR("Listen failed");
        return -1;
    }

	return g_server_fd;
    
}

int handleNewClientConnection(int fd)
{
    int client_socket = 0;
    static int num_fds   = 0;

	if(fd != g_server_fd)
	{
		PLATFORM_PRINTF_DEBUG_DETAIL("Attempting new connection on invalid fd\n");
		return -1;
	}
	
	if (-1 == (client_socket = accept(g_server_fd, NULL,NULL)))
	{
	 	PLATFORM_PRINTF_DEBUG_ERROR("Accept failed");
		return -1;
	}

	 //Close the newly connected socket	if number of clients exceeded the maximum count
	 if (num_fds >= MAX_CLIENTS+1) {
	 	PLATFORM_PRINTF_DEBUG_ERROR("Attempting unsupported new client connection\n");
	 	shutdown(client_socket,SHUT_RDWR);
		close(client_socket);
		return -1;
	 }
	 else {
	 	PLATFORM_PRINTF_DEBUG_DETAIL("Create the Client Socket\n");
	 	g_server_struct[0].socketfd = client_socket;
		num_fds++;
		return client_socket;
	}
}


void handleCloseServerConnection(int fd, int fd_index)
{
	PLATFORM_PRINTF_DEBUG_DETAIL("Close conection received for client with fd %d", fd);
	g_server_struct[0].socketfd = -1;
}


int handleServerMessage(int fd, register_data_t reg_data)
{
	PLATFORM_PRINTF_DEBUG_DETAIL("Registration received for client with fd %d", fd);
	if (fd == g_server_struct[0].socketfd){
		PLATFORM_PRINTF_DEBUG_DETAIL("Registration applied for server at index 0\n");
        g_server_struct[0].reg_data = reg_data;
		return 0;
	}
		
	return -1;
}

#endif

