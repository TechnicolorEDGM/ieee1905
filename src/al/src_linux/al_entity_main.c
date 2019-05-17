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

#include "platform.h"
#include "platform_interfaces_priv.h"            // addInterface
#include "platform_interfaces_ghnspirit_priv.h"  // registerGhnSpiritInterfaceType
#include "platform_interfaces_simulated_priv.h"  // registerSimulatedInterfaceType
#include "platform_alme_server_priv.h"           // almeServerPortSet()
#include "al.h"                                  // start1905AL

#include <stdio.h>   // printf
#include <unistd.h>  // getopt
#include <stdlib.h>  // exit
#include <string.h>  // strtok

////////////////////////////////////////////////////////////////////////////////
// Static (auxiliary) private functions, structures and macros
////////////////////////////////////////////////////////////////////////////////

// Port number where the ALME server will be listening to by default
//
#define DEFAULT_ALME_SERVER_PORT 8888

// Convert a character to lower case
//
static char _asciiToLowCase (char c)
{
    if (c >= 'a' && c <= 'z')
    {
        return c;
    }
    else if (c >= 'A' && c <= 'Z')
    {
        return c + ('a' - 'A');
    }
    else
    {
        return c;
    }
}

// Convert a MAC string representation (example: "0a:fa:41:a3:ff:40") into a
// six bytes array (example: {0x0a, 0xfa, 0x41, 0xa3, 0xff, 0x40})
//
static void _asciiToMac (const char *str, INT8U *addr)
{
    int i = 0;

    if (NULL == str)
    {
        addr[0] = 0x00;
        addr[1] = 0x00;
        addr[2] = 0x00;
        addr[3] = 0x00;
        addr[4] = 0x00;
        addr[5] = 0x00;

        return;
    }

    while (0x00 != *str && i < 6)
    {
        INT8U byte = 0;

        while (0x00 != *str && ':' != *str)
        {
            char low;

            byte <<= 4;
            low    = _asciiToLowCase (*str);

            if (low >= 'a')
            {
                byte |= low - 'a' + 10;
            }
            else
            {
                byte |= low - '0';
            }
            str++;
        }

        addr[i] = byte;
        i++;

        if (*str == 0)
        {
            break;
        }

        str++;
      }
}

// This function receives a comma separated list of interface names (example:
// "eth0,eth1,wlan0") and, for each of them, calls "addInterface()" (example:
// addInterface("eth0") + addInterface("eth1") + addInterface("wlan0"))
//
static void _parseInterfacesList(const char *str)
{
    char *aux;
    char *interface_name;
    char *save_ptr;

    if (NULL == str)
    {
        return;
    }

    aux = strdup(str);

    interface_name = strtok_r(aux, ",", &save_ptr);
    if (NULL != interface_name)
    {
        addInterface(interface_name);

        while (NULL != (interface_name = strtok_r(NULL, ",", &save_ptr)))
        {
            addInterface(interface_name);
        }
    }

    free(aux);
    return;
}

static void _printUsage(char *program_name)
{
    printf("AL entity (build %s)\n", _BUILD_NUMBER_);
    printf("\n");
    printf("Usage: %s -m <al_mac_address> -i <interfaces_list> [-w] [-r <registrar_interface>] [-v] [-p <alme_port_number>]\n", program_name);
    printf("\n");
    printf("  ...where:\n");
    printf("       '<al_mac_address>' is the AL MAC address that this AL entity will receive\n");
    printf("       (ex: '00:4f:21:03:ab:0c'\n");
    printf("\n");
    printf("       '<interfaces_list>' is a comma sepparated list of local interfaces that will be\n");
    printf("        managed by the AL entity (ex: 'eth0,eth1,wlan0')\n");
    printf("\n");
    printf("       '-w', if present, will instruct the AL entity to map the whole network (instead of\n");
    printf("       just its local neighbors)\n");
    printf("\n");
    printf("       '-r', if present, will tell the AL entity that '<registrar_interface>' is the name\n");
    printf("       of the local interface that will act as the *unique* wifi registrar in the whole\n");
    printf("       network.\n");
    printf("\n");
    printf("       '-v', if present, will increase the verbosity level. Can be present more than once,\n");
    printf("       making the AL entity even more verbose each time.\n");
    printf("\n");
    printf("       '<alme_port_number>', is the port number where a TCP socket will be opened to receive\n");
    printf("       ALME messages. If this argument is not given, a default value of '8888' is used.\n");
    printf("\n");

    return;
}


////////////////////////////////////////////////////////////////////////////////
// External public functions
////////////////////////////////////////////////////////////////////////////////

int main(int argc, char *argv[])
{
    INT8U al_mac_address[6] = {0x00, 0x00, 0x00, 0x00, 0x00, 0x00};
    INT8U map_whole_network = 0;

    int   c;
    char *al_mac              = NULL;
    char *al_interfaces       = NULL;
    int  alme_port_number     = 0;
    char *registrar_interface = NULL;

    int verbosity_counter = 1; // Only ERROR and WARNING messages

    registerGhnSpiritInterfaceType();
    registerSimulatedInterfaceType();

    while ((c = getopt (argc, argv, "m:i:wr:vh:p:")) != -1)
    {
        switch (c)
        {
            case 'm':
            {
                // AL MAC address in "xx:xx:..:xx" format
                //
                al_mac = optarg; 
                break;
            }

            case 'i':
            {
                // Comma sepparated list of interfaces: 'eth0,eth1,wlan0'
                //
                al_interfaces = optarg; 
                break;
            }

            case 'w':
            {
                // If set to '1', the AL entity will not only query its direct
                // neighbors, but also its neighbors's neighbors and so on...
                // taking much more memory but obtaining a whole network map.
                //
                map_whole_network = 1; 
                break;
            }

            case 'r':
            {
                // This is the interface that acts as Wifi registrar in the
                // network.
                // Remember that only one interface in the whole network should
                // act as a registrar.
                //
                registrar_interface = optarg;
                break;
            }

            case 'v':
            {
                // Each time this flag appears, the verbosity counter is
                // incremented.
                //
                verbosity_counter++;
                break;
            }

            case 'p':
            {
                // Alme server port number
                //
                alme_port_number = atoi(optarg);
                break;
            }

            case 'h':
            {
                _printUsage(argv[0]);
                exit(0);
            }

        }
    }

    if (NULL == al_mac || NULL == al_interfaces)
    {
        _printUsage(argv[0]);
        exit(1);
    }

    if (0 == alme_port_number)
    {
        alme_port_number = DEFAULT_ALME_SERVER_PORT;
    }

    PLATFORM_PRINTF_DEBUG_SET_VERBOSITY_LEVEL(verbosity_counter);

    _parseInterfacesList(al_interfaces);
    _asciiToMac(al_mac, al_mac_address);

    almeServerPortSet(alme_port_number);

    start1905AL(al_mac_address, map_whole_network, registrar_interface);

    return 0;
}
