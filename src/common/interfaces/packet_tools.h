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

#ifndef _PACKET_TOOLS_H_
#define _PACKET_TOOLS_H_

#include "platform.h"


// Auxiliary functions to:
//
//   A) Extract 1, 2 or 4 bytes from a stream received from the network.
//
//   B) Insert  1, 2 or 4 bytes into a stream which is going to be sent into
//      the network.
//
// These functions do three things:
//
//   1. Avoid unaligned memory accesses (which might cause slowdowns or even
//      exceptions on some architectures)
//
//   2. Convert from network order to host order (and the other way)
//
//   3. Advance the packet pointer as many bytes as those which have just
//      been extracted/inserted.

// Extract/insert 1 byte
//
static inline void _E1B(INT8U **packet_ppointer, INT8U *memory_pointer)
{
    *memory_pointer     = **packet_ppointer;
    (*packet_ppointer) += 1;
}
static inline void _I1B(INT8U *memory_pointer, INT8U **packet_ppointer)
{
    **packet_ppointer   = *memory_pointer;
    (*packet_ppointer) += 1;
}

// Extract/insert 2 bytes
//
static inline void _E2B(INT8U **packet_ppointer, INT16U *memory_pointer)
{
#if _HOST_IS_BIG_ENDIAN_ == 1
    *(((INT8U *)memory_pointer)+0)  = **packet_ppointer; (*packet_ppointer)++;
    *(((INT8U *)memory_pointer)+1)  = **packet_ppointer; (*packet_ppointer)++;
#elif _HOST_IS_LITTLE_ENDIAN_ == 1
    *(((INT8U *)memory_pointer)+1)  = **packet_ppointer; (*packet_ppointer)++;
    *(((INT8U *)memory_pointer)+0)  = **packet_ppointer; (*packet_ppointer)++;
#else
#error You must specify your architecture endianess
#endif
}
static inline void _I2B(INT16U *memory_pointer, INT8U **packet_ppointer)
{
#if _HOST_IS_BIG_ENDIAN_ == 1
    **packet_ppointer = *(((INT8U *)memory_pointer)+0); (*packet_ppointer)++;
    **packet_ppointer = *(((INT8U *)memory_pointer)+1); (*packet_ppointer)++;
#elif _HOST_IS_LITTLE_ENDIAN_ == 1
    **packet_ppointer = *(((INT8U *)memory_pointer)+1); (*packet_ppointer)++;
    **packet_ppointer = *(((INT8U *)memory_pointer)+0); (*packet_ppointer)++;
#else
#error You must specify your architecture endianess
#endif
}

// Extract/insert 4 bytes
//
static inline void _E4B(INT8U **packet_ppointer, INT32U *memory_pointer)
{
#if _HOST_IS_BIG_ENDIAN_ == 1
    *(((INT8U *)memory_pointer)+0)  = **packet_ppointer; (*packet_ppointer)++;
    *(((INT8U *)memory_pointer)+1)  = **packet_ppointer; (*packet_ppointer)++;
    *(((INT8U *)memory_pointer)+2)  = **packet_ppointer; (*packet_ppointer)++;
    *(((INT8U *)memory_pointer)+3)  = **packet_ppointer; (*packet_ppointer)++;
#elif _HOST_IS_LITTLE_ENDIAN_ == 1
    *(((INT8U *)memory_pointer)+3)  = **packet_ppointer; (*packet_ppointer)++;
    *(((INT8U *)memory_pointer)+2)  = **packet_ppointer; (*packet_ppointer)++;
    *(((INT8U *)memory_pointer)+1)  = **packet_ppointer; (*packet_ppointer)++;
    *(((INT8U *)memory_pointer)+0)  = **packet_ppointer; (*packet_ppointer)++;
#else
#error You must specify your architecture endianess
#endif
}
static inline void _I4B(INT32U *memory_pointer, INT8U **packet_ppointer)
{
#if _HOST_IS_BIG_ENDIAN_ == 1
    **packet_ppointer = *(((INT8U *)memory_pointer)+0); (*packet_ppointer)++;
    **packet_ppointer = *(((INT8U *)memory_pointer)+1); (*packet_ppointer)++;
    **packet_ppointer = *(((INT8U *)memory_pointer)+2); (*packet_ppointer)++;
    **packet_ppointer = *(((INT8U *)memory_pointer)+3); (*packet_ppointer)++;
#elif _HOST_IS_LITTLE_ENDIAN_ == 1
    **packet_ppointer = *(((INT8U *)memory_pointer)+3); (*packet_ppointer)++;
    **packet_ppointer = *(((INT8U *)memory_pointer)+2); (*packet_ppointer)++;
    **packet_ppointer = *(((INT8U *)memory_pointer)+1); (*packet_ppointer)++;
    **packet_ppointer = *(((INT8U *)memory_pointer)+0); (*packet_ppointer)++;
#else
#error You must specify your architecture endianess
#endif
}

// Extract/insert N bytes (ignore endianess)
//
static inline void _EnB(INT8U **packet_ppointer, void *memory_pointer, INT32U n)
{
    PLATFORM_MEMCPY(memory_pointer, *packet_ppointer, n);
    (*packet_ppointer) += n;
}
static inline void _InB(void *memory_pointer, INT8U **packet_ppointer, INT32U n)
{
    PLATFORM_MEMCPY(*packet_ppointer, memory_pointer, n);
    (*packet_ppointer) += n;
}

#endif
