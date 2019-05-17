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

#ifndef _BBF_SEND_H_
#define _BBF_SEND_H_

#include "1905_cmdus.h"


////////////////////////////////////////////////////////////////////////////////
// CMDU extension callbacks
////////////////////////////////////////////////////////////////////////////////

// This function inserts BBF TLVs (if appropriate) to the input CMDU.
//
// According to the standard, any CMDU is subject to be extended with extra
// Vendor Specific TLVs, so each inserted BBF TLV will be embedded inside a
// Vendor Specific TLV.
//
// BBF TLVs inserted (zero or more) depend on the CMDU type. They are always
// inserted at the end of the current TLV list of the CMDU.
// This function makes use of the generic API:
// embedExtensionInVendorSpecificTLV() and insertVendorSpecificTLV() to insert
// the BBF TLVs in the CMDU.
//
// 'memory_structure' is a pointer to the CMDU structure
//
// Return '0' if there was a problem, '1' otherwise
//
INT8U CBKSend1905BBFExtensions(struct CMDU *memory_structure);

////////////////////////////////////////////////////////////////////////////////
// Datamodel extension callbacks
////////////////////////////////////////////////////////////////////////////////

// This function obtains local non-standard info
//
// Local non-standard info is encoded in one of the defined BBF TLVs, which in
// turn, is embedded in a standard Vendor Specific TLV.
// This process will result in an array of Vendor Specific TLVs (one per BBF
// TLV)
//
// This TLV list will be used to update the datamodel 'extensions' section by
// the 'CBKUpdateBBFExtendedInfo()' callback.
//
// 'extensions' is a pointer to the local extensions
//
// 'nr' is the number of local extensions
//
void CBKObtainBBFExtendedLocalInfo(struct vendorSpecificTLV ***extensions, INT8U *nr);

// This function updates the datamodel extensions section with non-standard info
//
// The datamodel structure keeps an extension TLV list per device. This TLV
// list may be a set of TLVs from different registered actors (i.e. BBF, DPM,
// ...), so each registered actor must update its own TLVs in the common
// datamodel.
//
// 'extensions' is a pointer to the extensions section belonging to the device
// with 'al_mac_address' AL mac address.
//
// 'nr' is the number of TLV extensions
//
// 'al_mac_address' is the AL mac address of the requested device.
//
void CBKUpdateBBFExtendedInfo(struct vendorSpecificTLV  **extensions, INT8U  nr, INT8U *al_mac_address);

// This function extendes the ALME 'dnd' report
//
// This callback is called once per device. At this point, the standard
// datamodel info is already added to the ALME 'dnd' report. This function may
// add extra non-standard info obtained from the extensions TLV list
// (previously updated via CBKUpdateBBFExtendedInfo())
//
// The extensions TLV list may be a mix of TLVs from different registered
// actors.  This function preprocesses the whole list, takes care only of its
// own TLVs, reorganizes data and presents the info in a user friendly manner
// (i.e. non-1905 metrics (tx and rx) are classified by device)
//
// 'memory_structure' is a pointer to an array of TLV extensions. Each
// registered function must represent its own extensions and ignore the rest.
//
// 'structure_nr' is the number of TLV extensions
//
// 'callback' is a function that will be executed on each element with the
// following arguments:
// * A pointer to the "write()" function that will be used to dump text.
//   This is always the "write_function()" pointer provided as third argument
//   to the "visit_1905_TLV_structure()" function.
// * The size of the element to print (1, 2, 4, n bytes)
// * A prefix string.
//   This is always the "prefix" value provided as fourth argument to the
//   "visit_1905_TLV_structure()" function
// * The name of the element (ex: "mac_address")
// * A 'fmt' string which must be used to print the contents of the element
// * A pointer to the element itself
//
// 'write' is a function that will be used when the callback is executed
//
// 'prefix' is a string argument that will be used when the callback is
// executed (it usually contains "context" information that the callback
// function prints before anything else to make it easy to follow the structure
// traversing order)
//
// These last three arguments will be passed to the 'visit_bbf_TLV_structure()'
// function, which is defined in the 'bbf_tlvs.h' file and it's responsible for
// converting the datamodel structure data into user friendly text.
//
void CBKDumpBBFExtendedInfo(INT8U **memory_structure,
                            INT8U   structure_nr,
                            void  (*callback)(void (*write_function)(const char *fmt, ...), const char *prefix, INT8U size, const char *name, const char *fmt, void *p),
                            void  (*write_function)(const char *fmt, ...),
                            const char *prefix);

#endif

