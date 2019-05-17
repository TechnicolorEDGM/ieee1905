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
 *  This is draft software, is subject to change, and has not been
 *  approved by members of the Broadband Forum. It is made available to
 *  non-members for internal study purposes only. For such study
 *  purposes, you have the right to make copies and modifications only
 *  for distributing this software internally within your organization
 *  among those who are working on it (redistribution outside of your
 *  organization for other than study purposes of the original or
 *  modified works is not permitted). For the avoidance of doubt, no
 *  patent rights are conferred by this license.
 *  
 *  THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS
 *  "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT
 *  LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS
 *  FOR A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE
 *  COPYRIGHT HOLDER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT,
 *  INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING,
 *  BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES;
 *  LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER
 *  CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
 *  LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN
 *  ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE
 *  POSSIBILITY OF SUCH DAMAGE.
 *  
 *  Unless a different date is specified upon issuance of a draft
 *  software release, all member and non-member license rights under the
 *  draft software release will expire on the earliest to occur of (i)
 *  nine months from the date of issuance, (ii) the issuance of another
 *  version of the same software release, or (iii) the adoption of the
 *  draft software release as final.
 *  
 *  ---
 *  
 *  This version of this source file is part of the Broadband Forum
 *  WT-382 IEEE 1905.1/1a stack project.
 *  
 *  Please follow the release link (given below) for further details
 *  of the release, e.g. license validity dates and availability of
 *  more recent draft or final releases.
 *  
 *  Release name: WT-382_draft1
 *  Release link: https://www.broadband-forum.org/software#WT-382_draft1
 */

#ifndef _MAP_TLVS_H_
#define _MAP_TLVS_H_

#include "platform.h"

// In the comments below, every time a reference is made (ex: "See Section 6.4"
// or "See Table 6-11") we are talking about the contents of the following
// document:
//
//   "IEEE Std 1905.1-2013"

////////////////////////////////////////////////////////////////////////////////
// TLV types as detailed in "Section 6.4"
////////////////////////////////////////////////////////////////////////////////
#define TLV_TYPE_MAP_SUPPORTED_SERVICE                   (0x80) 

#define TLV_TYPE_SUPPORTED_SERVICE                        0x80
#define TLV_TYPE_SEARCHED_SERVICE                         0x81
#define TLV_TYPE_AP_RADIO_IDENTIFIER                      0x82
#define TLV_TYPE_AP_OPERATIONAL_BSS                       0x83
#define TLV_TYPE_ASSOCIATED_STA_TLV                       0x84
#define TLV_TYPE_AP_RADIO_BASIC_CAPABILITY                0x85
#define TLV_TYPE_AP_HT_CAPABILITY                         0x86
#define TLV_TYPE_AP_VHT_CAPABILITY                        0x87
#define TLV_TYPE_AP_HE_CAPABILITY                         0x88
#define TLV_TYPE_STEERING_POLICY                          0x89
#define TLV_TYPE_METRIC_REPORTING_POLICY                  0x8A
#define TLV_TYPE_CHANNEL_PREFERENCE                       0x8B
#define TLV_TYPE_RADIO_OPERATION_RESTRICTION              0x8C
#define TLV_TYPE_TRANSMIT_POWER                           0x8D
#define TLV_TYPE_CHANNEL_SELECTION_RESPONSE               0x8E
#define TLV_TYPE_OPERATING_CHANNEL_REPORT                 0x8F
#define TLV_TYPE_CLIENT_INFO                              0x90
#define TLV_TYPE_CLIENT_CAPABILITY_REPORT                 0x91
#define TLV_TYPE_CLIENT_ASSOCIATION_EVENT                 0x92
#define TLV_TYPE_AP_METRICS_QUERY                         0x93
#define TLV_TYPE_AP_METRICS_RESPONSE                      0x94
#define TLV_TYPE_STA_MAC_ADDRESS                          0x95
#define TLV_TYPE_ASSOCIATED_STA_LINK_METRICS              0x96
#define TLV_TYPE_UNASSOCIATED_STA_METRICS_QUERY           0x97
#define TLV_TYPE_UNASSOCIATED_STA_METRICS_RESPONSE        0x98
#define TLV_TYPE_BEACON_METRICS_QUERY                     0x99
#define TLV_TYPE_BEACON_METRICS_RESPONSE                  0x9A
#define TLV_TYPE_STEERING_REQUEST                         0x9B
#define TLV_TYPE_BTM_REPORT                               0x9C
#define TLV_TYPE_CLIENT_ASSOCIATION_CONTROL_REQUEST       0x9D
#define TLV_TYPE_HIGHER_LAYER_DATA_MSG                    0xA0
#define TLV_TYPE_AP_CAPABILITY                            0xA1
#define TLV_TYPE_ASSOC_STA_TRAFFIC_STATS                  0xA2
#define TLV_TYPE_ERROR                                    0xA3

#define AP_CAPABILITY_TLV_LEN                1    // As per MULTIAP standard(17.2.6), AP Capability Tlv length *must* be 1
#define AP_HT_CAPABILITY_TLV_LEN             7    // As per MULTIAP standard(17.2.8), AP HT Capability Tlv length *must* be 7
#define AP_VHT_CAPABILITY_TLV_LEN            12   // As per MULTIAP standard(17.2.9), AP VHT Capability Tlv length *must* be 12
#define AP_HE_CAPABILITY_TLV_MIN_LEN         9    // As per MULTIAP standard(17.2.10), AP HE Capability Tlv length *must* be atleast 9
#define CLIENT_INFO_TLV_LEN                  12   // As per MULTIAP standard(17.2.18), Client Info Tlv length *must* be 12
#define CLIENT_CAPABILITY_REPORT_TLV_MIN_LEN 1    // As per MULTIAP standard(17.2.19), Client Capability Report Tlv length *must* be atleast 1
#define STA_MAC_ADDRESS_TLV_LEN              6    // As per MULTIAP standard(17.2.23), Sta Mac address Tlv length *must* be 6
#define ASSOCIATED_STA_LINK_METRICS_TLV_MIN_LEN 7 // As per MULTIAP standard(17.2.24), Associated Sta link metrics tlv length *must* be atleast 7
#define BEACON_METRICS_QUERY_TLV_MIN_LEN     18   // As per MULTIAP standard(17.2.27), Beacon metrics query tlv length *must* be at least 21
#define BEACON_METRICS_RESPONSE_TLV_MIN_LEN  8    // As per MULTIAP standard(17.2.28), Beacon metrics report tlv length *must* be at least 8
#define STEERING_BTM_REPORT_TLV_MIN_LEN      13   // As per MULTIAP standard(17.2.30), Steering BTM Report Tlv length *must* be atleast 13
#define CLIENT_ASSOCIATION_CONTROL_REQUEST_TLV_MIN_LEN 16 // As per MULTIAP standard(17.2.31), Client Association Control Request tlv length *must* be atleast 16
#define TRANSMIT_POWER_TLV_LEN               7
#define CHANNEL_SELECTION_RESPONSE_TLV_LEN   7
#define ERROR_CODE_TLV_LEN                   7    // As per MULTIAP standard(17.2.36), Eroor Code Tlv length *must* be 7
#define STATION_METRICS_PER_BSS_LEN          19
#define MAX_BSSID_PER_AP_METRICS_QUERY       32   // Since 8 (MAX BSS) * 4 (Max Radio) = 32 BSSMax/agent
#define MIN_AP_METRICS_QUERY_TLV_LEN         1   //Atleast there should be "numBss" (i.e, 1 Byte)
#define MIN_HIGHER_LAYER_DATA_TLV_LEN        1     // As per MULTIAP standard(17.2.34), minimum of 1 bytes to specify protocol should be available for higher layer data msg
#define MIN_AP_METRICS_RESPONSE_TLV_LEN      13  // Min len = 6 (bssid_len) + 1 (channel_util_len) + 2(no_of_sta) + 1(ESP bitfield) + 3(ESP info)
#define MIN_ASSOC_STA_TRAFFIC_STATS_TLV_LEN  34    // Min len = 6 (sta mac) + 4(txBytes) + 4(rxBytes) + 4 (txpkts) + 4(rxpkts) + 4(txerrors) + 4(rxerrors) + 4(re-tx cnt)


// BIT MASKs
#define BIT_MASK_7 0x80
#define BIT_MASK_6 0x40
#define BIT_MASK_5 0x20
#define BIT_MASK_4 0x10
#define BIT_MASK_3 0x08
#define BIT_MASK_2 0x04
#define BIT_MASK_1 0x02
#define BIT_MASK_0 0x01

//BIT SHIFTs
#define BIT_SHIFT_7   7
#define BIT_SHIFT_6   6
#define BIT_SHIFT_5   5
#define BIT_SHIFT_4   4
#define BIT_SHIFT_3   3
#define BIT_SHIFT_2   2
#define BIT_SHIFT_1   1

/* SET/RESET a bit */
#define RESET_BIT 0x00
#define SET_BIT   0x01

enum result_codes
{
    SUCCESS = 0x00,
    FAILURE = 0x01
};

enum reason_codes
{
    STA_ASSOCIATED              = 0x01,
    STA_UNASSOCIATED            = 0x02,
    UNSPECIFIED_FAILURE         = 0x03,
    NON_OPERABLE_CHANNEL        = 0x04,
    BSS_SIGNAL_WEAK             = 0x05,
    STEERING_REJECTED_BY_TARGET = 0x06
};

enum association_control_flags
{
    STA_BLOCK   = 0x00,
    STA_UNBLOCK = 0x01
};

typedef struct mapAPCapabilityTLV {
    INT8U   tlv_type;
    INT8U   operating_unsupported_link_metrics:1;
    INT8U   non_operating_unsupported_link_metrics:1;
    INT8U   agent_initiated_steering:1;
    INT8U   reserved:5;
} AP_capability_tlv_t;

typedef struct mapAPHTCapabilityTLV {
    INT8U   tlv_type;
    INT8U   radio_id[ETHER_ADDR_LEN];
    INT8U   max_supported_tx_streams:2;
    INT8U   max_supported_rx_streams:2;
    INT8U   gi_support_20mhz:1;
    INT8U   gi_support_40mhz:1;
    INT8U   ht_support_40mhz:1;
    INT8U   reserved:1;
} AP_HT_capability_tlv_t;

typedef struct mapAPVHTCapabilityTLV {
    INT8U   tlv_type;
    INT8U   radio_id[ETHER_ADDR_LEN];
    INT16U  supported_tx_mcs;
    INT16U  supported_rx_mcs;
    INT8U   max_supported_tx_streams:3;
    INT8U   max_supported_rx_streams:3;
    INT8U   gi_support_80mhz:1;
    INT8U   gi_support_160mhz:1;
    INT8U   support_80_80_mhz:1;
    INT8U   support_160mhz:1;
    INT8U   su_beamformer_capable:1;
    INT8U   mu_beamformer_capable:1;
    INT8U   reserved:4;
} AP_VHT_capability_tlv_t;

typedef struct mapAPHECapabilityTLV {
    INT8U   tlv_type;
    INT8U   radio_id[ETHER_ADDR_LEN];
    INT8U   supported_mcs_length;
    INT8U   supported_tx_rx_mcs[12];
    INT8U   max_supported_tx_streams:3;
    INT8U   max_supported_rx_streams:3;
    INT8U   support_80_80_mhz:1;
    INT8U   support_160mhz:1;
    INT8U   su_beamformer_capable:1;
    INT8U   mu_beamformer_capable:1;
    INT8U   ul_mimo_capable:1;
    INT8U   ul_mimo_ofdma_capable:1;
    INT8U   dl_mimo_ofdma_capable:1;
    INT8U   ul_ofdma_capable:1;
    INT8U   dl_ofdma_capable:1;
    INT8U   reserved:1;
} AP_HE_capability_tlv_t;

typedef struct mapClientInfoTLV {
    INT8U   tlv_type;
    INT8U   bssid[ETHER_ADDR_LEN];
    INT8U   client_mac[ETHER_ADDR_LEN];
} client_info_tlv_t;

typedef struct mapHigherLayerDataTLV {
    INT8U tlv_type;
    INT16U tlv_length;
    INT8U higher_layer_proto;
    uint8_t *payload;
} higher_layer_data_tlv_t;

typedef struct mapClientCapabilityReportTLV {
    INT8U    tlv_type;
    INT16U    tlv_length;
    INT8U    result_code;
    INT16U   assoc_frame_len;
    INT8U    *assoc_frame; /* Since association frame is not fixed, a place holder, will allocated accordingly*/
} client_capability_report_tlv_t;

typedef struct mapStaMacAddressTLV {
    INT8U   tlv_type;
    INT8U   associated_sta_mac[ETHER_ADDR_LEN];
} sta_mac_address_tlv_t;

typedef struct sta_link_metric_s {
    INT8U   bssid[ETHER_ADDR_LEN];
    INT32U  report_time_interval;
    INT32U  downlink_data_rate;
    INT32U  uplink_data_rate;
    INT8U   uplink_rssi;
} sta_link_metric_t;

typedef struct mapAssociatedStaLinkMetricsTLV {
    INT8U   tlv_type;
    INT8U   associated_sta_mac[ETHER_ADDR_LEN];
    INT8U   reported_bssid_count;
    sta_link_metric_t sta_metrics[1]; /* Since reported_bssid_count is not fixed, a place holder, will allocated accordingly*/
} associated_sta_link_metrics_t;

typedef struct sta_list_s {
    INT8U   sta_mac[ETHER_ADDR_LEN];
}sta_list_t;

typedef struct mapClientAsociationControlRequestTLV {
    INT8U   tlv_type;
    INT8U   bssid[ETHER_ADDR_LEN];
    INT8U   association_control;
    INT16U  validity_period;
    INT8U   sta_count;
    sta_list_t sta_list[1];  /* Since sta_count is not fixed, a place holder, will allocated accordingly*/
} client_association_control_request_tlv_t;

typedef struct mapErrorCodeTLV {
    INT8U   tlv_type;
    INT8U   reason_code;
    INT8U   sta_mac_addr[ETHER_ADDR_LEN];
} error_code_tlv_t;

typedef struct mapSteeringBTMReportTLV {
    INT8U tlv_type;
    INT8U bssid[ETHER_ADDR_LEN];
    INT8U sta_mac[ETHER_ADDR_LEN];
    INT8U btm_status_code;
    INT8U target_bssid_present;
    INT8U target_bssid[ETHER_ADDR_LEN]; /* This field is valid only if target_bssid_present = 1 */
} steering_btm_report_tlv_t;

typedef struct steering_request_target_bss_s
{
    INT8U target_bssid[ETHER_ADDR_LEN];
    INT8U operating_class;
    INT8U channel_no;
} steering_request_target_bss;

typedef struct mapSteeringRequestTLV {
    INT8U tlv_type;
    INT16U tlv_length;
    INT8U bssid[ETHER_ADDR_LEN];
    INT8U flag;
    INT16U opportunity_wnd;
    INT16U disassociation_timer;
    INT8U sta_count;
    INT8U mac_addr[MAX_STATIONS][ETHER_ADDR_LEN];
    INT8U bssid_count;
    steering_request_target_bss target_bss[MAX_STATIONS];
}steering_request_tlv;

typedef struct generic_map_tlv_t {
    INT8U tlv_type;
    INT16U tlv_length;
    INT8U* tlv_bytes;
}generic_map_tlv;

typedef struct operating_class_s {
    INT8U operating_class;
    INT8U eirp;
    INT8U number_of_channels;
    INT8U channel_num[52];
} operating_class_t;

typedef struct mapApBasicCapabilityTLV {
    INT8U tlv_type;
	INT16U tlv_length;
    INT8U radioId[6];
    INT8U max_bss;
    INT8U numOperating_class;
    operating_class_t operating_class[36];
} AP_basic_capability_tlv_t;

typedef struct mapSupportedServiceTLV {
    INT8U tlv_type;
	INT16U tlv_length;
    INT8U number_of_service;
    INT8U supported_service_array[5];
} supported_service_tlv_t;

typedef struct mapSearchedServiceTLV {
    INT8U tlv_type;
	INT16U tlv_length;
    INT8U number_of_searched_service;
    INT8U searched_service_array[5];
} searched_service_tlv_t;

typedef struct mapApRadioIdTLV {
    INT8U tlv_type;
	INT16U tlv_length;
    INT8U radioId[6];
} AP_radio_id_tlv_t;

typedef struct radio_steering_s {
	INT8U radioId[6];
	INT8U steering_policy;
	INT8U channel_utilization_threshold;
	INT8U rssi_steering_threshold;
}radio_steering_t;

typedef struct mapSteeringPolicyTLV {
	INT8U tlv_type;
	INT16U tlv_length;
	INT8U number_of_local_steering_disallowed;
	INT8U *local_steering_macs;
	INT8U number_of_btm_steering_disallowed;
	INT8U *btm_steering_macs;
	INT8U number_of_radio;
	radio_steering_t radio_policy[MAX_RADIOS_PER_AGENT];
} steering_policy_tlv_t;

typedef struct radio_metric_s {
	INT8U radioId[6];
	INT8U reporting_rssi_threshold;
	INT8U reporting_rssi_margin_override;
	INT8U channel_utilization_reporting_threshold;
	INT8U associated_sta_policy;
}radio_metric_t;

typedef struct mapMetricPolicyTLV {
	INT8U tlv_type;
	INT16U tlv_length;
	INT8U metric_reporting_interval;
	INT8U number_of_radio;
	radio_metric_t radio_policy[MAX_RADIOS_PER_AGENT];
} metric_policy_tlv_t;

typedef struct mapClientAssociationEventTLV {
    INT8U tlv_type;
	INT16U tlv_length;
    INT8U mac[ETHER_ADDR_LEN];
    INT8U bssid[ETHER_ADDR_LEN];
    INT8U association_event;
} client_association_event_tlv_t;

/*
 * Data structures for AP Operational BSS Tlv
 * The below are the sub structures and 
 * main structure
 */
struct bssInfo {
    INT8U   bssid[ETHER_ADDR_LEN];
    INT8U   ssid_len;
    INT8U   ssid[MAX_SSID_LEN];
};

struct radioInfo {
    INT8U          radioId[ETHER_ADDR_LEN];
    INT8U          no_of_bss;
    struct bssInfo bss_info[MAX_BSS_PER_RADIO];
};

typedef struct mapApOperationalBssTLV {
    INT8U            tlv_type;
    INT16U           tlv_length;
    INT8U            no_of_radios;
    struct radioInfo radioInfo[MAX_RADIOS_PER_AGENT];
} ap_oerational_BSS_tlv_t;


/*
 * Data structures for AP Operational BSS Tlv
 * The below are the sub structures and 
 * main structure
 */
struct sta_time {
  INT8U   sta_mac[ETHER_ADDR_LEN];
  INT16U  since_assoc_time;
};

struct bss_info {
    INT8U           bssid[ETHER_ADDR_LEN];
    INT16U          no_of_sta;
    struct sta_time sta_assoc_time[MAX_STA_PER_BSS];
};

typedef struct mapAssociatedClientsTLV {
    INT8U            tlv_type;
    INT16U           tlv_length;
    INT8U            no_of_bss;
    struct bss_info  bssinfo[MAX_BSS_PER_RADIO];
} associated_clients_tlv_t;

typedef struct channel_pref_operating_class_s {
    INT8U operating_class;
    INT8U number_of_channels;
    INT8U channel_num[MAX_CHANNEL_IN_OPERATING_CLASS];
	INT8U pref_reason;
} channel_pref_operating_class_t;

typedef struct mapChannelPreferenceTLV {
    INT8U tlv_type;
	INT16U tlv_length;
    INT8U radio_id[ETHER_ADDR_LEN];
    INT8U numOperating_class;
    channel_pref_operating_class_t operating_class[MAX_OPERATING_CLASS];
} channel_preference_tlv_t;

typedef struct channel_restriction_s {
	INT8U channel_num;
	INT8U freq_restriction;
}channel_restriction_t;

typedef struct channel_restriction_operating_class_s {
    INT8U operating_class;
    INT8U number_of_channels;
    channel_restriction_t channel_restriction_set[MAX_CHANNEL_IN_OPERATING_CLASS];
} channel_restriction_operating_class_t;

typedef struct mapRadioOperationRestrictionTLV {
    INT8U tlv_type;
    INT16U tlv_length;
    INT8U radio_id[ETHER_ADDR_LEN];
    INT8U numOperating_class;
    channel_restriction_operating_class_t operating_class[MAX_OPERATING_CLASS];
} radio_operation_restriction_tlv_t;

typedef struct mapTransmitPowerTLV {
    INT8U tlv_type;
    INT16U tlv_length;
    INT8U radio_id[ETHER_ADDR_LEN];
    INT8U transmit_power_eirp;
} transmit_power_tlv_t;

typedef struct mapChannelSelectionResponseTLV {
    INT8U tlv_type;
    INT16U tlv_length;
    INT8U radio_id[ETHER_ADDR_LEN];
    INT8U channel_selection_response;
} channel_selection_response_tlv_t;

typedef struct operating_class_channel_s {
    INT8U operating_class;
    INT8U current_op_channel;
}operating_class_channel_t;

typedef struct mapOperatingChannelReportTLV {
    INT8U tlv_type;
    INT16U tlv_length;
    INT8U radio_id[ETHER_ADDR_LEN];
    INT8U numOperating_class;
    operating_class_channel_t operating_class[MAX_OPERATING_CLASS];
	INT8U current_transmit_power_eirp;
} operating_channel_report_tlv_t;

typedef struct mapApMetricsQueryTLV {
    INT8U tlv_type;
    INT16U tlv_length;
    INT8U numBss;
    INT8U bssid[MAX_BSSID_PER_AP_METRICS_QUERY][ETHER_ADDR_LEN];
} ap_metrics_query_tlv_t;

typedef union mapEspInfo { //esp = estimated service parameters
    struct {
       INT8U   esp_subelement;               //This holds access_category->0-1bits, data_format->3-4bits, ba_window_size->5-7
       INT8U   estimated_air_time_fraction;    // TBD
       INT8U   ppdu_target_duration;           // TBD
    };
    INT8U byte_stream[3];
} esp_info_t;

typedef struct mapApMetricsResponseTLV {
    INT8U          tlv_type;
    INT16U         tlv_length;
    INT8U          bssid[ETHER_ADDR_LEN];
    INT8U          channel_util;
    INT16U         sta_count;
    INT8U          esp_present;
    esp_info_t esp[MAX_ACCESS_CATEGORIES];
} ap_metrics_response_tlv_t;

typedef struct mapAssocStaTrafficStatsTLV {
    INT8U          tlv_type;
    INT16U         tlv_length;
    INT8U          sta_mac[ETHER_ADDR_LEN];
    INT32U          txbytes;
    INT32U          rxbytes;
    INT32U          txpkts;
    INT32U          rxpkts;
    INT32U          txpkterrors;
    INT32U          rxpkterrors;
    INT32U          retransmission_cnt;
} assoc_sta_traffic_stats_tlv_t;

typedef struct mapBeaconMetricsQueryTLV {
    INT8U         tlv_type;
    INT16U        tlv_length;
    INT8U         sta_mac[ETHER_ADDR_LEN]; 
    INT8U         operating_class;
    INT8U         channel;
    INT8U         bssid[ETHER_ADDR_LEN];
    INT8U         reporting_detail;
    INT8U         ssid_len;
    INT8U         ssid[MAX_SSID_LEN];
    INT8U         element_id_count;
    INT8U         elementIds[255];
    INT8U         ap_channel_report_count;
    struct ap_channel_report_elem {
        INT8U         length;
        INT8U         operating_class;
        INT8U         channel_list[MAX_TOTAL_CHANNELS];
    } ap_channel_report[1];

} beacon_metrics_query_tlv_t;

typedef struct mapBeaconMetricsResponseTLV {
    INT8U        tlv_type;
    INT16U       tlv_length;
    INT8U        sta_mac[ETHER_ADDR_LEN];
    INT8U        status_code;  /* MAP spec mentions "reserved" but looking at BRCM agent this seems to be a status code */
    INT8U        no_of_reports;
    map_beacon_report_element_t reports[1]; 
} beacon_metrics_response_tlv_t;

typedef struct mapUnassocStaMetricsQueryTLV {
    INT8U        tlv_type;
    INT16U       tlv_length;
    INT8U        oper_class;
    INT8U        channel_list_cnt;
    struct sta_channel_mac_list {
        uint8_t channel;
        uint8_t sta_count;
        uint8_t (*sta_mac)[MAC_ADDR_LEN];
    } sta_list[MAX_CHANNEL_IN_OPERATING_CLASS];
} unassoc_sta_metrics_query_tlv_t;

typedef struct mapUnassocStaMetricsResponseTLV {
    INT8U        tlv_type;
    INT16U       tlv_length;
    INT8U        oper_class;
    INT8U        sta_cnt;
    struct sta_rcpi_list {
        INT8U sta_mac[MAC_ADDR_LEN];
        INT8U channel;
        INT32U time_delta;
        INT8U rcpi_uplink;
    }sta_list[1];
} unassoc_sta_metrics_response_tlv_t;


extern INT8U* parse_multiap_tlvs_from_packet(INT8U *packet_stream);
extern INT8U *forge_multiap_tlvs_from_packet(INT8U *memory_structure, INT16U *len);
extern void free_multiap_TLV_structure(INT8U *memory_structure);

#endif
