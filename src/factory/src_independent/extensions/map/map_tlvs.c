/************* COPYRIGHT AND CONFIDENTIALITY INFORMATION NOTICE ************
** Copyright (c) [2019] – [Technicolor Delivery Technologies, SAS]          
** All Rights Reserved                                                      
** The source code form of this Open Source Project components              
** is subject to the terms of the BSD-2-Clause-Patent.                      
** You can redistribute it and/or modify it under the terms of              
** the BSD-2-Clause-Patent. (https://opensource.org/licenses/BSDplusPatent) 
** See COPYING file/LICENSE file for more details.    

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
 */

//#include "al_datamodel.h"
//#include "al_recv.h"
//#include "al_extension.h" // VendorSpecificTLVDuplicate
#include "1905_tlvs.h"
#include "packet_tools.h"
#include "map_server.h"
#include "map_tlvs.h"

#define MIN(a,b) \
   ({ __typeof__ (a) _a = (a); \
       __typeof__ (b) _b = (b); \
     _a < _b ? _a : _b; })


INT8U *forge_multiap_tlvs_from_packet(INT8U *memory_structure, INT16U *len)
{
    switch (*memory_structure)
    {
        case TLV_TYPE_SEARCHED_SERVICE:
        {
            searched_service_tlv_t *m;
            INT8U *ret, *p;
            INT16U tlv_length;

            m = (searched_service_tlv_t *)memory_structure;

            //#tlv_length = (INT16U)((searched_service_tlv_t *)m->number_of_searched_service + 1);
            //tlv_length = m->tlv_length;

            tlv_length = m->number_of_searched_service + 1;
            *len = TLV_TYPE_FIELD + TLV_LENGTH_FIELD + tlv_length;

            p = ret = (INT8U *)PLATFORM_MALLOC(1 + 2  + tlv_length);

            _I1B(&m->tlv_type,          &p);
            _I2B(&tlv_length,           &p);
            _I1B( &m->number_of_searched_service,    &p);
            _InB( m->searched_service_array,    &p, m->number_of_searched_service);

            return (INT8U *)ret;
        }

        case TLV_TYPE_SUPPORTED_SERVICE:
        {
            // This parsing is done according to the information detailed in
            // "IEEE Std 1905.1-2013 Section 6.4.1"
            supported_service_tlv_t *m;
            INT8U *p, *ret;
            INT16U tlv_length;

            m = (supported_service_tlv_t *)memory_structure;

            tlv_length = m->number_of_service + 1;
            *len = TLV_TYPE_FIELD + TLV_LENGTH_FIELD + tlv_length;
             p = ret = (INT8U *)PLATFORM_MALLOC(1 + 2  + tlv_length);

            _I1B(&m->tlv_type,          &p);
            _I2B(&tlv_length,           &p);
            _I1B( &m->number_of_service,    &p);
            _InB( m->supported_service_array,    &p, m->number_of_service);

            return (INT8U *)ret;
        }

        case TLV_TYPE_AP_RADIO_IDENTIFIER:
        {
            // This parsing is done according to the information detailed in
            // "IEEE Std 1905.1-2013 Section 6.4.1"
            AP_radio_id_tlv_t *m;
            INT8U *p, *ret;
            INT16U tlv_length;

            m = (AP_radio_id_tlv_t *)memory_structure;

            tlv_length = 6;
            *len = TLV_TYPE_FIELD + TLV_LENGTH_FIELD + tlv_length;
            p = ret = (INT8U *)PLATFORM_MALLOC(1 + 2  + tlv_length);

            _I1B(&m->tlv_type,          &p);
            _I2B(&tlv_length,           &p);
            _InB( m->radioId,    &p, tlv_length);

            return (INT8U *)ret;
        }

        case TLV_TYPE_AP_RADIO_BASIC_CAPABILITY:
        {
            AP_basic_capability_tlv_t *m;
            INT8U *p, *ret, i=0;
            INT16U tlv_length;

            m = (AP_basic_capability_tlv_t *)memory_structure;

            tlv_length = m->tlv_length;
            *len = TLV_TYPE_FIELD + TLV_LENGTH_FIELD + tlv_length;
            p = ret = (INT8U *)PLATFORM_MALLOC(1 + 2  + tlv_length);

            _I1B(&m->tlv_type,          &p);
            _I2B(&tlv_length,           &p);
            _InB( m->radioId,    &p, 6);
            _I1B( &m->max_bss,    &p);
            _I1B( &m->numOperating_class,    &p);

            for (i=0; i< m->numOperating_class; i++) {
                _I1B( &m->operating_class[i].operating_class,    &p);
                _I1B( &m->operating_class[i].eirp,    &p);
                _I1B( &m->operating_class[i].number_of_channels,    &p);
                _InB( m->operating_class[i].channel_num,    &p, m->operating_class[i].number_of_channels);
            }
            return (INT8U *)ret;
        }

        case TLV_TYPE_STEERING_POLICY:
        {
            steering_policy_tlv_t *m;
            INT8U *p, *ret, i=0;
            INT16U tlv_length;
            m = (steering_policy_tlv_t *)memory_structure;

            tlv_length = m->tlv_length;
            *len = TLV_TYPE_FIELD + TLV_LENGTH_FIELD + tlv_length;

            p = ret = (INT8U *)PLATFORM_MALLOC(1 + 2  + tlv_length);
            if (ret != NULL)
            {

	            _I1B(&m->tlv_type,          &p);
        	    _I2B(&tlv_length,           &p);
	            _I1B(&m->number_of_local_steering_disallowed, &p);

        	    for (i=0; i<m->number_of_local_steering_disallowed; i++)
	            {
        	        _InB((m->local_steering_macs + i*ETHER_ADDR_LEN), &p, ETHER_ADDR_LEN);
	            }

	            _I1B(&m->number_of_btm_steering_disallowed, &p);

	            for (i=0; i<m->number_of_btm_steering_disallowed; i++)
	            {
        	        _InB((m->btm_steering_macs + i*ETHER_ADDR_LEN), &p, ETHER_ADDR_LEN);
	            }

        	    _I1B(&m->number_of_radio, &p);

	            for (i=0; i<m->number_of_radio; i++)
        	    {
	                _InB(m->radio_policy[i].radioId, &p, 6);
        	        _I1B(&m->radio_policy[i].steering_policy, &p);
                	_I1B(&m->radio_policy[i].channel_utilization_threshold, &p);
	                _I1B(&m->radio_policy[i].rssi_steering_threshold, &p);
        	    }
	   }
	   else
                PLATFORM_PRINTF_DEBUG_ERROR("%s: %d, Malloc Failure TLV_TYPE_STEERING_POLICY \n",__func__, __LINE__);

           return (INT8U *)ret;
        }

        case TLV_TYPE_METRIC_REPORTING_POLICY:
        {
            metric_policy_tlv_t *m;
            INT8U *p, *ret, i=0;
            INT16U tlv_length;

            m = (metric_policy_tlv_t *)memory_structure;

            tlv_length = m->tlv_length;
            *len = TLV_TYPE_FIELD + TLV_LENGTH_FIELD + tlv_length;

            p = ret = (INT8U *)PLATFORM_MALLOC(1 + 2  + tlv_length);
            if (ret  != NULL)
            {

	            _I1B(&m->tlv_type,          &p);
	            _I2B(&tlv_length,           &p);
	            _I1B(&m->metric_reporting_interval, &p);
	            _I1B(&m->number_of_radio, &p);

	            for (i=0; i<m->number_of_radio; i++)
        	    {
	                _InB(m->radio_policy[i].radioId, &p, 6);
	                _I1B(&m->radio_policy[i].reporting_rssi_threshold, &p);
	                _I1B(&m->radio_policy[i].reporting_rssi_margin_override, &p);
	                _I1B(&m->radio_policy[i].channel_utilization_reporting_threshold, &p);
	                _I1B(&m->radio_policy[i].associated_sta_policy, &p);
	            }

	    }
	    else
                PLATFORM_PRINTF_DEBUG_ERROR("%s: %d, Malloc Failure TLV_TYPE_METRIC_REPORTING_POLICY \n",__func__, __LINE__);
            return (INT8U *)ret;
        }

        case TLV_TYPE_STEERING_REQUEST:
        {

			INT8U *p, *ret = NULL; int i = 0;
            steering_request_tlv * m = (steering_request_tlv*) memory_structure;

            p = ret = PLATFORM_MALLOC(TLV_TYPE_FIELD + TLV_LENGTH_FIELD + m->tlv_length);

			*len =  m->tlv_length + TLV_TYPE_FIELD + TLV_LENGTH_FIELD;

            _I1B(&m->tlv_type,          &p);
            _I2B(&m->tlv_length,        &p);
            _InB(&m->bssid,        &p, ETHER_ADDR_LEN);
            _I1B(&m->flag,        &p);			
			_I2B(&m->opportunity_wnd,	   &p);
			_I2B(&m->disassociation_timer,		  &p);

			_I1B(&m->sta_count, 	   &p);
			for(i = 0; i<m->sta_count;i++)
			{
				_InB(&m->mac_addr[i],		 &p, ETHER_ADDR_LEN);
			}

			_I1B(&m->bssid_count,		 &p);					
			for(i = 0; i<m->bssid_count; i++)
			{
				_InB(&m->target_bss[i].target_bssid,		&p, ETHER_ADDR_LEN);
				_I1B(&m->target_bss[i].operating_class, 	   &p);
				_I1B(&m->target_bss[i].channel_no,		  &p);
				
				PLATFORM_PRINTF_DEBUG_DETAIL("%s target bssid %02x:%02x:%02x:%02x:%02x:%02x\n", __FUNCTION__, m->target_bss[i].target_bssid[0], m->target_bss[i].target_bssid[1],
									m->target_bss[i].target_bssid[2], m->target_bss[i].target_bssid[3], m->target_bss[i].target_bssid[4], m->target_bss[i].target_bssid[5]);
			}						

			PLATFORM_PRINTF_DEBUG_DETAIL("opp wind %x, disassociation_timer %x, \n ", m->opportunity_wnd, m->disassociation_timer);
			PLATFORM_PRINTF_DEBUG_DETAIL("sta_count %x, bssid_count %x\n ", m->sta_count, m->bssid_count);
			PLATFORM_PRINTF_DEBUG_DETAIL("operating_class %x, channel_no %x\n ", m->target_bss[0].operating_class, m->target_bss[0].channel_no);
            
            return (INT8U*) ret;
        }

        case TLV_TYPE_CLIENT_ASSOCIATION_EVENT:
        {
            // This parsing is done according to the information detailed in
            // "IEEE Std 1905.1-2013 Section 6.4.1"
            client_association_event_tlv_t *m;
            INT8U *p, *ret;
            INT16U tlv_length;
             m = (client_association_event_tlv_t *)memory_structure;

             tlv_length = 13;
             *len = TLV_TYPE_FIELD + TLV_LENGTH_FIELD + tlv_length;
             p = ret = (INT8U *)PLATFORM_MALLOC(1 + 2  + tlv_length);

             _I1B(&m->tlv_type,&p);
             _I2B(&tlv_length,&p);
             _InB( m->mac,&p, ETHER_ADDR_LEN);
             _InB( m->bssid,&p, ETHER_ADDR_LEN);
             _I1B(&m->association_event,&p);

            return (INT8U *)ret;
        }
        case TLV_TYPE_AP_CAPABILITY:
        {
            struct mapAPCapabilityTLV *ap_capability_tlv;
            INT8U *p, *ret, temp;
            INT16U tlv_length;

            ap_capability_tlv = (struct mapAPCapabilityTLV *)memory_structure;

            tlv_length = AP_CAPABILITY_TLV_LEN;
            *len = TLV_TYPE_FIELD + TLV_LENGTH_FIELD + tlv_length;

            p = ret = (INT8U *)PLATFORM_MALLOC(*len);
            if (ret  == NULL)
            {
                PLATFORM_PRINTF_DEBUG_ERROR("%s: %d, Malloc failure for TLV_TYPE_AP_CAPABILITY\n",__func__, __LINE__);
                return NULL;
            }

            _I1B(&ap_capability_tlv->tlv_type,&p);
            _I2B(&tlv_length,&p);

            temp = ((ap_capability_tlv->operating_unsupported_link_metrics << BIT_SHIFT_7) |
                    (ap_capability_tlv->non_operating_unsupported_link_metrics << BIT_SHIFT_6) |
                    (ap_capability_tlv->agent_initiated_steering << BIT_SHIFT_5) | ap_capability_tlv->reserved);
            _I1B(&temp,&p);

            return (INT8U *)ret;
        }

        case TLV_TYPE_AP_HT_CAPABILITY:
        {
            struct mapAPHTCapabilityTLV *ap_ht_capability_tlv;
            INT8U *p, *ret, temp;
            INT16U tlv_length;

            ap_ht_capability_tlv = (struct mapAPHTCapabilityTLV *)memory_structure;

            tlv_length = AP_HT_CAPABILITY_TLV_LEN;
            *len = TLV_TYPE_FIELD + TLV_LENGTH_FIELD + tlv_length;

            p = ret = (INT8U *)PLATFORM_MALLOC(*len);
            if (ret  == NULL)
            {
                PLATFORM_PRINTF_DEBUG_ERROR("%s: %d, Malloc failure for TLV_TYPE_AP_HT_CAPABILITY\n",__func__, __LINE__);
                return NULL;
            }

            _I1B(&ap_ht_capability_tlv->tlv_type,&p);
            _I2B(&tlv_length,&p);
            _InB(&ap_ht_capability_tlv->radio_id,&p,ETHER_ADDR_LEN);

            temp = ((ap_ht_capability_tlv->max_supported_tx_streams << BIT_SHIFT_6) |
                    (ap_ht_capability_tlv->max_supported_rx_streams << BIT_SHIFT_4) |
                    (ap_ht_capability_tlv->gi_support_20mhz << BIT_SHIFT_3) |
                    (ap_ht_capability_tlv->gi_support_40mhz << BIT_SHIFT_2) |
                    (ap_ht_capability_tlv->ht_support_40mhz << BIT_SHIFT_1) |
                    ap_ht_capability_tlv->reserved);

            _I1B(&temp,&p);

            return (INT8U *)ret;
        }

        case TLV_TYPE_AP_VHT_CAPABILITY:
        {
            struct mapAPVHTCapabilityTLV *ap_vht_capability_tlv;
            INT8U *p, *ret, temp;
            INT16U tlv_length;

            ap_vht_capability_tlv = (struct mapAPVHTCapabilityTLV *)memory_structure;

            tlv_length = AP_VHT_CAPABILITY_TLV_LEN;
            *len = TLV_TYPE_FIELD + TLV_LENGTH_FIELD + tlv_length;

            p = ret = (INT8U *)PLATFORM_MALLOC(*len);
            if (ret  == NULL)
            {
                PLATFORM_PRINTF_DEBUG_ERROR("%s: %d, Malloc failure for TLV_TYPE_AP_VHT_CAPABILITY\n",__func__, __LINE__);
                return NULL;
            }

            _I1B(&ap_vht_capability_tlv->tlv_type,&p);
            _I2B(&tlv_length,&p);
            _InB(&ap_vht_capability_tlv->radio_id,&p,ETHER_ADDR_LEN);
            _I2B(&ap_vht_capability_tlv->supported_tx_mcs,&p);
            _I2B(&ap_vht_capability_tlv->supported_rx_mcs,&p);

            temp = ((ap_vht_capability_tlv->max_supported_tx_streams << BIT_SHIFT_5) |
                    (ap_vht_capability_tlv->max_supported_rx_streams << BIT_SHIFT_2) |
                    (ap_vht_capability_tlv->gi_support_80mhz << BIT_SHIFT_1) |
                    ap_vht_capability_tlv->gi_support_160mhz);
            _I1B(&temp,&p);

            temp = ((ap_vht_capability_tlv->support_80_80_mhz << BIT_SHIFT_7) |
                    (ap_vht_capability_tlv->support_160mhz << BIT_SHIFT_6) |
                    (ap_vht_capability_tlv->su_beamformer_capable << BIT_SHIFT_5) |
                    (ap_vht_capability_tlv->mu_beamformer_capable << BIT_SHIFT_4) |
                    ap_vht_capability_tlv->reserved);
            _I1B(&temp,&p);

            return (INT8U *)ret;
        }

        case TLV_TYPE_AP_HE_CAPABILITY:
        {
            struct mapAPHECapabilityTLV *ap_he_capability_tlv;
            INT8U *p, *ret, temp;
            INT16U tlv_length;

            ap_he_capability_tlv = (struct mapAPHECapabilityTLV *)memory_structure;

            tlv_length = AP_HE_CAPABILITY_TLV_MIN_LEN + ap_he_capability_tlv->supported_mcs_length;
            *len = TLV_TYPE_FIELD + TLV_LENGTH_FIELD + tlv_length;

            p = ret = (INT8U *)PLATFORM_MALLOC(*len);
            if (ret  == NULL)
            {
                PLATFORM_PRINTF_DEBUG_ERROR("%s: %d, Malloc failure for TLV_TYPE_AP_HE_CAPABILITY\n",__func__, __LINE__);
                return NULL;
            }

            _I1B(&ap_he_capability_tlv->tlv_type,&p);
            _I2B(&tlv_length,&p);
            _InB(&ap_he_capability_tlv->radio_id,&p,ETHER_ADDR_LEN);
            _I1B(&ap_he_capability_tlv->supported_mcs_length,&p);

            if(ap_he_capability_tlv->supported_mcs_length > 0)
                _InB(&ap_he_capability_tlv->supported_tx_rx_mcs, &p, ap_he_capability_tlv->supported_mcs_length);

            temp = ((ap_he_capability_tlv->max_supported_tx_streams << BIT_SHIFT_5) |
                    (ap_he_capability_tlv->max_supported_rx_streams << BIT_SHIFT_2) |
                    (ap_he_capability_tlv->support_80_80_mhz << BIT_SHIFT_1) |
                    ap_he_capability_tlv->support_160mhz);

            _I1B(&temp,&p);

            temp = ((ap_he_capability_tlv->su_beamformer_capable << BIT_SHIFT_7) |
                    (ap_he_capability_tlv->mu_beamformer_capable << BIT_SHIFT_6) |
                    (ap_he_capability_tlv->ul_mimo_capable << BIT_SHIFT_5) |
                    (ap_he_capability_tlv->ul_mimo_ofdma_capable << BIT_SHIFT_4) |
                    (ap_he_capability_tlv->dl_mimo_ofdma_capable << BIT_SHIFT_3) |
                    (ap_he_capability_tlv->ul_ofdma_capable << BIT_SHIFT_2) |
                    (ap_he_capability_tlv->dl_ofdma_capable << BIT_SHIFT_1) |
                    ap_he_capability_tlv->reserved);

            _I1B(&temp,&p);

            return (INT8U *)ret;
        }

        case TLV_TYPE_CLIENT_INFO:
        {
            struct mapClientInfoTLV *client_info_tlv;
            INT8U *p, *ret;
            INT16U tlv_length;

            client_info_tlv = (struct mapClientInfoTLV *)memory_structure;

            tlv_length = CLIENT_INFO_TLV_LEN;
            *len = TLV_TYPE_FIELD + TLV_LENGTH_FIELD + tlv_length;

            p = ret = (INT8U *)PLATFORM_MALLOC(*len);
            if (ret  == NULL)
            {
                PLATFORM_PRINTF_DEBUG_ERROR("%s: %d, Malloc failure for TLV_TYPE_CLIENT_INFO\n",__func__, __LINE__);
                return NULL;
            }

            _I1B(&client_info_tlv->tlv_type,&p);
            _I2B(&tlv_length,&p);
            _InB(&client_info_tlv->bssid, &p, ETHER_ADDR_LEN);
            _InB(&client_info_tlv->client_mac, &p, ETHER_ADDR_LEN);

            return (INT8U *)ret;
        }

        case TLV_TYPE_CLIENT_CAPABILITY_REPORT:
        {
            struct mapClientCapabilityReportTLV *client_capability_report_tlv;
            INT8U *p, *ret;

            client_capability_report_tlv = (struct mapClientCapabilityReportTLV *)memory_structure;

            *len = TLV_TYPE_FIELD + TLV_LENGTH_FIELD + client_capability_report_tlv->tlv_length;

            p = ret = (INT8U *)PLATFORM_MALLOC(*len);
            if (ret  == NULL)
            {
                PLATFORM_PRINTF_DEBUG_ERROR("%s: %d, Malloc failure for TLV_TYPE_CLIENT_CAPABILITY_REPORT\n",__func__, __LINE__);
                return NULL;
            }

            _I1B(&client_capability_report_tlv->tlv_type,   &p);
            _I2B(&client_capability_report_tlv->tlv_length, &p);
            _I1B(&client_capability_report_tlv->result_code,&p);

            if (client_capability_report_tlv->assoc_frame_len > 0)
                _InB(client_capability_report_tlv->assoc_frame, &p, client_capability_report_tlv->assoc_frame_len);

            return (INT8U *)ret;
        }

        case TLV_TYPE_STA_MAC_ADDRESS:
        {
            struct mapStaMacAddressTLV *sta_mac_tlv;
            INT8U *p, *ret;
            INT16U tlv_length;

            sta_mac_tlv = (struct mapStaMacAddressTLV *)memory_structure;

            tlv_length = STA_MAC_ADDRESS_TLV_LEN;
            *len = TLV_TYPE_FIELD + TLV_LENGTH_FIELD + tlv_length;

            p = ret = (INT8U *)PLATFORM_MALLOC(*len);
            if (ret  == NULL)
            {
                PLATFORM_PRINTF_DEBUG_ERROR("%s: %d, Malloc failure for TLV_TYPE_STA_MAC_ADDRESS\n",__func__, __LINE__);
                return NULL;
            }

            _I1B(&sta_mac_tlv->tlv_type, &p);
            _I2B(&tlv_length, &p);
            _InB(&sta_mac_tlv->associated_sta_mac, &p, ETHER_ADDR_LEN);

            return (INT8U *)ret;
        }

        case TLV_TYPE_ASSOCIATED_STA_LINK_METRICS:
        {
            struct mapAssociatedStaLinkMetricsTLV *assoc_sta_metric_tlv;
            INT8U *p, *ret, i;
            INT16U tlv_length;

            assoc_sta_metric_tlv = (struct mapAssociatedStaLinkMetricsTLV *)memory_structure;

            tlv_length = ASSOCIATED_STA_LINK_METRICS_TLV_MIN_LEN + (assoc_sta_metric_tlv->reported_bssid_count * STATION_METRICS_PER_BSS_LEN);
            *len = TLV_TYPE_FIELD + TLV_LENGTH_FIELD + tlv_length;

            p = ret = (INT8U *)PLATFORM_MALLOC(*len);
            if (ret  == NULL)
            {
                PLATFORM_PRINTF_DEBUG_ERROR("%s: %d, Malloc failure for TLV_TYPE_ASSOCIATED_STA_LINK_METRICS\n",__func__, __LINE__);
                return NULL;
            }

            _I1B(&assoc_sta_metric_tlv->tlv_type, &p);
            _I2B(&tlv_length, &p);
            _InB(&assoc_sta_metric_tlv->associated_sta_mac, &p, ETHER_ADDR_LEN);
            _I1B(&assoc_sta_metric_tlv->reported_bssid_count, &p);

            for (i = 0; i < assoc_sta_metric_tlv->reported_bssid_count; i++)
            {
                _InB(&assoc_sta_metric_tlv->sta_metrics[i].bssid,  &p, ETHER_ADDR_LEN);
                _I4B(&assoc_sta_metric_tlv->sta_metrics[i].report_time_interval, &p);
                _I4B(&assoc_sta_metric_tlv->sta_metrics[i].downlink_data_rate, &p);
                _I4B(&assoc_sta_metric_tlv->sta_metrics[i].uplink_data_rate, &p);
                _I1B(&assoc_sta_metric_tlv->sta_metrics[i].uplink_rssi, &p);
            }

            return (INT8U *)ret;
        }

        case TLV_TYPE_CLIENT_ASSOCIATION_CONTROL_REQUEST:
        {
            struct mapClientAsociationControlRequestTLV *client_assoc_req_tlv;
            INT8U *p, *ret, i;
            INT16U tlv_length;

            client_assoc_req_tlv = (struct mapClientAsociationControlRequestTLV *)memory_structure;

            tlv_length = CLIENT_ASSOCIATION_CONTROL_REQUEST_TLV_MIN_LEN + ((client_assoc_req_tlv->sta_count-1) * sizeof(sta_list_t));
            *len = TLV_TYPE_FIELD + TLV_LENGTH_FIELD + tlv_length;

            p = ret = (INT8U *)PLATFORM_MALLOC(*len);
            if (ret  == NULL)
            {
                PLATFORM_PRINTF_DEBUG_ERROR("%s: %d, Malloc failure for TLV_TYPE_CLIENT_ASSOCIATION_CONTROL_REQUEST\n",__func__, __LINE__);
                return NULL;
            }

            _I1B(&client_assoc_req_tlv->tlv_type, &p);
            _I2B(&tlv_length, &p);
            _InB(&client_assoc_req_tlv->bssid, &p, ETHER_ADDR_LEN);
            _I1B(&client_assoc_req_tlv->association_control, &p);
            _I2B(&client_assoc_req_tlv->validity_period, &p);
            _I1B(&client_assoc_req_tlv->sta_count, &p);

            for (i = 0; i < client_assoc_req_tlv->sta_count; i++)
            {
               _InB(&client_assoc_req_tlv->sta_list[i].sta_mac, &p, ETHER_ADDR_LEN);
            }

            return (INT8U *)ret;
        }

        case TLV_TYPE_BTM_REPORT:
        {
            struct mapSteeringBTMReportTLV *steering_btm_report_tlv = NULL;
            INT8U *p, *ret;
            INT16U tlv_length;

            steering_btm_report_tlv = (struct mapSteeringBTMReportTLV *)memory_structure;

           tlv_length = STEERING_BTM_REPORT_TLV_MIN_LEN;

            if (1 == steering_btm_report_tlv->target_bssid_present)
                tlv_length = tlv_length + ETHER_ADDR_LEN;

            *len = TLV_TYPE_FIELD + TLV_LENGTH_FIELD + tlv_length;

            p = ret = (INT8U *)PLATFORM_MALLOC(*len);
            if (ret  == NULL)
            {
                PLATFORM_PRINTF_DEBUG_ERROR("%s: %d, Malloc failure for TLV_TYPE_BTM_REPORT\n",__func__, __LINE__);
                return NULL;
            }

            _I1B(&steering_btm_report_tlv->tlv_type, &p);
            _I2B(&tlv_length, &p);
            _InB(&steering_btm_report_tlv->bssid, &p, ETHER_ADDR_LEN);
            _InB(&steering_btm_report_tlv->sta_mac, &p, ETHER_ADDR_LEN);
            _I1B(&steering_btm_report_tlv->btm_status_code, &p);

            if (1 == steering_btm_report_tlv->target_bssid_present)
                _InB(&steering_btm_report_tlv->target_bssid, &p, ETHER_ADDR_LEN);

            return (INT8U *)ret;
        }

        case TLV_TYPE_AP_OPERATIONAL_BSS:
        {
            // This parsing is done according to the information detailed in
            // "IEEE Std 1905.1-2013 Section 6.4.1"
            struct mapApOperationalBssTLV  *oper_bss_tlv = NULL;

            INT8U  *p                         = NULL; 
            INT8U  *ret                       = NULL;
            INT8U  index                      = 0;
            INT8U  j                          = 0;
            INT16U tlv_length                 = 0;

            PLATFORM_PRINTF_DEBUG_DETAIL("%s %d\n",__func__,__LINE__);

            oper_bss_tlv = (struct mapApOperationalBssTLV *)memory_structure;

            tlv_length = oper_bss_tlv->tlv_length;
            *len = (INT8U)sizeof(oper_bss_tlv->tlv_type) + (INT8U)sizeof(oper_bss_tlv->tlv_length) + tlv_length;
            p = ret = (INT8U *)PLATFORM_MALLOC(*len);

            _I1B(&oper_bss_tlv->tlv_type,     &p);
            _I2B(&tlv_length,      &p);

            _I1B(&oper_bss_tlv->no_of_radios, &p); 
            for (index=0; index< oper_bss_tlv->no_of_radios; index++) {
                _InB(oper_bss_tlv->radioInfo[index].radioId, &p, MAC_ADDR_LEN);
  
                _I1B(&oper_bss_tlv->radioInfo[index].no_of_bss, &p);
  
                for (j = 0; j< oper_bss_tlv->radioInfo[index].no_of_bss; j++) {
                    _InB(oper_bss_tlv->radioInfo[index].bss_info[j].bssid, &p, MAC_ADDR_LEN);
  
                    _I1B(&oper_bss_tlv->radioInfo[index].bss_info[j].ssid_len, &p);

                    _InB(oper_bss_tlv->radioInfo[index].bss_info[j].ssid, &p, oper_bss_tlv->radioInfo[index].bss_info[j].ssid_len);
  
                }
            }

            return (INT8U *)ret;

        }

        case TLV_TYPE_ASSOCIATED_STA_TLV:
        {
            // This parsing is done according to the information detailed in
            // "IEEE Std 1905.1-2013 Section 6.4.1"
            struct mapAssociatedClientsTLV *assoc_sta_tlv = NULL;
            INT8U  *p                         = NULL; 
            INT8U  *ret                       = NULL;
            INT8U  j                          = 0;
            INT8U  k                          = 0;
            INT16U tlv_length                 = 0;
            INT16U total_sta_count            = 0;

            PLATFORM_PRINTF_DEBUG_DETAIL("%s %d\n",__func__,__LINE__);

            assoc_sta_tlv = (struct mapAssociatedClientsTLV *)memory_structure;

            tlv_length = assoc_sta_tlv->tlv_length;
            *len = (INT8U)sizeof(assoc_sta_tlv->tlv_type) + (INT8U)sizeof(assoc_sta_tlv->tlv_length) + tlv_length;
            p = ret = (INT8U *)PLATFORM_MALLOC(*len);
            _I1B(&assoc_sta_tlv->tlv_type,    &p);
            _I2B(&tlv_length,     &p);

            _I1B(&assoc_sta_tlv->no_of_bss,    &p);
            for (j = 0; j< assoc_sta_tlv->no_of_bss; j++) {
               _InB(assoc_sta_tlv->bssinfo[j].bssid, &p, MAC_ADDR_LEN);

               if (assoc_sta_tlv->bssinfo[j].no_of_sta > MAX_STA_PER_BSS)
                   assoc_sta_tlv->bssinfo[j].no_of_sta = MAX_STA_PER_BSS;

               if (total_sta_count >= MAX_STATIONS)
                   assoc_sta_tlv->bssinfo[j].no_of_sta = 0;
               else if ((total_sta_count + assoc_sta_tlv->bssinfo[j].no_of_sta) > MAX_STATIONS)
                   assoc_sta_tlv->bssinfo[j].no_of_sta = MAX_STATIONS - total_sta_count;

               total_sta_count += assoc_sta_tlv->bssinfo[j].no_of_sta;

               _I2B(&assoc_sta_tlv->bssinfo[j].no_of_sta, &p);

               for(k = 0; k < assoc_sta_tlv->bssinfo[j].no_of_sta; k++) {
                   _InB(assoc_sta_tlv->bssinfo[j].sta_assoc_time[k].sta_mac, &p, MAC_ADDR_LEN);
                   _I2B(&assoc_sta_tlv->bssinfo[j].sta_assoc_time[k].since_assoc_time,     &p);
               }
            }

            return (INT8U *)ret;

        }

	case TLV_TYPE_CHANNEL_PREFERENCE:
        {
            
            channel_preference_tlv_t *m;
            INT8U *p, *ret, i=0;
            m = (channel_preference_tlv_t *)memory_structure;

            *len = TLV_TYPE_FIELD + TLV_LENGTH_FIELD + m->tlv_length;
	    p = ret = (INT8U *)PLATFORM_MALLOC(*len);
	    if (ret  == NULL)
            {
                PLATFORM_PRINTF_DEBUG_ERROR("%s: %d, Malloc failure for TLV_TYPE_CHANNEL_PREFERENCE\n",__func__, __LINE__);
                return NULL;
            }

	    _I1B(&m->tlv_type,&p);
	    _I2B(&m->tlv_length,&p);
	    _InB(m->radio_id,&p, ETHER_ADDR_LEN);
	    _I1B(&m->numOperating_class,&p);

            for (i=0; i< m->numOperating_class; i++) {
                _I1B( &m->operating_class[i].operating_class,&p);
                _I1B( &m->operating_class[i].number_of_channels,&p);
                _InB( m->operating_class[i].channel_num,&p, m->operating_class[i].number_of_channels);
				_I1B( &m->operating_class[i].pref_reason,&p);
            }

            return (INT8U *)ret;
        }

	case TLV_TYPE_RADIO_OPERATION_RESTRICTION:
        {
            
            radio_operation_restriction_tlv_t *m;
            INT8U *p, *ret, i=0, j=0;
	    m = (radio_operation_restriction_tlv_t *)memory_structure;

	    *len = TLV_TYPE_FIELD + TLV_LENGTH_FIELD + m->tlv_length;
	    p = ret = (INT8U *)PLATFORM_MALLOC(*len);
	    if (ret  == NULL)
            {
                PLATFORM_PRINTF_DEBUG_ERROR("%s: %d, Malloc failure for TLV_TYPE_RADIO_OPERATION_RESTRICTION\n",__func__, __LINE__);
                return NULL;
            }

	    _I1B(&m->tlv_type,&p);
	    _I2B(&m->tlv_length,&p);
	    _InB(m->radio_id,&p, ETHER_ADDR_LEN);
	    _I1B(&m->numOperating_class,&p);

            for (i=0; i< m->numOperating_class; i++) {
                _I1B( &m->operating_class[i].operating_class,&p);
                _I1B( &m->operating_class[i].number_of_channels,&p);
				for (j=0; j< m->operating_class[i].number_of_channels ; j++) {
                	_I1B( &m->operating_class[i].channel_restriction_set[j].channel_num,&p);
					_I1B( &m->operating_class[i].channel_restriction_set[j].freq_restriction,&p);
				}
            }

            return (INT8U *)ret;
        }

	case TLV_TYPE_TRANSMIT_POWER:
        {
            
            transmit_power_tlv_t *m;
            INT8U *p, *ret;
            INT16U tlv_length;
	    m = (transmit_power_tlv_t *)memory_structure;

	    tlv_length = TRANSMIT_POWER_TLV_LEN;
	    *len = TLV_TYPE_FIELD + TLV_LENGTH_FIELD + tlv_length;
	    p = ret = (INT8U *)PLATFORM_MALLOC(*len);
	    if (ret  == NULL)
            {
                PLATFORM_PRINTF_DEBUG_ERROR("%s: %d, Malloc failure for TLV_TYPE_TRANSMIT_POWER\n",__func__, __LINE__);
                return NULL;
            }

	    _I1B(&m->tlv_type,&p);
	    _I2B(&tlv_length,&p);
	    _InB(m->radio_id,&p, ETHER_ADDR_LEN);
	    _I1B(&m->transmit_power_eirp,&p);

            return (INT8U *)ret;
        }

		
	case TLV_TYPE_CHANNEL_SELECTION_RESPONSE:
	{
		
		channel_selection_response_tlv_t *m;
		INT8U *p, *ret;
		INT16U tlv_length;
		m = (channel_selection_response_tlv_t *)memory_structure;
		
		tlv_length = CHANNEL_SELECTION_RESPONSE_TLV_LEN;
		*len = TLV_TYPE_FIELD + TLV_LENGTH_FIELD + tlv_length;
		p = ret = (INT8U *)PLATFORM_MALLOC(*len);
		
		if (ret  == NULL)
		{
			PLATFORM_PRINTF_DEBUG_ERROR("%s: %d, Malloc failure for TLV_TYPE_CHANNEL_SELECTION_RESPONSE\n",__func__, __LINE__);
			return NULL;
		}

		_I1B(&m->tlv_type,&p);
		_I2B(&tlv_length,&p);
		_InB(m->radio_id,&p, ETHER_ADDR_LEN);
		_I1B(&m->channel_selection_response,&p);

		return (INT8U *)ret;
	}

       case TLV_TYPE_OPERATING_CHANNEL_REPORT:
       {
           
            operating_channel_report_tlv_t *m;
            INT8U *p, *ret, i=0;
            m = (operating_channel_report_tlv_t *)memory_structure;

	    *len = TLV_TYPE_FIELD + TLV_LENGTH_FIELD + m->tlv_length;
	    p = ret = (INT8U *)PLATFORM_MALLOC(*len);
			
	    if (ret  == NULL)
	    {
	 	   	PLATFORM_PRINTF_DEBUG_ERROR("%s: %d, Malloc failure for TLV_TYPE_OPERATING_CHANNEL_REPORT\n",__func__, __LINE__);
			return NULL;
	    }

	    _I1B(&m->tlv_type,&p);
	    _I2B(&m->tlv_length,&p);
	    _InB(m->radio_id,&p, ETHER_ADDR_LEN);
	    _I1B(&m->numOperating_class,&p);

            for (i=0; i< m->numOperating_class; i++) {
                _I1B( &m->operating_class[i].operating_class,&p);
                _I1B( &m->operating_class[i].current_op_channel,&p);
            }

	    _I1B(&m->current_transmit_power_eirp,&p);

            return (INT8U *)ret;
        }

        case TLV_TYPE_ERROR:
        {
            struct mapErrorCodeTLV *error_code_tlv;
            INT8U *p, *ret;
            INT16U tlv_length;

            error_code_tlv = (struct mapErrorCodeTLV *)memory_structure;

            tlv_length = ERROR_CODE_TLV_LEN;
            *len = TLV_TYPE_FIELD + TLV_LENGTH_FIELD + tlv_length;

            p = ret = (INT8U *)PLATFORM_MALLOC(*len);
            if (ret  == NULL)
            {
                PLATFORM_PRINTF_DEBUG_ERROR("%s: %d, Malloc failure for TLV_TYPE_ERROR \n",__func__, __LINE__);
                return NULL;
            }

            _I1B(&error_code_tlv->tlv_type,&p);
            _I2B(&tlv_length,&p);
            _I1B(&error_code_tlv->reason_code, &p);
            _InB(&error_code_tlv->sta_mac_addr, &p,ETHER_ADDR_LEN);

            return (INT8U *)ret;
        }

        case TLV_TYPE_AP_METRICS_QUERY:
        {
            struct mapApMetricsQueryTLV *ap_metrics_query_tlv = NULL;
            INT8U *p = NULL, *ret = NULL;
            INT8U  i   = 0;

            ap_metrics_query_tlv = (struct mapApMetricsQueryTLV *)memory_structure;

            *len = TLV_TYPE_FIELD + TLV_LENGTH_FIELD + ap_metrics_query_tlv->tlv_length;

            p = ret = (INT8U *)PLATFORM_MALLOC(*len);
            if (ret  == NULL)
            {
                PLATFORM_PRINTF_DEBUG_ERROR("%s: %d, Malloc failure for TLV_TYPE_ERROR \n",__func__, __LINE__);
                return NULL;
            }

            _I1B(&ap_metrics_query_tlv->tlv_type,   &p);
            _I2B(&ap_metrics_query_tlv->tlv_length, &p);
            _I1B(&ap_metrics_query_tlv->numBss, &p);
            for(i = 0; i<ap_metrics_query_tlv->numBss; i++) {
                _InB(&ap_metrics_query_tlv->bssid[i][0], &p, ETHER_ADDR_LEN);
            }

            return (INT8U *)ret;
        }

        case TLV_TYPE_AP_METRICS_RESPONSE:
        {
            struct mapApMetricsResponseTLV *ap_metrics_response;
            INT8U *p = NULL, *ret = NULL;
            INT8U  i   = 0;

            ap_metrics_response = (struct mapApMetricsResponseTLV *)memory_structure;
            *len = 0;

            if (ap_metrics_response->tlv_length < MIN_AP_METRICS_RESPONSE_TLV_LEN) 
           {
                // Malformed packet

                PLATFORM_PRINTF_DEBUG_ERROR("%s: %d, Malformed packet TLV_TYPE_AP_METRICS_RESPONSE \n",__func__, __LINE__);
                return NULL;
            }

            *len = TLV_TYPE_FIELD + TLV_LENGTH_FIELD + ap_metrics_response->tlv_length;

            p = ret = (INT8U *)PLATFORM_MALLOC(*len);
            if (ret  == NULL)
            {
                PLATFORM_PRINTF_DEBUG_ERROR("%s: %d, Malloc failure for TLV_TYPE_ERROR \n",__func__, __LINE__);
                return NULL;
            }

            _I1B(&ap_metrics_response->tlv_type,    &p);
            _I2B(&ap_metrics_response->tlv_length, &p);

            _InB(ap_metrics_response->bssid, &p, ETHER_ADDR_LEN);

            _I1B(&ap_metrics_response->channel_util, &p);
            _I2B(&ap_metrics_response->sta_count, &p);

            _I1B(&ap_metrics_response->esp_present, &p);

            for(i = 0; i<MAX_ACCESS_CATEGORIES; i++) {
                if(ap_metrics_response->esp_present & (1<<(7-i))) {
                     _InB(&ap_metrics_response->esp[i].byte_stream[0], &p, 3);
                }
            }
            return (INT8U *)ret;
        }

        case TLV_TYPE_ASSOC_STA_TRAFFIC_STATS:
        {
            struct mapAssocStaTrafficStatsTLV *assoc_sta_traffic_stats;
            INT8U *p = NULL, *ret = NULL;


            assoc_sta_traffic_stats = (struct mapAssocStaTrafficStatsTLV *)memory_structure;

            if (assoc_sta_traffic_stats->tlv_length < MIN_ASSOC_STA_TRAFFIC_STATS_TLV_LEN) 
            {
                // Malformed packet
                return NULL;
            }


            *len = TLV_TYPE_FIELD + TLV_LENGTH_FIELD + assoc_sta_traffic_stats->tlv_length;

            p = ret = (INT8U *)PLATFORM_MALLOC(*len);
            if (ret  == NULL)
            {
                PLATFORM_PRINTF_DEBUG_ERROR("%s: %d, Malloc failure for TLV_TYPE_ERROR \n",__func__, __LINE__);
                return NULL;
            }

            _I1B(&assoc_sta_traffic_stats->tlv_type,    &p);
            _I2B(&assoc_sta_traffic_stats->tlv_length,  &p);

            _InB(assoc_sta_traffic_stats->sta_mac, &p, ETHER_ADDR_LEN);

            _I4B(&assoc_sta_traffic_stats->txbytes, &p);
            _I4B(&assoc_sta_traffic_stats->rxbytes, &p);
            _I4B(&assoc_sta_traffic_stats->txpkts, &p);
            _I4B(&assoc_sta_traffic_stats->rxpkts, &p);
            _I4B(&assoc_sta_traffic_stats->txpkterrors, &p);
            _I4B(&assoc_sta_traffic_stats->rxpkterrors, &p);
            _I4B(&assoc_sta_traffic_stats->retransmission_cnt, &p);

            return (INT8U *)ret;
        }
        
        case TLV_TYPE_HIGHER_LAYER_DATA_MSG:
        {
            higher_layer_data_tlv_t *higher_layer_data;
            INT8U *p = NULL, *ret = NULL;

            higher_layer_data = (higher_layer_data_tlv_t *)memory_structure;

            *len = TLV_TYPE_FIELD + TLV_LENGTH_FIELD + higher_layer_data->tlv_length;

            p = ret = (INT8U *) PLATFORM_MALLOC(*len);
            if (ret  == NULL)
            {
                PLATFORM_PRINTF_DEBUG_ERROR("%s: %d, Malloc failure for TLV_TYPE_ERROR \n",__func__, __LINE__);
                return NULL;
            }

            _I1B(&higher_layer_data->tlv_type, &p);
            _I2B(&higher_layer_data->tlv_length, &p);

            _I1B(&higher_layer_data->higher_layer_proto, &p);
            _InB(higher_layer_data->payload, &p, (*len) - 4);

            return (INT8U *)ret;          
        }

        case TLV_TYPE_BEACON_METRICS_QUERY: 
        {
            beacon_metrics_query_tlv_t *beacon_metrics_query;
            INT8U *p = NULL, *ret = NULL, i =0;


            beacon_metrics_query = (beacon_metrics_query_tlv_t *)memory_structure;

            *len = TLV_TYPE_FIELD + TLV_LENGTH_FIELD + beacon_metrics_query->tlv_length;

            p = ret = (INT8U *)PLATFORM_MALLOC(*len);
            if (ret  == NULL)
            {
                PLATFORM_PRINTF_DEBUG_ERROR("%s: %d, Malloc failure for TLV_TYPE_ERROR \n",__func__, __LINE__);
                return NULL;
            }

            _I1B(&beacon_metrics_query->tlv_type,    &p);
            _I2B(&beacon_metrics_query->tlv_length,  &p);

            _InB(beacon_metrics_query->sta_mac, &p, ETHER_ADDR_LEN);
            _I1B(&beacon_metrics_query->operating_class,    &p);
            _I1B(&beacon_metrics_query->channel,    &p);
            _InB(beacon_metrics_query->bssid, &p, ETHER_ADDR_LEN);
            _I1B(&beacon_metrics_query->reporting_detail,    &p);
            _I1B(&beacon_metrics_query->ssid_len,    &p);
            _InB(beacon_metrics_query->ssid, &p, beacon_metrics_query->ssid_len);

            _I1B(&beacon_metrics_query->ap_channel_report_count,    &p);
             for(i=0; i<beacon_metrics_query->ap_channel_report_count; i++) {
                
                _I1B(&beacon_metrics_query->ap_channel_report[i].length,    &p);
                _I1B(&beacon_metrics_query->ap_channel_report[i].operating_class,    &p);
                /* Copy channel list - length includes the operating_class byte */
                _InB(beacon_metrics_query->ap_channel_report[i].channel_list, &p, beacon_metrics_query->ap_channel_report[i].length - 1);
                
              }

            _I1B(&beacon_metrics_query->element_id_count,    &p);
            _InB(beacon_metrics_query->elementIds, &p, beacon_metrics_query->element_id_count);
            return (INT8U *)ret;  
        }
        case TLV_TYPE_BEACON_METRICS_RESPONSE:
        {
            beacon_metrics_response_tlv_t *beacon_metrics_response;
            INT8U *p = NULL, *ret = NULL, i = 0;


            beacon_metrics_response = (beacon_metrics_response_tlv_t *)memory_structure;

            *len = TLV_TYPE_FIELD + TLV_LENGTH_FIELD + beacon_metrics_response->tlv_length;

            p = ret = (INT8U *)PLATFORM_MALLOC(*len);
            if (ret  == NULL)
            {
                PLATFORM_PRINTF_DEBUG_ERROR("%s: %d, Malloc failure for TLV_TYPE_ERROR \n",__func__, __LINE__);
                return NULL;
            }

            _I1B(&beacon_metrics_response->tlv_type,    &p);
            _I2B(&beacon_metrics_response->tlv_length,  &p);

            _InB(beacon_metrics_response->sta_mac, &p, ETHER_ADDR_LEN);

            _I1B(&beacon_metrics_response->status_code,  &p);
            _I1B(&beacon_metrics_response->no_of_reports,  &p);
            for(i=0; i<beacon_metrics_response->no_of_reports; i++) { 
                _InB(&beacon_metrics_response->reports[i], &p, 
                             sizeof(map_beacon_report_element_t));
            }
            return (INT8U *)ret;
        }

        case TLV_TYPE_UNASSOCIATED_STA_METRICS_QUERY:
        {
            struct mapUnassocStaMetricsQueryTLV *unassoc_sta_met;
            INT8U *p = NULL, *ret = NULL;
            INT8U (*sta_mac_ptr)[MAC_ADDR_LEN] = NULL;

            unassoc_sta_met = (struct mapUnassocStaMetricsQueryTLV*)memory_structure;

            *len = TLV_TYPE_FIELD + TLV_LENGTH_FIELD + unassoc_sta_met->tlv_length;

            p = ret = (INT8U *)PLATFORM_MALLOC(*len);
            if (ret  == NULL)
            {
                PLATFORM_PRINTF_DEBUG_ERROR("%s: %d, Malloc failure for TLV_TYPE_ERROR \n",__func__, __LINE__);
                return NULL;
            }

            _I1B(&unassoc_sta_met->tlv_type,    &p);
            _I2B(&unassoc_sta_met->tlv_length,  &p);

            _I1B(&unassoc_sta_met->oper_class,  &p);
            _I1B(&unassoc_sta_met->channel_list_cnt, &p);

            for(int i = 0; i <unassoc_sta_met->channel_list_cnt; i++){
                _I1B(&unassoc_sta_met->sta_list[i].channel, &p);
                _I1B(&unassoc_sta_met->sta_list[i].sta_count, &p);
                sta_mac_ptr = unassoc_sta_met->sta_list[i].sta_mac;
                for(int j = 0; j<unassoc_sta_met->sta_list[i].sta_count; j++) {
                    _InB((INT8U *)sta_mac_ptr, &p, MAC_ADDR_LEN);
                    sta_mac_ptr++;
                }
            }

            return (INT8U *)ret;
        }

        case TLV_TYPE_UNASSOCIATED_STA_METRICS_RESPONSE:
        {
            struct mapUnassocStaMetricsResponseTLV *unassoc_sta_met;
            INT8U *p = NULL, *ret = NULL, i = 0;

            unassoc_sta_met = (struct mapUnassocStaMetricsResponseTLV*)memory_structure;

            *len = TLV_TYPE_FIELD + TLV_LENGTH_FIELD + unassoc_sta_met->tlv_length;

            p = ret = (INT8U *)PLATFORM_MALLOC(*len);
            if (ret  == NULL)
            {
                PLATFORM_PRINTF_DEBUG_ERROR("%s: %d, Malloc failure for TLV_TYPE_ERROR \n",__func__, __LINE__);
                return NULL;
            }

            _I1B(&unassoc_sta_met->tlv_type,    &p);
            _I2B(&unassoc_sta_met->tlv_length,  &p);

            _I1B(&unassoc_sta_met->oper_class,  &p);
            _I1B(&unassoc_sta_met->sta_cnt, &p);


            for(i = 0; i <unassoc_sta_met->sta_cnt; i++){
                _InB(unassoc_sta_met->sta_list[i].sta_mac, &p, ETHER_ADDR_LEN);
                _I1B(&unassoc_sta_met->sta_list[i].channel, &p);
                _I4B(&unassoc_sta_met->sta_list[i].time_delta, &p);
                _I1B(&unassoc_sta_met->sta_list[i].rcpi_uplink, &p);
            }

            return (INT8U *)ret;
        }

        default:
            // Ignore
            //
        return NULL;
    }
    return 0;
}

INT8U* parse_multiap_tlvs_from_packet(INT8U *packet_stream)
{
    switch (*packet_stream)
    {
        case TLV_TYPE_SEARCHED_SERVICE:
        {
            searched_service_tlv_t *ret=NULL;
            INT8U *p;
            INT16U len;

            ret = (searched_service_tlv_t *)PLATFORM_MALLOC(sizeof(searched_service_tlv_t));
            if (ret  != NULL)
            {
            	ret->tlv_type = TLV_TYPE_SEARCHED_SERVICE;
            	p = packet_stream + 1;
            	_E2B(&p, &len);

	        _E1B(&p, &ret->number_of_searched_service);
	        _EnB(&p, ret->searched_service_array, ret->number_of_searched_service);
	    }
	    else
                PLATFORM_PRINTF_DEBUG_ERROR("%s: %d, Malloc Failure TLV_TYPE_SEARCHED_SERVICE \n",__func__, __LINE__);

            return (INT8U *)ret;
        }

        case TLV_TYPE_SUPPORTED_SERVICE:
        {
            // This parsing is done according to the information detailed in
            // "IEEE Std 1905.1-2013 Section 6.4.1"

            supported_service_tlv_t *ret=NULL;
            INT8U *p, i=0;
            INT16U len;

            ret = (supported_service_tlv_t *)PLATFORM_MALLOC(sizeof(supported_service_tlv_t));
            if (ret  != NULL) {
            	PLATFORM_PRINTF_DEBUG_DETAIL("%s: %d, Malloc TLV_TYPE_SUPPORTED_SERVICE ret=0x%p\n",__func__, __LINE__, ret);
            	ret->tlv_type = TLV_TYPE_SUPPORTED_SERVICE;
	        p = packet_stream + 1;

        	_E2B(&p, &len);
	       _E1B(&p, &ret->number_of_service);

               for (i=0; i<ret->number_of_service; i++) {
                    _E1B(&p, &ret->supported_service_array[i]);
               } 
//            _EnB(&p, ret->supported_service_array, ret->number_of_service);
    	    }
	    else
                PLATFORM_PRINTF_DEBUG_ERROR("%s: %d, Malloc Failure TLV_TYPE_SUPPORTED_SERVICE \n",__func__, __LINE__);
            return (INT8U *)ret;
        }

        case TLV_TYPE_AP_RADIO_IDENTIFIER:
        {
            // This parsing is done according to the information detailed in
            // "IEEE Std 1905.1-2013 Section 6.4.1"
            AP_radio_id_tlv_t *ret=NULL;
            INT8U *p;
            INT16U len;

            ret = (AP_radio_id_tlv_t *)PLATFORM_MALLOC(sizeof(AP_radio_id_tlv_t));
            if (ret  != NULL) {
            	ret->tlv_type = TLV_TYPE_AP_RADIO_IDENTIFIER;
            	p = packet_stream + 1;
            	_E2B(&p, &len);
            	_EnB(&p, ret->radioId, 6);
            }
	    else
                PLATFORM_PRINTF_DEBUG_ERROR("%s: %d, Malloc Failure TLV_TYPE_AP_RADIO_IDENTIFIER \n",__func__, __LINE__);
	    return (INT8U *)ret;
        }

        case TLV_TYPE_AP_RADIO_BASIC_CAPABILITY:
        {
            AP_basic_capability_tlv_t *ret;
            INT8U *p, i=0;

            ret = (AP_basic_capability_tlv_t *)PLATFORM_MALLOC(sizeof(AP_basic_capability_tlv_t));
            if (ret  != NULL) {
            	ret->tlv_type=TLV_TYPE_AP_RADIO_BASIC_CAPABILITY;
            	p = packet_stream + 1;
            	_E2B(&p,&ret->tlv_length);

            	_EnB( &p, ret->radioId, 6);
                _E1B(  &p,&ret->max_bss);
                _E1B( &p, &ret->numOperating_class);

                for (i=0; i< ret->numOperating_class; i++) {
                    _E1B( &p, &ret->operating_class[i].operating_class);
                    _E1B( &p,&ret->operating_class[i].eirp);
                    _E1B(&p,&ret->operating_class[i].number_of_channels);
                    _EnB(&p, ret->operating_class[i].channel_num,ret->operating_class[i].number_of_channels);
                }
	    }
	    else
                PLATFORM_PRINTF_DEBUG_ERROR("%s: %d, Malloc Failure TLV_TYPE_AP_RADIO_BASIC_CAPABILITY \n",__func__, __LINE__);
            return (INT8U *)ret;
        }
		
        case TLV_TYPE_STEERING_POLICY:
        {
            steering_policy_tlv_t *ret = NULL;
            INT8U *p, i=0;
            INT16U len;

            ret = (steering_policy_tlv_t *)PLATFORM_MALLOC(sizeof(steering_policy_tlv_t));
            if (ret  != NULL) {
            	ret->tlv_type = TLV_TYPE_STEERING_POLICY;
            	p = packet_stream +  (INT8U)sizeof(ret->tlv_type);
            	_E2B(&p, &len);
            	PLATFORM_PRINTF_DEBUG_DETAIL("%s: %d, TLV Policy =%d\n",__func__, __LINE__, ret->tlv_type);

                /* Check if number of disallow ever exceeds MAX_STATIONS */
            	_E1B(&p, &ret->number_of_local_steering_disallowed);
            	 PLATFORM_PRINTF_DEBUG_DETAIL("%s: %d, TLV steering disallowed =%d\n",__func__, __LINE__, ret->number_of_local_steering_disallowed);
		 if(ret->number_of_local_steering_disallowed > 0) {
			ret->local_steering_macs = (INT8U*)PLATFORM_MALLOC(ret->number_of_local_steering_disallowed*ETHER_ADDR_LEN*sizeof(INT8U));
			if(NULL != 	ret->local_steering_macs) {
				PLATFORM_MEMSET(ret->local_steering_macs, 0 ,ret->number_of_local_steering_disallowed*ETHER_ADDR_LEN*sizeof(INT8U));
		                for (i=0; i<ret->number_of_local_steering_disallowed; i++) {
		                    _EnB(&p, (ret->local_steering_macs + (i*ETHER_ADDR_LEN)), ETHER_ADDR_LEN);
	                	}
			}
		}
        else {
            ret->local_steering_macs = NULL;
        }

                _E1B(&p, &ret->number_of_btm_steering_disallowed);
		if(ret->number_of_btm_steering_disallowed > 0) {
			ret->btm_steering_macs = (INT8U*)PLATFORM_MALLOC(ret->number_of_btm_steering_disallowed*ETHER_ADDR_LEN*sizeof(INT8U));
			if(NULL != 	ret->btm_steering_macs) {
					PLATFORM_MEMSET(ret->btm_steering_macs, 0 ,ret->number_of_btm_steering_disallowed*ETHER_ADDR_LEN*sizeof(INT8U));	
	        		        for (i=0; i<ret->number_of_btm_steering_disallowed; i++) {
	                    		_EnB(&p, (ret->btm_steering_macs + (i*ETHER_ADDR_LEN)), ETHER_ADDR_LEN);
	                		}
			}
		}
        else {
            ret->btm_steering_macs = NULL;
        }

            	_E1B(&p, &ret->number_of_radio);
            	/* Check if number of radio ever exceeds 4 - TBD */
            	for (i=0; i<ret->number_of_radio && i<4; i++) {
                	_EnB(&p, &ret->radio_policy[i].radioId, ETHER_ADDR_LEN);
                	_E1B(&p, &ret->radio_policy[i].steering_policy);
               		_E1B(&p, &ret->radio_policy[i].channel_utilization_threshold);
                	_E1B(&p, &ret->radio_policy[i].rssi_steering_threshold);
                	PLATFORM_PRINTF_DEBUG_DETAIL("%s: %d, Radio Policy =%d\n",__func__, __LINE__, ret->radio_policy[i].steering_policy);
            	}
	    }
	    else
                PLATFORM_PRINTF_DEBUG_ERROR("%s: %d, Malloc Failure TLV_TYPE_STEERING_POLICY \n",__func__, __LINE__);

            return (INT8U *)ret;
        }

        case TLV_TYPE_METRIC_REPORTING_POLICY:
        {
            metric_policy_tlv_t *ret = NULL;
            INT8U *p, i=0;
            INT16U len;

            ret = (metric_policy_tlv_t *)PLATFORM_MALLOC(sizeof(metric_policy_tlv_t));
            if (ret != NULL) {

	        ret->tlv_type = TLV_TYPE_METRIC_REPORTING_POLICY;
            	p = packet_stream + (INT8U)sizeof(ret->tlv_type);
            	_E2B(&p, &len);

            	PLATFORM_PRINTF_DEBUG_DETAIL("%s: %d, TLV Policy =%d\n",__func__, __LINE__, ret->tlv_type);

            	_E1B(&p, &ret->metric_reporting_interval);
            	_E1B(&p, &ret->number_of_radio);

            	PLATFORM_PRINTF_DEBUG_DETAIL("%s: %d, METRIC INTERVAL =%d\n",__func__, __LINE__, ret->metric_reporting_interval);
            	/* Check if number of radio ever exceeds 4 - TBD */
            	for (i=0; i<ret->number_of_radio && i<4; i++) {
                	_EnB(&p, &ret->radio_policy[i].radioId, 6);
                	_E1B(&p, &ret->radio_policy[i].reporting_rssi_threshold);
                	_E1B(&p, &ret->radio_policy[i].reporting_rssi_margin_override);
                	_E1B(&p, &ret->radio_policy[i].channel_utilization_reporting_threshold);
                	_E1B(&p, &ret->radio_policy[i].associated_sta_policy);
                	PLATFORM_PRINTF_DEBUG_DETAIL("%s: %d, Radio RSSI threshold =%d\n",__func__, __LINE__, ret->radio_policy[i].reporting_rssi_threshold);
             	}
            }
	    else
                PLATFORM_PRINTF_DEBUG_ERROR("%s: %d, Malloc Failure TLV_TYPE_METRIC_REPORTING_POLICY \n",__func__, __LINE__);
            
	    return (INT8U *)ret;
        }

        case TLV_TYPE_STEERING_REQUEST:
        {
            INT8U *p; int i = 0;
            steering_request_tlv* ret = (steering_request_tlv *) PLATFORM_MALLOC(sizeof(steering_request_tlv));
			PLATFORM_MEMSET(ret, 0, sizeof(steering_request_tlv));

            p = packet_stream;
            _E1B(&p, &ret->tlv_type);
            _E2B(&p, &ret->tlv_length);
            _EnB(&p, &ret->bssid,   ETHER_ADDR_LEN);
            _E1B(&p, &ret->flag);			
			_E2B(&p, &ret->opportunity_wnd);
			_E2B(&p, &ret->disassociation_timer);

			_E1B(&p, &ret->sta_count);
			for(i = 0; i<ret->sta_count;i++) {
				_EnB(&p, &ret->mac_addr[i], ETHER_ADDR_LEN);
			}			 

			_E1B(&p, &ret->bssid_count);				
			for(i = 0; i<ret->bssid_count;i++) {
				_EnB(&p, &ret->target_bss[i].target_bssid,		  ETHER_ADDR_LEN);
				_E1B(&p, &ret->target_bss[i].operating_class);
				_E1B(&p, &ret->target_bss[i].channel_no);
				PLATFORM_PRINTF_DEBUG_DETAIL("%s: target bssid %02x:%02x:%02x:%02x:%02x:%02x operating_class %x, channel %x \n",__func__,ret->target_bss[i].target_bssid[0], 
											ret->target_bss[i].target_bssid[1],ret->target_bss[i].target_bssid[2], ret->target_bss[i].target_bssid[3], ret->target_bss[i].target_bssid[4],
											ret->target_bss[i].target_bssid[5],ret->target_bss[i].operating_class,ret->target_bss[i].channel_no);
			}

			PLATFORM_PRINTF_DEBUG_DETAIL("%s opp wind %x, disassociation_timer %x\n ", __func__, ret->opportunity_wnd, ret->disassociation_timer);
			PLATFORM_PRINTF_DEBUG_DETAIL("%s sta_count %x, bssid_count %x\n ", __func__, ret->sta_count, ret->bssid_count);
			PLATFORM_PRINTF_DEBUG_DETAIL("%s operating_class %x, channel_no %x\n ", __func__, ret->target_bss[0].operating_class, ret->target_bss[0].channel_no);			

            return (INT8U*) ret;
        }

        case TLV_TYPE_CLIENT_ASSOCIATION_EVENT:
        {
            // This parsing is done according to the information detailed in
            // "IEEE Std 1905.1-2013 Section 6.4.1"

            client_association_event_tlv_t *ret=NULL;

            INT8U *p;
            INT16U len;

            ret = (client_association_event_tlv_t *)PLATFORM_MALLOC(sizeof(client_association_event_tlv_t));
            if (ret  != NULL) {
            	ret->tlv_type = TLV_TYPE_CLIENT_ASSOCIATION_EVENT;
            	p = packet_stream + 1;
            	_E2B(&p, &len);
            	_EnB(&p, ret->mac, ETHER_ADDR_LEN);
            	_EnB(&p, ret->bssid, ETHER_ADDR_LEN);
            	_E1B(&p, &ret->association_event);
            }
	    else
                PLATFORM_PRINTF_DEBUG_ERROR("%s: %d, Malloc Failure TLV_TYPE_CLIENT_ASSOCIATION_EVENT \n",__func__, __LINE__);
            
	    return (INT8U *)ret;
        }

        case TLV_TYPE_AP_CAPABILITY:
        {
            struct mapAPCapabilityTLV *ap_capability_tlv;
            INT8U *p,temp;
            INT16U len;

            p = packet_stream + TLV_TYPE_FIELD;

            _E2B(&p,&len);

            if (AP_CAPABILITY_TLV_LEN != len)
            {
                // Malformed packet
                return NULL;
            }

            ap_capability_tlv = (struct mapAPCapabilityTLV *) PLATFORM_MALLOC(sizeof(struct mapAPCapabilityTLV));
            if (ap_capability_tlv  == NULL)
            {
                PLATFORM_PRINTF_DEBUG_ERROR("%s: %d, Malloc failure for TLV_TYPE_AP_CAPABILITY\n",__func__, __LINE__);
                return NULL;
            }

            ap_capability_tlv->tlv_type = TLV_TYPE_AP_CAPABILITY;

            _E1B(&p,&temp);

            ap_capability_tlv->operating_unsupported_link_metrics     = (temp & BIT_MASK_7) ? SET_BIT : RESET_BIT;
            ap_capability_tlv->non_operating_unsupported_link_metrics = (temp & BIT_MASK_6) ? SET_BIT : RESET_BIT;
            ap_capability_tlv->agent_initiated_steering               = (temp & BIT_MASK_5) ? SET_BIT : RESET_BIT;
            ap_capability_tlv->reserved                               = temp & (BIT_MASK_4 | BIT_MASK_3 | BIT_MASK_2 | BIT_MASK_1 | BIT_MASK_0);

            return (INT8U *)ap_capability_tlv;
        }

        case TLV_TYPE_AP_HT_CAPABILITY:
        {
            struct mapAPHTCapabilityTLV *ap_ht_capability_tlv;
            INT8U *p, temp;
            INT16U len;

            p = packet_stream + TLV_TYPE_FIELD;

            _E2B(&p,&len);

            if (AP_HT_CAPABILITY_TLV_LEN != len)
            {
                // Malformed packet
                return NULL;
            }

            ap_ht_capability_tlv = (struct mapAPHTCapabilityTLV *) PLATFORM_MALLOC(sizeof(struct mapAPHTCapabilityTLV));
            if (ap_ht_capability_tlv  == NULL)
            {
                PLATFORM_PRINTF_DEBUG_ERROR("%s: %d, Malloc failure for TLV_TYPE_AP_HT_CAPABILITY\n",__func__, __LINE__);
                return NULL;
            }

            ap_ht_capability_tlv->tlv_type = TLV_TYPE_AP_HT_CAPABILITY;

            _EnB(&p, ap_ht_capability_tlv->radio_id, ETHER_ADDR_LEN);
            _E1B(&p,&temp);

            ap_ht_capability_tlv->max_supported_tx_streams = (temp & (BIT_MASK_7 | BIT_MASK_6)) >> BIT_SHIFT_6;
            ap_ht_capability_tlv->max_supported_rx_streams = (temp & (BIT_MASK_5 | BIT_MASK_4)) >> BIT_SHIFT_4;
            ap_ht_capability_tlv->gi_support_20mhz         = (temp & BIT_MASK_3) ? SET_BIT : RESET_BIT;
            ap_ht_capability_tlv->gi_support_40mhz         = (temp & BIT_MASK_2) ? SET_BIT : RESET_BIT;
            ap_ht_capability_tlv->ht_support_40mhz         = (temp & BIT_MASK_1) ? SET_BIT : RESET_BIT;
            ap_ht_capability_tlv->reserved                 = (temp & BIT_MASK_0) ? SET_BIT : RESET_BIT;

            return (INT8U *)ap_ht_capability_tlv;
        }

        case TLV_TYPE_AP_VHT_CAPABILITY:
        {
            struct mapAPVHTCapabilityTLV *ap_vht_capability_tlv;
            INT8U *p, temp;
            INT16U len;

            p = packet_stream + TLV_TYPE_FIELD;

            _E2B(&p, &len);

            if (AP_VHT_CAPABILITY_TLV_LEN != len)
            {
                // Malformed packet
                return NULL;
            }

            ap_vht_capability_tlv = (struct mapAPVHTCapabilityTLV *)  PLATFORM_MALLOC(sizeof(struct mapAPVHTCapabilityTLV));
            if (ap_vht_capability_tlv  == NULL)
            {
                PLATFORM_PRINTF_DEBUG_ERROR("%s: %d, Malloc failure for TLV_TYPE_AP_VHT_CAPABILITY\n",__func__, __LINE__);
                return NULL;
            }

            ap_vht_capability_tlv->tlv_type = TLV_TYPE_AP_VHT_CAPABILITY;

            _EnB(&p, ap_vht_capability_tlv->radio_id, ETHER_ADDR_LEN);
            _E2B(&p, &ap_vht_capability_tlv->supported_tx_mcs);
            _E2B(&p, &ap_vht_capability_tlv->supported_rx_mcs);
            _E1B(&p, &temp);

            ap_vht_capability_tlv->max_supported_tx_streams = (temp & (BIT_MASK_7 | BIT_MASK_6 | BIT_MASK_5)) >> BIT_SHIFT_5;
            ap_vht_capability_tlv->max_supported_rx_streams = (temp & (BIT_MASK_4 | BIT_MASK_3 | BIT_MASK_2)) >> BIT_SHIFT_2;
            ap_vht_capability_tlv->gi_support_80mhz         = (temp & BIT_MASK_1) ? SET_BIT : RESET_BIT;
            ap_vht_capability_tlv->gi_support_160mhz        = (temp & BIT_MASK_0) ? SET_BIT : RESET_BIT;

             _E1B(&p, &temp);

            ap_vht_capability_tlv->support_80_80_mhz        = (temp & BIT_MASK_7) ? SET_BIT : RESET_BIT;
            ap_vht_capability_tlv->support_160mhz           = (temp & BIT_MASK_6) ? SET_BIT : RESET_BIT;
            ap_vht_capability_tlv->su_beamformer_capable    = (temp & BIT_MASK_5) ? SET_BIT : RESET_BIT;
            ap_vht_capability_tlv->mu_beamformer_capable    = (temp & BIT_MASK_4) ? SET_BIT : RESET_BIT;
            ap_vht_capability_tlv->reserved                 = temp & (BIT_MASK_3 | BIT_MASK_2 | BIT_MASK_1 | BIT_MASK_0);

            return (INT8U *)ap_vht_capability_tlv;
        }

        case TLV_TYPE_AP_HE_CAPABILITY:
        {
            struct mapAPHECapabilityTLV *ap_he_capability_tlv;
            INT8U *p, temp;
            INT16U len;

            p = packet_stream + TLV_TYPE_FIELD;

            _E2B(&p, &len);

            if (len < AP_HE_CAPABILITY_TLV_MIN_LEN)
            {
                // Malformed packet
                return NULL;
            }

            ap_he_capability_tlv = (struct mapAPHECapabilityTLV *)PLATFORM_MALLOC(sizeof(struct mapAPHECapabilityTLV));
            if (ap_he_capability_tlv  == NULL)
            {
                PLATFORM_PRINTF_DEBUG_ERROR("%s: %d, Malloc failure for TLV_TYPE_AP_HE_CAPABILITY\n",__func__, __LINE__);
                return NULL;
            }

            ap_he_capability_tlv->tlv_type = TLV_TYPE_AP_HE_CAPABILITY;

            _EnB(&p, ap_he_capability_tlv->radio_id, ETHER_ADDR_LEN);
            _E1B(&p, &ap_he_capability_tlv->supported_mcs_length);

            if(ap_he_capability_tlv->supported_mcs_length > 0)
                _EnB(&p, ap_he_capability_tlv->supported_tx_rx_mcs, ap_he_capability_tlv->supported_mcs_length);

            _E1B(&p, &temp);

            ap_he_capability_tlv->max_supported_tx_streams  = (temp & (BIT_MASK_7 | BIT_MASK_6 | BIT_MASK_5)) >> BIT_SHIFT_5;
            ap_he_capability_tlv->max_supported_rx_streams  = (temp & (BIT_MASK_4 | BIT_MASK_3 | BIT_MASK_2)) >> BIT_SHIFT_2;
            ap_he_capability_tlv->support_80_80_mhz         = (temp & BIT_MASK_1) ? SET_BIT : RESET_BIT;
            ap_he_capability_tlv->support_160mhz            = (temp & BIT_MASK_0) ? SET_BIT : RESET_BIT;

            _E1B(&p, &temp);

            ap_he_capability_tlv->su_beamformer_capable     = (temp & BIT_MASK_7) ? SET_BIT : RESET_BIT;
            ap_he_capability_tlv->mu_beamformer_capable     = (temp & BIT_MASK_6) ? SET_BIT : RESET_BIT;
            ap_he_capability_tlv->ul_mimo_capable           = (temp & BIT_MASK_5) ? SET_BIT : RESET_BIT;
            ap_he_capability_tlv->ul_mimo_ofdma_capable     = (temp & BIT_MASK_4) ? SET_BIT : RESET_BIT;
            ap_he_capability_tlv->dl_mimo_ofdma_capable     = (temp & BIT_MASK_3) ? SET_BIT : RESET_BIT;
            ap_he_capability_tlv->ul_ofdma_capable          = (temp & BIT_MASK_2) ? SET_BIT : RESET_BIT;
            ap_he_capability_tlv->dl_ofdma_capable          = (temp & BIT_MASK_1) ? SET_BIT : RESET_BIT;
            ap_he_capability_tlv->reserved                  = (temp & BIT_MASK_0) ? SET_BIT : RESET_BIT;

            return (INT8U *)ap_he_capability_tlv;
        }

        case TLV_TYPE_CLIENT_INFO:
        {
            struct mapClientInfoTLV *client_info_tlv;
            INT8U *p;
            INT16U len;

            p = packet_stream + TLV_TYPE_FIELD;

            _E2B(&p, &len);

            if (len != CLIENT_INFO_TLV_LEN)
            {
                // Malformed packet
                return NULL;
            }

            client_info_tlv = (struct mapClientInfoTLV *) PLATFORM_MALLOC(sizeof(struct mapClientInfoTLV));
            if (client_info_tlv  == NULL)
            {
                PLATFORM_PRINTF_DEBUG_ERROR("%s: %d, Malloc failure for TLV_TYPE_CLIENT_INFO\n",__func__, __LINE__);
                return NULL;
            }

            client_info_tlv->tlv_type = TLV_TYPE_CLIENT_INFO;

            _EnB(&p, client_info_tlv->bssid, ETHER_ADDR_LEN);
            _EnB(&p, client_info_tlv->client_mac, ETHER_ADDR_LEN);

            return (INT8U *)client_info_tlv;
        }

        case TLV_TYPE_CLIENT_CAPABILITY_REPORT:
        {
            struct mapClientCapabilityReportTLV *client_capability_report_tlv;
            INT8U *p;
            INT8U *tlv_stream = NULL;
            INT16U len;

            p = packet_stream + TLV_TYPE_FIELD;

            _E2B(&p, &len);

            if (len < CLIENT_CAPABILITY_REPORT_TLV_MIN_LEN)
            {
                // Malformed packet
                return NULL;
            }

            /*
             * Allocate the memory for client_capability_report_tlv.
             * 
             * Allocate the memory for assoc frame as well with in this 
             * , so that we dont't need sepetate malloc for assoc frame.
             *
             * The allocated memory will be in format:
             * 0 -  sizeof(client_capability_report_tlv_t)  --> for client cap structure. 
             * sizeof(client_capability_report_tlv_t) - end --> for assoc frame.
             *
             */

            client_capability_report_tlv = (struct mapClientCapabilityReportTLV *) PLATFORM_MALLOC(len + sizeof(client_capability_report_tlv_t));

            if (client_capability_report_tlv  == NULL)
            {
                PLATFORM_PRINTF_DEBUG_ERROR("%s: %d, Malloc failure for TLV_TYPE_CLIENT_CAPABILITY_REPORT\n",__func__, __LINE__);
                return NULL;
            }

            tlv_stream =  (uint8_t *)client_capability_report_tlv;

            client_capability_report_tlv->tlv_type = TLV_TYPE_CLIENT_CAPABILITY_REPORT;

            _E1B(&p, &client_capability_report_tlv->result_code);

            client_capability_report_tlv->assoc_frame_len = 0;
            client_capability_report_tlv->assoc_frame   = NULL;

            len--;

            if (client_capability_report_tlv->result_code == SUCCESS && len > 0) {
                client_capability_report_tlv->assoc_frame_len = len;
                client_capability_report_tlv->assoc_frame = (uint8_t *)&tlv_stream[sizeof(client_capability_report_tlv_t)];
                _EnB(&p, client_capability_report_tlv->assoc_frame,len); 
            }

            return (INT8U *)client_capability_report_tlv;
        }

        case TLV_TYPE_STA_MAC_ADDRESS:
        {
            struct mapStaMacAddressTLV *sta_mac_tlv;
            INT8U *p;
            INT16U len;

            p = packet_stream + TLV_TYPE_FIELD;

            _E2B(&p, &len);

            if (len < STA_MAC_ADDRESS_TLV_LEN)
            {
                // Malformed packet
                return NULL;
            }

            sta_mac_tlv = (struct mapStaMacAddressTLV *) PLATFORM_MALLOC(sizeof(struct mapStaMacAddressTLV));
            if (NULL == sta_mac_tlv)
            {
                PLATFORM_PRINTF_DEBUG_ERROR("%s: %d, Malloc failure for STA_MAC_ADDRESS_TLV_LEN\n",__func__, __LINE__);
                return NULL;
            }

            sta_mac_tlv->tlv_type = TLV_TYPE_STA_MAC_ADDRESS;

            _EnB(&p, &sta_mac_tlv->associated_sta_mac, ETHER_ADDR_LEN);

            return (INT8U *)sta_mac_tlv;
        }

        case TLV_TYPE_ASSOCIATED_STA_LINK_METRICS:
        {
            struct mapAssociatedStaLinkMetricsTLV *assoc_sta_metric_tlv;
            INT8U *p, i;
            INT16U len, tlv_len;
            INT8U sta_mac[ETHER_ADDR_LEN];
            INT8U bssid_count = 0;

            p = packet_stream + TLV_TYPE_FIELD;

            _E2B(&p, &len);

            if (len < ASSOCIATED_STA_LINK_METRICS_TLV_MIN_LEN)
            {
                // Malformed packet
                return NULL;
            }

            _EnB(&p, &sta_mac, ETHER_ADDR_LEN);
            _E1B(&p, &bssid_count);

            if (bssid_count > 1)
                tlv_len = sizeof(struct mapAssociatedStaLinkMetricsTLV) + ((bssid_count - 1) * sizeof(struct sta_link_metric_s));
            else
                tlv_len = sizeof(struct mapAssociatedStaLinkMetricsTLV);

            assoc_sta_metric_tlv = (struct mapAssociatedStaLinkMetricsTLV *) PLATFORM_MALLOC(tlv_len);

            if (NULL == assoc_sta_metric_tlv)
            {
                PLATFORM_PRINTF_DEBUG_ERROR("%s: %d, Malloc failure for TLV_TYPE_ASSOCIATED_STA_LINK_METRICS\n",__func__, __LINE__);
                return NULL;
            }

            assoc_sta_metric_tlv->tlv_type = TLV_TYPE_ASSOCIATED_STA_LINK_METRICS;

            PLATFORM_MEMCPY(assoc_sta_metric_tlv->associated_sta_mac, sta_mac, ETHER_ADDR_LEN);
            assoc_sta_metric_tlv->reported_bssid_count = bssid_count;

            for (i = 0; i < assoc_sta_metric_tlv->reported_bssid_count; i++)
            {
                _EnB(&p, &assoc_sta_metric_tlv->sta_metrics[i].bssid, ETHER_ADDR_LEN);
                _E4B(&p, &assoc_sta_metric_tlv->sta_metrics[i].report_time_interval);
                _E4B(&p, &assoc_sta_metric_tlv->sta_metrics[i].downlink_data_rate);
                _E4B(&p, &assoc_sta_metric_tlv->sta_metrics[i].uplink_data_rate);
                _E1B(&p, &assoc_sta_metric_tlv->sta_metrics[i].uplink_rssi);
            }

            return (INT8U *)assoc_sta_metric_tlv;
        }

        case TLV_TYPE_CLIENT_ASSOCIATION_CONTROL_REQUEST:
        {
            struct mapClientAsociationControlRequestTLV *client_assoc_req_tlv;
            INT8U *p, i;
            INT16U len, tlv_len;
            INT8U bssid[ETHER_ADDR_LEN] = {0};
            INT8U association_control   = 0;
            INT16U validity_period      = 0;
            INT8U sta_count             = 0;

            p = packet_stream + TLV_TYPE_FIELD;

            _E2B(&p, &len);

            if (len < CLIENT_ASSOCIATION_CONTROL_REQUEST_TLV_MIN_LEN)
            {
                // Malformed packet
                return NULL;
            }

            _EnB(&p, &bssid, ETHER_ADDR_LEN);
            _E1B(&p, &association_control);
            _E2B(&p, &validity_period);
            _E1B(&p, &sta_count);

            tlv_len = sizeof(struct mapClientAsociationControlRequestTLV) + ((sta_count-1) * sizeof(sta_list_t));
            client_assoc_req_tlv = (struct mapClientAsociationControlRequestTLV *) PLATFORM_MALLOC(tlv_len);

            if (NULL == client_assoc_req_tlv)
            {
                PLATFORM_PRINTF_DEBUG_ERROR("%s: %d, Malloc failure for TLV_TYPE_CLIENT_ASSOCIATION_CONTROL_REQUEST\n",__func__, __LINE__);
                return NULL;
            }

            client_assoc_req_tlv->tlv_type = TLV_TYPE_CLIENT_ASSOCIATION_CONTROL_REQUEST;

            PLATFORM_MEMCPY(client_assoc_req_tlv->bssid, bssid, ETHER_ADDR_LEN);
            client_assoc_req_tlv->association_control = association_control;
            client_assoc_req_tlv->validity_period     = validity_period;
            client_assoc_req_tlv->sta_count           = sta_count;

            for (i = 0; i < sta_count; i++)
                _EnB(&p, &client_assoc_req_tlv->sta_list[i].sta_mac, ETHER_ADDR_LEN);

            return (INT8U *)client_assoc_req_tlv;
        }

        case TLV_TYPE_BTM_REPORT:
        {
            struct mapSteeringBTMReportTLV *steering_btm_report_tlv = NULL;
            INT8U *p;
            INT16U len;

            p = packet_stream + TLV_TYPE_FIELD;
            _E2B(&p, &len);

            if (len < STEERING_BTM_REPORT_TLV_MIN_LEN)
            {
                // Malformed packet
                return NULL;
            }

            steering_btm_report_tlv = (struct mapSteeringBTMReportTLV *) PLATFORM_MALLOC(sizeof(struct mapSteeringBTMReportTLV));
            if (NULL == steering_btm_report_tlv)
            {
                PLATFORM_PRINTF_DEBUG_ERROR("%s: %d, Malloc failure for TLV_TYPE_BTM_REPORT\n",__func__, __LINE__);
                return NULL;
            }

            steering_btm_report_tlv->tlv_type = TLV_TYPE_BTM_REPORT;

            _EnB(&p, &steering_btm_report_tlv->bssid, ETHER_ADDR_LEN);
            _EnB(&p, &steering_btm_report_tlv->sta_mac, ETHER_ADDR_LEN);
            _E1B(&p, &steering_btm_report_tlv->btm_status_code);
            steering_btm_report_tlv->target_bssid_present = 0;

            if (len == (STEERING_BTM_REPORT_TLV_MIN_LEN + ETHER_ADDR_LEN)) {
                steering_btm_report_tlv->target_bssid_present = 1;
                _EnB(&p, &steering_btm_report_tlv->target_bssid, ETHER_ADDR_LEN);
            }

            return (INT8U *)steering_btm_report_tlv;
        }

        case TLV_TYPE_AP_OPERATIONAL_BSS:
        {
            // This parsing is done according to the information detailed in
            // "IEEE Std 1905.1-2013 Section 6.4.1"

            struct mapApOperationalBssTLV  *oper_bss_tlv = NULL;

            INT8U  *p                           = NULL; 
            INT8U  index                        = 0;
            INT8U  j                            = 0;
            INT16U tlv_length                   = 0;

            PLATFORM_PRINTF_DEBUG_DETAIL("%s: %d \n",__func__, __LINE__);
            oper_bss_tlv = (struct mapApOperationalBssTLV *)PLATFORM_MALLOC(sizeof(struct mapApOperationalBssTLV));
            if (oper_bss_tlv  == NULL) {
                PLATFORM_PRINTF_DEBUG_ERROR("%s: %d, Malloc Failure TLV_TYPE_AP_OPERATIONAL_BSS \n",__func__, __LINE__);
                return (INT8U *)oper_bss_tlv;
            }
            oper_bss_tlv->tlv_type = TLV_TYPE_AP_OPERATIONAL_BSS;
            p = packet_stream + (INT8U)sizeof(oper_bss_tlv->tlv_type);

            _E2B(&p, &tlv_length);

            _E1B(&p, &oper_bss_tlv->no_of_radios); 
			if (oper_bss_tlv->no_of_radios > MAX_RADIOS_PER_AGENT)
				oper_bss_tlv->no_of_radios = MAX_RADIOS_PER_AGENT;
				
            for (index=0; index< oper_bss_tlv->no_of_radios; index++) {
                _EnB(&p, oper_bss_tlv->radioInfo[index].radioId, MAC_ADDR_LEN);
  
                _E1B(&p, &oper_bss_tlv->radioInfo[index].no_of_bss);
  
                for (j = 0; j< oper_bss_tlv->radioInfo[index].no_of_bss; j++) {
                    _EnB(&p, oper_bss_tlv->radioInfo[index].bss_info[j].bssid, MAC_ADDR_LEN);
                    _E1B(&p, &oper_bss_tlv->radioInfo[index].bss_info[j].ssid_len);
                    _EnB(&p, oper_bss_tlv->radioInfo[index].bss_info[j].ssid, oper_bss_tlv->radioInfo[index].bss_info[j].ssid_len);
                }
            }
            return (INT8U *)oper_bss_tlv;
        }

        case TLV_TYPE_ASSOCIATED_STA_TLV:
        {
            // This parsing is done according to the information detailed in
            // "IEEE Std 1905.1-2013 Section 6.4.1"

            struct mapAssociatedClientsTLV *assoc_sta_tlv = NULL;
            INT8U  *p                           = NULL; 
            INT8U  j                            = 0;
            INT8U  k                            = 0;
            INT16U tlv_length                   = 0;
            INT16U total_sta_count              = 0;

            PLATFORM_PRINTF_DEBUG_DETAIL("%s: %d \n",__func__, __LINE__);
            assoc_sta_tlv = (struct mapAssociatedClientsTLV *)PLATFORM_MALLOC(sizeof(struct mapAssociatedClientsTLV));
            if (assoc_sta_tlv  == NULL) {
                PLATFORM_PRINTF_DEBUG_ERROR("%s: %d, Malloc Failure TLV_TYPE_ASSOCIATED_STA_TLV \n",__func__, __LINE__);
                return (INT8U *)assoc_sta_tlv;
            }
            assoc_sta_tlv->tlv_type = TLV_TYPE_ASSOCIATED_STA_TLV;
            p = packet_stream + (INT8U)sizeof(assoc_sta_tlv->tlv_type);
            _E2B(&p, &tlv_length);

            _E1B(&p, &assoc_sta_tlv->no_of_bss);

            for (j = 0; j< assoc_sta_tlv->no_of_bss; j++) {

               _EnB(&p, assoc_sta_tlv->bssinfo[j].bssid, MAC_ADDR_LEN);
               _E2B(&p, &assoc_sta_tlv->bssinfo[j].no_of_sta);

               if (assoc_sta_tlv->bssinfo[j].no_of_sta > MAX_STA_PER_BSS)
                   assoc_sta_tlv->bssinfo[j].no_of_sta = MAX_STA_PER_BSS;

               if (total_sta_count >= MAX_STATIONS)
                   assoc_sta_tlv->bssinfo[j].no_of_sta = 0;
               else if ((assoc_sta_tlv->bssinfo[j].no_of_sta + total_sta_count) > MAX_STATIONS)
                   assoc_sta_tlv->bssinfo[j].no_of_sta =  MAX_STATIONS - total_sta_count;

               total_sta_count += assoc_sta_tlv->bssinfo[j].no_of_sta;

               for(k = 0; k < assoc_sta_tlv->bssinfo[j].no_of_sta; k++) {
                   _EnB(&p, assoc_sta_tlv->bssinfo[j].sta_assoc_time[k].sta_mac, MAC_ADDR_LEN);
                   _E2B(&p, &assoc_sta_tlv->bssinfo[j].sta_assoc_time[k].since_assoc_time);
               }
            }

            return (INT8U *)assoc_sta_tlv;
        }

	case TLV_TYPE_CHANNEL_PREFERENCE:
        {
            
            channel_preference_tlv_t *ret=NULL;

            INT8U *p, i=0;

            ret = (channel_preference_tlv_t *)PLATFORM_MALLOC(sizeof(channel_preference_tlv_t));
            if (ret  == NULL) {
                PLATFORM_PRINTF_DEBUG_ERROR("%s: %d, Malloc Failure TLV_TYPE_CHANNEL_PREFERENCE\n",__func__, __LINE__);
		return NULL;
            }
            ret->tlv_type = TLV_TYPE_CHANNEL_PREFERENCE;
            p = packet_stream + 1;
            _E2B(&p,&ret->tlv_length);
            _EnB(&p,ret->radio_id, ETHER_ADDR_LEN);
            _E1B(&p,&ret->numOperating_class);
             for (i=0; i< ret->numOperating_class; i++) {
                _E1B(&p,&ret->operating_class[i].operating_class);
                _E1B(&p,&ret->operating_class[i].number_of_channels);
                _EnB(&p,ret->operating_class[i].channel_num,ret->operating_class[i].number_of_channels);
				_E1B(&p,&ret->operating_class[i].pref_reason);
            }
            return (INT8U *)ret;
        }

	case TLV_TYPE_RADIO_OPERATION_RESTRICTION:
        {
            
            radio_operation_restriction_tlv_t *ret=NULL;

            INT8U *p, i=0, j=0;

            ret = (radio_operation_restriction_tlv_t *)PLATFORM_MALLOC(sizeof(radio_operation_restriction_tlv_t));
            if (ret  == NULL) {
                PLATFORM_PRINTF_DEBUG_ERROR("%s: %d, Malloc Failure TLV_TYPE_RADIO_OPERATION_RESTRICTION \n",__func__, __LINE__);
		return NULL;
            }
            ret->tlv_type = TLV_TYPE_RADIO_OPERATION_RESTRICTION;
            p = packet_stream + 1;
            _E2B(&p,&ret->tlv_length);
            _EnB(&p,ret->radio_id, ETHER_ADDR_LEN);
            _E1B(&p,&ret->numOperating_class);
             for (i=0; i< ret->numOperating_class; i++) 
			 {
                _E1B(&p,&ret->operating_class[i].operating_class);
                _E1B(&p,&ret->operating_class[i].number_of_channels);
				for(j=0; j<ret->operating_class[i].number_of_channels; j++)
				{
	                _E1B(&p,&ret->operating_class[i].channel_restriction_set[j].channel_num);
					_E1B(&p,&ret->operating_class[i].channel_restriction_set[j].freq_restriction);
				}
            }
            return (INT8U *)ret;
        }

	case TLV_TYPE_TRANSMIT_POWER:
        {
           
            transmit_power_tlv_t *ret=NULL;

            INT8U *p;
            ret = (transmit_power_tlv_t *)PLATFORM_MALLOC(sizeof(transmit_power_tlv_t));
            if (ret  == NULL) {
                PLATFORM_PRINTF_DEBUG_ERROR("%s: %d, Malloc Failure TLV_TYPE_TRANSMIT_POWER \n",__func__, __LINE__);
		return NULL;
            }
            ret->tlv_type = TLV_TYPE_TRANSMIT_POWER;
            p = packet_stream + 1;
            _E2B(&p,&ret->tlv_length);
            _EnB(&p,ret->radio_id, ETHER_ADDR_LEN);
            _E1B(&p,&ret->transmit_power_eirp);
             
            return (INT8U *)ret;
        }

	case TLV_TYPE_CHANNEL_SELECTION_RESPONSE:
        {
           
            channel_selection_response_tlv_t *ret=NULL;

            INT8U *p;
            ret = (channel_selection_response_tlv_t *)PLATFORM_MALLOC(sizeof(channel_selection_response_tlv_t));
            if (ret  == NULL) {
                PLATFORM_PRINTF_DEBUG_ERROR("%s: %d, Malloc Failure TLV_TYPE_CHANNEL_SELECTION_RESPONSE \n",__func__, __LINE__);
		return NULL;
            }
            ret->tlv_type = TLV_TYPE_CHANNEL_SELECTION_RESPONSE;
            p = packet_stream + 1;
            _E2B(&p,&ret->tlv_length);
            _EnB(&p,ret->radio_id, ETHER_ADDR_LEN);
            _E1B(&p,&ret->channel_selection_response);
             
            return (INT8U *)ret;
        }

	case TLV_TYPE_OPERATING_CHANNEL_REPORT:
        {
            operating_channel_report_tlv_t *ret=NULL;

            INT8U *p, i=0;

            ret = (operating_channel_report_tlv_t *)PLATFORM_MALLOC(sizeof(operating_channel_report_tlv_t));
            if (ret  == NULL) {
                PLATFORM_PRINTF_DEBUG_ERROR("%s: %d, Malloc Failure TLV_TYPE_OPERATING_CHANNEL_REPORT \n",__func__, __LINE__);
		return NULL;
            }
            ret->tlv_type = TLV_TYPE_OPERATING_CHANNEL_REPORT;
            p = packet_stream + 1;
            _E2B(&p,&ret->tlv_length);
            _EnB(&p,ret->radio_id, ETHER_ADDR_LEN);
            _E1B(&p,&ret->numOperating_class);
            for (i=0; i< ret->numOperating_class; i++) 
	    {
	    		_E1B(&p,&ret->operating_class[i].operating_class);
			_E1B(&p,&ret->operating_class[i].current_op_channel);
	    }
			 
	     _E1B(&p,&ret->current_transmit_power_eirp);
            return (INT8U *)ret;
        }

        case TLV_TYPE_ERROR:
        {
            struct mapErrorCodeTLV *error_code_tlv;
            INT8U *p;
            INT16U len;

            p = packet_stream + TLV_TYPE_FIELD;

            _E2B(&p, &len);

            if (len < ERROR_CODE_TLV_LEN)
            {
                // Malformed packet
                return NULL;
            }

            error_code_tlv = (struct mapErrorCodeTLV *) PLATFORM_MALLOC(sizeof(struct mapErrorCodeTLV));
            if (error_code_tlv  == NULL)
            {
                PLATFORM_PRINTF_DEBUG_ERROR("%s: %d, Malloc failure for TLV_TYPE_ERROR \n",__func__, __LINE__);
                return NULL;
            }

            error_code_tlv->tlv_type = TLV_TYPE_ERROR;

            _E1B(&p, &error_code_tlv->reason_code);
            _EnB(&p, error_code_tlv->sta_mac_addr, ETHER_ADDR_LEN);

            return (INT8U *)error_code_tlv;
        }

        case TLV_TYPE_AP_METRICS_QUERY:
        {
            struct mapApMetricsQueryTLV *ap_metrics_query;
            INT8U  *p   = NULL;
            INT16U len  = 0;
            INT8U  i    = 0;

            p = packet_stream + 1;

            /* Extract the length of the tlv */
            _E2B(&p, &len);

            if (len < MIN_AP_METRICS_QUERY_TLV_LEN) //Atleast there should be "numBss" (i.e, 1 Byte) 
            {
                // Malformed packet
                return NULL;
            }

            ap_metrics_query = (struct mapApMetricsQueryTLV *) PLATFORM_MALLOC(sizeof(struct mapApMetricsQueryTLV));
            if (ap_metrics_query  == NULL)
            {
                PLATFORM_PRINTF_DEBUG_ERROR("%s: %d, Malloc failure for TLV_TYPE_ERROR \n",__func__, __LINE__);
                return NULL;
            }

            ap_metrics_query->tlv_type = TLV_TYPE_AP_METRICS_QUERY;

            ap_metrics_query->tlv_length  = len;

            _E1B(&p, &ap_metrics_query->numBss);
            for(i = 0; i<ap_metrics_query->numBss; i++) {
                _EnB(&p, &ap_metrics_query->bssid[i][0], ETHER_ADDR_LEN);
            }
            return (INT8U *)ap_metrics_query;
        }

        case TLV_TYPE_AP_METRICS_RESPONSE:
        {
            struct mapApMetricsResponseTLV *ap_metrics_response;
            INT8U  *p  = NULL;
            INT16U len = 0;
            INT8U  i   = 0;

            p = packet_stream + 1;

            /* Extract the length of the tlv */
            _E2B(&p, &len);

            if (len < MIN_AP_METRICS_RESPONSE_TLV_LEN) 
            {
                // Malformed packet
                return NULL;
            }

            ap_metrics_response = (struct mapApMetricsResponseTLV *) PLATFORM_MALLOC(sizeof(struct mapApMetricsResponseTLV));
            if (ap_metrics_response  == NULL)
            {
                PLATFORM_PRINTF_DEBUG_ERROR("%s: %d, Malloc failure for TLV_TYPE_ERROR \n",__func__, __LINE__);
                return NULL;
            }

            ap_metrics_response->tlv_type   = TLV_TYPE_AP_METRICS_RESPONSE;
            ap_metrics_response->tlv_length = len;

            _EnB(&p, ap_metrics_response->bssid, ETHER_ADDR_LEN);

            _E1B(&p, &ap_metrics_response->channel_util);
            _E2B(&p, &ap_metrics_response->sta_count);

            _E1B(&p, &ap_metrics_response->esp_present);

            for(i = 0; i<MAX_ACCESS_CATEGORIES; i++) {
                if(ap_metrics_response->esp_present & (1<<(7-i))) {
                    _EnB(&p, &ap_metrics_response->esp[i].byte_stream[0], 3);
                }
            }
            return (INT8U *)ap_metrics_response;
        }

        case TLV_TYPE_ASSOC_STA_TRAFFIC_STATS:
        {
            struct mapAssocStaTrafficStatsTLV *assoc_sta_traffic_stats;
            INT8U  *p  = NULL;
            INT16U len = 0;

            p = packet_stream + 1;

            /* Extract the length of the tlv */
            _E2B(&p, &len);

            if (len < MIN_ASSOC_STA_TRAFFIC_STATS_TLV_LEN) 
            {
                // Malformed packet
                return NULL;
            }

            assoc_sta_traffic_stats = (struct mapAssocStaTrafficStatsTLV *) PLATFORM_MALLOC(sizeof(struct mapAssocStaTrafficStatsTLV));
            if (assoc_sta_traffic_stats  == NULL)
            {
                PLATFORM_PRINTF_DEBUG_ERROR("%s: %d, Malloc failure for TLV_TYPE_ERROR \n",__func__, __LINE__);
                return NULL;
            }

            assoc_sta_traffic_stats->tlv_type   = TLV_TYPE_ASSOC_STA_TRAFFIC_STATS;
            assoc_sta_traffic_stats->tlv_length = len;

            _EnB(&p, assoc_sta_traffic_stats->sta_mac, ETHER_ADDR_LEN);

            _E4B(&p, &assoc_sta_traffic_stats->txbytes);
            _E4B(&p, &assoc_sta_traffic_stats->rxbytes);
            _E4B(&p, &assoc_sta_traffic_stats->txpkts);
            _E4B(&p, &assoc_sta_traffic_stats->rxpkts);
            _E4B(&p, &assoc_sta_traffic_stats->txpkterrors);
            _E4B(&p, &assoc_sta_traffic_stats->rxpkterrors);
            _E4B(&p, &assoc_sta_traffic_stats->retransmission_cnt);

            return (INT8U *)assoc_sta_traffic_stats;
        }

        case TLV_TYPE_HIGHER_LAYER_DATA_MSG:
        {
            higher_layer_data_tlv_t *higher_layer_data;
            INT16U len = 0;
            INT8U *p = NULL;

            INT8U protocol;
            uint8_t *payload;

            p = packet_stream + 1;

            /* Extract the length of the tlv */
            _E2B(&p, &len);

            if (len < MIN_HIGHER_LAYER_DATA_TLV_LEN) {
                // Malformed packet
                return NULL;
            }
            _E1B(&p, &protocol);
            payload = (uint8_t *)PLATFORM_MALLOC(len - 1);
            if (payload == NULL) {
                PLATFORM_PRINTF_DEBUG_ERROR("%s: %d, Malloc failure for TLV_TYPE_ERROR \n",__func__, __LINE__);
                return NULL;
            }
            _EnB(&p, payload, len - 1);

            higher_layer_data = (higher_layer_data_tlv_t *) PLATFORM_MALLOC (sizeof(higher_layer_data_tlv_t));
            if (higher_layer_data == NULL) {
                PLATFORM_PRINTF_DEBUG_ERROR("%s: %d, Malloc failure for TLV_TYPE_ERROR \n",__func__, __LINE__);
                return NULL;
            }
            
            higher_layer_data->tlv_type = TLV_TYPE_HIGHER_LAYER_DATA_MSG;
            higher_layer_data->tlv_length = len;
            higher_layer_data->higher_layer_proto = protocol;
            higher_layer_data->payload = payload;
            return (INT8U*)higher_layer_data;
            
        }

        case TLV_TYPE_BEACON_METRICS_QUERY: 
        {
            beacon_metrics_query_tlv_t *beacon_metrics_query;
            INT16U  len = 0;
            INT8U  *p = NULL;
            int     alloc_len = sizeof(beacon_metrics_query_tlv_t);
            int     i;

            INT8U   sta_mac[ETHER_ADDR_LEN];
            INT8U   bssid[ETHER_ADDR_LEN];
            INT8U   ssid[MAX_SSID_LEN];
            INT8U   operating_class, channel, reporting_detail, ssid_len, ap_channel_report_count;

            p = packet_stream + 1;

            /* Extract the length of the tlv */
            _E2B(&p, &len);

            if (len < BEACON_METRICS_QUERY_TLV_MIN_LEN) {
                // Malformed packet
                return NULL;
            }

            /* Read until ap_channel_report_count before allocating tlv */
            _EnB(&p, sta_mac, ETHER_ADDR_LEN);
            _E1B(&p, &operating_class);
            _E1B(&p, &channel);
            _EnB(&p, bssid, ETHER_ADDR_LEN);
            _E1B(&p, &reporting_detail);
            _E1B(&p, &ssid_len);
            _EnB(&p, ssid, ssid_len);
            _E1B(&p, &ap_channel_report_count);

            if (ap_channel_report_count > 1) {
                alloc_len += (ap_channel_report_count - 1) * sizeof(struct ap_channel_report_elem);
            }
            beacon_metrics_query = (beacon_metrics_query_tlv_t *) PLATFORM_MALLOC(alloc_len);
            if (beacon_metrics_query  == NULL)
            {
                PLATFORM_PRINTF_DEBUG_ERROR("%s: %d, Malloc failure for TLV_TYPE_ERROR \n",__func__, __LINE__);
                return NULL;
            }

            beacon_metrics_query->tlv_type   = TLV_TYPE_BEACON_METRICS_QUERY;
            beacon_metrics_query->tlv_length = len;
            PLATFORM_MEMCPY(beacon_metrics_query->sta_mac, sta_mac, ETHER_ADDR_LEN);
            beacon_metrics_query->operating_class = operating_class;
            beacon_metrics_query->channel = channel;
            PLATFORM_MEMCPY(beacon_metrics_query->bssid, bssid, ETHER_ADDR_LEN);
            beacon_metrics_query->reporting_detail = reporting_detail;
            beacon_metrics_query->ssid_len = ssid_len;
            PLATFORM_MEMCPY(beacon_metrics_query->ssid, ssid, ssid_len);
            beacon_metrics_query->ap_channel_report_count = ap_channel_report_count;

            for(i=0; i<beacon_metrics_query->ap_channel_report_count; i++) {                
                _E1B(&p, &beacon_metrics_query->ap_channel_report[i].length);
                _E1B(&p, &beacon_metrics_query->ap_channel_report[i].operating_class);
                /* Copy channel list - length includes the operating_class byte */
                _EnB(&p, beacon_metrics_query->ap_channel_report[i].channel_list, beacon_metrics_query->ap_channel_report[i].length - 1);
            }
            _E1B(&p, &beacon_metrics_query->element_id_count);
            _EnB(&p, beacon_metrics_query->elementIds, beacon_metrics_query->element_id_count);

             return (INT8U*)beacon_metrics_query;
        }
        case TLV_TYPE_BEACON_METRICS_RESPONSE:
        {
            beacon_metrics_response_tlv_t *beacon_metrics_response;
            INT8U  *p = NULL;
            INT16U  len = 0;
            int     alloc_len = sizeof(beacon_metrics_response_tlv_t);
            int     i;

            INT8U   sta_mac[ETHER_ADDR_LEN];
            INT8U   status_code, no_of_reports;

            p = packet_stream + 1;

            /* Extract the length of the tlv */
            _E2B(&p, &len);

            if (len < BEACON_METRICS_RESPONSE_TLV_MIN_LEN) {
                // Malformed packet
                return NULL;
            }

            /* Read until no_of_reports before allocating tlv */
            _EnB(&p, sta_mac, ETHER_ADDR_LEN);
            _E1B(&p, &status_code);
            _E1B(&p, &no_of_reports);

            if (no_of_reports > 1) {
                alloc_len += (no_of_reports - 1) * sizeof(map_beacon_report_element_t);
            }         
            beacon_metrics_response = (beacon_metrics_response_tlv_t *) PLATFORM_MALLOC(alloc_len);
            if (beacon_metrics_response  == NULL)
            {
                PLATFORM_PRINTF_DEBUG_ERROR("%s: %d, Malloc failure for TLV_TYPE_ERROR \n",__func__, __LINE__);
                return NULL;
            }

            beacon_metrics_response->tlv_type   = TLV_TYPE_BEACON_METRICS_RESPONSE;
            beacon_metrics_response->tlv_length = len;
            PLATFORM_MEMCPY(beacon_metrics_response->sta_mac, sta_mac, ETHER_ADDR_LEN);
            beacon_metrics_response->status_code = status_code;

            /* Add valid reports */
            beacon_metrics_response->no_of_reports = 0;
            for (i=0; i<no_of_reports; i++) {
                INT8U elem_id  = p[0];
                INT8U elem_len = p[1];

                if (elem_id == MEASUREMENT_REPORT_ELEMENTID) {
                    /* Copy no more than what was received or the room we have */
                    memcpy(&beacon_metrics_response->reports[i], p, MIN(elem_len + 2, sizeof(map_beacon_report_element_t)));

                    /* Skip complete IE in received data */
                    p += elem_len + 2;

                    beacon_metrics_response->no_of_reports++;
                }
            }

            return (INT8U*)beacon_metrics_response;
        }

        case TLV_TYPE_UNASSOCIATED_STA_METRICS_QUERY:
        {
            struct mapUnassocStaMetricsQueryTLV *unassoc_sta_met;
            INT8U *p = NULL;
            INT16U len = 0;
            INT8U (*sta_mac_ptr)[MAC_ADDR_LEN] = NULL;

            p = packet_stream + 1;

            /* Extract the length of the tlv */
            _E2B(&p, &len);

            unassoc_sta_met = (struct mapUnassocStaMetricsQueryTLV *) PLATFORM_MALLOC(sizeof(struct mapUnassocStaMetricsQueryTLV) + TLV_TYPE_FIELD + TLV_LENGTH_FIELD);
            if (unassoc_sta_met  == NULL)
            {
                PLATFORM_PRINTF_DEBUG_ERROR("%s: %d, Malloc failure for TLV_TYPE_ERROR \n",__func__, __LINE__);
                return NULL;
            }
            
            unassoc_sta_met->tlv_type = TLV_TYPE_UNASSOCIATED_STA_METRICS_QUERY;

            _E1B(&p, &unassoc_sta_met->oper_class);
            _E1B(&p, &unassoc_sta_met->channel_list_cnt);

            for(int i = 0; i <unassoc_sta_met->channel_list_cnt; i++){
                _E1B(&p, &unassoc_sta_met->sta_list[i].channel);
                _E1B(&p, &unassoc_sta_met->sta_list[i].sta_count);
                unassoc_sta_met->sta_list[i].sta_mac   = (uint8_t (*)[MAC_ADDR_LEN])calloc(unassoc_sta_met->sta_list[i].sta_count, MAC_ADDR_LEN);
                if(unassoc_sta_met->sta_list[i].sta_mac == NULL) {
                    PLATFORM_PRINTF_DEBUG_ERROR("%s: %d, Malloc failure for TLV_TYPE_ERROR \n",__func__, __LINE__);
                    return NULL;
                }
                sta_mac_ptr = unassoc_sta_met->sta_list[i].sta_mac;
                for(int j = 0; j<unassoc_sta_met->sta_list[i].sta_count; j++) {
                    _EnB(&p, (INT8U *)sta_mac_ptr, MAC_ADDR_LEN);
                    sta_mac_ptr++;
                }
            }

            return (INT8U*)unassoc_sta_met;
        }
        case TLV_TYPE_UNASSOCIATED_STA_METRICS_RESPONSE:
        {
            struct mapUnassocStaMetricsResponseTLV *unassoc_sta_met;
            INT8U *p = NULL;
            INT16U len = 0;
            INT8U i = 0;
            INT8U oper_class = 0;
            INT8U sta_cnt    = 0;

            p = packet_stream + 1;

            /* Extract the length of the tlv */
            _E2B(&p, &len);
            _E1B(&p, &oper_class);
            _E1B(&p, &sta_cnt);


            unassoc_sta_met = (struct mapUnassocStaMetricsResponseTLV *) PLATFORM_MALLOC(sizeof(struct mapUnassocStaMetricsResponseTLV) + (sizeof(struct sta_rcpi_list) * sta_cnt) + TLV_TYPE_FIELD + TLV_LENGTH_FIELD);
            if (unassoc_sta_met  == NULL)
            {
                PLATFORM_PRINTF_DEBUG_ERROR("%s: %d, Malloc failure for TLV_TYPE_ERROR \n",__func__, __LINE__);
                return NULL;
            }
            
            unassoc_sta_met->tlv_type   = TLV_TYPE_UNASSOCIATED_STA_METRICS_RESPONSE;
            unassoc_sta_met->tlv_length = len;
            unassoc_sta_met->oper_class = oper_class;
            unassoc_sta_met->sta_cnt    = sta_cnt;

            for(i = 0; i <unassoc_sta_met->sta_cnt; i++){
               _EnB(&p, unassoc_sta_met->sta_list[i].sta_mac, ETHER_ADDR_LEN);
                _E1B(&p, &unassoc_sta_met->sta_list[i].channel);
                _E4B(&p, &unassoc_sta_met->sta_list[i].time_delta);
                _E1B(&p, &unassoc_sta_met->sta_list[i].rcpi_uplink);
            }
            return (INT8U*)unassoc_sta_met;
        }

        default:
        {
            // Ignore
            //
            return NULL;
        }
    }
    return 0;
}

void free_multiap_TLV_structure(INT8U *memory_structure)
{
    if (NULL == memory_structure)
    {
        return;
    }

    // The first byte of any of the valid structures is always the "tlv_type"
    // field.
    switch (*memory_structure)
    {
		case TLV_TYPE_STEERING_POLICY:
		{
			steering_policy_tlv_t *m;
			m = (steering_policy_tlv_t*)memory_structure;
			if( NULL != m->local_steering_macs)
				PLATFORM_FREE(m->local_steering_macs);
			if( NULL != m->btm_steering_macs)
				PLATFORM_FREE(m->btm_steering_macs);
			PLATFORM_FREE(m);
			return;
		}            

        case TLV_TYPE_SEARCHED_SERVICE:
        {
                 searched_service_tlv_t *m;

                 m = (searched_service_tlv_t *)memory_structure;

                 PLATFORM_FREE(m);
                 return;
        }

        case TLV_TYPE_SUPPORTED_SERVICE:
        {
             // This parsing is done according to the information detailed in
             // "IEEE Std 1905.1-2013 Section 6.4.1"
 
             supported_service_tlv_t *m;
 
 
             m = (supported_service_tlv_t *)memory_structure;
 
             PLATFORM_FREE(m);
             return;
        }
 
        case TLV_TYPE_AP_RADIO_IDENTIFIER:
        {
             // This parsing is done according to the information detailed in
             // "IEEE Std 1905.1-2013 Section 6.4.1"
 
             AP_radio_id_tlv_t *m;
 
             m = (AP_radio_id_tlv_t *)memory_structure;
             PLATFORM_FREE(m);
             return;
        }
 
        case TLV_TYPE_AP_RADIO_BASIC_CAPABILITY:
        {
            struct mapApBasicCapabilityTLV *m;
 
            m = (struct mapApBasicCapabilityTLV *)memory_structure; 
            PLATFORM_FREE(m);
            return;
        }

        case TLV_TYPE_AP_OPERATIONAL_BSS:
        {
            struct mapApOperationalBssTLV *oper_bss_tlv;
 
            oper_bss_tlv = (struct mapApOperationalBssTLV *)memory_structure; 
            PLATFORM_FREE(oper_bss_tlv);
            return;
        }
 
        case TLV_TYPE_ASSOCIATED_STA_TLV:
        {
            struct mapAssociatedClientsTLV *assoc_sta_tlv;
 
            assoc_sta_tlv = (struct mapAssociatedClientsTLV *)memory_structure; 
            PLATFORM_FREE(assoc_sta_tlv);
            return;
        }

        case TLV_TYPE_HIGHER_LAYER_DATA_MSG:
        {
            struct mapHigherLayerDataTLV *higher_layer_tlv;
            higher_layer_tlv = (struct mapHigherLayerDataTLV *)memory_structure;
            if (higher_layer_tlv != NULL) {
                PLATFORM_FREE(higher_layer_tlv->payload);
                higher_layer_tlv->payload = NULL;
            }
            PLATFORM_FREE(higher_layer_tlv);
            return;            
        }

        case TLV_TYPE_UNASSOCIATED_STA_METRICS_QUERY:
        {
            struct mapUnassocStaMetricsQueryTLV *unassoc_sta_tlv = NULL;

            unassoc_sta_tlv = (struct mapUnassocStaMetricsQueryTLV *)memory_structure;
            if(unassoc_sta_tlv!= NULL) {
                for(int i = 0; i <unassoc_sta_tlv->channel_list_cnt; i++) {
                    PLATFORM_FREE(unassoc_sta_tlv->sta_list[i].sta_mac);
                }
                PLATFORM_FREE(unassoc_sta_tlv);
            }
            return;
        }

        default:
        {
            PLATFORM_FREE((void *)memory_structure);
            return;
        }
    }
}
