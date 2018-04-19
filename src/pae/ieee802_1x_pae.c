/*
 * IEEE 802.1X-2010 PAE/Logon Process
 * Copyright (c) 2018, Qualcomm Atheros, Inc.
 *
 * This software may be distributed under the terms of the BSD license.
 * See README for more details.
 */

#include "utils/includes.h"
#include "utils/common.h"
#include "utils/eloop.h"

#include "common/defs.h"
#include "common/ieee802_1x_defs.h"
#include "common/eapol_common.h"
#include "ieee802_1x_pae.h"


#define ANNOUNCEMENT_TIME 5000


/**
 * ieee802_1x_pae_validate_announcement -
 */
static int
ieee802_1x_pae_validate_announcement(int tlv_type, int packet_type, int global)
{
       switch (tlv_type & 0x7f) {
       case IEEE802_1X_ANN_TLV_ACCESS_INFO:
	       if (packet_type == IEEE802_1X_TYPE_EAPOL_ANNOUNCEMENT_GENERIC ||
		   packet_type == IEEE802_1X_TYPE_EAPOL_ANNOUNCEMENT_SPECIFIC ||
		   packet_type == IEEE802_1X_TYPE_EAPOL_ANNOUNCEMENT_REQ ||
		   packet_type == IEEE802_1X_TYPE_EAPOL_START) {
		   return 1;
	       }
	       break;
       case IEEE802_1X_ANN_TLV_MACSEC_CS:
       case IEEE802_1X_ANN_TLV_KMD:
	       if (packet_type == IEEE802_1X_TYPE_EAPOL_ANNOUNCEMENT_GENERIC ||
		   packet_type == IEEE802_1X_TYPE_EAPOL_ANNOUNCEMENT_SPECIFIC) {
		   return 1;
	       }
	       break;
       case IEEE802_1X_ANN_TLV_NID:
	       if (global &&
		   (packet_type == IEEE802_1X_TYPE_EAPOL_ANNOUNCEMENT_GENERIC ||
		    packet_type == IEEE802_1X_TYPE_EAPOL_ANNOUNCEMENT_SPECIFIC ||
		    packet_type == IEEE802_1X_TYPE_EAPOL_ANNOUNCEMENT_REQ ||
		    packet_type == IEEE802_1X_TYPE_EAPOL_START)) {
		   return 1;
	       }
	       break;
       default:
	       wpa_printf(MSG_DEBUG, "IEEE 802.1X: Ignored EAPOL-Announcement "
			  "TLV type %d", tlv_type);
	       break;
       }
       return 0;
}


/**
 * ieee802_1x_pae_decode_announcement -
 */
void ieee802_1x_decode_announcement(u8 *ann, size_t ann_len, int packet_type,
				    const ieee802_1x_announcement_handler *handlers)
{
	struct ieee802_1x_ann_tlv_hdr *hdr;
	u8 *pos;
	size_t left, len;
	int type, global = 1;

	pos = ann;
	left = ann_len;

	while (left > sizeof(*hdr)) {
		hdr = (struct ieee802_1x_ann_tlv_hdr *) pos;
		type = be_to_host16(hdr->type);
		len = be_to_host16(hdr->len);
		pos += sizeof(*hdr);
		left -= sizeof(*hdr);
		if (len > left) {
			wpa_printf(MSG_DEBUG, "IEEE 802.1X: EAPOL-Announcement "
			   "TLV overrun (type=%d len=%lu left=%lu)",
			   type, (unsigned long) len,
			   (unsigned long) left);
		}

		if (ieee802_1x_pae_validate_announcement(type, packet_type,
							 global)) {
			handlers[type & 0x7f](NULL, packet_type, &global);
		}

		pos += len;
		left -= len;
       }
}


/**
 * ieee802_1x_pae_encode_announcement_generic -
 */
int ieee802_1x_pae_encode_announcement_generic(u8 *own_addr,
					       struct wpabuf *pbuf)
{
	struct ieee8023_hdr *ether_hdr;
	struct ieee802_1x_hdr *eapol_hdr;
	int i;

	ether_hdr = wpabuf_put(pbuf, sizeof(*ether_hdr));
	os_memcpy(ether_hdr->dest, pae_group_addr, sizeof(ether_hdr->dest));
	os_memcpy(ether_hdr->src, own_addr, sizeof(ether_hdr->src));
	ether_hdr->ethertype = host_to_be16(ETH_P_EAPOL);

	eapol_hdr = wpabuf_put(pbuf, sizeof(*eapol_hdr));
	eapol_hdr->version = EAPOL_VERSION;
	eapol_hdr->type = IEEE802_1X_TYPE_EAPOL_ANNOUNCEMENT_GENERIC;

	/* unimplemented */
}


/**
 * ieee802_1x_pae_xmit_announcement -
 */
void ieee802_1x_xmit_announcement(void *priv)
{
	/* unimplemented */
}