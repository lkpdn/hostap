/*
 * IEEE 802.1X-2010 PAE/Logon Process
 * Copyright (c) 2018, Qualcomm Atheros, Inc.
 *
 * This software may be distributed under the terms of the BSD license.
 * See README for more details.
 */

#include <time.h>
#include "includes.h"
#include "common.h"
#include "list.h"
#include "eloop.h"


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
static void ieee802_1x_decode_announcement(u8 *ann, size_t ann_len, int packet_type)
{
       struct ieee801_1x_ann_tlv_hdr *hdr;
       u8 *pos;
       size_t left, len;
       int type, global = 1;

       pos = ann;
       left = ann_len;

       while (left > sizeof(*hdr)) {
	       hdr = (struct ieee801_1x_ann_tlv_hdr *) pos;
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

	       if (ieee802_1x_pae_validate_announcement(type, packet_type, global)) {
		       ieee802_1x_parse_ann_tlv(type, pos, len, &global);
	       }

	       pos += len;
	       left -= len;
       }
}


/**
 * ieee802_1x_pae_encode_announcement_generic -
 */
static int
ieee802_1x_pae_encode_announcement_generic(struct hostapd_data *hapd,
					   struct wpabuf *pbuf)
{
	ether_hdr = wpabuf_put(pbuf, sizeof(*ether_hdr));
	os_memcpy(ether_hdr->dest, pae_group_addr, sizeof(ether_hdr->dest));
	os_memcpy(ether_hdr->src, hapd->own_addr);
	ether_hdr->ethertype = host_to_be16(ETH_P_EAPOL);

	eapol_hdr = wpabuf_put(pbuf, sizeof(*eapol_hdr);
	eapol_hdr->version = EAPOL_VERSION;
	eapol_hdr->type = IEEE802_1X_TYPE_EAPOL_ANNOUNCEMENT_GENERIC;

	for (i = 0; i < ARRAY_SIZE(announcement_tlvs); i++) {
		/* unimplemented */
	}
}


/**
 * ieee802_1x_pae_xmit_announcement -
 */
static void ieee802_1x_xmit_announcement(struct hostapd_data *hapd)
{
	/* unimplemented */
}


/**
 * ieee802_1x_announcement_timer -
 */
static void ieee802_1x_announcement_timer(void *eloop_ctx, void *timeout_ctx)
{
	struct hostapd_data *hapd;

	hapd = (struct hostapd_data *)eloop_ctx;
	ieee802_1x_xmit_announcement(hapd);
	eloop_register_timeout(ANNOUNCEMENT_TIME / 1000, 0,
			       ieee802_1x_announcement_timer,
			       hapd, NULL);
	return;
}
