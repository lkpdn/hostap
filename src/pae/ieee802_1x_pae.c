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
ieee802_1x_pae_validate_announcement(int tlv_type, int packet_type, char *nid)
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
	       if (!nid &&
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
void ieee802_1x_decode_announcement(
		void *priv, u8 *ann, size_t ann_len, int packet_type,
		const struct ieee802_1x_announcement_handler *handlers)
{
	struct ieee802_1x_ann_tlv_hdr *hdr;
	u8 *pos;
	size_t left, len;
	int type;
	char nid[101] = { 0 };

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

		/* IEEE 802.1X-2010 11.12.8 g). - If a particular TLV is
		 * encountered more than once as Global, or more than once
		 * within an identified Set, only one of its values shall be
		 * recorded (for Global, or for the identified Set as
		 * appropriate). It is undefined whether the recorded value is
		 * to be the first, last, or any other encountered by the
		 * decoder.
		 */
		if (ieee802_1x_pae_validate_announcement(type, packet_type,
							 nid)) {
			handlers[type & 0x7f].body_rx(priv, len, pos,
						      packet_type, nid);
		}

		pos += len;
		left -= len;
       }
}


/**
 * ieee802_1x_pae_len_announcement_generic -
 */
int ieee802_1x_pae_len_announcement_generic(
		const struct ieee802_1x_announcement_handler *handlers,
		char *nid, struct wpabuf *pbuf, void *priv)
{
	return 0;
}


/**
 * ieee802_1x_pae_encode_announcement_generic -
 */
int ieee802_1x_pae_encode_announcement_generic(
		const struct ieee802_1x_announcement_handler *handlers,
		char *nid, struct wpabuf *pbuf, void *priv)
{
	struct ieee802_1x_hdr *eapol_hdr;
	struct ieee802_1x_ann_tlv_hdr *nid_header;
	size_t nid_offset;
	int i;

	eapol_hdr = wpabuf_put(pbuf, sizeof(*eapol_hdr));
	eapol_hdr->version = EAPOL_VERSION;
	eapol_hdr->type = IEEE802_1X_TYPE_EAPOL_ANNOUNCEMENT_GENERIC;

	if (nid) {
		if (!handlers[IEEE802_1X_ANN_TLV_NID].body_present(priv, nid))
			return -1;

		nid_header = (struct ieee802_1x_ann_tlv_hdr *) pbuf->buf;
		nid_offset = pbuf->used;
		if (handlers[IEEE802_1X_ANN_TLV_NID].body_tx(priv, pbuf, nid))
			return -1;
	}

	for (i = 0; i < ARRAY_SIZE(handlers); i++) {
		if (handlers[i].body_tx &&
		    handlers[i].body_present(priv, nid) &&
		    handlers[i].body_tx(priv, pbuf, nid))
			return -1;
	}

	if (nid)
		nid_header->len = pbuf->used - nid_offset - 2;

	return 0;
}


/**
 * ieee802_1x_pae_xmit_announcement -
 */
void ieee802_1x_xmit_announcement(
	void *priv, void(*timeout)(void *eloop_ctx, void *timeout_ctx),
	struct eapol_pending_announcement *pending)
{
	struct os_reltime now, oldest, age;

	os_get_reltime(&now);
	oldest = pending->last_tx[(pending->last_tx_index + 1)
				  % (2 * IEEE8021X_ANN_RATE_LIMIT)];
	if (!oldest.sec && !oldest.usec) {
		os_reltime_sub(&now, &oldest, &age);
		if (age.sec > 0) {
			/* rate limit */
			return;
		}
	}
	pending->last_tx[pending->last_tx_index++] = now;

	eloop_register_timeout(IEEE8021X_ANN_DELAY / 1000, 0,
			       timeout, priv, NULL);
}
