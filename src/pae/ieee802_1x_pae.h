/*
 * IEEE 802.1X-2010 PAE/Logon Process
 * Copyright (c) 2018, Qualcomm Atheros, Inc.
 *
 * This software may be distributed under the terms of the BSD license.
 * See README for more details.
 */

#ifndef IEEE802_1X_PAE_H
#define IEEE802_1X_PAE_H

#include "includes.h"
#include "common.h"
#include "list.h"
#include "common/eapol_common.h"
#include "common/ieee802_1x_defs.h"

#define ANNOUNCEMENT_TIME 5000

typedef int (*ieee802_1x_announcement_handler)(void *priv, size_t len, u8 *pos,
					       int packet_type, char *nid);

struct ann_body_handler {
	int (*body_tx)(void *priv, struct wpabuf *buf);
	int (*body_rx)(void *priv, const u8 *announce, size_t msg_len);
	int (*body_length)(void *priv);
	Boolean (*body_present)(void *priv);
};

struct eapol_pending_announcement {
	struct os_reltime last_tx[2 * IEEE8021X_ANN_RATE_LIMIT];
	u8 last_tx_index;

	u8 access_status;
	u8 access_requested;
	Boolean is_vport_access;
	Boolean is_group_access;

	struct ieee802_1x_announcement last_rx;
};

struct ieee802_1x_peer_pae {
       Boolean soliciting_announcement;
       struct eapol_pending_announcement *pending_announcement;
};

void ieee802_1x_decode_announcement(void *priv, u8 *ann, size_t ann_len,
				    int packet_type,
				    const ieee802_1x_announcement_handler *hdr);
int ieee802_1x_pae_encode_announcement_generic(struct ann_body_handler *handlers,
					       u8 *addr, struct wpabuf *pbuf);
void ieee802_1x_xmit_announcement(void *priv,
				  struct eapol_pending_announcement *pending);

#endif /* IEEE802_1X_PAE_H */
