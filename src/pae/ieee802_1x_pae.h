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

#define ANNOUNCEMENT_TIME 5000

typedef int (*ieee802_1x_announcement_handler)(void *priv, size_t len, u8 *pos,
					       int packet_type, char *nid);

struct ieee802_1x_peer_pae {
       Boolean soliciting_announcement;
};

void ieee802_1x_decode_announcement(void *priv, u8 *ann, size_t ann_len,
				    int packet_type,
				    const ieee802_1x_announcement_handler *hdr);
int ieee802_1x_pae_encode_announcement_generic(u8 *addr, struct wpabuf *pbuf);
void ieee802_1x_xmit_announcement(void *priv);

#endif /* IEEE802_1X_PAE_H */
