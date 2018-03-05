/*
 * IEEE 802.1X-2010 KaY Interface
 * Copyright (c) 2013-2014, Qualcomm Atheros, Inc.
 *
 * This software may be distributed under the terms of the BSD license.
 * See README for more details.
 */

#ifndef WPA_AUTH_KAY_H
#define WPA_AUTH_KAY_H

struct hostapd_data;

#ifdef CONFIG_MACSEC

int ieee802_1x_alloc_kay_sm(struct hostapd_data *hapd);

#else /* CONFIG_MACSEC */

static inline int ieee802_1x_alloc_kay_sm(struct hostapd_data *hapd);
{
        return 0;
};

#endif /* CONFIG_MACSEC */

#endif /* WPA_AUTH_KAY_H */
