/*
 * IEEE 802.1X-2010 Key Agree Protocol of PAE state machine
 * Copyright (c) 2013, Qualcomm Atheros, Inc.
 *
 * This software may be distributed under the terms of the BSD license.
 * See README for more details.
 */

#ifndef IEEE802_1X_DRIVER_I_H
#define IEEE802_1X_DRIVER_I_H

#include "utils/list.h"
#include "common/defs.h"
#include "common/ieee802_1x_defs.h"
#include "drivers/driver.h"

struct macsec_init_params;

#define MI_LEN			12  /* 96-bit Member Identifier */
#define MAX_KEY_LEN		32  /* 32 bytes, 256 bits */
#define MAX_CKN_LEN		32  /* 32 bytes, 256 bits */

/* MKA timer, unit: millisecond */
#define MKA_HELLO_TIME		2000
#define MKA_LIFE_TIME		6000
#define MKA_SAK_RETIRE_TIME	3000

struct transmit_sc;
struct transmit_sa;
struct receive_sc;
struct receive_sa;

static int ieee802_1x_kay_macsec_init(const struct wpa_driver_ops *driver,
				      void *drv_priv,
				      struct macsec_init_params *params)
{
	if (!driver->macsec_init)
		return -1;
	return driver->macsec_init(drv_priv, params);
};


static int ieee802_1x_kay_macsec_deinit(const struct wpa_driver_ops *driver,
					void *drv_priv)
{
	if (!driver->macsec_deinit)
		return -1;
	return driver->macsec_deinit(drv_priv);
};


static int ieee802_1x_kay_macsec_get_capability(const struct wpa_driver_ops *driver,
						void *drv_priv,
						enum macsec_cap *cap)
{
	if (!driver->macsec_get_capability)
		return -1;
	return driver->macsec_get_capability(drv_priv, cap);
};


static int ieee802_1x_kay_enable_protect_frames(const struct wpa_driver_ops *driver,
						void *drv_priv,
						Boolean enabled)
{
	if (!driver->enable_protect_frames)
		return -1;
	return driver->enable_protect_frames(drv_priv, enabled);
}


static int ieee802_1x_kay_enable_encrypt(const struct wpa_driver_ops *driver,
					 void *drv_priv,
					 Boolean enabled)
{
	if (!driver->enable_encrypt)
		return -1;
	return driver->enable_encrypt(drv_priv, enabled);
}


static int ieee802_1x_kay_set_replay_protect(const struct wpa_driver_ops *driver,
					     void *drv_priv,
					     Boolean enabled, u32 window)
{
	if (!driver->set_replay_protect)
		return -1;
	return driver->set_replay_protect(drv_priv, enabled, window);
}


static int ieee802_1x_set_current_cipher_suite(const struct wpa_driver_ops *driver,
					       void *drv_priv,
					       u64 cs)
{
	if (!driver->set_current_cipher_suite)
		return -1;
	return driver->set_current_cipher_suite(drv_priv, cs);
}


static int ieee802_1x_enable_controlled_port(const struct wpa_driver_ops *driver,
					     void *drv_priv,
					     Boolean enabled)
{
	if (!driver->enable_controlled_port)
		return -1;
	return driver->enable_controlled_port(drv_priv, enabled);
}


static int ieee802_1x_get_receive_lowest_pn(const struct wpa_driver_ops *driver,
					    void *drv_priv,
					    struct receive_sa *sa)
{
	if (!driver->get_receive_lowest_pn)
		return -1;
	return driver->get_receive_lowest_pn(drv_priv, sa);
}


static int ieee802_1x_get_transmit_next_pn(const struct wpa_driver_ops *driver,
					   void *drv_priv,
					   struct transmit_sa *sa)
{
	if (!driver->get_transmit_next_pn)
		return -1;
	return driver->get_transmit_next_pn(drv_priv, sa);
}


static int ieee802_1x_set_transmit_next_pn(const struct wpa_driver_ops *driver,
					   void *drv_priv,
					   struct transmit_sa *sa)
{
	if (!driver->set_transmit_next_pn)
		return -1;
	return driver->set_transmit_next_pn(drv_priv, sa);
}


static int ieee802_1x_create_receive_sc(const struct wpa_driver_ops *driver,
					void *drv_priv,
					struct receive_sc *sc,
					unsigned int conf_offset,
					int validation)
{
	if (!driver->create_receive_sc)
		return -1;
	return driver->create_receive_sc(drv_priv, sc, conf_offset,
					 validation);
}


static int ieee802_1x_delete_receive_sc(const struct wpa_driver_ops *driver,
					void *drv_priv,
					struct receive_sc *sc)
{
	if (!driver->delete_receive_sc)
		return -1;
	return driver->delete_receive_sc(drv_priv, sc);
}


static int ieee802_1x_create_receive_sa(const struct wpa_driver_ops *driver,
					void *drv_priv,
					struct receive_sa *sa)
{
	if (!driver->create_receive_sa)
		return -1;
	return driver->create_receive_sa(drv_priv, sa);
}


static int ieee802_1x_delete_receive_sa(const struct wpa_driver_ops *driver,
					void *drv_priv,
					struct receive_sa *sa)
{
	if (!driver->delete_receive_sa)
		return -1;
	return driver->delete_receive_sa(drv_priv, sa);
}


static int ieee802_1x_enable_receive_sa(const struct wpa_driver_ops *driver,
					void *drv_priv,
					struct receive_sa *sa)
{
	if (!driver->enable_receive_sa)
		return -1;
	return driver->enable_receive_sa(drv_priv, sa);
}


static int ieee802_1x_disable_receive_sa(const struct wpa_driver_ops *driver,
					void *drv_priv,
					struct receive_sa *sa)
{
	if (!driver->disable_receive_sa)
		return -1;
	return driver->disable_receive_sa(drv_priv, sa);
}


static int ieee802_1x_create_transmit_sc(const struct wpa_driver_ops *driver,
					 void *drv_priv, struct transmit_sc *sc,
					 unsigned int conf_offset)
{
	if (!driver->create_transmit_sc)
		return -1;
	return driver->create_transmit_sc(drv_priv, sc, conf_offset);
}


static int ieee802_1x_delete_transmit_sc(const struct wpa_driver_ops *driver,
					 void *drv_priv, struct transmit_sc *sc)
{
	if (!driver->delete_transmit_sc)
		return -1;
	return driver->delete_transmit_sc(drv_priv, sc);
}


static int ieee802_1x_create_transmit_sa(const struct wpa_driver_ops *driver,
					 void *drv_priv, struct transmit_sa *sa)
{
	if (!driver->create_transmit_sa)
		return -1;
	return driver->create_transmit_sa(drv_priv, sa);
}


static int ieee802_1x_delete_transmit_sa(const struct wpa_driver_ops *driver,
					 void *drv_priv, struct transmit_sa *sa)
{
	if (!driver->delete_transmit_sa)
		return -1;
	return driver->delete_transmit_sa(drv_priv, sa);
}


static int ieee802_1x_enable_transmit_sa(const struct wpa_driver_ops *driver,
					 void *drv_priv, struct transmit_sa *sa)
{
	if (!driver->enable_transmit_sa)
		return -1;
	return driver->enable_transmit_sa(drv_priv, sa);
}


static int ieee802_1x_disable_transmit_sa(const struct wpa_driver_ops *driver,
					  void *drv_priv, struct transmit_sa *sa)
{
	if (!driver->disable_transmit_sa)
		return -1;
	return driver->disable_transmit_sa(drv_priv, sa);
}

#endif /* IEEE802_1X_DRIVER_I_H */
