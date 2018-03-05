/*
 * IEEE 802.1X-2010 KaY Interface
 * Copyright (c) 2013-2014, Qualcomm Atheros, Inc.
 *
 * This software may be distributed under the terms of the BSD license.
 * See README for more details.
 */

#include "utils/includes.h"

#include "utils/common.h"
#include "eap_server/eap.h"
#include "eapol_auth/eapol_auth_sm.h"
#include "eapol_auth/eapol_auth_sm_i.h"
#include "pae/ieee802_1x_key.h"
#include "pae/ieee802_1x_kay.h"
#include "pae/ieee802_1x_driver_i.h"
#include "hostapd.h"


#define DEFAULT_KEY_LEN		16
/* secure Connectivity Association Key Name (CKN) */
#define DEFAULT_CKN_LEN		16


static int wpa_auth_macsec_init(void *priv, struct macsec_init_params *params)
{
	struct hostapd_data *hapd = (struct hostapd_data *)priv;

	return ieee802_1x_kay_macsec_init(hapd->driver, hapd->drv_priv,
					  params);
};


static int wpa_auth_macsec_deinit(void *priv)
{
	struct hostapd_data *hapd = (struct hostapd_data *)priv;

	return ieee802_1x_kay_macsec_deinit(hapd->driver,
						hapd->drv_priv);
};


static int wpa_auth_macsec_get_capability(void *priv, enum macsec_cap *cap)
{
	struct hostapd_data *hapd = (struct hostapd_data *)priv;

	return ieee802_1x_kay_macsec_get_capability(hapd->driver,
						    hapd->drv_priv,
						    cap);
};


static int wpa_auth_enable_protect_frames(void *priv, Boolean enabled)
{
	struct hostapd_data *hapd = (struct hostapd_data *)priv;

	return ieee802_1x_kay_enable_protect_frames(hapd->driver,
						    hapd->drv_priv,
						    enabled);
};


static int wpa_auth_enable_encrypt(void *priv, Boolean enabled)
{
	struct hostapd_data *hapd = (struct hostapd_data *)priv;

	return ieee802_1x_kay_enable_encrypt(hapd->driver,
					     hapd->drv_priv,
					     enabled);
};


static int wpa_auth_set_replay_protect(void *priv, Boolean enabled, u32 window)
{
	struct hostapd_data *hapd = (struct hostapd_data *)priv;

	return ieee802_1x_kay_set_replay_protect(hapd->driver,
						 hapd->drv_priv,
						 enabled, window);
};


static int wpa_auth_set_current_cipher_suite(void *priv, u64 cs)
{
	struct hostapd_data *hapd = (struct hostapd_data *)priv;

	return ieee802_1x_set_current_cipher_suite(hapd->driver,
						   hapd->drv_priv,
						   cs);
};


static int wpa_auth_enable_controlled_port(void *priv, Boolean enabled)
{
	struct hostapd_data *hapd = (struct hostapd_data *)priv;

	return ieee802_1x_enable_controlled_port(hapd->driver,
						 hapd->drv_priv,
						 enabled);
};


static int wpa_auth_get_receive_lowest_pn(void *priv, struct receive_sa *sa)
{
	struct hostapd_data *hapd = (struct hostapd_data *)priv;

	return ieee802_1x_get_receive_lowest_pn(hapd->driver,
						hapd->drv_priv, sa);
};


static int wpa_auth_get_transmit_next_pn(void *priv, struct transmit_sa *sa)
{
	struct hostapd_data *hapd = (struct hostapd_data *)priv;

	return ieee802_1x_get_transmit_next_pn(hapd->driver,
					       hapd->drv_priv, sa);
};


static int wpa_auth_set_transmit_next_pn(void *priv, struct transmit_sa *sa)
{
	struct hostapd_data *hapd = (struct hostapd_data *)priv;

	return ieee802_1x_set_transmit_next_pn(hapd->driver,
					       hapd->drv_priv, sa);
};


static unsigned int conf_offset_val(enum confidentiality_offset co)
{
	switch (co) {
	case CONFIDENTIALITY_OFFSET_30:
		return 30;
		break;
	case CONFIDENTIALITY_OFFSET_50:
		return 50;
	default:
		return 0;
	}
};


static int wpa_auth_create_receive_sc(void *priv, struct receive_sc *sc,
				  enum validate_frames vf,
				  enum confidentiality_offset co)
{
	struct hostapd_data *hapd = (struct hostapd_data *)priv;

	return ieee802_1x_create_receive_sc(hapd->driver, hapd->drv_priv,
					    sc, conf_offset_val(co), vf);
};


static int wpa_auth_delete_receive_sc(void *priv, struct receive_sc *sc)
{
	struct hostapd_data *hapd = (struct hostapd_data *)priv;

	return ieee802_1x_delete_receive_sc(hapd->driver, hapd->drv_priv, sc);
};


static int wpa_auth_create_receive_sa(void *priv, struct receive_sa *sa)
{
	struct hostapd_data *hapd = (struct hostapd_data *)priv;

	return ieee802_1x_create_receive_sa(hapd->driver, hapd->drv_priv, sa);
};


static int wpa_auth_delete_receive_sa(void *priv, struct receive_sa *sa)
{
	struct hostapd_data *hapd = (struct hostapd_data *)priv;

	return ieee802_1x_delete_receive_sa(hapd->driver, hapd->drv_priv, sa);
};


static int wpa_auth_enable_receive_sa(void *priv, struct receive_sa *sa)
{
	struct hostapd_data *hapd = (struct hostapd_data *)priv;

	return ieee802_1x_enable_receive_sa(hapd->driver, hapd->drv_priv, sa);
};


static int wpa_auth_disable_receive_sa(void *priv, struct receive_sa *sa)
{
	struct hostapd_data *hapd = (struct hostapd_data *)priv;

	return ieee802_1x_disable_receive_sa(hapd->driver, hapd->drv_priv, sa);
};


static int
wpa_auth_create_transmit_sc(void *priv, struct transmit_sc *sc,
			enum confidentiality_offset co)
{
	struct hostapd_data *hapd = (struct hostapd_data *)priv;

	return ieee802_1x_create_transmit_sc(hapd->driver, hapd->drv_priv, sc,
					     conf_offset_val(co));
};


static int wpa_auth_delete_transmit_sc(void *priv, struct transmit_sc *sc)
{
	struct hostapd_data *hapd = (struct hostapd_data *)priv;

	return ieee802_1x_delete_transmit_sc(hapd->driver, hapd->drv_priv, sc);
};


static int wpa_auth_create_transmit_sa(void *priv, struct transmit_sa *sa)
{
	struct hostapd_data *hapd = (struct hostapd_data *)priv;

	return ieee802_1x_create_transmit_sa(hapd->driver, hapd->drv_priv, sa);
};


static int wpa_auth_delete_transmit_sa(void *priv, struct transmit_sa *sa)
{
	struct hostapd_data *hapd = (struct hostapd_data *)priv;

	return ieee802_1x_delete_transmit_sa(hapd->driver, hapd->drv_priv, sa);
};


static int wpa_auth_enable_transmit_sa(void *priv, struct transmit_sa *sa)
{
	struct hostapd_data *hapd = (struct hostapd_data *)priv;

	return ieee802_1x_enable_transmit_sa(hapd->driver, hapd->drv_priv, sa);
};


static int wpa_auth_disable_transmit_sa(void *priv, struct transmit_sa *sa)
{
	struct hostapd_data *hapd = (struct hostapd_data *)priv;

	return ieee802_1x_disable_transmit_sa(hapd->driver, hapd->drv_priv, sa);
};


int ieee802_1x_alloc_kay_sm(struct hostapd_data *hapd)
{
	struct ieee802_1x_kay_ctx *kay_ctx;
	struct ieee802_1x_kay *res = NULL;
	enum macsec_policy policy;

	/* XXX */
	policy = SHOULD_ENCRYPT;

	kay_ctx = os_zalloc(sizeof(*kay_ctx));
	if (!kay_ctx)
		return -1;

	kay_ctx->ctx = hapd;

	kay_ctx->macsec_init = wpa_auth_macsec_init;
	kay_ctx->macsec_deinit = wpa_auth_macsec_deinit;
	kay_ctx->macsec_get_capability = wpa_auth_macsec_get_capability;
	kay_ctx->enable_protect_frames = wpa_auth_enable_protect_frames;
	kay_ctx->enable_encrypt = wpa_auth_enable_encrypt;
	kay_ctx->set_replay_protect = wpa_auth_set_replay_protect;
	kay_ctx->set_current_cipher_suite = wpa_auth_set_current_cipher_suite;
	kay_ctx->enable_controlled_port = wpa_auth_enable_controlled_port;
	kay_ctx->get_receive_lowest_pn = wpa_auth_get_receive_lowest_pn;
	kay_ctx->get_transmit_next_pn = wpa_auth_get_transmit_next_pn;
	kay_ctx->set_transmit_next_pn = wpa_auth_set_transmit_next_pn;
	kay_ctx->create_receive_sc = wpa_auth_create_receive_sc;
	kay_ctx->delete_receive_sc = wpa_auth_delete_receive_sc;
	kay_ctx->create_receive_sa = wpa_auth_create_receive_sa;
	kay_ctx->delete_receive_sa = wpa_auth_delete_receive_sa;
	kay_ctx->enable_receive_sa = wpa_auth_enable_receive_sa;
	kay_ctx->disable_receive_sa = wpa_auth_disable_receive_sa;
	kay_ctx->create_transmit_sc = wpa_auth_create_transmit_sc;
	kay_ctx->delete_transmit_sc = wpa_auth_delete_transmit_sc;
	kay_ctx->create_transmit_sa = wpa_auth_create_transmit_sa;
	kay_ctx->delete_transmit_sa = wpa_auth_delete_transmit_sa;
	kay_ctx->enable_transmit_sa = wpa_auth_enable_transmit_sa;
	kay_ctx->disable_transmit_sa = wpa_auth_disable_transmit_sa;

	res = ieee802_1x_kay_init(kay_ctx, policy, 0, 0,
				  hapd->iconf->bss[0]->iface,
				  hapd->own_addr);
	/* ieee802_1x_kay_init() frees kay_ctx on failure */
	if (res == NULL)
		return -1;

	hapd->kay = res;

	return 0;
};
