/*
 * IEEE Std 802.1X-2010 definitions
 * Copyright (c) 2013-2014, Qualcomm Atheros, Inc.
 *
 * This software may be distributed under the terms of the BSD license.
 * See README for more details.
 */

#ifndef IEEE802_1X_DEFS_H
#define IEEE802_1X_DEFS_H

#define CS_ID_LEN		8
#define CS_ID_GCM_AES_128_OBSOLETE	0x0080020001000001ULL
#define CS_ID_GCM_AES_128	0x0080C20001000001ULL
#define CS_ID_GCM_AES_256	0x0080C20001000002ULL
#define CS_ID_GCM_AES_XPN_128	0x0080C20001000003ULL
#define CS_ID_GCM_AES_XPN_256	0x0080C20001000004ULL
#define CS_NAME_GCM_AES_128	"GCM-AES-128"
#define CS_NAME_GCM_AES_256	"GCM-AES-256"
#define CS_NAME_GCM_AES_XPN_128	"GCM-AES-XPN-128"
#define CS_NAME_GCM_AES_XPN_256	"GCM-AES-XPN-256"

enum macsec_policy {
	/**
	 * Should secure sessions.
	 * This accepts key server's advice to determine whether to secure the
	 * session or not.
	 */
	SHOULD_SECURE,

	/**
	 * Disabled MACsec - do not secure sessions.
	 */
	DO_NOT_SECURE,

	/**
	 * Should secure sessions, and try to use encryption.
	 * Like @SHOULD_SECURE, this follows the key server's decision.
	 */
	SHOULD_ENCRYPT,
};


/* IEEE Std 802.1X-2010 - Table 11-6 - MACsec Capability */
enum macsec_cap {
	/**
	 * MACsec is not implemented
	 */
	MACSEC_CAP_NOT_IMPLEMENTED,

	/**
	 * 'Integrity without confidentiality'
	 */
	MACSEC_CAP_INTEGRITY,

	/**
	 * 'Integrity without confidentiality' and
	 * 'Integrity and confidentiality' with a confidentiality offset of 0
	 */
	MACSEC_CAP_INTEG_AND_CONF,

	/**
	 * 'Integrity without confidentiality' and
	 * 'Integrity and confidentiality' with a confidentiality offset of 0,
	 * 30, 50
	 */
	MACSEC_CAP_INTEG_AND_CONF_0_30_50,
};

enum validate_frames {
	Disabled,
	Checked,
	Strict,
};

/* IEEE Std 802.1X-2010 - Table 11-6 - Confidentiality Offset */
enum confidentiality_offset {
	CONFIDENTIALITY_NONE      = 0,
	CONFIDENTIALITY_OFFSET_0  = 1,
	CONFIDENTIALITY_OFFSET_30 = 2,
	CONFIDENTIALITY_OFFSET_50 = 3,
};

/* IEEE Std 802.1X-2010 - Table 9-2 */
#define DEFAULT_PRIO_INFRA_PORT        0x10
#define DEFAULT_PRIO_PRIMRAY_AP        0x30
#define DEFAULT_PRIO_SECONDARY_AP      0x50
#define DEFAULT_PRIO_GROUP_CA_MEMBER   0x70
#define DEFAULT_PRIO_NOT_KEY_SERVER    0xFF

/* EAPOL Announcement */
#define IEEE8021X_ANN_MAX_KMD_NAME 253
#define IEEE8021X_ANN_MAX_NID_NAME 100

#define IEEE8021X_ANN_TIME 5000
#define IEEE8021X_ANN_HOLD_TIME 15000
#define IEEE8021X_ANN_RATE_LIMIT 5
#define IEEE8021X_ANN_DELAY 30

/* IEEE Std 802.1X-2010 - Table 11-8 */
enum { IEEE802_1X_ANN_TLV_ACCESS_INFO = 111,
       IEEE802_1X_ANN_TLV_MACSEC_CS = 112,
       IEEE802_1X_ANN_TLV_KMD = 113,
       IEEE802_1X_ANN_TLV_NID = 114,
       IEEE802_1X_ANN_TLV_MAX = 127,
};

/* IEEE Std 802.1X-2010 - Table 11-9 */
#define IEEE802_1X_ACCESS_INFO_CAP_EAP BIT(0)
#define IEEE802_1X_ACCESS_INFO_CAP_EAP_MKA BIT(1)
#define IEEE802_1X_ACCESS_INFO_CAP_EAP_MKA_MACSEC BIT(2)
#define IEEE802_1X_ACCESS_INFO_CAP_MKA BIT(3)
#define IEEE802_1X_ACCESS_INFO_CAP_MKA_MACSEC BIT(4)
#define IEEE802_1X_ACCESS_INFO_CAP_HIGHER_LAYER BIT(5)
#define IEEE802_1X_ACCESS_INFO_CAP_HIGHER_LAYER_FALLBACK BIT(6)
#define IEEE802_1X_ACCESS_INFO_CAP_VENDOR_SPECIFIC BIT(7)

#endif /* IEEE802_1X_DEFS_H */
