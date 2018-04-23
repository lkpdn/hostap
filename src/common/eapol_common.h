/*
 * EAPOL definitions shared between hostapd and wpa_supplicant
 * Copyright (c) 2002-2007, Jouni Malinen <j@w1.fi>
 *
 * This software may be distributed under the terms of the BSD license.
 * See README for more details.
 */

#ifndef EAPOL_COMMON_H
#define EAPOL_COMMON_H

/* IEEE Std 802.1X-2004 */

static const u8 pae_group_addr[ETH_ALEN] = {
	0x01, 0x80, 0xc2, 0x00, 0x00, 0x03
};

#ifdef _MSC_VER
#pragma pack(push, 1)
#endif /* _MSC_VER */

struct ieee802_1x_hdr {
	u8 version;
	u8 type;
	be16 length;
	/* followed by length octets of data */
} STRUCT_PACKED;

struct ieee8023_hdr {
	u8 dest[ETH_ALEN];
	u8 src[ETH_ALEN];
	be16 ethertype;
} STRUCT_PACKED;

#ifdef _MSC_VER
#pragma pack(pop)
#endif /* _MSC_VER */

#ifdef CONFIG_MACSEC
#define EAPOL_VERSION 3
#else /* CONFIG_MACSEC */
#define EAPOL_VERSION 2
#endif /* CONFIG_MACSEC */

enum { IEEE802_1X_TYPE_EAP_PACKET = 0,
       IEEE802_1X_TYPE_EAPOL_START = 1,
       IEEE802_1X_TYPE_EAPOL_LOGOFF = 2,
       IEEE802_1X_TYPE_EAPOL_KEY = 3,
       IEEE802_1X_TYPE_EAPOL_ENCAPSULATED_ASF_ALERT = 4,
       /* IEEE 802.1X-2010 */
       IEEE802_1X_TYPE_EAPOL_MKA = 5,
       IEEE802_1X_TYPE_EAPOL_ANNOUNCEMENT_GENERIC = 6,
       IEEE802_1X_TYPE_EAPOL_ANNOUNCEMENT_SPECIFIC = 7,
       IEEE802_1X_TYPE_EAPOL_ANNOUNCEMENT_REQ = 8,
};

enum { EAPOL_KEY_TYPE_RC4 = 1, EAPOL_KEY_TYPE_RSN = 2,
       EAPOL_KEY_TYPE_WPA = 254 };


#define IEEE8021X_REPLAY_COUNTER_LEN 8
#define IEEE8021X_KEY_SIGN_LEN 16
#define IEEE8021X_KEY_IV_LEN 16

#define IEEE8021X_KEY_INDEX_FLAG 0x80
#define IEEE8021X_KEY_INDEX_MASK 0x03

#ifdef _MSC_VER
#pragma pack(push, 1)
#endif /* _MSC_VER */

struct ieee802_1x_eapol_key {
	u8 type;
	/* Note: key_length is unaligned */
	u8 key_length[2];
	/* does not repeat within the life of the keying material used to
	 * encrypt the Key field; 64-bit NTP timestamp MAY be used here */
	u8 replay_counter[IEEE8021X_REPLAY_COUNTER_LEN];
	u8 key_iv[IEEE8021X_KEY_IV_LEN]; /* cryptographically random number */
	u8 key_index; /* key flag in the most significant bit:
		       * 0 = broadcast (default key),
		       * 1 = unicast (key mapping key); key index is in the
		       * 7 least significant bits */
	/* HMAC-MD5 message integrity check computed with MS-MPPE-Send-Key as
	 * the key */
	u8 key_signature[IEEE8021X_KEY_SIGN_LEN];

	/* followed by key: if packet body length = 44 + key length, then the
	 * key field (of key_length bytes) contains the key in encrypted form;
	 * if packet body length = 44, key field is absent and key_length
	 * represents the number of least significant octets from
	 * MS-MPPE-Send-Key attribute to be used as the keying material;
	 * RC4 key used in encryption = Key-IV + MS-MPPE-Recv-Key */
} STRUCT_PACKED;

/* IEEE Std 802.1X-2010 */

#ifdef CONFIG_MACSEC
struct ieee802_1x_ann_tlv_hdr {
#if __BYTE_ORDER == __LITTLE_ENDIAN
	u16 len:9;
	u16 type:7;
#elif __BYTE_ORDER == __BIG_ENDIAN
	u16 type:7;
	u16 len:9;
#else
#error "Please fix <bits/endian.h>"
#endif
} STRUCT_PACKED;

struct ieee802_1x_eapol_start {
	u8 request;
	u8 tlvs[0];
} STRUCT_PACKED;

/* 802.1X-2010 11.12.2 */
struct ieee802_1x_eapol_ann_tlv_access_info {
#if __BYTE_ORDER == __LITTLE_ENDIAN
	u8 status:2;
	u8 requested:1;
	u8 unauthenticated_access:2;
	u8 virtual_port_access:1;
	u8 group_access:1;
	u8 reserved:1;
#elif __BYTE_ORDER == __BIG_ENDIAN
	u8 reserved:1;
	u8 group_access:1;
	u8 virtual_port_access:1;
	u8 unauthenticated_access:2;
	u8 requested:1;
	u8 status:2;
#else
#error "Please fix <bits/endian.h>"
#endif
	u8 capabilities;
};

struct ieee802_1x_eapol_ann_macsec_cs {
	u16 capability;
	u64 ieee802_1ae_cs_ref_number;
} STRUCT_PACKED;

/* 802.1X-2010 11.12.3 */
struct ieee802_1x_eapol_ann_tlv_macsec_cs {
	struct ieee802_1x_eapol_ann_macsec_cs *cs;
} STRUCT_PACKED;

/* 802.1X-2010 11.12.4 */
struct ieee802_1x_eapol_ann_tlv_kmd {
	char *name;
};

/* 802.1X-2010 11.12.1 */
struct ieee802_1x_eapol_ann_tlv_nid {
	char *name;
};

/* IEEE 802.1X-2010 Figure 12-3. */
struct ieee802_1x_announcement {
	char *nid;
	char *kmd;
	u8 access_status;
	u8 unauthenticated_access;
	u8 access_capabilities;
	struct ieee802_1x_eapol_ann_macsec_cs *cs;
	u8 specific;
	u8 requested_nid;
};
#endif /* CONFIG_MACSEC */

#ifdef _MSC_VER
#pragma pack(pop)
#endif /* _MSC_VER */

#endif /* EAPOL_COMMON_H */
