/*
 * Common functions for Wired Ethernet driver interfaces
 * Copyright (c) 2005-2009, Jouni Malinen <j@w1.fi>
 * Copyright (c) 2004, Gunter Burchardt <tira@isx.de>
 *
 * This software may be distributed under the terms of the BSD license.
 * See README for more details.
 */

#include "includes.h"

#include "common.h"
#include "eloop.h"
#include "driver.h"
#include "driver_wired_common.h"

#include <sys/ioctl.h>
#include <net/if.h>
#ifdef __linux__
#include <netpacket/packet.h>
#include <net/if_arp.h>
#include <net/if.h>
#endif /* __linux__ */
#if defined(__FreeBSD__) || defined(__DragonFly__) || defined(__FreeBSD_kernel__)
#include <net/if_dl.h>
#include <net/if_media.h>
#endif /* defined(__FreeBSD__) || defined(__DragonFly__) || defined(__FreeBSD_kernel__) */
#ifdef __sun__
#include <sys/sockio.h>
#endif /* __sun__ */

#ifdef _MSC_VER
#pragma pack(push, 1)
#endif /* _MSC_VER */

struct ieee8023_hdr {
	u8 dest[6];
	u8 src[6];
	u16 ethertype;
} STRUCT_PACKED;

#ifdef _MSC_VER
#pragma pack(pop)
#endif /* _MSC_VER */

/* TODO: detecting new devices should eventually be changed from using DHCP
 * snooping to trigger on any packet from a new layer 2 MAC address, e.g.,
 * based on ebtables, etc. */

struct dhcp_message {
	u_int8_t op;
	u_int8_t htype;
	u_int8_t hlen;
	u_int8_t hops;
	u_int32_t xid;
	u_int16_t secs;
	u_int16_t flags;
	u_int32_t ciaddr;
	u_int32_t yiaddr;
	u_int32_t siaddr;
	u_int32_t giaddr;
	u_int8_t chaddr[16];
	u_int8_t sname[64];
	u_int8_t file[128];
	u_int32_t cookie;
	u_int8_t options[308]; /* 312 - cookie */
};


#ifdef __linux__
static void handle_data(void *ctx, unsigned char *buf, size_t len)
{
#ifdef HOSTAPD
	struct ieee8023_hdr *hdr;
	u8 *pos, *sa;
	size_t left;
	union wpa_event_data event;

	/* must contain at least ieee8023_hdr 6 byte source, 6 byte dest,
	 * 2 byte ethertype */
	if (len < 14) {
		wpa_printf(MSG_MSGDUMP, "handle_data: too short (%lu)",
			   (unsigned long) len);
		return;
	}

	hdr = (struct ieee8023_hdr *) buf;

	switch (ntohs(hdr->ethertype)) {
		case ETH_P_PAE:
			wpa_printf(MSG_MSGDUMP, "Received EAPOL packet");
			sa = hdr->src;
			os_memset(&event, 0, sizeof(event));
			event.new_sta.addr = sa;
			wpa_supplicant_event(ctx, EVENT_NEW_STA, &event);

			pos = (u8 *) (hdr + 1);
			left = len - sizeof(*hdr);
			drv_event_eapol_rx(ctx, sa, pos, left);
		break;

	default:
		wpa_printf(MSG_DEBUG, "Unknown ethertype 0x%04x in data frame",
			   ntohs(hdr->ethertype));
		break;
	}
#endif /* HOSTAPD */
}


static void handle_read(int sock, void *eloop_ctx, void *sock_ctx)
{
	int len;
	unsigned char buf[3000];

	len = recv(sock, buf, sizeof(buf), 0);
	if (len < 0) {
		wpa_printf(MSG_ERROR, "recv: %s", strerror(errno));
		return;
	}

	handle_data(eloop_ctx, buf, len);
}


static void handle_dhcp(int sock, void *eloop_ctx, void *sock_ctx)
{
	int len;
	unsigned char buf[3000];
	struct dhcp_message *msg;
	u8 *mac_address;
	union wpa_event_data event;

	len = recv(sock, buf, sizeof(buf), 0);
	if (len < 0) {
		wpa_printf(MSG_ERROR, "recv: %s", strerror(errno));
		return;
	}

	/* must contain at least dhcp_message->chaddr */
	if (len < 44) {
		wpa_printf(MSG_MSGDUMP, "handle_dhcp: too short (%d)", len);
		return;
	}

	msg = (struct dhcp_message *) buf;
	mac_address = (u8 *) &(msg->chaddr);

	wpa_printf(MSG_MSGDUMP, "Got DHCP broadcast packet from " MACSTR,
		   MAC2STR(mac_address));

	os_memset(&event, 0, sizeof(event));
	event.new_sta.addr = mac_address;
	wpa_supplicant_event(eloop_ctx, EVENT_NEW_STA, &event);
}
#endif /* __linux__ */


static int wired_init_sockets(struct driver_wired_common_data *common, u8 *own_addr)
{
#ifdef __linux__
	struct ifreq ifr;
	struct sockaddr_ll addr;
	struct sockaddr_in addr2;
	int n = 1;

	common->sock = socket(PF_PACKET, SOCK_RAW, htons(ETH_P_PAE));
	if (common->sock < 0) {
		wpa_printf(MSG_ERROR, "socket[PF_PACKET,SOCK_RAW]: %s",
			   strerror(errno));
		return -1;
	}

	if (eloop_register_read_sock(common->sock, handle_read,
				     common->ctx, NULL)) {
		wpa_printf(MSG_INFO, "Could not register read socket");
		return -1;
	}

	os_memset(&ifr, 0, sizeof(ifr));
	os_strlcpy(ifr.ifr_name, common->ifname, sizeof(ifr.ifr_name));
	if (ioctl(common->sock, SIOCGIFINDEX, &ifr) != 0) {
		wpa_printf(MSG_ERROR, "ioctl(SIOCGIFINDEX): %s",
			   strerror(errno));
		return -1;
	}

	os_memset(&addr, 0, sizeof(addr));
	addr.sll_family = AF_PACKET;
	addr.sll_ifindex = ifr.ifr_ifindex;
	wpa_printf(MSG_DEBUG, "Opening raw packet socket for ifindex %d",
		   addr.sll_ifindex);

	if (bind(common->sock, (struct sockaddr *) &addr, sizeof(addr)) < 0)
	{
		wpa_printf(MSG_ERROR, "bind: %s", strerror(errno));
		return -1;
	}

	/* filter multicast address */
	if (wired_multicast_membership(common->sock, ifr.ifr_ifindex,
				       pae_group_addr, 1) < 0) {
		wpa_printf(MSG_ERROR, "wired: Failed to add multicast group "
			   "membership");
		return -1;
	}

	os_memset(&ifr, 0, sizeof(ifr));
	os_strlcpy(ifr.ifr_name, common->ifname, sizeof(ifr.ifr_name));
	if (ioctl(common->sock, SIOCGIFHWADDR, &ifr) != 0) {
		wpa_printf(MSG_ERROR, "ioctl(SIOCGIFHWADDR): %s",
			   strerror(errno));
		return -1;
	}

	if (ifr.ifr_hwaddr.sa_family != ARPHRD_ETHER) {
		wpa_printf(MSG_INFO, "Invalid HW-addr family 0x%04x",
			   ifr.ifr_hwaddr.sa_family);
		return -1;
	}
	os_memcpy(own_addr, ifr.ifr_hwaddr.sa_data, ETH_ALEN);

	/* setup dhcp listen socket for sta detection */
	if ((common->dhcp_sock = socket(PF_INET, SOCK_DGRAM, IPPROTO_UDP)) < 0) {
		wpa_printf(MSG_ERROR, "socket call failed for dhcp: %s",
			   strerror(errno));
		return -1;
	}

	if (eloop_register_read_sock(common->dhcp_sock, handle_dhcp,
				     common->ctx, NULL)) {
		wpa_printf(MSG_INFO, "Could not register read socket");
		return -1;
	}

	os_memset(&addr2, 0, sizeof(addr2));
	addr2.sin_family = AF_INET;
	addr2.sin_port = htons(67);
	addr2.sin_addr.s_addr = INADDR_ANY;

	if (setsockopt(common->dhcp_sock, SOL_SOCKET, SO_REUSEADDR, (char *) &n,
		       sizeof(n)) == -1) {
		wpa_printf(MSG_ERROR, "setsockopt[SOL_SOCKET,SO_REUSEADDR]: %s",
			   strerror(errno));
		return -1;
	}
	if (setsockopt(common->dhcp_sock, SOL_SOCKET, SO_BROADCAST, (char *) &n,
		       sizeof(n)) == -1) {
		wpa_printf(MSG_ERROR, "setsockopt[SOL_SOCKET,SO_BROADCAST]: %s",
			   strerror(errno));
		return -1;
	}

	os_memset(&ifr, 0, sizeof(ifr));
	os_strlcpy(ifr.ifr_ifrn.ifrn_name, common->ifname, IFNAMSIZ);
	if (setsockopt(common->dhcp_sock, SOL_SOCKET, SO_BINDTODEVICE,
		       (char *) &ifr, sizeof(ifr)) < 0) {
		wpa_printf(MSG_ERROR,
			   "setsockopt[SOL_SOCKET,SO_BINDTODEVICE]: %s",
			   strerror(errno));
		return -1;
	}

	if (bind(common->dhcp_sock, (struct sockaddr *) &addr2,
		 sizeof(struct sockaddr)) == -1) {
		wpa_printf(MSG_ERROR, "bind: %s", strerror(errno));
		return -1;
	}

	return 0;
#else /* __linux__ */
	return -1;
#endif /* __linux__ */
}


static int driver_wired_get_ifflags(const char *ifname, int *flags)
{
	struct ifreq ifr;
	int s;

	s = socket(PF_INET, SOCK_DGRAM, 0);
	if (s < 0) {
		wpa_printf(MSG_ERROR, "socket: %s", strerror(errno));
		return -1;
	}

	os_memset(&ifr, 0, sizeof(ifr));
	os_strlcpy(ifr.ifr_name, ifname, IFNAMSIZ);
	if (ioctl(s, SIOCGIFFLAGS, (caddr_t) &ifr) < 0) {
		wpa_printf(MSG_ERROR, "ioctl[SIOCGIFFLAGS]: %s",
			   strerror(errno));
		close(s);
		return -1;
	}
	close(s);
	*flags = ifr.ifr_flags & 0xffff;
	return 0;
}


static int driver_wired_set_ifflags(const char *ifname, int flags)
{
	struct ifreq ifr;
	int s;

	s = socket(PF_INET, SOCK_DGRAM, 0);
	if (s < 0) {
		wpa_printf(MSG_ERROR, "socket: %s", strerror(errno));
		return -1;
	}

	os_memset(&ifr, 0, sizeof(ifr));
	os_strlcpy(ifr.ifr_name, ifname, IFNAMSIZ);
	ifr.ifr_flags = flags & 0xffff;
	if (ioctl(s, SIOCSIFFLAGS, (caddr_t) &ifr) < 0) {
		wpa_printf(MSG_ERROR, "ioctl[SIOCSIFFLAGS]: %s",
			   strerror(errno));
		close(s);
		return -1;
	}
	close(s);
	return 0;
}


static int driver_wired_multi(const char *ifname, const u8 *addr, int add)
{
	struct ifreq ifr;
	int s;

#ifdef __sun__
	return -1;
#endif /* __sun__ */

	s = socket(PF_INET, SOCK_DGRAM, 0);
	if (s < 0) {
		wpa_printf(MSG_ERROR, "socket: %s", strerror(errno));
		return -1;
	}

	os_memset(&ifr, 0, sizeof(ifr));
	os_strlcpy(ifr.ifr_name, ifname, IFNAMSIZ);
#ifdef __linux__
	ifr.ifr_hwaddr.sa_family = AF_UNSPEC;
	os_memcpy(ifr.ifr_hwaddr.sa_data, addr, ETH_ALEN);
#endif /* __linux__ */
#if defined(__FreeBSD__) || defined(__DragonFly__) || defined(__FreeBSD_kernel__)
	{
		struct sockaddr_dl *dlp;

		dlp = (struct sockaddr_dl *) &ifr.ifr_addr;
		dlp->sdl_len = sizeof(struct sockaddr_dl);
		dlp->sdl_family = AF_LINK;
		dlp->sdl_index = 0;
		dlp->sdl_nlen = 0;
		dlp->sdl_alen = ETH_ALEN;
		dlp->sdl_slen = 0;
		os_memcpy(LLADDR(dlp), addr, ETH_ALEN);
	}
#endif /* defined(__FreeBSD__) || defined(__DragonFly__) || defined(FreeBSD_kernel__) */
#if defined(__NetBSD__) || defined(__OpenBSD__) || defined(__APPLE__)
	{
		struct sockaddr *sap;

		sap = (struct sockaddr *) &ifr.ifr_addr;
		sap->sa_len = sizeof(struct sockaddr);
		sap->sa_family = AF_UNSPEC;
		os_memcpy(sap->sa_data, addr, ETH_ALEN);
	}
#endif /* defined(__NetBSD__) || defined(__OpenBSD__) || defined(__APPLE__) */

	if (ioctl(s, add ? SIOCADDMULTI : SIOCDELMULTI, (caddr_t) &ifr) < 0) {
		wpa_printf(MSG_ERROR, "ioctl[SIOC{ADD/DEL}MULTI]: %s",
			   strerror(errno));
		close(s);
		return -1;
	}
	close(s);
	return 0;
}


int wired_multicast_membership(int sock, int ifindex, const u8 *addr, int add)
{
#ifdef __linux__
	struct packet_mreq mreq;

	if (sock < 0)
		return -1;

	os_memset(&mreq, 0, sizeof(mreq));
	mreq.mr_ifindex = ifindex;
	mreq.mr_type = PACKET_MR_MULTICAST;
	mreq.mr_alen = ETH_ALEN;
	os_memcpy(mreq.mr_address, addr, ETH_ALEN);

	if (setsockopt(sock, SOL_PACKET,
		       add ? PACKET_ADD_MEMBERSHIP : PACKET_DROP_MEMBERSHIP,
		       &mreq, sizeof(mreq)) < 0) {
		wpa_printf(MSG_ERROR, "setsockopt: %s", strerror(errno));
		return -1;
	}
	return 0;
#else /* __linux__ */
	return -1;
#endif /* __linux__ */
}


int driver_wired_get_ssid(void *priv, u8 *ssid)
{
	ssid[0] = 0;
	return 0;
}


int driver_wired_get_bssid(void *priv, u8 *bssid)
{
	/* Report PAE group address as the "BSSID" for wired connection. */
	os_memcpy(bssid, pae_group_addr, ETH_ALEN);
	return 0;
}


int driver_wired_get_capa(void *priv, struct wpa_driver_capa *capa)
{
	os_memset(capa, 0, sizeof(*capa));
	capa->flags = WPA_DRIVER_FLAGS_WIRED;
	return 0;
}


#if defined(__FreeBSD__) || defined(__DragonFly__) || defined(__FreeBSD_kernel__)
static int driver_wired_get_ifstatus(const char *ifname, int *status)
{
	struct ifmediareq ifmr;
	int s;

	s = socket(PF_INET, SOCK_DGRAM, 0);
	if (s < 0) {
		wpa_printf(MSG_ERROR, "socket: %s", strerror(errno));
		return -1;
	}

	os_memset(&ifmr, 0, sizeof(ifmr));
	os_strlcpy(ifmr.ifm_name, ifname, IFNAMSIZ);
	if (ioctl(s, SIOCGIFMEDIA, (caddr_t) &ifmr) < 0) {
		wpa_printf(MSG_ERROR, "ioctl[SIOCGIFMEDIA]: %s",
			   strerror(errno));
		close(s);
		return -1;
	}
	close(s);
	*status = (ifmr.ifm_status & (IFM_ACTIVE | IFM_AVALID)) ==
		(IFM_ACTIVE | IFM_AVALID);

	return 0;
}
#endif /* defined(__FreeBSD__) || defined(__DragonFly__) || defined(FreeBSD_kernel__) */


int driver_wired_send_eapol_common(struct driver_wired_common_data *common,
				   const u8 *addr, const u8 *data,
				   size_t data_len, int encrypt,
				   const u8 *own_addr, u32 flags)
{
	struct ieee8023_hdr *hdr;
	size_t len;
	u8 *pos;
	int res;

	len = sizeof(*hdr) + data_len;
	hdr = os_zalloc(len);
	if (hdr == NULL) {
		wpa_printf(MSG_INFO,
			   "malloc() failed for wired_send_eapol_common(len=%lu)",
			   (unsigned long) len);
		return -1;
	}

	os_memcpy(hdr->dest, common->use_pae_group_addr ? pae_group_addr : addr,
		  ETH_ALEN);
	os_memcpy(hdr->src, own_addr, ETH_ALEN);
	hdr->ethertype = htons(ETH_P_PAE);

	pos = (u8 *) (hdr + 1);
	os_memcpy(pos, data, data_len);

	res = send(common->sock, (u8 *) hdr, len, 0);
	os_free(hdr);

	if (res < 0) {
		wpa_printf(MSG_ERROR,
			   "wired_send_eapol_common - packet len: %lu - failed: send: %s",
			   (unsigned long) len, strerror(errno));
	}

	return res;
}


int driver_wired_hapd_init_common(struct driver_wired_common_data *common,
				  struct wpa_init_params *params,
				  void *ctx)
{
	common->ctx = ctx;
	os_strlcpy(common->ifname, params->ifname, sizeof(common->ifname));
	common->use_pae_group_addr = params->use_pae_group_addr;

	if (wired_init_sockets(common, params->own_addr)) {
		return -1;
	}

	return 0;
}


void driver_wired_hapd_deinit_common(struct driver_wired_common_data *common)
{
	if (common->sock >= 0) {
		eloop_unregister_read_sock(common->sock);
		close(common->sock);
	}

	if (common->dhcp_sock >= 0) {
		eloop_unregister_read_sock(common->dhcp_sock);
		close(common->dhcp_sock);
	}
}


int driver_wired_init_common(struct driver_wired_common_data *common,
			     const char *ifname, void *ctx)
{
	int flags;

	os_strlcpy(common->ifname, ifname, sizeof(common->ifname));
	common->ctx = ctx;

#ifdef __linux__
	common->pf_sock = socket(PF_PACKET, SOCK_DGRAM, 0);
	if (common->pf_sock < 0)
		wpa_printf(MSG_ERROR, "socket(PF_PACKET): %s", strerror(errno));
#else /* __linux__ */
	common->pf_sock = -1;
#endif /* __linux__ */

	if (driver_wired_get_ifflags(ifname, &flags) == 0 &&
	    !(flags & IFF_UP) &&
	    driver_wired_set_ifflags(ifname, flags | IFF_UP) == 0)
		common->iff_up = 1;

	if (wired_multicast_membership(common->pf_sock,
				       if_nametoindex(common->ifname),
				       pae_group_addr, 1) == 0) {
		wpa_printf(MSG_DEBUG,
			   "%s: Added multicast membership with packet socket",
			   __func__);
		common->membership = 1;
	} else if (driver_wired_multi(ifname, pae_group_addr, 1) == 0) {
		wpa_printf(MSG_DEBUG,
			   "%s: Added multicast membership with SIOCADDMULTI",
			   __func__);
		common->multi = 1;
	} else if (driver_wired_get_ifflags(ifname, &flags) < 0) {
		wpa_printf(MSG_INFO, "%s: Could not get interface flags",
			   __func__);
		return -1;
	} else if (flags & IFF_ALLMULTI) {
		wpa_printf(MSG_DEBUG,
			   "%s: Interface is already configured for multicast",
			   __func__);
	} else if (driver_wired_set_ifflags(ifname,
						flags | IFF_ALLMULTI) < 0) {
		wpa_printf(MSG_INFO, "%s: Failed to enable allmulti", __func__);
		return -1;
	} else {
		wpa_printf(MSG_DEBUG, "%s: Enabled allmulti mode", __func__);
		common->iff_allmulti = 1;
	}
#if defined(__FreeBSD__) || defined(__DragonFly__) || defined(__FreeBSD_kernel__)
	{
		int status;

		wpa_printf(MSG_DEBUG, "%s: waiting for link to become active",
			   __func__);
		while (driver_wired_get_ifstatus(ifname, &status) == 0 &&
		       status == 0)
			sleep(1);
	}
#endif /* defined(__FreeBSD__) || defined(__DragonFly__) || defined(FreeBSD_kernel__) */

	return 0;
}


void driver_wired_deinit_common(struct driver_wired_common_data *common)
{
	int flags;

	if (common->membership &&
	    wired_multicast_membership(common->pf_sock,
				       if_nametoindex(common->ifname),
				       pae_group_addr, 0) < 0) {
		wpa_printf(MSG_DEBUG,
			   "%s: Failed to remove PAE multicast group (PACKET)",
			   __func__);
	}

	if (common->multi &&
	    driver_wired_multi(common->ifname, pae_group_addr, 0) < 0) {
		wpa_printf(MSG_DEBUG,
			   "%s: Failed to remove PAE multicast group (SIOCDELMULTI)",
			   __func__);
	}

	if (common->iff_allmulti &&
	    (driver_wired_get_ifflags(common->ifname, &flags) < 0 ||
	     driver_wired_set_ifflags(common->ifname,
				      flags & ~IFF_ALLMULTI) < 0)) {
		wpa_printf(MSG_DEBUG, "%s: Failed to disable allmulti mode",
			   __func__);
	}

	if (common->iff_up &&
	    driver_wired_get_ifflags(common->ifname, &flags) == 0 &&
	    (flags & IFF_UP) &&
	    driver_wired_set_ifflags(common->ifname, flags & ~IFF_UP) < 0) {
		wpa_printf(MSG_DEBUG, "%s: Failed to set the interface down",
			   __func__);
	}

	if (common->pf_sock != -1)
		close(common->pf_sock);
}
