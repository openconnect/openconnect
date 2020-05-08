/*
 * OpenConnect (SSL + DTLS) VPN client
 *
 * Copyright © 2020 David Woodhouse
 *
 * Author: David Woodhouse <dwmw2@infradead.org>
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU Lesser General Public License
 * version 2.1, as published by the Free Software Foundation.
 *
 * This program is distributed in the hope that it will be useful, but
 * WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * Lesser General Public License for more details.
 */

#include <config.h>

#include <errno.h>

#include "openconnect-internal.h"

#define PPP_LCP 0xc021
#define PPP_IPCP 0x8021
#define PPP_IP6CP 0x8057
#define PPP_IP 0x21
#define PPP_IP6 0x57

#define CONFREQ 1
#define CONFACK 2
#define CONFNAK 3
#define CONFREJ 4
#define TERMREQ 5
#define TERMACK 6
#define CODEREJ 7
#define PROTREJ 8
#define ECHOREQ 9
#define ECHOREP 10
#define DISCREQ 11

#define ASYNCMAP_LCP 0xffffffffUL

#define NEED_ESCAPE(c, map) ( ((c < 0x20) && (map && (1UL << (c)))) || (c == 0x7d) || (c == 0x7e) )

void buf_append_ppphdlc(struct oc_text_buf *buf, const unsigned char *bytes, int len, uint32_t asyncmap)
{
	const unsigned char *data = bytes;
	unsigned char esc[2] = { 0x7d, };
	int s = 0, i;

	buf_ensure_space(buf, len);
	buf_append_bytes(buf, "\x7e", 1);

	for (i = 0; i < len; i++) {
		if (NEED_ESCAPE(data[i], asyncmap)) {
			if (i > s)
				buf_append_bytes(buf, data + s, i - s - 1);
			esc[1] = data[i] ^ 0x20;
			buf_append_bytes(buf, esc, 2);
			s = i + 1;
		}
	}
}

#define ACCOMP 1
#define PFCOMP 2
#define VJCOMP 4

const char *ppps_names[] = {"DEAD", "ESTABLISH", "OPENED/AUTHENTICATE", "NETWORK", "TERMINATE"};

#define PPPS_DEAD 0
#define PPPS_ESTABLISH 1
#define PPPS_OPENED 2
#define PPPS_AUTHENTICATE 2
#define PPPS_NETWORK 3
#define PPPS_TERMINATE 4

#define NCP_REQ_RECEIVED 1
#define NCP_REQ_SENT 2
#define NCP_ACK_RECEIVED 4
#define NCP_ACK_SENT 8

struct oc_ppp {
	int hdlc;

	int ppp_state;
	int lcp_state;
	int ipcp_state;
	int ip6cp_state;

	uint32_t out_asyncmap;
	int out_lcp_opts;
	int32_t out_lcp_magic;
	struct in_addr out_peer_addr;
	uint64_t out_ipv6_int_ident;

	uint32_t in_asyncmap;
	int in_lcp_opts;
	int32_t in_lcp_magic;
	struct in_addr in_peer_addr;
	uint64_t in_ipv6_int_ident;
};

void ppp_print_state(struct openconnect_info *vpninfo, struct oc_ppp *ppp)
{
	vpn_progress(vpninfo, PRG_INFO, _("PPP state: %s (%d)\n  hdlc: %d\n"), ppps_names[ppp->ppp_state], ppp->ppp_state, ppp->hdlc);
	vpn_progress(vpninfo, PRG_INFO, _("    in: asyncmap=0x%08x, lcp_opts=%d, lcp_magic=0x%08x, peer=%s\n"),
		     ppp->in_asyncmap, ppp->in_lcp_opts, ppp->in_lcp_magic, inet_ntoa(ppp->in_peer_addr));
	vpn_progress(vpninfo, PRG_INFO, _("   out: asyncmap=0x%08x, lcp_opts=%d, lcp_magic=0x%08x, peer=%s\n"),
		     ppp->out_asyncmap, ppp->out_lcp_opts, ppp->out_lcp_magic, inet_ntoa(ppp->out_peer_addr));
}

#define buf_append_ppp(buf, hdlc, bytes, len, asyncmap)			\
	do {								\
		if (hdlc)						\
			buf_append_ppphdlc(buf, bytes, len, asyncmap);	\
		else							\
			buf_append_bytes(buf, bytes, len);		\
	} while (0)

/* XX: length of -2, -4 means to treat as host-endian which must be converted
 * to BE on the wire.
 */
static int buf_append_ppp_tlv(struct oc_text_buf *buf, int tag, int len, const void *data)
{
	unsigned char b[2];

	b[0] = tag;
	b[1] = (len>=0 ? len : -len) + 2;
	buf_append_bytes(buf, b, 2);
	switch (len) {
	case -2: buf_append_be16(buf, *(uint16_t *)(data)); break;
	case -4: buf_append_be32(buf, *(uint32_t *)(data)); break;
	case 0: break;
	default: buf_append_bytes(buf, data, len);
	}
	return len + 2;
}

void buf_append_ppp_hdr(struct oc_text_buf *buf, struct oc_ppp *ppp, uint16_t proto,
				uint8_t code, uint8_t id)
{
	uint32_t asyncmap = ASYNCMAP_LCP;
	unsigned char bytes[6];
	int lcp_opts = 0, n = 0;

	/* No ACCOMP or PFCOMP for LCP frames */
	if (proto != PPP_LCP) {
		asyncmap = ppp->out_asyncmap;
		lcp_opts = ppp->out_lcp_opts;
	}

	if (!(lcp_opts & ACCOMP)) {
		bytes[n++] = 0xff; /* Address */
		bytes[n++] = 0x03; /* Control */
	}

	if (proto > 0xff || !(lcp_opts & PFCOMP))
		bytes[n++] = proto >> 8;
	bytes[n++] = proto & 0xff;

	bytes[n++] = code;
	bytes[n++] = id;

	if (ppp->hdlc)
		buf_append_ppphdlc(buf, bytes, n, asyncmap);
	else
		buf_append_bytes(buf, bytes, n);
}

#define PROTO_TAG_LEN(p, t, l) (((p) << 16) | ((t) << 8) | (l))

static int handle_config_request(struct openconnect_info *vpninfo, struct oc_ppp *ppp,
				 int proto, int id, unsigned char *payload, int len)
{
	unsigned char ipv6a[16] = {0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0};
	const uint16_t vjc = htons(0x002d);
	struct oc_text_buf *buf;
	int ret, payload_len, pl_pos;
	unsigned char *p;

	for (p = payload ; p+1 < payload+len && p+p[1] <= payload+len; p += p[1]) {
		unsigned char t = p[0], l = p[1];
		switch (PROTO_TAG_LEN(proto, t, l-2)) {
		case PROTO_TAG_LEN(PPP_LCP, 1, 2):
			vpninfo->ip_info.mtu = load_be16(p+2);
			vpn_progress(vpninfo, PRG_DEBUG,
				     _("Received MTU %d from server\n"),
				     vpninfo->ip_info.mtu);
			break;
		case PROTO_TAG_LEN(PPP_LCP, 2, 4):
			ppp->in_asyncmap = load_be32(p+2);
			vpn_progress(vpninfo, PRG_DEBUG,
				     _("Received asyncmap of 0x%08x from server\n"),
				     ppp->in_asyncmap);
			break;
		case PROTO_TAG_LEN(PPP_LCP, 5, 4):
			ppp->in_lcp_magic = load_be32(p+2);
			vpn_progress(vpninfo, PRG_DEBUG,
				     _("Received magic number of 0x%08x from server\n"),
				     ppp->in_lcp_magic);
			break;
		case PROTO_TAG_LEN(PPP_LCP, 7, 0):
			vpn_progress(vpninfo, PRG_DEBUG,
				     _("Received protocol field compression from server\n"));
			ppp->in_lcp_opts |= PFCOMP;
			break;
		case PROTO_TAG_LEN(PPP_LCP, 8, 0):
			vpn_progress(vpninfo, PRG_DEBUG,
				     _("Received address and control field compression from server\n"));
			ppp->in_lcp_opts |= ACCOMP;
			break;
		case PROTO_TAG_LEN(PPP_IPCP, 2, 2):
			if (load_be16(p+2) == 0x002d) {
				/* Van Jacobson TCP/IP compression */
				vpn_progress(vpninfo, PRG_DEBUG,
					     _("Received Van Jacobson TCP/IP compression from server\n"));
				ppp->in_lcp_opts |= VJCOMP;
				break;
			}
			goto unknown;
		case PROTO_TAG_LEN(PPP_IPCP, 3, 4):
			memcpy(&ppp->in_peer_addr, p+2, 4);
			vpn_progress(vpninfo, PRG_DEBUG,
				     _("Received peer IPv4 address %s from server\n"),
				     inet_ntoa(ppp->in_peer_addr));
			break;
		case PROTO_TAG_LEN(PPP_IP6CP, 1, 8):
			memcpy(&ppp->in_ipv6_int_ident, p+2, 8);
			vpn_progress(vpninfo, PRG_DEBUG,
				     _("Received peer IPv6 interface identifier :%x:%x:%x:%x from server\n"),
				     load_be16(p+2), load_be16(p+4), load_be16(p+6), load_be16(p+8));
			break;
		default:
		unknown:
			vpn_progress(vpninfo, PRG_DEBUG,
				     _("Received unknown proto 0x%04x TLV (tag %d, len %d+2) from server:\n"),
				     proto, t, l);
			dump_buf_hex(vpninfo, PRG_DEBUG, '<', p, (int)p[1]);
			ret = -EINVAL;
			goto out;
		}
	}
	if (p != payload+len) {
		vpn_progress(vpninfo, PRG_DEBUG,
			     _("Received %ld extra bytes at end of config request:\n"), payload + len - p);
		dump_buf_hex(vpninfo, PRG_DEBUG, '<', p, payload + len - p);
	}

	/* Ack server's request */
	buf = buf_alloc();
	buf_append_be32(buf, 0xf5000000);	    /* F5 00, length placeholder */
	buf_append_ppp_hdr(buf, ppp, proto, 2 /* Configure-Ack */, id);
	buf_append_be16(buf, 4 + len);              /* payload length including code, id, own bytes */
	buf_append_bytes(buf, payload, len);
	if ((ret = buf_error(buf)) != 0)
		goto buf_out;
	store_be16(buf->data + 2, buf->pos - 4);    /* excludes F5 header */

	vpn_progress(vpninfo, PRG_DEBUG, _("Ack proto 0x%04x/id %d config from server\n"), proto, id);
	if (vpninfo->dump_http_traffic)
		dump_buf_hex(vpninfo, PRG_DEBUG, '>', (void *)buf->data, buf->pos);
	if ((ret = vpninfo->ssl_write(vpninfo, buf->data, buf->pos)) < 0)
		goto buf_out;
	buf_truncate(buf);

	/* Now send our own request */
	id++;
	buf_append_be32(buf, 0xf5000000);           /* F5 00, length placeholder  */
	buf_append_ppp_hdr(buf, ppp, proto, 1 /* Configure-Request */, id);
	payload_len = 4;			   /* XX: includes code, id, own bytes */
	pl_pos = buf->pos;
	buf_append_be16(buf, 0);	           /* payload length placeholder  */

	switch (proto) {
	case PPP_LCP:
		ppp->lcp_state |= NCP_REQ_RECEIVED | NCP_REQ_SENT | NCP_ACK_SENT;
		ppp->out_asyncmap = 0;
		ppp->out_lcp_magic = ~ppp->in_lcp_magic;
		ppp->out_lcp_opts = ACCOMP | PFCOMP;

		payload_len += buf_append_ppp_tlv(buf, 1, -2, &vpninfo->ip_info.mtu);
		payload_len += buf_append_ppp_tlv(buf, 2, -4, &ppp->out_asyncmap);
		payload_len += buf_append_ppp_tlv(buf, 5, -4, &ppp->out_lcp_magic);
		if (ppp->out_lcp_opts & PFCOMP)
			payload_len += buf_append_ppp_tlv(buf, 7, 0, NULL);
		if (ppp->out_lcp_opts & ACCOMP)
			payload_len += buf_append_ppp_tlv(buf, 8, 0, NULL);
		break;

	case PPP_IPCP:
		ppp->ipcp_state |= NCP_REQ_RECEIVED | NCP_REQ_SENT | NCP_ACK_SENT;
		if (vpninfo->ip_info.addr)
			ppp->out_peer_addr.s_addr = inet_addr(vpninfo->ip_info.addr);

		if (ppp->out_lcp_opts & VJCOMP) payload_len += buf_append_ppp_tlv(buf, 2, -2, &vjc);
		payload_len += buf_append_ppp_tlv(buf, 3, 4, &ppp->out_peer_addr);
		break;

	case PPP_IP6CP:
		ppp->ip6cp_state |= NCP_REQ_RECEIVED | NCP_REQ_SENT | NCP_ACK_SENT;
		if (vpninfo->ip_info.addr6)
			inet_pton(AF_INET6, vpninfo->ip_info.addr6, &ipv6a);
		memcpy(&ppp->out_ipv6_int_ident, ipv6a+8, 8); /* last 8 bytes of addr6 */

		payload_len += buf_append_ppp_tlv(buf, 1, 8, &ppp->out_ipv6_int_ident);
		break;
	}

	if ((ret = buf_error(buf)) != 0)
		goto buf_out;
	store_be16(buf->data + 2, buf->pos - 4);
	store_be16(buf->data + pl_pos, payload_len);

	vpn_progress(vpninfo, PRG_DEBUG, _("Sending our proto 0x%04x/id %d config request to server\n"), proto, id);
	if (vpninfo->dump_http_traffic)
		dump_buf_hex(vpninfo, PRG_DEBUG, '>', (void *)buf->data, buf->pos);
	if ((ret = vpninfo->ssl_write(vpninfo, buf->data, buf->pos)) >= 0)
		ret = 0;

buf_out:
        buf_free(buf);
out:
	return ret;
}

static int send_echo_reply(struct openconnect_info *vpninfo, struct oc_ppp *ppp,
			   uint16_t proto, int id)
{
	struct oc_text_buf *buf = buf_alloc();
	int ret;

	buf_append_be32(buf, 0xf5000000);
	buf_append_ppp_hdr(buf, ppp, proto, 10 /* Echo-Reply */, id);
	buf_append_be16(buf, 8);	       /* payload length includes code, id, own 2 bytes, magic */
	buf_append_be32(buf, ppp->out_lcp_magic);
	if ((ret = buf_error(buf)) != 0)
		goto out;
	store_be16(buf->data + 2, buf->pos - 4);
	vpn_progress(vpninfo, PRG_DEBUG, _("Sending proto 0x%04x/id %d echo reply to server\n"), proto, id);
	if (vpninfo->dump_http_traffic)
		dump_buf_hex(vpninfo, PRG_DEBUG, '>', (void *)buf->data, buf->pos);
	if ((ret = vpninfo->ssl_write(vpninfo, buf->data, buf->pos)) >= 0)
		ret = 0;

out:
	buf_free(buf);
	return ret;
}

static int send_terminate_ack(struct openconnect_info *vpninfo, struct oc_ppp *ppp,
			      uint16_t proto, int id)
{
	struct oc_text_buf *buf = buf_alloc();
	int ret;

	buf_append_be32(buf, 0xf5000000);
	buf_append_ppp_hdr(buf, ppp, proto, 6 /* Terminate-Ack */, id);
	buf_append_be16(buf, 4);	       /* payload length includes code, id, own 2 bytes */
	if ((ret = buf_error(buf)) != 0)
		goto out;
	store_be16(buf->data + 2, buf->pos - 4);
	vpn_progress(vpninfo, PRG_DEBUG, _("Sending proto 0x%04x/id %d terminate ack to server\n"), proto, id);
	if (vpninfo->dump_http_traffic)
		dump_buf_hex(vpninfo, PRG_DEBUG, '>', (void *)buf->data, buf->pos);
	if ((ret = vpninfo->ssl_write(vpninfo, buf->data, buf->pos)) >= 0)
		ret = 0;

out:
	buf_free(buf);
	return ret;
}

static int handle_config_packet(struct openconnect_info *vpninfo, struct oc_ppp *ppp,
				uint16_t proto, unsigned char *p, int len)
{
	int code = p[0], id = p[1];

	switch (code) {
	case 1: /* Configure-Request */
		vpn_progress(vpninfo, PRG_DEBUG, _("Received proto 0x%04x/id %d config request from server\n"), proto, id);
		return handle_config_request(vpninfo, ppp, proto, id, p + 4, len - 4);

	/* XX: we could verify that the ack/reply bytes match the request bytes,
	 * and the ID is the expected one, but it isn't 1992, so let's not.
	 */
	case 2: /* Configure-Ack */
		vpn_progress(vpninfo, PRG_DEBUG, _("Received ack of our proto 0x%04x/id %d config request from server\n"), proto, id);
		switch (proto) {
		case PPP_LCP:   ppp->lcp_state |= NCP_ACK_RECEIVED; break;
		case PPP_IPCP:  ppp->ipcp_state |= NCP_ACK_RECEIVED; break;
		case PPP_IP6CP: ppp->ip6cp_state |= NCP_ACK_RECEIVED; break;
		}
		return 0;

	case 9: /* Echo-Request */
		vpn_progress(vpninfo, PRG_DEBUG, _("Received proto 0x%04x/id %d echo request from server\n"), proto, id);
		if (ppp->ppp_state >= PPPS_OPENED)
			return send_echo_reply(vpninfo, ppp, proto, id);
		return 0;

	case 5:	/* Terminate-Request */
		vpninfo->quit_reason = strndup((char *)(p + 4), len - 4);
		ppp->ppp_state = PPPS_TERMINATE;
		return send_terminate_ack(vpninfo, ppp, proto, id);

	case 6: /* Terminate-Ack */
		ppp->ppp_state = PPPS_TERMINATE;
		return 0;

	case 10: /* Echo-Reply */
	case 11: /* Discard-Request */
		return 0;

	case 3: /* Configure-Nak */
	case 4: /* Configure-Reject */
	case 7: /* Code-Reject */
	case 8: /* Protocol-Reject */
	default:
		return -EINVAL;
	}
}

int ppp_negotiate_config(struct openconnect_info *vpninfo, struct oc_ppp *ppp, int hdlc, int ipv4, int ipv6)
{
	unsigned char bytes[16384], *p;
	uint16_t proto;
	int ret = 0, payload_len, last_state;

	ppp->ppp_state = PPPS_ESTABLISH;
	ppp->hdlc = hdlc;

	while (ppp->ppp_state >= PPPS_ESTABLISH && ppp->ppp_state < PPPS_NETWORK) {
		last_state = ppp->ppp_state;

		ret = vpninfo->ssl_read(vpninfo, (char *)bytes, 65536);
		if (ret < 0) {
			vpn_progress(vpninfo, PRG_ERR,
				     _("Failed to read incoming PPP config packet."));
			ret = -EINVAL;
			goto out;
		}
		if (vpninfo->dump_http_traffic) {
			vpn_progress(vpninfo, PRG_DEBUG, _("Received PPP config packet:\n"));
			dump_buf_hex(vpninfo, PRG_DEBUG, '<', bytes, ret);
		}

		if (ret < 8 || load_be16(bytes) != 0xf500 || load_be16(bytes + 2) != ret - 4) {
		bad_config_pkt:
			vpn_progress(vpninfo, PRG_ERR,
				     _("Bad incoming PPP config packet:\n"));
			dump_buf_hex(vpninfo, PRG_ERR, '<', bytes, ret);
			ret = -EINVAL;
			goto out;
		}

		if (bytes[4] == 0xff && bytes[5] == 0x03 && load_be16(bytes + 6) == PPP_LCP) {
			/* No ACCOMP or PFCOMP for LCP frames */
			proto = PPP_LCP;
			p = bytes + 8;
		} else {
			if (ppp->in_lcp_opts & ACCOMP) {
				if (bytes[4] == 0xff && bytes [5] == 0x03)
					p = bytes + 6; /* ACCOMP is still optional */
				else
					p = bytes + 4;
			} else {
				if (bytes[4] != 0xff || bytes [5] != 0x03)
					goto bad_config_pkt;
				p = bytes + 6;
			}

			if (ppp->in_lcp_opts & PFCOMP) {
				proto = *p++;
				if (!(proto & 1)) {
					proto <<= 8;
					proto += *p++;
				}
			} else {
				proto = load_be16(p);
				p += 2;
			}
		}

		payload_len = ret - (p - bytes);

		vpn_progress(vpninfo, PRG_TRACE,
			     _("Received %d bytes PPP packet with protocol 0x%04x (%d bytes payload)\n"),
			     ret, proto, payload_len);
		if (vpninfo->dump_http_traffic)
			dump_buf_hex(vpninfo, PRG_TRACE, '<', bytes, ret);

		switch (proto) {
		case PPP_LCP:
		case PPP_IPCP:
		case PPP_IP6CP:
			if (payload_len < 4 || load_be16(p + 2) != payload_len)
				goto bad_config_pkt;
			if ((ret = handle_config_packet(vpninfo, ppp, proto, p, payload_len)) < 0)
				goto out;
			break;

		case PPP_IP:
		case PPP_IP6:
			vpn_progress(vpninfo, PRG_ERR,
				     _("Unexpected IPv%d packet in PPP config phase."),
				     proto == PPP_IP ? 4 : 6);
			dump_buf_hex(vpninfo, PRG_ERR, '<', p, payload_len);
			break;

		default:
			vpn_progress(vpninfo, PRG_ERR,
				     _("PPP packet with unknown protocol 0x%04x. Payload:\n"),
				     proto);
			dump_buf_hex(vpninfo, PRG_ERR, '<', p, payload_len);
			ret = -EINVAL;
			goto out;
		}

		switch (ppp->ppp_state) {
		case PPPS_ESTABLISH:
			if ((ppp->lcp_state & NCP_ACK_SENT) && (ppp->lcp_state & NCP_ACK_RECEIVED))
				ppp->ppp_state = PPPS_OPENED;
			break;
		case PPPS_OPENED:
			/* Have we configured all the protocols we want? */
			if ( (!ipv4 || ((ppp->ipcp_state & NCP_ACK_SENT) && (ppp->ipcp_state & NCP_ACK_RECEIVED))) &&
			     (!ipv6 || ((ppp->ip6cp_state & NCP_ACK_SENT) && (ppp->ip6cp_state & NCP_ACK_RECEIVED))) )
				ppp->ppp_state = PPPS_NETWORK;
			break;
		}
		if (last_state != ppp->ppp_state)
			vpn_progress(vpninfo, PRG_DEBUG,
				     _("PPP state transition from %s (%d) to %s (%d)\n"),
				     ppps_names[last_state], last_state, ppps_names[ppp->ppp_state], ppp->ppp_state);

	}

out:
	return (ppp->ppp_state == PPPS_NETWORK);
}
