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

const char *lcp_names[] = {"Configure-Request", "Configure-Ack", "Configure-Nak", "Configure-Reject", "Terminate-Request",
			   "Terminate-Ack", "Code-Reject", "Protocol-Reject", "Echo-Request", "Echo-Reply", "Discard-Request"};

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

const char *ppps_names[] = {"DEAD", "ESTABLISH", "OPENED", "AUTHENTICATE", "NETWORK", "TERMINATE"};

#define PPPS_DEAD		0
#define PPPS_ESTABLISH		1
#define PPPS_OPENED		2
#define PPPS_AUTHENTICATE	3
#define PPPS_NETWORK		4
#define PPPS_TERMINATE		5

#define NCP_CONF_REQ_RECEIVED	1
#define NCP_CONF_REQ_SENT	2
#define NCP_CONF_ACK_RECEIVED	4
#define NCP_CONF_ACK_SENT	8
#define NCP_TERM_REQ_SENT	16
#define NCP_TERM_REQ_RECEIVED	32
#define NCP_TERM_ACK_SENT	16
#define NCP_TERM_ACK_RECEIVED	32

struct oc_ppp {
	/* We need to know these before we start */
	int encap;
	int encap_len;
	int hdlc;
	int want_ipv4;
	int want_ipv6;
	int we_go_first;

	int ppp_state;
	int lcp_state;
	int ipcp_state;
	int ip6cp_state;

	/* Outgoing options */
	uint32_t out_asyncmap;
	int out_lcp_opts;
	int32_t out_lcp_magic;
	struct in_addr out_peer_addr;
	uint64_t out_ipv6_int_ident;
	uint8_t util_id;

	/* Incoming options */
	int exp_ppp_hdr_size;
	uint32_t in_asyncmap;
	int in_lcp_opts;
	int32_t in_lcp_magic;
	struct in_addr in_peer_addr;
	uint64_t in_ipv6_int_ident;
};

struct oc_ppp *openconnect_ppp_new(int encap, int hdlc, int want_ipv4, int want_ipv6, int we_go_first)
{
	struct oc_ppp *ppp = calloc(sizeof(*ppp), 1);

	if (!ppp)
		return NULL;

	ppp->encap = encap;
	switch (encap) {
	case PPP_ENCAP_F5:
		ppp->encap_len = 4;
		break;
	default:
		/* XX: fail */
		break;
	}

	ppp->hdlc = hdlc;
	ppp->want_ipv4 = want_ipv4;
	ppp->want_ipv6 = want_ipv6;
	ppp->we_go_first = we_go_first;
	ppp->exp_ppp_hdr_size = 4; /* Address(1), Control(1), Proto(2) */
	return ppp;
}

void ppp_print_state(struct openconnect_info *vpninfo)
{
	struct oc_ppp *ppp = vpninfo->ppp;

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
	return b[1];
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

static int queue_util_packet(struct openconnect_info *vpninfo,
			     uint16_t proto, int id, int code, int len, const void *payload)
{
	struct pkt *p = malloc(sizeof(struct pkt) + 64);

	if (!p)
		return -ENOMEM;

	p->ppp.proto = proto;
	p->data[0] = code;
	p->data[1] = id;
	p->len = 4 + len; /* payload length includes code, id, own 2 bytes */
	store_be16(p->data + 2, p->len);
	if (len)
		memcpy(p->data + 4, payload, len);

	queue_packet(&vpninfo->outgoing_queue, p);
	return 0;
}

#define PROTO_TAG_LEN(p, t, l) (((p) << 16) | ((t) << 8) | (l))

static int handle_config_request(struct openconnect_info *vpninfo,
				 int proto, int id, unsigned char *payload, int len)
{
	struct oc_ppp *ppp = vpninfo->ppp;
	int ret, *ncp_state;
	unsigned char *p;

	switch (proto) {
	case PPP_LCP: ncp_state = &ppp->lcp_state; break;
	case PPP_IPCP: ncp_state = &ppp->ipcp_state; break;
	case PPP_IP6CP: ncp_state = &ppp->ip6cp_state; break;
	default: return -EINVAL;
	}

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
			memcpy(&ppp->in_lcp_magic, p+2, 4);
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
	*ncp_state |= NCP_CONF_REQ_RECEIVED;

	if (p != payload+len) {
		vpn_progress(vpninfo, PRG_DEBUG,
			     _("Received %ld extra bytes at end of Config-Request:\n"), payload + len - p);
		dump_buf_hex(vpninfo, PRG_DEBUG, '<', p, payload + len - p);
	}

	vpn_progress(vpninfo, PRG_DEBUG, _("Ack proto 0x%04x/id %d config from server\n"), proto, id);
	if ((ret = queue_util_packet(vpninfo, proto, id, CONFACK, len, payload)) >= 0) {
		*ncp_state |= NCP_CONF_ACK_SENT;
		ret = 0;
	}

out:
	return ret;
}

static int send_config_request(struct openconnect_info *vpninfo,
			       int proto, int id)
{
	struct oc_ppp *ppp = vpninfo->ppp;
	unsigned char ipv6a[16] = {0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0};
	struct oc_text_buf *buf;
	int ret, payload_len, pl_pos, *ncp_state;

	buf = buf_alloc();
	buf_append_be32(buf, 0xf5000000);           /* F5 00, length placeholder  */
	buf_append_ppp_hdr(buf, ppp, proto, 1 /* Configure-Request */, id);
	payload_len = 4;			   /* XX: includes code, id, own bytes */
	pl_pos = buf->pos;
	buf_append_be16(buf, 0);	           /* payload length placeholder  */

	switch (proto) {
	case PPP_LCP:
		ncp_state = &ppp->lcp_state;
		ppp->out_asyncmap = 0;
		ppp->out_lcp_magic = ~ppp->in_lcp_magic;
		ppp->out_lcp_opts = ACCOMP | PFCOMP;
		if (!vpninfo->ip_info.mtu)
			vpninfo->ip_info.mtu = 1300; /* FIXME */

		payload_len += buf_append_ppp_tlv(buf, 1, -2, &vpninfo->ip_info.mtu); /* store as BE */
		payload_len += buf_append_ppp_tlv(buf, 2, -4, &ppp->out_asyncmap);    /* store as BE */
		payload_len += buf_append_ppp_tlv(buf, 5, +4, &ppp->out_lcp_magic);   /* store as-is */
		if (ppp->out_lcp_opts & PFCOMP)
			payload_len += buf_append_ppp_tlv(buf, 7, 0, NULL);
		if (ppp->out_lcp_opts & ACCOMP)
			payload_len += buf_append_ppp_tlv(buf, 8, 0, NULL);
		break;

	case PPP_IPCP:
		ncp_state = &ppp->ipcp_state;
		if (vpninfo->ip_info.addr)
			ppp->out_peer_addr.s_addr = inet_addr(vpninfo->ip_info.addr);

		payload_len += buf_append_ppp_tlv(buf, 3, 4, &ppp->out_peer_addr);
		break;

	case PPP_IP6CP:
		ncp_state = &ppp->ip6cp_state;
		if (vpninfo->ip_info.addr6)
			inet_pton(AF_INET6, vpninfo->ip_info.addr6, &ipv6a);
		memcpy(&ppp->out_ipv6_int_ident, ipv6a+8, 8); /* last 8 bytes of addr6 */

		payload_len += buf_append_ppp_tlv(buf, 1, 8, &ppp->out_ipv6_int_ident);
		break;

	default:
		ret = -EINVAL;
		goto out;
	}

	if ((ret = buf_error(buf)) != 0)
		goto out;
	store_be16(buf->data + 2, buf->pos - 4);
	store_be16(buf->data + pl_pos, payload_len);

	vpn_progress(vpninfo, PRG_DEBUG, _("Sending our proto 0x%04x/id %d config request to server\n"), proto, id);
	if (vpninfo->dump_http_traffic)
		dump_buf_hex(vpninfo, PRG_DEBUG, '>', (void *)buf->data, buf->pos);
	if ((ret = vpninfo->ssl_write(vpninfo, buf->data, buf->pos)) >= 0) {
		*ncp_state |= NCP_CONF_REQ_SENT;
		ret = 0;
	}

out:
        buf_free(buf);
	return ret;
}

static int handle_config_packet(struct openconnect_info *vpninfo,
				uint16_t proto, unsigned char *p, int len)
{
	struct oc_ppp *ppp = vpninfo->ppp;
	int code = p[0], id = p[1];
	int ret = 0, add_state = 0;

        if (code > 0 && code <= 11)
		vpn_progress(vpninfo, PRG_TRACE, _("Received proto 0x%04x/id %d %s from server\n"), proto, id, lcp_names[code-1]);
	switch (code) {
	case CONFREQ:
		ret = handle_config_request(vpninfo, proto, id, p + 4, len - 4);
		break;

	case CONFACK:
		/* XX: we could verify that the ack/reply bytes match the request bytes,
		 * and the ID is the expected one, but it isn't 1992, so let's not.
		 */
		add_state = NCP_CONF_ACK_RECEIVED;
		break;

	case ECHOREQ:
		if (ppp->ppp_state >= PPPS_OPENED)
			ret = queue_util_packet(vpninfo, proto, id, ECHOREP, 4, &ppp->out_lcp_magic);
		break;

	case TERMREQ:
		add_state = NCP_TERM_REQ_RECEIVED;
		ret = queue_util_packet(vpninfo, proto, id, TERMACK, 0, NULL);
		if (ret >= 0)
			add_state = NCP_TERM_ACK_SENT;
		goto set_quit_reason;

	case TERMACK:
		add_state = NCP_TERM_ACK_RECEIVED;
	set_quit_reason:
		if (!vpninfo->quit_reason && len > 4)
			vpninfo->quit_reason = strndup((char *)(p + 4), len - 4);
		ppp->ppp_state = PPPS_TERMINATE;
		break;

	case ECHOREP:
	case DISCREQ:
		break;

	case CONFNAK:
	case CONFREJ:
	case CODEREJ:
	case PROTREJ:
	default:
		ret = -EINVAL;
	}

	switch (proto) {
	case PPP_LCP: ppp->lcp_state |= add_state; break;
	case PPP_IPCP: ppp->ipcp_state |= add_state; break;
	case PPP_IP6CP: ppp->ip6cp_state |= add_state; break;
	default: return -EINVAL;
	}
	return ret;
}

int ppp_mainloop(struct openconnect_info *vpninfo, int *timeout, int readable)
{
	int ret, last_state, magic, rsv_hdr_size;
	int work_done = 0;
	unsigned char *ph, *pp;

	struct oc_ppp *ppp = vpninfo->ppp;
	int proto;

	if (vpninfo->ssl_fd == -1)
		goto do_reconnect;

	/* Handle PPP state transitions */
	last_state = ppp->ppp_state;
	switch (ppp->ppp_state) {
	case PPPS_DEAD:
		ppp->ppp_state = PPPS_ESTABLISH;
		/* fall through */
	case PPPS_ESTABLISH:
		if (!(ppp->lcp_state & NCP_CONF_REQ_SENT))
			if ((ppp->lcp_state & NCP_CONF_REQ_RECEIVED) || ppp->we_go_first)
				send_config_request(vpninfo, PPP_LCP, 1);

		if ((ppp->lcp_state & NCP_CONF_ACK_SENT) && (ppp->lcp_state & NCP_CONF_ACK_RECEIVED))
			ppp->ppp_state = PPPS_OPENED;
		break;

	case PPPS_OPENED:
		/* Have we configured all the protocols we want? */
		if (ppp->want_ipv4 && !(ppp->ipcp_state & NCP_CONF_REQ_SENT))
			if ((ppp->ipcp_state & NCP_CONF_REQ_RECEIVED) || ppp->we_go_first)
				send_config_request(vpninfo, PPP_IPCP, 1);
		if (ppp->want_ipv6 && !(ppp->ip6cp_state & NCP_CONF_REQ_SENT))
			if ((ppp->ip6cp_state & NCP_CONF_REQ_RECEIVED) || ppp->we_go_first)
				send_config_request(vpninfo, PPP_IP6CP, 1);

		if ( (!ppp->want_ipv4 || ((ppp->ipcp_state & NCP_CONF_ACK_SENT) && (ppp->ipcp_state & NCP_CONF_ACK_RECEIVED))) &&
		     (!ppp->want_ipv6 || ((ppp->ip6cp_state & NCP_CONF_ACK_SENT) && (ppp->ip6cp_state & NCP_CONF_ACK_RECEIVED))) )
			ppp->ppp_state = PPPS_NETWORK;
		/* fall through */
	case PPPS_NETWORK:
		break;
	case PPPS_TERMINATE:
		return 1;
	case PPPS_AUTHENTICATE: /* XX: should never */
	default:
		vpninfo->quit_reason = "Unexpected state";
		return 1;
	}
	if (last_state != ppp->ppp_state)
		vpn_progress(vpninfo, PRG_DEBUG,
			     _("PPP state transition from %s (%d) to %s (%d)\n"),
			     ppps_names[last_state], last_state, ppps_names[ppp->ppp_state], ppp->ppp_state);

	/* FIXME: The poll() handling here is fairly simplistic. Actually,
	   if the SSL connection stalls it could return a WANT_WRITE error
	   on _either_ of the SSL_read() or SSL_write() calls. In that case,
	   we should probably remove POLLIN from the events we're looking for,
	   and add POLLOUT. As it is, though, it'll just chew CPU time in that
	   fairly unlikely situation, until the write backlog clears. */
	while (readable) {
		/* Some servers send us packets that are larger than
		   negotiated MTU. We reserve some extra space to
		   handle that */
		int receive_mtu = MAX(16384, vpninfo->ip_info.mtu);
		int len, payload_len;

		if (!vpninfo->cstp_pkt) {
			vpninfo->cstp_pkt = malloc(sizeof(struct pkt) + receive_mtu);
			if (!vpninfo->cstp_pkt) {
				vpn_progress(vpninfo, PRG_ERR, _("Allocation failed\n"));
				break;
			}
		}

		/* XX: PPP header is of variable length. We attempt to
		 * anticipate the actual length received, so we don't have to memmove
		 * the payload later. */
		rsv_hdr_size = ppp->encap_len + ppp->exp_ppp_hdr_size;

		/* Load the header to end up with the payload where we expect it */
		ph = vpninfo->cstp_pkt->data - rsv_hdr_size;
		len = ssl_nonblock_read(vpninfo, ph, receive_mtu + rsv_hdr_size);
		if (!len)
			break;
		if (len < 0)
			goto do_reconnect;
		if (len < 8) {
			vpn_progress(vpninfo, PRG_ERR, _("Short packet received (%d bytes)\n"), len);
			vpninfo->quit_reason = "Short packet received";
			return 1;
		}

		/* check pre-PPP header */
		switch (ppp->encap) {
		case PPP_ENCAP_F5:
			magic = load_be16(ph);
			payload_len = load_be16(ph + 2);

			if (magic != 0xf500) {
				vpn_progress(vpninfo, PRG_ERR,
					     _("Unexpected pre-PPP packet header for encap %d.\n"),
					     ppp->encap);
				dump_buf_hex(vpninfo, PRG_ERR, '<', ph, len);
				continue;
			}

			if (len != 4 + payload_len) {
				vpn_progress(vpninfo, PRG_ERR,
					     _("Unexpected packet length. SSL_read returned %d (includes %d encap) but header payload_len is %d\n"),
					     len, ppp->encap_len, payload_len);
				dump_buf_hex(vpninfo, PRG_ERR, '<', ph, len);
				continue;
			}
			break;
		default:
			payload_len = len;
			/* XX: fail */
			break;
		}

		/* check PPP header and extract protocol */
		pp = ph += ppp->encap_len;
		if (pp[0] == 0xff && pp[0] == 0x03 && load_be16(pp + 6) == PPP_LCP) {
			/* No ACCOMP or PFCOMP for LCP frames */
			proto = PPP_LCP;
			pp += 4;
		} else {
			if (ppp->in_lcp_opts & ACCOMP) {
				if (pp[0] == 0xff && pp[1] == 0x03)
					pp += 2; /* ACCOMP is still optional */
			} else {
				if (pp[0] != 0xff || pp[1] != 0x03) {
				bad_ppp_pkt:
					vpn_progress(vpninfo, PRG_ERR,
						     _("Bad incoming PPP packet:\n"));
					dump_buf_hex(vpninfo, PRG_ERR, '<', ph, len);
					return 1;
				}
				pp += 2;
			}
			if (ppp->in_lcp_opts & PFCOMP) {
				proto = *pp++;
				if (!(proto & 1)) {
					proto <<= 8;
					proto += *pp++;
				}
			} else {
				proto = load_be16(pp);
				pp += 2;
			}
		}
		payload_len -= pp - ph;

		vpninfo->ssl_times.last_rx = time(NULL);

		switch (proto) {
		case PPP_LCP:
		case PPP_IPCP:
		case PPP_IP6CP:
			if (payload_len < 4 || load_be16(pp + 2) != payload_len) {
				vpn_progress(vpninfo, PRG_ERR, "payload_len %d, PPP header len %d\n", payload_len, load_be16(pp+2));
				goto bad_ppp_pkt;
			}
			ret = handle_config_packet(vpninfo, proto, pp, payload_len);
			break;

		case PPP_IP:
		case PPP_IP6:
			if (ppp->ppp_state != PPPS_NETWORK) {
				vpn_progress(vpninfo, PRG_ERR,
					     _("Unexpected IPv%d packet in PPP state %s (%d)."),
					     (proto == PPP_IP6 ? 6 : 4), ppps_names[ppp->ppp_state], ppp->ppp_state);
				dump_buf_hex(vpninfo, PRG_ERR, '<', pp, payload_len);
			} else {
				vpn_progress(vpninfo, PRG_TRACE,
					     _("Received IPv%d data packet of %d bytes\n"),
					     proto == PPP_IP6 ? 6 : 4, payload_len);

				if (pp != vpninfo->cstp_pkt->data) {
					vpn_progress(vpninfo, PRG_TRACE,
						     _("Expected %d header bytes (%d encap + %d PPP) but got %ld, shifting payload.\n"),
						     rsv_hdr_size, ppp->encap_len, ppp->exp_ppp_hdr_size, pp - ph);
					/* Save it for next time */
					ppp->exp_ppp_hdr_size = pp - ph - ppp->encap_len;
					/* XX: if PPP header was SMALLER than expected, we could conceivably be moving a huge packet
					 * past the allocated buffer. */
					memmove(vpninfo->cstp_pkt->data, pp, payload_len);
				}

				vpninfo->cstp_pkt->len = payload_len;
				queue_packet(&vpninfo->incoming_queue, vpninfo->cstp_pkt);
				vpninfo->cstp_pkt = NULL;
				work_done = 1;
				continue;
			}
			break;

		default:
			vpn_progress(vpninfo, PRG_ERR,
				     _("PPP packet with unknown protocol 0x%04x. Payload:\n"),
				     proto);
			dump_buf_hex(vpninfo, PRG_ERR, '<', pp, payload_len);
			return 1;
		}
	}

	/* If SSL_write() fails we are expected to try again. With exactly
	   the same data, at exactly the same location. So we keep the
	   packet we had before.... */
	if (vpninfo->current_ssl_pkt) {
	handle_outgoing:
		vpninfo->ssl_times.last_tx = time(NULL);
		unmonitor_write_fd(vpninfo, ssl);

		ret = ssl_nonblock_write(vpninfo,
					 vpninfo->current_ssl_pkt->data - vpninfo->current_ssl_pkt->ppp.hlen,
					 vpninfo->current_ssl_pkt->len + vpninfo->current_ssl_pkt->ppp.hlen);
		if (ret < 0)
			goto do_reconnect;
		else if (!ret) {
			/* -EAGAIN: ssl_nonblock_write() will have added the SSL
			   fd to ->select_wfds if appropriate, so we can just
			   return and wait. Unless it's been stalled for so long
			   that DPD kicks in and we kill the connection. */
			switch (ka_stalled_action(&vpninfo->ssl_times, timeout)) {
			case KA_DPD_DEAD:
				goto peer_dead;
			case KA_REKEY:
//				goto do_rekey;
			case KA_NONE:
//				return work_done;
			default:
				/* This should never happen */
				;
			}
		}

		if (ret != vpninfo->current_ssl_pkt->len + vpninfo->current_ssl_pkt->ppp.hlen) {
			vpn_progress(vpninfo, PRG_ERR,
				     _("SSL wrote too few bytes! Asked for %d, sent %d\n"),
				     vpninfo->current_ssl_pkt->len + vpninfo->current_ssl_pkt->ppp.hlen, ret);
			vpninfo->quit_reason = "Internal error";
			return 1;
		}

		if (1 /*vpninfo->current_ssl_pkt != &dpd_pkt*/)
			free(vpninfo->current_ssl_pkt);

		vpninfo->current_ssl_pkt = NULL;
	}

	switch (keepalive_action(&vpninfo->ssl_times, timeout)) {
	case KA_DPD_DEAD:
	peer_dead:
		vpn_progress(vpninfo, PRG_ERR,
			     _("Detected dead peer!\n"));
		/* fall through */
	case KA_REKEY:
	do_reconnect:
		ret = ssl_reconnect(vpninfo);
		if (ret) {
			vpn_progress(vpninfo, PRG_ERR, _("Reconnect failed\n"));
			vpninfo->quit_reason = "PPP reconnect failed";
			return ret;
		}
		return 1;

	case KA_KEEPALIVE:
		/* No need to send an explicit keepalive
		   if we have real data to send */
		if (vpninfo->dtls_state != DTLS_CONNECTED &&
		    vpninfo->outgoing_queue.head)
			break;
		vpn_progress(vpninfo, PRG_DEBUG, _("Send PPP discard request as keepalive\n"));
		queue_util_packet(vpninfo, PPP_LCP, ppp->util_id++, DISCREQ, 0, NULL);
		break;
	case KA_DPD:
		vpn_progress(vpninfo, PRG_DEBUG, _("Send PPP echo request as DPD\n"));
		queue_util_packet(vpninfo, PPP_LCP, ppp->util_id++, ECHOREQ, 4, &ppp->out_lcp_magic);
	}

	/* Service outgoing packet queue, if no DTLS */
	while (vpninfo->dtls_state != DTLS_CONNECTED &&
	       (vpninfo->current_ssl_pkt = dequeue_packet(&vpninfo->outgoing_queue))) {
		struct pkt *this = vpninfo->current_ssl_pkt;
		int n = 0;

		/* XX: Set protocol for IP, or grab it where we pre-stashed it
		 * in the header for config packets. Takes advantage of the fact
		 * that first byte of LCP/IPCP/IP6CP packets is always <0x10, while
		 * first byte of IP packets is always >0x10.
		 */
		if (this->len && (this->data[0] & 0xf0))
			proto = ((this->data[0] & 0xf0) == 0x60) ? PPP_IP6 : PPP_IP;
		else
			proto = this->ppp.proto;

		/* XX: store PPP header, in reverse (FIXME: HDLC, asyncmap, etc.) */
		this->data[--n] = proto & 0xff;
		if (proto > 0xff || !(ppp->out_lcp_opts & PFCOMP))
			this->data[--n] = proto >> 8;
		if (proto == PPP_LCP || !(ppp->out_lcp_opts & ACCOMP)) {
			this->data[--n] = 0x03; /* Control */
			this->data[--n] = 0xff; /* Address */
		}
		switch (ppp->encap) {
		case PPP_ENCAP_F5:
			store_be16(this->data + n - 2, this->len - n);
			store_be16(this->data + n - 4, 0xf500);
			n -= 4;
		default:
			/* XX: fail */
			break;
		}

		this->ppp.hlen = -n;
		vpn_progress(vpninfo, PRG_TRACE,
			     _("Sending proto 0x%04x packet (%d bytes total)\n"),
			     proto, this->len - n);
		if (vpninfo->dump_http_traffic)
			dump_buf_hex(vpninfo, PRG_TRACE, '>', this->data + n, this->len - n);

		vpninfo->current_ssl_pkt = this;
		goto handle_outgoing;
	}

	/* Work is not done if we just got rid of packets off the queue */
	return work_done;
}
