/*
 * OpenConnect (SSL + DTLS) VPN client
 *
 * Copyright © 2020 David Woodhouse, Daniel Lenski
 *
 * Authors: David Woodhouse <dwmw2@infradead.org>, Daniel Lenski <dlenski@gmail.com>
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
#include "ppp.h"

static const uint16_t fcstab[256] = {
	0x0000, 0x1189, 0x2312, 0x329b, 0x4624, 0x57ad, 0x6536, 0x74bf,
	0x8c48, 0x9dc1, 0xaf5a, 0xbed3, 0xca6c, 0xdbe5, 0xe97e, 0xf8f7,
	0x1081, 0x0108, 0x3393, 0x221a, 0x56a5, 0x472c, 0x75b7, 0x643e,
	0x9cc9, 0x8d40, 0xbfdb, 0xae52, 0xdaed, 0xcb64, 0xf9ff, 0xe876,
	0x2102, 0x308b, 0x0210, 0x1399, 0x6726, 0x76af, 0x4434, 0x55bd,
	0xad4a, 0xbcc3, 0x8e58, 0x9fd1, 0xeb6e, 0xfae7, 0xc87c, 0xd9f5,
	0x3183, 0x200a, 0x1291, 0x0318, 0x77a7, 0x662e, 0x54b5, 0x453c,
	0xbdcb, 0xac42, 0x9ed9, 0x8f50, 0xfbef, 0xea66, 0xd8fd, 0xc974,
	0x4204, 0x538d, 0x6116, 0x709f, 0x0420, 0x15a9, 0x2732, 0x36bb,
	0xce4c, 0xdfc5, 0xed5e, 0xfcd7, 0x8868, 0x99e1, 0xab7a, 0xbaf3,
	0x5285, 0x430c, 0x7197, 0x601e, 0x14a1, 0x0528, 0x37b3, 0x263a,
	0xdecd, 0xcf44, 0xfddf, 0xec56, 0x98e9, 0x8960, 0xbbfb, 0xaa72,
	0x6306, 0x728f, 0x4014, 0x519d, 0x2522, 0x34ab, 0x0630, 0x17b9,
	0xef4e, 0xfec7, 0xcc5c, 0xddd5, 0xa96a, 0xb8e3, 0x8a78, 0x9bf1,
	0x7387, 0x620e, 0x5095, 0x411c, 0x35a3, 0x242a, 0x16b1, 0x0738,
	0xffcf, 0xee46, 0xdcdd, 0xcd54, 0xb9eb, 0xa862, 0x9af9, 0x8b70,
	0x8408, 0x9581, 0xa71a, 0xb693, 0xc22c, 0xd3a5, 0xe13e, 0xf0b7,
	0x0840, 0x19c9, 0x2b52, 0x3adb, 0x4e64, 0x5fed, 0x6d76, 0x7cff,
	0x9489, 0x8500, 0xb79b, 0xa612, 0xd2ad, 0xc324, 0xf1bf, 0xe036,
	0x18c1, 0x0948, 0x3bd3, 0x2a5a, 0x5ee5, 0x4f6c, 0x7df7, 0x6c7e,
	0xa50a, 0xb483, 0x8618, 0x9791, 0xe32e, 0xf2a7, 0xc03c, 0xd1b5,
	0x2942, 0x38cb, 0x0a50, 0x1bd9, 0x6f66, 0x7eef, 0x4c74, 0x5dfd,
	0xb58b, 0xa402, 0x9699, 0x8710, 0xf3af, 0xe226, 0xd0bd, 0xc134,
	0x39c3, 0x284a, 0x1ad1, 0x0b58, 0x7fe7, 0x6e6e, 0x5cf5, 0x4d7c,
	0xc60c, 0xd785, 0xe51e, 0xf497, 0x8028, 0x91a1, 0xa33a, 0xb2b3,
	0x4a44, 0x5bcd, 0x6956, 0x78df, 0x0c60, 0x1de9, 0x2f72, 0x3efb,
	0xd68d, 0xc704, 0xf59f, 0xe416, 0x90a9, 0x8120, 0xb3bb, 0xa232,
	0x5ac5, 0x4b4c, 0x79d7, 0x685e, 0x1ce1, 0x0d68, 0x3ff3, 0x2e7a,
	0xe70e, 0xf687, 0xc41c, 0xd595, 0xa12a, 0xb0a3, 0x8238, 0x93b1,
	0x6b46, 0x7acf, 0x4854, 0x59dd, 0x2d62, 0x3ceb, 0x0e70, 0x1ff9,
	0xf78f, 0xe606, 0xd49d, 0xc514, 0xb1ab, 0xa022, 0x92b9, 0x8330,
	0x7bc7, 0x6a4e, 0x58d5, 0x495c, 0x3de3, 0x2c6a, 0x1ef1, 0x0f78
};

#define foldfcs(fcs, c) (  ( (fcs) >> 8 ) ^ fcstab[(fcs ^ (c)) & 0xff] )
#define NEED_ESCAPE(c, map) ( (((c) < 0x20) && (map && (1UL << (c)))) || ((c) == 0x7d) || ((c) == 0x7e) )
#define HDLC_OUT(outp, c, map) do {   \
	if (NEED_ESCAPE((c), map)) {  \
		*outp++ = 0x7d;       \
		*outp++ = (c) ^ 0x20; \
	} else                        \
		*outp++ = (c);        \
} while (0)

static struct pkt *hdlc_into_new_pkt(struct openconnect_info *vpninfo, unsigned char *bytes, int len, int asyncmap)
{
        const unsigned char *inp = bytes, *endp = bytes + len;
	unsigned char *outp;
	uint16_t fcs = PPPINITFCS16;
	struct pkt *p = malloc(sizeof(struct pkt) + len*2 + 6);
	if (!p)
		return NULL;

	outp = p->data;
	*outp++ = 0x7e;

	for (; inp < endp; inp++) {
		fcs = foldfcs(fcs, *inp);
		HDLC_OUT(outp, *inp, asyncmap);
	}

	/* Append FCS, escaped, little-endian */
	fcs ^= 0xffff;
	HDLC_OUT(outp, fcs & 0xff, asyncmap);
	HDLC_OUT(outp, fcs >> 8, asyncmap);

	*outp++ = 0x7e;
	p->ppp.hlen = 0;
	p->len = outp - p->data;
	return p;
}

static int unhdlc_in_place(struct openconnect_info *vpninfo, unsigned char *bytes, int len, unsigned char **next)
{
	unsigned char *inp = bytes, *endp = bytes + len;
	unsigned char *outp = bytes;
	int escape = 0;
	uint16_t fcs = PPPINITFCS16;

	if (*inp == 0x7e)
		inp++;
	else
		vpn_progress(vpninfo, PRG_DEBUG,
			     _("HDLC initial flag sequence (0x7e) is missing\n"));

	for (; inp < endp; inp++) {
		unsigned char c = *inp;
		if (c == 0x7e)
			goto done;
		else if (escape) {
			c ^= 0x20;
			escape = 0;
		} else if (c == 0x7d) {
			escape = 1;
			continue;
		}

		fcs = foldfcs(fcs, c);
		*outp++ = c;
	}
	vpn_progress(vpninfo, PRG_ERR,
		     _("HDLC buffer ended without FCS and flag sequence (0x7e)\n"));
	return -EINVAL;

 done:
	if (outp < bytes + 2) {
		vpn_progress(vpninfo, PRG_ERR,
			     _("HDLC frame too short (%d bytes)\n"),
			     (int)(outp - bytes));
		return -EINVAL;
	}

	outp -= 2; /* FCS */

	if (next)
		*next = inp+1; /* Pointing at the byte AFTER final 0x7e */

	if (fcs != PPPGOODFCS16) {
		vpn_progress(vpninfo, PRG_INFO,
			     _("Bad HDLC packet FCS %04x\n"), fcs);
		dump_buf_hex(vpninfo, PRG_INFO, '<', bytes, len);
		return -EINVAL;
	} else {
		vpn_progress(vpninfo, PRG_TRACE,
			     _("Un-HDLC'ed packet (%d bytes -> %ld), FCS=0x%04x\n"),
			     len, outp - bytes, fcs);
		return outp - bytes;
	}
}

static const char *ppps_names[] = { "DEAD", "ESTABLISH", "OPENED", "AUTHENTICATE", "NETWORK", "TERMINATE" };
static const char *encap_names[] = { NULL, "F5", "F5 HDLC" };
static const char *lcp_names[] = { NULL,
			   "Configure-Request", "Configure-Ack",
			   "Configure-Nak", "Configure-Reject",
			   "Terminate-Request", "Terminate-Ack",
			   "Code-Reject", "Protocol-Reject",
			   "Echo-Request", "Echo-Reply",
			   "Discard-Request" };

struct oc_ppp *openconnect_ppp_new(int encap, int want_ipv4, int want_ipv6)
{
	struct oc_ppp *ppp = calloc(sizeof(*ppp), 1);

	if (!ppp)
		return NULL;

	ppp->encap = encap;
	switch (encap) {
	case PPP_ENCAP_F5:
		ppp->encap_len = 4;
		break;

	case PPP_ENCAP_F5_HDLC:
	case PPP_ENCAP_FORTINET_HDLC:
		ppp->encap_len = 0;
		ppp->hdlc = 1;
		break;

	default:
		/* XX: fail */
		break;
	}

	ppp->want_ipv4 = want_ipv4;
	ppp->want_ipv6 = want_ipv6;
	ppp->exp_ppp_hdr_size = 4; /* Address(1), Control(1), Proto(2) */
	return ppp;
}

static void print_ppp_state(struct openconnect_info *vpninfo, int level)
{
	struct oc_ppp *ppp = vpninfo->ppp;

	vpn_progress(vpninfo, level, _("Current PPP state: %s (encap %s):\n"), ppps_names[ppp->ppp_state], encap_names[ppp->encap]);
	vpn_progress(vpninfo, level, _("    in: asyncmap=0x%08x, lcp_opts=%d, lcp_magic=0x%08x, peer=%s\n"),
		     ppp->in_asyncmap, ppp->in_lcp_opts, ntohl(ppp->in_lcp_magic), inet_ntoa(ppp->in_peer_addr));
	vpn_progress(vpninfo, level, _("   out: asyncmap=0x%08x, lcp_opts=%d, lcp_magic=0x%08x, peer=%s\n"),
		     ppp->out_asyncmap, ppp->out_lcp_opts, ntohl(ppp->out_lcp_magic), inet_ntoa(ppp->out_peer_addr));
}

static int buf_append_ppp_tlv(struct oc_text_buf *buf, int tag, int len, const void *data)
{
	unsigned char b[2];

	b[0] = tag;
	b[1] = len + 2;

	buf_append_bytes(buf, b, 2);
	if (len)
		buf_append_bytes(buf, data, len);

	return b[1];
}

static int buf_append_ppp_tlv_be16(struct oc_text_buf *buf, int tag, uint16_t value)
{
	uint16_t val_be;

	store_be16(&val_be, value);
	return buf_append_ppp_tlv(buf, tag, 2, &val_be);
}

static int buf_append_ppp_tlv_be32(struct oc_text_buf *buf, int tag, uint32_t value)
{
	uint32_t val_be;

	store_be32(&val_be, value);
	return buf_append_ppp_tlv(buf, tag, 4, &val_be);
}

static int queue_config_packet(struct openconnect_info *vpninfo,
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

	queue_packet(&vpninfo->tcp_control_queue, p);
	return 0;
}

#define PROTO_TAG_LEN(p, t, l) (((p) << 16) | ((t) << 8) | (l))

static int handle_config_request(struct openconnect_info *vpninfo,
				 int proto, int id, unsigned char *payload, int len)
{
	struct oc_ppp *ppp = vpninfo->ppp;
	struct oc_text_buf *rejbuf = NULL;
	int ret;
	struct oc_ncp *ncp;
	unsigned char *p;

	switch (proto) {
	case PPP_LCP: ncp = &ppp->lcp; break;
	case PPP_IPCP: ncp = &ppp->ipcp; break;
	case PPP_IP6CP: ncp = &ppp->ip6cp; break;
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
				     ntohl(ppp->in_lcp_magic));
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
		case PROTO_TAG_LEN(PPP_IPCP, 1, 8):
			/* XX: Ancient and deprecated. We're supposed to ignore it if we receive it, unless
			 * we've been Nak'ed. https://tools.ietf.org/html/rfc1332#section-3.1 */
			vpn_progress(vpninfo, PRG_DEBUG,
				     _("Received deprecated IP-Addresses from server, ignoring\n"));
			break;
		case PROTO_TAG_LEN(PPP_IPCP, 2, 2):
			if (load_be16(p+2) == 0x002d) {
				/* Van Jacobson TCP/IP compression */
				vpn_progress(vpninfo, PRG_DEBUG,
					     _("Received Van Jacobson TCP/IP compression from server\n"));
				/* No. Just no. */
				goto reject;
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
		reject:
			if (!rejbuf)
				rejbuf = buf_alloc();
			if (!rejbuf)
				return -ENOMEM;
			buf_append_bytes(rejbuf, p, l);
			break;
		}
	}
	ncp->state |= NCP_CONF_REQ_RECEIVED;

	if (p != payload+len) {
		vpn_progress(vpninfo, PRG_DEBUG,
			     _("Received %ld extra bytes at end of Config-Request:\n"), payload + len - p);
		dump_buf_hex(vpninfo, PRG_DEBUG, '<', p, payload + len - p);
	}

	if (rejbuf) {
		if (buf_error(rejbuf)) {
			vpn_progress(vpninfo, PRG_ERR,
				     _("Error composing ConfRej packet\n"));
			return buf_free(rejbuf);
		}
		vpn_progress(vpninfo, PRG_DEBUG, _("Nak proto 0x%04x/id %d config from server\n"), proto, id);
		if ((ret = queue_config_packet(vpninfo, proto, id, CONFREJ, rejbuf->pos, rejbuf->data)) >= 0) {
			ret = 0;
		}
	} else {
		vpn_progress(vpninfo, PRG_DEBUG, _("Ack proto 0x%04x/id %d config from server\n"), proto, id);
		if ((ret = queue_config_packet(vpninfo, proto, id, CONFACK, len, payload)) >= 0) {
			ncp->state |= NCP_CONF_ACK_SENT;
			ret = 0;
		}
	}

	buf_free(rejbuf);
	return ret;
}

static int queue_config_request(struct openconnect_info *vpninfo, int proto)
{
	struct oc_ppp *ppp = vpninfo->ppp;
	unsigned char ipv6a[16] = {0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0};
	int ret, id;
	struct oc_ncp *ncp;
	struct oc_text_buf *buf;

	buf = buf_alloc();
	buf_ensure_space(buf, 64);

	switch (proto) {
	case PPP_LCP:
		ncp = &ppp->lcp;
		ppp->out_asyncmap = 0;
		ppp->out_lcp_magic = ~ppp->in_lcp_magic;
		ppp->out_lcp_opts = ACCOMP | PFCOMP;
		if (!vpninfo->ip_info.mtu)
			vpninfo->ip_info.mtu = 1300; /* FIXME */

		buf_append_ppp_tlv_be16(buf, 1, vpninfo->ip_info.mtu);
		buf_append_ppp_tlv_be32(buf, 2, ppp->out_asyncmap);
		buf_append_ppp_tlv(buf, 5, 4, &ppp->out_lcp_magic);
		if (ppp->out_lcp_opts & PFCOMP)
			buf_append_ppp_tlv(buf, 7, 0, NULL);
		if (ppp->out_lcp_opts & ACCOMP)
			buf_append_ppp_tlv(buf, 8, 0, NULL);
		break;

	case PPP_IPCP:
		ncp = &ppp->ipcp;
		if (vpninfo->ip_info.addr)
			ppp->out_peer_addr.s_addr = inet_addr(vpninfo->ip_info.addr);

		buf_append_ppp_tlv(buf, 3, 4, &ppp->out_peer_addr);
		break;

	case PPP_IP6CP:
		ncp = &ppp->ip6cp;
		if (vpninfo->ip_info.addr6)
			inet_pton(AF_INET6, vpninfo->ip_info.addr6, &ipv6a);
		memcpy(&ppp->out_ipv6_int_ident, ipv6a+8, 8); /* last 8 bytes of addr6 */

		buf_append_ppp_tlv(buf, 1, 8, &ppp->out_ipv6_int_ident);
		break;

	default:
		ret = -EINVAL;
		goto out;
	}

	if ((ret = buf_error(buf)) != 0)
		goto out;

	id = ++ncp->id;
	vpn_progress(vpninfo, PRG_DEBUG, _("Sending our proto 0x%04x/id %d config request to server\n"),
		     proto, id);
	if ((ret = queue_config_packet(vpninfo, proto, id, CONFREQ, buf->pos, buf->data)) >= 0) {
		ncp->state |= NCP_CONF_REQ_SENT;
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
		vpn_progress(vpninfo, PRG_TRACE, _("Received proto 0x%04x/id %d %s from server\n"), proto, id, lcp_names[code]);
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
			ret = queue_config_packet(vpninfo, proto, id, ECHOREP, 4, &ppp->out_lcp_magic);
		break;

	case TERMREQ:
		add_state = NCP_TERM_REQ_RECEIVED;
		ret = queue_config_packet(vpninfo, proto, id, TERMACK, 0, NULL);
		if (ret >= 0)
			add_state = NCP_TERM_ACK_SENT;
		goto set_quit_reason;

	case TERMACK:
		add_state = NCP_TERM_ACK_RECEIVED;
	set_quit_reason:
		if (!vpninfo->quit_reason && len > 4) {
			vpninfo->quit_reason = strndup((char *)(p + 4), len - 4);
			vpn_progress(vpninfo, PRG_ERR,
				     _("Server terminates with reason: %s\n"),
				     vpninfo->quit_reason);
		}
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
	case PPP_LCP: ppp->lcp.state |= add_state; break;
	case PPP_IPCP: ppp->ipcp.state |= add_state; break;
	case PPP_IP6CP: ppp->ip6cp.state |= add_state; break;
	default: return -EINVAL;
	}
	return ret;
}

static int handle_state_transition(struct openconnect_info *vpninfo, int *timeout)
{
	struct oc_ppp *ppp = vpninfo->ppp;
	time_t now = time(NULL);
	int last_state = ppp->ppp_state, network;

	switch (ppp->ppp_state) {
	case PPPS_DEAD:
		ppp->ppp_state = PPPS_ESTABLISH;
		break;
	case PPPS_ESTABLISH:
		if ((ppp->lcp.state & NCP_CONF_ACK_RECEIVED) && (ppp->lcp.state & NCP_CONF_ACK_SENT))
			ppp->ppp_state = PPPS_OPENED;
		else if (ka_check_deadline(timeout, now, ppp->lcp.last_req + 3)) {
			ppp->lcp.last_req = now;
			queue_config_request(vpninfo, PPP_LCP);
		}
		break;
	case PPPS_OPENED:
		network = 1;
		if (ppp->want_ipv4) {
			if (!(ppp->ipcp.state & NCP_CONF_ACK_SENT) || !(ppp->ipcp.state & NCP_CONF_ACK_RECEIVED)) {
				network = 0;
				if (ka_check_deadline(timeout, now, ppp->ipcp.last_req + 3)) {
					ppp->ipcp.last_req = now;
					queue_config_request(vpninfo, PPP_IPCP);
				}
			}
		}

		if (ppp->want_ipv6) {
			if (!(ppp->ip6cp.state & NCP_CONF_ACK_SENT) || !(ppp->ip6cp.state & NCP_CONF_ACK_RECEIVED)) {
				network = 0;
				if (ka_check_deadline(timeout, now, ppp->ip6cp.last_req + 3)) {
					ppp->ip6cp.last_req = now;
					queue_config_request(vpninfo, PPP_IP6CP);
				}
			}
		}

		if (network)
			ppp->ppp_state = PPPS_NETWORK;
		break;
	case PPPS_NETWORK:
		break;
	case PPPS_TERMINATE:
		if (!vpninfo->quit_reason)
			vpninfo->quit_reason = "Unknown";
		return -EPIPE;
	case PPPS_AUTHENTICATE: /* XX: should never */
	default:
		vpninfo->quit_reason = "Unexpected state";
		return -EINVAL;
	}

	if (last_state != ppp->ppp_state) {
		vpn_progress(vpninfo, PRG_DEBUG,
			     _("PPP state transition from %s to %s\n"),
			     ppps_names[last_state], ppps_names[ppp->ppp_state]);
		print_ppp_state(vpninfo, PRG_TRACE);
		return 1;
	}
	return 0;
}

int ppp_mainloop(struct openconnect_info *vpninfo, int *timeout, int readable)
{
	int ret, magic, rsv_hdr_size;
	int work_done = 0;
	struct pkt *this;
	struct oc_ppp *ppp = vpninfo->ppp;
	int proto;

	if (vpninfo->ssl_fd == -1)
		goto do_reconnect;

	if ((ret = handle_state_transition(vpninfo, timeout) < 0))
	    return ret;

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
		unsigned char *ph, *pp;
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
		short_pkt:
			vpn_progress(vpninfo, PRG_ERR, _("Short packet received (%d bytes)\n"), len);
			vpninfo->quit_reason = "Short packet received";
			return 1;
		}

		if (vpninfo->dump_http_traffic)
			dump_buf_hex(vpninfo, PRG_DEBUG, '<', ph, len);

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

			if (len > 4 + payload_len) {
				/* XX: SSL record contains another packet after this one */
				vpn_progress(vpninfo, PRG_ERR,
					     _("Packet contains %d bytes after payload. Concatenated packets are not handled yet.\n"),
					     len - 4 + payload_len);
			} else if (len < 4 + payload_len) {
				vpn_progress(vpninfo, PRG_ERR,
					     _("Packet is incomplete. Received %d bytes on wire (includes %d encap) but header payload_len is %d\n"),
					     len, ppp->encap_len, payload_len);
				dump_buf_hex(vpninfo, PRG_ERR, '<', ph, len);
				continue;
			}
			break;

		case PPP_ENCAP_F5_HDLC:
		case PPP_ENCAP_FORTINET_HDLC:
			payload_len = unhdlc_in_place(vpninfo, ph, len, &pp);
			if (payload_len < 0)
				continue; /* unhdlc_in_place already logged */
			if (pp != ph + len)
				vpn_progress(vpninfo, PRG_ERR,
					     _("Packet contains %ld bytes after payload. Concatenated packets are not handled yet.\n"),
					     len - (pp - ph));
			//if (vpninfo->dump_http_traffic)
			//	dump_buf_hex(vpninfo, PRG_TRACE, '<', pp, payload_len);
			break;

		default:
			vpn_progress(vpninfo, PRG_ERR, _("Invalid PPP encapsulation\n"));
			vpninfo->quit_reason = "Invalid encapsulation";
			return -EINVAL;
		}

		/* check PPP header and extract protocol */
		pp = ph += ppp->encap_len;
		if (pp[0] == 0xff && pp[1] == 0x03)
			/* XX: Neither byte is a possible proto value (https://tools.ietf.org/html/rfc1661#section-2) */
			pp += 2;
		proto = *pp++;
		if (!(proto & 1)) {
			proto <<= 8;
			proto += *pp++;
		}
		payload_len -= pp - ph;

		vpninfo->ssl_times.last_rx = time(NULL);

		switch (proto) {
		case PPP_LCP:
		case PPP_IPCP:
		case PPP_IP6CP:
			if (payload_len < 4) {
				goto short_pkt;
			} else if (load_be16(pp + 2) > payload_len) {
				vpn_progress(vpninfo, PRG_ERR, "PPP config packet too short (header says %d bytes, received %d)\n", load_be16(pp+2), payload_len);
				dump_buf_hex(vpninfo, PRG_ERR, '<', ph, payload_len+4);
				return 1;
			} else if (load_be16(pp + 2) < payload_len) {
				vpn_progress(vpninfo, PRG_DEBUG, "PPP config packet has junk at end (header says %d bytes, received %d)\n", load_be16(pp+2), payload_len);
				payload_len = load_be16(pp + 2);
			}
			if ((ret = handle_config_packet(vpninfo, proto, pp, payload_len)) >= 0)
				if ((ret = handle_state_transition(vpninfo, timeout)) < 0)
					return ret;
			break;

		case PPP_IP:
		case PPP_IP6:
			if (ppp->ppp_state != PPPS_NETWORK) {
				vpn_progress(vpninfo, PRG_ERR,
					     _("Unexpected IPv%d packet in PPP state %s."),
					     (proto == PPP_IP6 ? 6 : 4), ppps_names[ppp->ppp_state]);
				dump_buf_hex(vpninfo, PRG_ERR, '<', pp, payload_len);
			} else {
				vpn_progress(vpninfo, PRG_TRACE,
					     _("Received IPv%d data packet of %d bytes\n"),
					     proto == PPP_IP6 ? 6 : 4, payload_len);

				if (pp != vpninfo->cstp_pkt->data) {
					vpn_progress(vpninfo, PRG_TRACE,
						     _("Expected %d PPP header bytes but got %ld, shifting payload.\n"),
						     ppp->exp_ppp_hdr_size, pp - ph);
					/* Save it for next time */
					ppp->exp_ppp_hdr_size = pp - ph;
					/* XX: If PPP header was SMALLER than expected, we could be overwriting data for the
					 * following concatenated packet, or conceivably moving a huge packet past
					 * the allocated buffer. */
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
		if (vpninfo->tcp_control_queue.head ||
		    (vpninfo->dtls_state != DTLS_CONNECTED && ppp->ppp_state == PPPS_NETWORK && vpninfo->outgoing_queue.head))
			break;
		vpn_progress(vpninfo, PRG_DEBUG, _("Send PPP discard request as keepalive\n"));
		queue_config_packet(vpninfo, PPP_LCP, ++ppp->lcp.id, DISCREQ, 0, NULL);
		break;
	case KA_DPD:
		vpn_progress(vpninfo, PRG_DEBUG, _("Send PPP echo request as DPD\n"));
		queue_config_packet(vpninfo, PPP_LCP, ++ppp->lcp.id, ECHOREQ, 4, &ppp->out_lcp_magic);
	}

	/* Service control queue; also, outgoing packet queue, if no DTLS  */
	if ((this = vpninfo->current_ssl_pkt = dequeue_packet(&vpninfo->tcp_control_queue))) {
		/* XX: We pre-stash the PPP protocol field in the header for control packets */
		proto = this->ppp.proto;
	} else if (vpninfo->dtls_state != DTLS_CONNECTED &&
		   ppp->ppp_state == PPPS_NETWORK &&
		   (this = vpninfo->current_ssl_pkt = dequeue_packet(&vpninfo->outgoing_queue))) {
		/* XX: Set protocol for IP packets */
		proto = (this->len && (this->data[0] & 0xf0) == 0x60) ? PPP_IP6 : PPP_IP;
	}

	if (this) {
		int n = 0;

		/* XX: store PPP header, in reverse */
		this->data[--n] = proto & 0xff;
		if (proto > 0xff || !(ppp->out_lcp_opts & PFCOMP))
			this->data[--n] = proto >> 8;
		if (proto == PPP_LCP || !(ppp->out_lcp_opts & ACCOMP)) {
			this->data[--n] = 0x03; /* Control */
			this->data[--n] = 0xff; /* Address */
		}

		/* Add pre-PPP encapsulation header */
		switch (ppp->encap) {
		case PPP_ENCAP_F5:
			store_be16(this->data + n - 2, this->len - n);
			store_be16(this->data + n - 4, 0xf500);
			this->ppp.hlen = -n + 4;
			break;
		case PPP_ENCAP_F5_HDLC:
		case PPP_ENCAP_FORTINET_HDLC:
			/* XX: use worst-case escaping for LCP */
			this = hdlc_into_new_pkt(vpninfo, this->data + n, this->len - n,
						 proto == PPP_LCP ? ASYNCMAP_LCP : ppp->out_asyncmap);
			if (!this)
				return 1; /* XX */
			free(vpninfo->current_ssl_pkt);
			vpninfo->current_ssl_pkt = this;
			break;
		default:
			/* XX: fail */
			break;
		}

		vpn_progress(vpninfo, PRG_TRACE,
			     _("Sending proto 0x%04x packet (%d bytes total)\n"),
			     proto, this->len + this->ppp.hlen);
		if (vpninfo->dump_http_traffic)
			dump_buf_hex(vpninfo, PRG_TRACE, '>', this->data - this->ppp.hlen, this->len + this->ppp.hlen);

		vpninfo->current_ssl_pkt = this;
		goto handle_outgoing;
	}

	/* Work is not done if we just got rid of packets off the queue */
	return work_done;
}
