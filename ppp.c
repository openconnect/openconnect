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

struct oc_ppp {
	int hdlc;
	uint32_t out_asyncmap;
	int out_lcp_opts;
	uint32_t in_asyncmap;
	int in_lcp_opts;
};

#define buf_append_ppp(buf, hdlc, bytes, len, asyncmap)			\
	do {								\
		if (hdlc)						\
			buf_append_ppphdlc(buf, bytes, len, asyncmap);	\
		else							\
			buf_append_bytes(buf, bytes, len);		\
	} while (0)

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
