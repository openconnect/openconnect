/*
 * OpenConnect (SSL + DTLS) VPN client
 *
 * Copyright © 2019 David Woodhouse.
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

#include <unistd.h>
#include <fcntl.h>
#include <time.h>
#include <string.h>
#include <ctype.h>
#include <errno.h>
#include <stdlib.h>
#include <stdio.h>
#include <sys/types.h>
#include <stdarg.h>
#include <sys/types.h>

#include "openconnect-internal.h"

#define VENDOR_JUNIPER 0xa4c
#define VENDOR_JUNIPER2 0x583
#define VENDOR_TCG 0x5597

#define IFT_VERSION_REQUEST 1
#define IFT_VERSION_RESPONSE 2
#define IFT_CLIENT_AUTH_REQUEST 3
#define IFT_CLIENT_AUTH_SELECTION 4
#define IFT_CLIENT_AUTH_CHALLENGE 5
#define IFT_CLIENT_AUTH_RESPONSE 6
#define IFT_CLIENT_AUTH_SUCCESS 7

/* IF-T/TLS v1 authentication messages all start
 * with the Auth Type Vendor (Juniper) + Type (1) */
#define JUNIPER_1 ((VENDOR_JUNIPER << 8) | 1)

#define AVP_VENDOR 0x80
#define AVP_MANDATORY 0x40

#define EAP_REQUEST 1
#define EAP_RESPONSE 2
#define EAP_SUCCESS 3
#define EAP_FAILURE 4

#define EAP_TYPE_IDENTITY 1
#define EAP_TYPE_TTLS 0x15
#define EAP_TYPE_EXPANDED 0xfe

#define EXPANDED_JUNIPER ((EAP_TYPE_EXPANDED << 24) | VENDOR_JUNIPER)

#define AVP_CODE_EAP_MESSAGE 79

#if defined(OPENCONNECT_OPENSSL)
#define TTLS_SEND SSL_write
#define TTLS_RECV SSL_read
#elif defined(OPENCONNECT_GNUTLS)
#define TTLS_SEND gnutls_record_send
#define TTLS_RECV gnutls_record_recv
#endif

static void buf_append_be16(struct oc_text_buf *buf, uint16_t val)
{
	unsigned char b[2];

	store_be16(b, val);

	buf_append_bytes(buf, b, 2);
}

static void buf_append_be32(struct oc_text_buf *buf, uint32_t val)
{
	unsigned char b[4];

	store_be32(b, val);

	buf_append_bytes(buf, b, 4);
}

static void buf_append_ift_hdr(struct oc_text_buf *buf, uint32_t vendor, uint32_t type)
{
	uint32_t b[4];

	store_be32(&b[0], vendor);
	store_be32(&b[1], type);
	b[2] = 0; /* Length will be filled in later. */
	b[3] = 0;
	buf_append_bytes(buf, b, 16);
}

/* Append EAP header, using VENDOR_JUNIPER and the given subtype if
 * the main type is EAP_TYPE_EXPANDED */
static int buf_append_eap_hdr(struct oc_text_buf *buf, uint8_t code, uint8_t ident, uint8_t type,
			       uint32_t subtype)
{
	unsigned char b[24];
	int len_ofs = -1;

	if (!buf_error(buf))
		len_ofs = buf->pos;

	b[0] = code;
	b[1] = ident;
	b[2] = b[3] = 0; /* Length is filled in later. */
	if (type == EAP_TYPE_EXPANDED) {
		store_be32(b + 4, EXPANDED_JUNIPER);
		store_be32(b + 8, subtype);
		buf_append_bytes(buf, b, 12);
	} else {
		b[4] = type;
		buf_append_bytes(buf, b, 5);
	}
	return len_ofs;
}

/* For an IF-T/TLS auth frame containing the Juniper/1 Auth Type,
 * the EAP header is at offset 0x14. Fill in the length field,
 * based on the current length of the buf */
static void buf_fill_eap_len(struct oc_text_buf *buf, int ofs)
{
	/* EAP length word is always at 0x16, and counts bytes from 0x14 */
	if (ofs >= 0 && !buf_error(buf) && buf->pos > ofs + 8)
		store_be16(buf->data + ofs + 2, buf->pos - ofs);
}

static void buf_append_avp(struct oc_text_buf *buf, uint32_t type, const void *bytes, int len)
{
	buf_append_be32(buf, type);
	buf_append_be16(buf, 0x8000);
	buf_append_be16(buf, len + 12);
	buf_append_be32(buf, VENDOR_JUNIPER2);
	buf_append_bytes(buf, bytes, len);
	if (len & 3) {
		uint32_t pad = 0;
		buf_append_bytes(buf, &pad, 4 - ( len & 3 ));
	}
}

static void buf_append_avp_string(struct oc_text_buf *buf, uint32_t type, const char *str)
{
	buf_append_avp(buf, type, str, strlen(str));
}

static int valid_ift_success(unsigned char *bytes, int len)
{
	if (len != 0x18 || (load_be32(bytes) & 0xffffff) != VENDOR_TCG ||
	    load_be32(bytes + 4) != IFT_CLIENT_AUTH_SUCCESS ||
	    load_be32(bytes + 8) != len ||
	    load_be32(bytes + 0x10) != JUNIPER_1 ||
	    bytes[0x14] != EAP_SUCCESS ||
	    load_be16(bytes + 0x16) != len - 0x14)
		return 0;

	return 1;
}

/* Check for a valid IF-T/TLS auth challenge of the Juniper/1 Auth Type */
static int valid_ift_auth(unsigned char *bytes, int len)
{
	if (len < 0x14 || (load_be32(bytes) & 0xffffff) != VENDOR_TCG ||
	    load_be32(bytes + 4) != IFT_CLIENT_AUTH_CHALLENGE ||
	    load_be32(bytes + 8) != len ||
	    load_be32(bytes + 0x10) != JUNIPER_1)
		return 0;

	return 1;
}


static int valid_ift_auth_eap(unsigned char *bytes, int len)
{
	/* Needs to be a valid IF-T/TLS auth challenge with the
	 * expect Auth Type, *and* the payload has to be a valid
	 * EAP request with correct length field. */
	if (!valid_ift_auth(bytes, len) || len < 0x19 ||
	    bytes[0x14] != EAP_REQUEST ||
	    load_be16(bytes + 0x16) != len - 0x14)
		return 0;

	return 1;
}

static int valid_ift_auth_eap_exj1(unsigned char *bytes, int len)
{
	/* Also needs to be the Expanded Juniper/1 EAP Type */
	if (!valid_ift_auth_eap(bytes, len) || len < 0x20 ||
	    load_be32(bytes + 0x18) != EXPANDED_JUNIPER ||
	    load_be32(bytes + 0x1c) != 1)
		return 0;

	return 1;
}

/* We behave like CSTP — create a linked list in vpninfo->cstp_options
 * with the strings containing the information we got from the server,
 * and oc_ip_info contains const copies of those pointers. */

static const char *add_option(struct openconnect_info *vpninfo, const char *opt,
			      const char *val, int val_len)
{
	struct oc_vpn_option *new = malloc(sizeof(*new));
	if (!new)
		return NULL;

	new->option = strdup(opt);
	if (!new->option) {
		free(new);
		return NULL;
	}
	if (val_len >= 0)
		new->value = strndup(val, val_len);
	else
		new->value = strdup(val);
	if (!new->value) {
		free(new->option);
		free(new);
		return NULL;
	}
	new->next = vpninfo->cstp_options;
	vpninfo->cstp_options = new;

	return new->value;
}

static int process_attr(struct openconnect_info *vpninfo, uint16_t type,
			unsigned char *data, int attrlen)
{
	char buf[80];
	int i;

	switch (type) {

	case 0x0001:
		if (attrlen != 4)
			goto badlen;
		snprintf(buf, sizeof(buf), "%d.%d.%d.%d", data[0], data[1], data[2], data[3]);

		vpn_progress(vpninfo, PRG_DEBUG, _("Received internal Legacy IP address %s\n"), buf);
		vpninfo->ip_info.addr = add_option(vpninfo, "ipaddr", buf, -1);
		break;

	case 0x0002:
		if (attrlen != 4)
			goto badlen;
		snprintf(buf, sizeof(buf), "%d.%d.%d.%d", data[0], data[1], data[2], data[3]);

		vpn_progress(vpninfo, PRG_DEBUG, _("Received netmask %s\n"), buf);
		vpninfo->ip_info.netmask = add_option(vpninfo, "netmask", buf, -1);
		break;

	case 0x0003:
		if (attrlen != 4)
			goto badlen;
		snprintf(buf, sizeof(buf), "%d.%d.%d.%d", data[0], data[1], data[2], data[3]);

		vpn_progress(vpninfo, PRG_DEBUG, _("Received DNS server %s\n"), buf);

		for (i = 0; i < 3; i++) {
			if (!vpninfo->ip_info.dns[i]) {
				vpninfo->ip_info.dns[i] = add_option(vpninfo, "DNS", buf, -1);
				break;
			}
		}
		break;

	case 0x0004:
		if (attrlen != 4)
			goto badlen;
		snprintf(buf, sizeof(buf), "%d.%d.%d.%d", data[0], data[1], data[2], data[3]);

		vpn_progress(vpninfo, PRG_DEBUG, _("Received WINS server %s\n"), buf);

		for (i = 0; i < 3; i++) {
			if (!vpninfo->ip_info.nbns[i]) {
				vpninfo->ip_info.nbns[i] = add_option(vpninfo, "WINS", buf, -1);
				break;
			}
		}
		break;

	case 0x0008:
		if (attrlen != 17)
			goto badlen;
		if (!inet_ntop(AF_INET6, data, buf, sizeof(buf))) {
			vpn_progress(vpninfo, PRG_ERR,
				     _("Failed to handle IPv6 address\n"));
			return -EINVAL;
		}
		i = strlen(buf);
		snprintf(buf + i, sizeof(buf) - i, "/%d", data[16]);
		vpn_progress(vpninfo, PRG_DEBUG, _("Received internal IPv6 address %s\n"), buf);
		vpninfo->ip_info.addr6 = add_option(vpninfo, "ip6addr", buf, -1);
		break;

	case 0x4005:
		if (attrlen != 4) {
		badlen:
			vpn_progress(vpninfo, PRG_ERR,
				     _("Unexpected length %d for attr 0x%x\n"),
				     attrlen, type);
			return -EINVAL;
		}
		vpninfo->ip_info.mtu = load_be32(data);
		vpn_progress(vpninfo, PRG_DEBUG,
			     _("Received MTU %d from server\n"),
			     vpninfo->ip_info.mtu);
		break;

	case 0x4006:
		if (!attrlen)
			goto badlen;
		if (!data[attrlen-1])
		    attrlen--;
		vpn_progress(vpninfo, PRG_DEBUG, _("Received DNS search domain %.*s\n"),
			     attrlen, (char *)data);
		vpninfo->ip_info.domain = add_option(vpninfo, "search", (char *)data, attrlen);
		if (vpninfo->ip_info.domain) {
			char *p = (char *)vpninfo->ip_info.domain;
			while ((p = strchr(p, ',')))
				*p = ' ';
		}
		break;

	case 0x400b:
		if (attrlen != 4)
			goto badlen;
		snprintf(buf, sizeof(buf), "%d.%d.%d.%d", data[0], data[1], data[2], data[3]);

		vpn_progress(vpninfo, PRG_DEBUG, _("Received internal gateway address %s\n"), buf);
		/* Hm, what are we supposed to do with this? It's a tunnel;
		   having a gateway is meaningless. */
		add_option(vpninfo, "ipaddr", buf, -1);
		break;

	case 0x4010: {
		const char *enctype;
		uint16_t val;

		if (attrlen != 2)
			goto badlen;
		val = load_be16(data);
		if (val == ENC_AES_128_CBC) {
			enctype = "AES-128";
			vpninfo->enc_key_len = 16;
		} else if (val == ENC_AES_256_CBC) {
			enctype = "AES-256";
			vpninfo->enc_key_len = 32;
		} else
			enctype = "unknown";
		vpn_progress(vpninfo, PRG_DEBUG, _("ESP encryption: 0x%04x (%s)\n"),
			      val, enctype);
		vpninfo->esp_enc = val;
		break;
	}

	case 0x4011: {
		const char *mactype;
		uint16_t val;

		if (attrlen != 2)
			goto badlen;
		val = load_be16(data);
		if (val == HMAC_MD5) {
			mactype = "MD5";
			vpninfo->hmac_key_len = 16;
		} else if (val == HMAC_SHA1) {
			mactype = "SHA1";
			vpninfo->hmac_key_len = 20;
		} else if (val == HMAC_SHA256) {
			mactype = "SHA256";
			vpninfo->hmac_key_len = 32;
		} else
			mactype = "unknown";
		vpn_progress(vpninfo, PRG_DEBUG, _("ESP HMAC: 0x%04x (%s)\n"),
			      val, mactype);
		vpninfo->esp_hmac = val;
		break;
	}

	case 0x4012:
		if (attrlen != 4)
			goto badlen;
		vpninfo->esp_lifetime_seconds = load_be32(data);
		vpn_progress(vpninfo, PRG_DEBUG, _("ESP key lifetime: %u seconds\n"),
			     vpninfo->esp_lifetime_seconds);
		break;

	case 0x4013:
		if (attrlen != 4)
			goto badlen;
		vpninfo->esp_lifetime_bytes = load_be32(data);
		vpn_progress(vpninfo, PRG_DEBUG, _("ESP key lifetime: %u bytes\n"),
			     vpninfo->esp_lifetime_bytes);
		break;

	case 0x4014:
		if (attrlen != 4)
			goto badlen;
		vpninfo->esp_replay_protect = load_be32(data);
		vpn_progress(vpninfo, PRG_DEBUG, _("ESP replay protection: %d\n"),
			     load_be32(data));
		break;

	case 0x4016:
		if (attrlen != 2)
			goto badlen;
		i = load_be16(data);
		udp_sockaddr(vpninfo, i);
		vpn_progress(vpninfo, PRG_DEBUG, _("ESP port: %d\n"), i);
		break;

	case 0x4017:
		if (attrlen != 4)
			goto badlen;
		vpninfo->esp_ssl_fallback = load_be32(data);
		vpn_progress(vpninfo, PRG_DEBUG, _("ESP to SSL fallback: %u seconds\n"),
			     vpninfo->esp_ssl_fallback);
		break;

	case 0x401a:
		if (attrlen != 1)
			goto badlen;
		/* Amusingly, this isn't enforced. It's client-only */
		vpn_progress(vpninfo, PRG_DEBUG, _("ESP only: %d\n"),
			     data[0]);
		break;
#if 0
	case GRP_ATTR(7, 1):
		if (attrlen != 4)
			goto badlen;
		memcpy(&vpninfo->esp_out.spi, data, 4);
		vpn_progress(vpninfo, PRG_DEBUG, _("ESP SPI (outbound): %x\n"),
			     load_be32(data));
		break;

	case GRP_ATTR(7, 2):
		if (attrlen != 0x40)
			goto badlen;
		/* data contains enc_key and hmac_key concatenated */
		memcpy(vpninfo->esp_out.enc_key, data, 0x40);
		vpn_progress(vpninfo, PRG_DEBUG, _("%d bytes of ESP secrets\n"),
			     attrlen);
		break;
#endif
	/* 0x4022: disable proxy
	   0x400a: preserve proxy
	   0x4008: proxy (string)
	   0x4000: disconnect when routes changed
	   0x4015: tos copy
	   0x4001:  tunnel routes take precedence
	   0x401f:  tunnel routes with subnet access (also 4001 set)
	   0x4020: Enforce IPv4
	   0x4021: Enforce IPv6
	   0x401e: Server IPv6 address
	   0x000f: IPv6 netmask?
	*/

	default:
		buf[0] = 0;
		for (i=0; i < 16 && i < attrlen; i++)
			sprintf(buf + strlen(buf), " %02x", data[i]);
		if (attrlen > 16)
			sprintf(buf + strlen(buf), "...");

		vpn_progress(vpninfo, PRG_DEBUG,
			     _("Unknown attr 0x%x len %d:%s\n"),
			     type, attrlen, buf);
	}
	return 0;
}

static int recv_ift_packet(struct openconnect_info *vpninfo, void *buf, int len)
{
	int ret = vpninfo->ssl_read(vpninfo, buf, len);
	if (ret > 0 && vpninfo->dump_http_traffic) {
		vpn_progress(vpninfo, PRG_TRACE,
			     _("Read %d bytes of IF-T/TLS record\n"), ret);
		dump_buf_hex(vpninfo, PRG_TRACE, '<', buf, ret);
	}
	return ret;
}

static int send_ift_packet(struct openconnect_info *vpninfo, struct oc_text_buf *buf)
{
	int ret;

	if (buf_error(buf) || buf->pos < 16) {
		vpn_progress(vpninfo, PRG_ERR,
			     _("Error creating IF-T packet\n"));
		return buf_error(buf);
	}

	/* Fill in the length word in the header with the full length of the buffer.
	 * Also populate the sequence number. */
	store_be32(buf->data + 8, buf->pos);
	store_be32(buf->data + 12, vpninfo->ift_seq++);

	dump_buf_hex(vpninfo, PRG_DEBUG, '>', (void *)buf->data, buf->pos);
	ret = vpninfo->ssl_write(vpninfo, buf->data, buf->pos);
	if (ret != buf->pos) {
		if (ret >= 0) {
			vpn_progress(vpninfo, PRG_ERR,
				     _("Short write to IF-T/TLS\n"));
			ret = -EIO;
		}
		return ret;
	}
	return 0;
}

/* We create packets with IF-T/TLS headers prepended because that's the
 * larger header. In the case where they need to be sent over EAP-TTLS,
 * convert the header to the EAP-Message AVP instead. */
static int send_eap_packet(struct openconnect_info *vpninfo, void *ttls, struct oc_text_buf *buf)
{
	int ret;

	if (buf_error(buf) || buf->pos < 16) {
		vpn_progress(vpninfo, PRG_ERR,
			     _("Error creating EAP packet\n"));
		return buf_error(buf);
	}

	if (!ttls)
		return send_ift_packet(vpninfo, buf);

	/* AVP EAP-Message header */
	store_be32(buf->data + 0x0c, AVP_CODE_EAP_MESSAGE);
	store_be32(buf->data + 0x10, buf->pos - 0xc);
	dump_buf_hex(vpninfo, PRG_DEBUG, '.', (void *)(buf->data + 0x0c), buf->pos - 0x0c);
	ret = TTLS_SEND(ttls, buf->data + 0x0c, buf->pos - 0x0c);
	if (ret != buf->pos - 0x0c)
		return -EIO;
	return 0;
}


/*
 * Using the given buffer, receive and validate an EAP request of the
 * Expanded Juniper/1 type, either natively over IF-T/TLS or by EAP-TTLS
 * over IF-T/TLS. Return a pointer to the EAP header, with its length and
 * type already validated.
 */
static void *recv_eap_packet(struct openconnect_info *vpninfo, void *ttls, void *buf, int len)
{
	unsigned char *cbuf = buf;
	int ret;

	if (!ttls) {
		ret = recv_ift_packet(vpninfo, buf, len);
		if (ret < 0)
			return NULL;
		if (!valid_ift_auth_eap_exj1(buf, ret)) {
			vpn_progress(vpninfo, PRG_ERR,
				     _("Unexpected IF-T/TLS authentication challenge:\n"));
			dump_buf_hex(vpninfo, PRG_ERR, '<', (void *)buf, ret);
			return NULL;
		}
		return cbuf + 0x14;
	} else {
		ret = TTLS_RECV(ttls, buf, len);
		if (ret <= 8)
			return NULL;
		if (/* EAP-Message AVP */
		    load_be32(cbuf) != AVP_CODE_EAP_MESSAGE ||
		    /* Ignore the mandatory bit */
		    (load_be32(cbuf+0x04) & ~0x40000000) != ret ||
		    cbuf[0x08] != EAP_REQUEST ||
		    load_be16(cbuf+0x0a) != ret - 8 ||
		    load_be32(cbuf+0x0c) != EXPANDED_JUNIPER ||
		    load_be32(cbuf+0x10) != 1) {
			vpn_progress(vpninfo, PRG_ERR,
				     _("Unexpected EAP-TTLS payload:\n"));
			dump_buf_hex(vpninfo, PRG_ERR, '<', buf, ret);
			return NULL;
		}
		return cbuf + 0x08;
	}
}

static void dump_avp(struct openconnect_info *vpninfo, uint8_t flags,
		     uint32_t vendor, uint32_t code, void *p, int len)
{
	struct oc_text_buf *buf = buf_alloc();
	const char *pretty;
	int i;

	for (i = 0; i < len; i++)
		if (!isprint( ((char *)p)[i] ))
			break;

	if (i == len) {
		buf_append(buf, " '");
		buf_append_bytes(buf, p, len);
		buf_append(buf, "'");
	} else {
		for (i = 0; i < len; i++)
			buf_append(buf, " %02x", ((unsigned char *)p)[i]);
	}
	if (buf_error(buf))
		pretty = " <error>";
	else
		pretty = buf->data;

	if (flags & AVP_VENDOR)
		vpn_progress(vpninfo, PRG_TRACE, _("AVP 0x%x/0x%x:%s\n"), vendor, code, pretty);
	else
		vpn_progress(vpninfo, PRG_TRACE, _("AVP %d:%s\n"), code, pretty);
	buf_free(buf);
}

/* RFC5281 §10 */
static int parse_avp(struct openconnect_info *vpninfo, void **pkt, int *pkt_len,
		    void **avp_out, int *avp_len, uint8_t *avp_flags,
		    uint32_t *avp_vendor, uint32_t *avp_code)
{
	unsigned char *p = *pkt;
	int l = *pkt_len;
	uint32_t code, len, vendor = 0;
	uint8_t flags;

	if (l < 8)
		return -EINVAL;

	code = load_be32(p);
	len = load_be32(p + 4) & 0xffffff;
	flags = p[4];

	if (len > l || len < 8)
		return -EINVAL;

	p += 8;
	l -= 8;
	len -= 8;

	/* Vendor field is optional. */
	if (flags & AVP_VENDOR) {
		if (l < 4)
			return -EINVAL;
		vendor = load_be32(p);
		p += 4;
		l -= 4;
		len -= 4;
	}

	*avp_vendor = vendor;
	*avp_flags = flags;
	*avp_code = code;
	*avp_out = p;
	*avp_len = len;

	/* Now set up packet pointer and length for next AVP,
	 * aligned to 4 octets (if they exist in the packet) */
	len = (len + 3) & ~3;
	if (len > l)
		len = l;
	*pkt = p + len;
	*pkt_len = l - len;

	return 0;
}


static int pulse_request_realm_entry(struct openconnect_info *vpninfo, struct oc_text_buf *reqbuf)
{
	struct oc_auth_form f;
	struct oc_form_opt o;
	int ret;

	memset(&f, 0, sizeof(f));
	memset(&o, 0, sizeof(o));
        f.auth_id = (char *)"pulse_realm_entry";
        f.opts = &o;

	f.message = _("Enter Pulse user realm:");

	o.next = NULL;
	o.type = OC_FORM_OPT_TEXT;
	o.name = (char *)"realm";
	o.label = (char *)_("Realm:");

	ret = process_auth_form(vpninfo, &f);
	if (ret)
		return ret;

	if (o._value) {
		buf_append_avp_string(reqbuf, 0xd50, o._value);
		free_pass(&o._value);
		return 0;
	}

	return -EINVAL;
}

static int pulse_request_realm_choice(struct openconnect_info *vpninfo, struct oc_text_buf *reqbuf,
				      int realms, unsigned char *eap)
{
	uint8_t avp_flags;
	uint32_t avp_code;
	uint32_t avp_vendor;
	int avp_len;
	void *avp_p;
	struct oc_auth_form f;
	struct oc_form_opt_select o;
	int i = 0, ret;
	void *p;
	int l;

	l = load_be16(eap + 2) - 0x0c; /* Already validated */
	p = eap + 0x0c;

	memset(&f, 0, sizeof(f));
	memset(&o, 0, sizeof(o));
	f.auth_id = (char *)"pulse_realm_choice";
	f.opts = &o.form;
	f.authgroup_opt = &o;
	f.authgroup_selection = 1;
	f.message = _("Choose Pulse user realm:");

	o.form.next = NULL;
	o.form.type = OC_FORM_OPT_SELECT;
	o.form.name = (char *)"realm_choice";
	o.form.label = (char *)_("Realm:");

	o.nr_choices = realms;
	o.choices = calloc(realms, sizeof(*o.choices));
	if (!o.choices)
		return -ENOMEM;

	while (l) {
		if (parse_avp(vpninfo, &p, &l, &avp_p, &avp_len, &avp_flags,
			      &avp_vendor, &avp_code)) {
			vpn_progress(vpninfo, PRG_ERR,
				     _("Failed to parse AVP\n"));
			ret = -EINVAL;
			goto out;
		}
		if (avp_vendor != VENDOR_JUNIPER2 || avp_code != 0xd4e)
			continue;

		o.choices[i] = malloc(sizeof(struct oc_choice));
		if (!o.choices[i]) {
			ret = -ENOMEM;
			goto out;
		}
		o.choices[i]->name = o.choices[i]->label = strndup(avp_p, avp_len);
		if (!o.choices[i]->name) {
			ret = -ENOMEM;
			goto out;
		}

		i++;
	}


	/* We don't need to do anything on group changes. */
	do {
		ret = process_auth_form(vpninfo, &f);
	} while (ret == OC_FORM_RESULT_NEWGROUP);

	if (!ret)
		buf_append_avp_string(reqbuf, 0xd50, o.form._value);
 out:
	if (o.choices) {
		for (i = 0; i < realms; i++) {
			if (o.choices[i]) {
				free(o.choices[i]->name);
				free(o.choices[i]);
			}
		}
		free(o.choices);
	}
	return ret;
}

static int pulse_request_session_kill(struct openconnect_info *vpninfo, struct oc_text_buf *reqbuf,
				      int sessions, unsigned char *eap)
{
	uint8_t avp_flags;
	uint32_t avp_code;
	uint32_t avp_vendor;
	int avp_len, avp_len2;
	void *avp_p, *avp_p2;
	struct oc_auth_form f;
	struct oc_form_opt_select o;
	int i = 0, ret;
	void *p;
	int l;
	struct oc_text_buf *form_msg = buf_alloc();
	char tmbuf[80];
	struct tm tm;

	l = load_be16(eap + 2) - 0x0c; /* Already validated */
	p = eap + 0x0c;

	memset(&f, 0, sizeof(f));
	memset(&o, 0, sizeof(o));
	f.auth_id = (char *)"pulse_session_kill";
	f.opts = &o.form;

	buf_append(form_msg, _("Session limit reached. Choose session to kill:\n"));

	o.form.next = NULL;
	o.form.type = OC_FORM_OPT_SELECT;
	o.form.name = (char *)"session_choice";
	o.form.label = (char *)_("Session:");

	o.nr_choices = sessions;
	o.choices = calloc(sessions, sizeof(*o.choices));
	if (!o.choices)
		return -ENOMEM;

	while (l) {
		char *from = NULL;
		time_t when = 0;
		char *sessid = NULL;

		if (parse_avp(vpninfo, &p, &l, &avp_p, &avp_len, &avp_flags,
			      &avp_vendor, &avp_code)) {
		badlist:
			vpn_progress(vpninfo, PRG_ERR,
				     _("Failed to parse session list\n"));
			ret = -EINVAL;
			goto out;
		}

		if (avp_vendor != VENDOR_JUNIPER2 || avp_code != 0xd65)
			continue;

		while (avp_len) {
			if (parse_avp(vpninfo, &avp_p, &avp_len, &avp_p2, &avp_len2,
				      &avp_flags, &avp_vendor, &avp_code))
				goto badlist;

			dump_avp(vpninfo, avp_flags, avp_vendor, avp_code, avp_p2, avp_len2);

			if (avp_vendor == VENDOR_JUNIPER2 && avp_code == 0xd66) {
				sessid = strndup(avp_p2, avp_len2);
			} else if (avp_vendor == VENDOR_JUNIPER2 && avp_code == 0xd67) {
				from = strndup(avp_p2, avp_len2);
			} else if (avp_vendor == VENDOR_JUNIPER2 && avp_code == 0xd68 &&
				   avp_len2 == 8) {
				when = load_be32((char *)avp_p2 + 4);
				if (sizeof(time_t) > 4)
					when |= ((uint64_t)load_be32(avp_p2)) << 32;
			}
		}

		if (!from || !sessid || !when) {
			free(from);
			free(sessid);
			goto badlist;
		}

		localtime_r(&when, &tm);
		strftime(tmbuf, 80, "%a, %d %b %Y %H:%M:%S %Z", &tm);
		buf_append(form_msg, " - %s from %s at %s\n", sessid, from, tmbuf);
		free(from);
		o.choices[i] = malloc(sizeof(struct oc_choice));
		if (!o.choices[i]) {
			ret = -ENOMEM;
			goto out;
		}
		o.choices[i]->name = o.choices[i]->label = sessid;
		if (!o.choices[i]->name) {
			ret = -ENOMEM;
			goto out;
		}
		i++;
	}
	ret = buf_error(form_msg);
	if (ret)
		goto out;

	f.message = form_msg->data;

	ret = process_auth_form(vpninfo, &f);
	if (!ret)
		buf_append_avp_string(reqbuf, 0xd69, o.form._value);
 out:
	if (o.choices) {
		for (i = 0; i < sessions; i++) {
			if (o.choices[i]) {
				free(o.choices[i]->name);
				free(o.choices[i]);
			}
		}
		free(o.choices);
	}
	buf_free(form_msg);
	return ret;
}

static int pulse_request_user_auth(struct openconnect_info *vpninfo, struct oc_text_buf *reqbuf,
				   uint8_t eap_ident, char *user_prompt, char *pass_prompt)
{
	struct oc_auth_form f;
	struct oc_form_opt o[2];
	int ret;

	memset(&f, 0, sizeof(f));
	memset(o, 0, sizeof(o));
        f.auth_id = (char *)"pulse_user";
        f.opts = &o[0];

	f.message = _("Enter user credentials:");

	o[0].next = &o[1];
	o[0].type = OC_FORM_OPT_TEXT;
	o[0].name = (char *)"username";
	if (!user_prompt || asprintf(&o[0].label, "%s:", user_prompt) < 0) {
		user_prompt = NULL;
		o[0].label = (char *)_("Username:");
	}

	o[1].type = OC_FORM_OPT_PASSWORD;
	o[1].name = (char *)"password";
	if (!pass_prompt || asprintf(&o[1].label, "%s:", pass_prompt) < 0) {
		pass_prompt = NULL;
		o[1].label = (char *)_("Password:");
	}

	ret = process_auth_form(vpninfo, &f);
	if (ret)
		goto out;

	if (o[0]._value) {
		buf_append_avp_string(reqbuf, 0xd6d, o[0]._value);
		free_pass(&o[0]._value);
	}
	if (o[1]._value) {
		unsigned char eap_avp[23];
		int l = strlen(o[1]._value);
		if (l > 253) {
			free_pass(&o[1]._value);
			return -EINVAL;
		}

		/* AVP flags+mandatory+length */
		store_be32(eap_avp, AVP_CODE_EAP_MESSAGE);
		store_be32(eap_avp + 4, (AVP_MANDATORY << 24) + sizeof(eap_avp) + l);

		/* EAP header: code/ident/len */
		eap_avp[8] = EAP_RESPONSE;
		eap_avp[9] = eap_ident;
		store_be16(eap_avp + 10, l + 15); /* EAP length */
		store_be32(eap_avp + 12, EXPANDED_JUNIPER);
		store_be32(eap_avp + 16, 2);

		/* EAP Juniper/2 payload: 02 02 <len> <password> */
		eap_avp[20] = eap_avp[21] = 0x02;
		eap_avp[22] = l + 2; /* Why 2? */
		buf_append_bytes(reqbuf, eap_avp, sizeof(eap_avp));
		buf_append_bytes(reqbuf, o[1]._value, l);

		/* Padding */
		if ((sizeof(eap_avp) + l) & 3) {
			uint32_t pad = 0;

			buf_append_bytes(reqbuf, &pad,
					 4 - ((sizeof(eap_avp) + l) & 3));
		}
		free_pass(&o[1]._value);
	}
	ret = 0;
 out:
	if (user_prompt)
		free(o[0].label);
	if (pass_prompt)
		free(o[1].label);

	return ret;
}

/* IF-T/TLS session establishment is the same for both pulse_obtain_cookie() and
 * pulse_connect(). We have to go through the EAP phase of the connection either
 * way; it's just that we might do it with just the cookie, or we might need to
 * use the password/cert etc. */
static int pulse_authenticate(struct openconnect_info *vpninfo, int connecting)
{
	int ret;
	struct oc_text_buf *reqbuf;
	unsigned char bytes[16384];
	int eap_ofs;
	uint8_t eap_ident, eap2_ident = 0;
	uint8_t avp_flags;
	uint32_t avp_code;
	uint32_t avp_vendor;
	int avp_len, l;
	void *avp_p, *p;
	unsigned char *eap;
	int cookie_found = 0;
	int j2_found = 0, realms_found = 0, realm_entry = 0, old_sessions = 0;
	uint8_t j2_code = 0;
	void *ttls = NULL;
	char *user_prompt = NULL, *pass_prompt = NULL;

	/* XXX: We should do what cstp_connect() does to check that configuration
	   hasn't changed on a reconnect. */

	ret = openconnect_open_https(vpninfo);
	if (ret)
		return ret;

	reqbuf = buf_alloc();

	buf_append(reqbuf, "GET /%s HTTP/1.1\r\n", vpninfo->urlpath ?: "");
	http_common_headers(vpninfo, reqbuf);
	buf_append(reqbuf, "Content-Type: EAP\r\n");
	buf_append(reqbuf, "Upgrade: IF-T/TLS 1.0\r\n");
	buf_append(reqbuf, "Content-Length: 0\r\n");
	buf_append(reqbuf, "\r\n");

	if (buf_error(reqbuf)) {
		vpn_progress(vpninfo, PRG_ERR,
			     _("Error creating Pulse connection request\n"));
		ret = buf_error(reqbuf);
		goto out;
	}
	if (vpninfo->dump_http_traffic)
		dump_buf(vpninfo, '>', reqbuf->data);

	ret = vpninfo->ssl_write(vpninfo, reqbuf->data, reqbuf->pos);
	if (ret < 0)
		goto out;

	ret = process_http_response(vpninfo, 1, NULL, reqbuf);
	if (ret < 0)
		goto out;

	if (ret != 101) {
		vpn_progress(vpninfo, PRG_ERR,
			     _("Unexpected %d result from server\n"),
			     ret);
		ret = -EINVAL;
		goto out;
	}

	vpninfo->ift_seq = 0;
	/* IF-T version request. */
	buf_truncate(reqbuf);
	buf_append_ift_hdr(reqbuf, VENDOR_TCG, IFT_VERSION_REQUEST);
	/* Min version 1, max 2, preferred 2. Not that we actually do v2; the auth is
	 * still all IF-T/TLS v1. But the server won't offer us HMAC-SHA256 unless we
	 * advertise v2 */
	buf_append_be32(reqbuf, 0x00010202);
	ret = send_ift_packet(vpninfo, reqbuf);
	if (ret)
		goto out;

	ret = recv_ift_packet(vpninfo, (void *)bytes, sizeof(bytes));
	if (ret < 0)
		goto out;

	if (ret != 0x14 || (load_be32(bytes) & 0xffffff) != VENDOR_TCG ||
	    load_be32(bytes + 4) != IFT_VERSION_RESPONSE ||
	    load_be32(bytes + 8) != 0x14) {
		vpn_progress(vpninfo, PRG_ERR,
			     _("Unexpected response to IF-T/TLS version negotiation:\n"));
		dump_buf_hex(vpninfo, PRG_ERR, '<', (void *)bytes, ret);
		ret = -EINVAL;
		goto out;
	}
	vpn_progress(vpninfo, PRG_TRACE, _("IF-T/TLS version from server: %d\n"),
		     bytes[0x13]);

	/* Client information packet over IF-T/TLS */
	buf_truncate(reqbuf);
	buf_append_ift_hdr(reqbuf, VENDOR_JUNIPER, 0x88);
	buf_append(reqbuf, "clientHostName=%s", vpninfo->localname);
	bytes[0] = 0;
	if (vpninfo->peer_addr && vpninfo->peer_addr->sa_family == AF_INET6) {
		struct sockaddr_in6 a;
		socklen_t l = sizeof(a);
		if (!getsockname(vpninfo->ssl_fd, (void *)&a, &l))
			inet_ntop(AF_INET6, &a.sin6_addr, (void *)bytes, sizeof(bytes));
	} else if (vpninfo->peer_addr && vpninfo->peer_addr->sa_family == AF_INET) {
		struct sockaddr_in a;
		socklen_t l = sizeof(a);
		if (!getsockname(vpninfo->ssl_fd, (void *)&a, &l))
			inet_ntop(AF_INET, &a.sin_addr, (void *)bytes, sizeof(bytes));
	}
	if (bytes[0])
		buf_append(reqbuf, " clientIp=%s", bytes);
	buf_append(reqbuf, "\n%c", 0);
	ret = send_ift_packet(vpninfo, reqbuf);
	if (ret)
		goto out;

	/* Await start of auth negotiations */
	ret = recv_ift_packet(vpninfo, (void *)bytes, sizeof(bytes));
	if (ret < 0)
		goto out;

	/* Basically an empty IF-T/TLS auth challenge packet of type Juniper/1,
	 * without even an EAP header in the payload. */
	if (!valid_ift_auth(bytes, ret) || ret != 0x14) {
		vpn_progress(vpninfo, PRG_ERR,
			     _("Unexpected IF-T/TLS authentication challenge:\n"));
		dump_buf_hex(vpninfo, PRG_ERR, '<', (void *)bytes, ret);
		ret = -EINVAL;
		goto out;
	}

	/* Start by sending an EAP Identity of 'anonymous'. At this point we
	 * aren't yet very far down the rabbithole...
	 *
	 *     --------------------------------------
	 *     |                TCP/IP              |
	 *     |------------------------------------|
	 *     |                 TLS                |
	 *     |------------------------------------|
	 *     |               IF-T/TLS             |
	 *     |------------------------------------|
	 *     | EAP (IF-T/TLS Auth Type Juniper/1) |
	 *     |------------------------------------|
	 *     |             EAP-Identity           |
	 *     --------------------------------------
	 */
	buf_truncate(reqbuf);
	buf_append_ift_hdr(reqbuf, VENDOR_TCG, IFT_CLIENT_AUTH_RESPONSE);
	buf_append_be32(reqbuf, JUNIPER_1); /* IF-T/TLS Auth Type */
	eap_ofs = buf_append_eap_hdr(reqbuf, EAP_RESPONSE, 1, EAP_TYPE_IDENTITY, 0);
	buf_append(reqbuf, "anonymous");
	buf_fill_eap_len(reqbuf, eap_ofs);
	ret = send_ift_packet(vpninfo, reqbuf);
	if (ret)
		goto out;

	/*
	 * Phase 2 may continue directly with EAP within IF-T/TLS, or if certificate
	 * auth is enabled, the server may use EAP-TTLS. In that case, we end up
	 * with EAP within EAP-Message AVPs within EAP-TTLS within IF-T/TLS.
	 * The send_eap_packet() and recv_eap_packet() functions cope with both
	 * formats. The buffers have 0x14 bytes of header space, to allow for
	 * the IF-T/TLS header which is the larger of the two.
	 *
	 *     --------------------------------------
	 *     |                TCP/IP              |
	 *     |------------------------------------|
	 *     |                 TLS                |
	 *     |------------------------------------|
	 *     |               IF-T/TLS             |
	 *     |------------------------------------|
	 *     | EAP (IF-T/TLS Auth Type Juniper/1) |
	 *     |------------------                  |
	 *     |     EAP-TTLS    |                  |
	 *     |-----------------|  (or directly)   |
	 *     | EAP-Message AVP |                  |
	 *     |-----------------|------------------|
	 *     |            EAP-Juniper-1           |
	 *     --------------------------------------
	 */
	ret = recv_ift_packet(vpninfo, (void *)bytes, sizeof(bytes));
	if (ret < 0)
		goto out;

	/* Check EAP header and length */
	if (!valid_ift_auth_eap(bytes, ret)) {
	bad_ift:
		vpn_progress(vpninfo, PRG_ERR,
			     _("Unexpected IF-T/TLS authentication challenge:\n"));
		dump_buf_hex(vpninfo, PRG_ERR, '<', (void *)bytes, ret);
		ret = -EINVAL;
		goto out;
	}

	/*
	 * We know the packet is valid at least down to the first layer of
	 * EAP in the diagram above, directly within the IF-T/TLS Auth Type
	 * of Juniper/1. Now, disambiguate between the two cases where the
	 * diagram diverges. Is it EAP-TTLS or is it EAP-Juniper-1 directly?
	 */
	if (valid_ift_auth_eap_exj1(bytes, ret)) {
		eap = bytes + 0x14;
	} else {
		/* If it isn't that, it'd better be EAP-TTLS... */
		if (bytes[0x18] != EAP_TYPE_TTLS)
			goto bad_ift;

		vpninfo->ttls_eap_ident = bytes[0x15];
		vpninfo->ttls_recvbuf = malloc(16384);
		if (!vpninfo->ttls_recvbuf)
			return -ENOMEM;
		vpninfo->ttls_recvlen = 0;
		vpninfo->ttls_recvpos = 0;
		ttls = establish_eap_ttls(vpninfo);
		if (!ttls) {
			vpn_progress(vpninfo, PRG_ERR,
				     _("Failed to establish EAP-TTLS session\n"));
			ret = -EINVAL;
			goto out;
		}
		/* Resend the EAP Identity 'anonymous' packet within EAP-TTLS */
		ret = send_eap_packet(vpninfo, ttls, reqbuf);
		if (ret)
			goto out;

		/*
		 * The recv_eap_packet() function receives and validates the EAP
		 * packet of type Extended Juniper-1, either natively or within
		 * EAP-TTLS according to whether 'ttls' is set.
		 */
		eap = recv_eap_packet(vpninfo, ttls, bytes, sizeof(bytes));
		if (!eap) {
			ret = -EIO;
			goto out;
		}
	}

	/* Now we (hopefully) have the server information packet, in an EAP request
	 * from the server. Either it was received directly in IF-T/TLS, or within
	 * an EAP-Message within EAP-TTLS. Either way, the EAP message we're
	 * interested in will be at offset 0x14 in the packet, its header will
	 * have been checked, and is Expanded Juniper/1, and its payload thus
	 * starts at 0x20. And its length is sufficient that we won't underflow */
	eap_ident = eap[1];
	l = load_be16(eap + 2) - 0x0c; /* Already validated */
	p = eap + 0x0c;

	/* We don't actually use anything we get here. Typically it
	 * contains Juniper/0xd49 and Juniper/0xd4a word AVPs, and
	 * a Juniper/0xd56 AVP with server licensing information. */
	while (l) {
		if (parse_avp(vpninfo, &p, &l, &avp_p, &avp_len, &avp_flags,
			      &avp_vendor, &avp_code)) {
			vpn_progress(vpninfo, PRG_ERR,
				     _("Failed to parse AVP\n"));
		bad_eap:
			dump_buf_hex(vpninfo, PRG_ERR, 'E', eap, load_be16(eap + 2));
			ret = -EINVAL;
			goto out;
		}
		dump_avp(vpninfo, avp_flags, avp_vendor, avp_code, avp_p, avp_len);
	}

	/* Present the client information and auth cookie */
	buf_truncate(reqbuf);
	buf_append_ift_hdr(reqbuf, VENDOR_TCG, IFT_CLIENT_AUTH_RESPONSE);
	buf_append_be32(reqbuf, JUNIPER_1); /* IF-T/TLS Auth Type */
	eap_ofs = buf_append_eap_hdr(reqbuf, EAP_RESPONSE, eap_ident, EAP_TYPE_EXPANDED, 1);
	/* Their client sends a lot of other stuff here, which we don't
	 * understand and which doesn't appear to be mandatory. So leave
	 * it out for now until/unless it becomes necessary. */
	buf_append_avp_string(reqbuf, 0xd70, vpninfo->useragent);
	if (vpninfo->cookie)
		buf_append_avp_string(reqbuf, 0xd53, vpninfo->cookie);
	buf_fill_eap_len(reqbuf, eap_ofs);
	ret = send_eap_packet(vpninfo, ttls, reqbuf);
	if (ret)
		goto out;


	/* Await start of auth negotiations */
 auth_response:
	realm_entry = realms_found = j2_found = old_sessions = 0;
	eap = recv_eap_packet(vpninfo, ttls, (void *)bytes, sizeof(bytes));
	if (!eap) {
		ret = -EIO;
		goto out;
	}

	eap_ident = eap[1];
	l = load_be16(eap + 2) - 0x0c; /* Already validated */
	p = eap + 0x0c;

	while (l) {
		if (parse_avp(vpninfo, &p, &l, &avp_p, &avp_len, &avp_flags,
			      &avp_vendor, &avp_code)) {
			vpn_progress(vpninfo, PRG_ERR,
				     _("Failed to parse AVP\n"));
			goto bad_eap;
		}
		dump_avp(vpninfo, avp_flags, avp_vendor, avp_code, avp_p, avp_len);

		/* It's a bit late for this given that we don't get it until after
		 * we provide the password. */
		if (avp_vendor == VENDOR_JUNIPER2 && avp_code == 0xd55) {
			char md5buf[MD5_SIZE * 2 + 1];
			get_cert_md5_fingerprint(vpninfo, vpninfo->peer_cert, md5buf);
			if (avp_len != MD5_SIZE * 2 || strncasecmp(avp_p, md5buf, MD5_SIZE * 2)) {
				vpn_progress(vpninfo, PRG_ERR,
					     _("Server certificate mismatch. Aborting due to suspected MITM attack\n"));
				ret = -EPERM;
				goto out;
			}
		}
		if (avp_vendor == VENDOR_JUNIPER2 && avp_code == 0xd65) {
			old_sessions++;
		} else if (avp_vendor == VENDOR_JUNIPER2 && avp_code == 0xd80) {
			free(user_prompt);
			user_prompt = strndup(avp_p, avp_len);
		} else if (avp_vendor == VENDOR_JUNIPER2 && avp_code == 0xd81) {
			free(pass_prompt);
			pass_prompt = strndup(avp_p, avp_len);
		} else if (avp_vendor == VENDOR_JUNIPER2 && avp_code == 0xd4e) {
			realms_found++;
		} else if (avp_vendor == VENDOR_JUNIPER2 && avp_code == 0xd4f) {
			realm_entry++;
		} else if (avp_vendor == VENDOR_JUNIPER2 && avp_code == 0xd53) {
			free(vpninfo->cookie);
			vpninfo->cookie = strndup(avp_p, avp_len);
			cookie_found = 1;
		} else if (!avp_vendor && avp_code == AVP_CODE_EAP_MESSAGE) {
			char *avp_c = avp_p;

			/* EAP within AVP within EAP within IF-T/TLS.
			 * The only thing we understand here is another form of Expanded EAP,
			 * this time with the type Juniper/2. */
			if (avp_len != 13 || avp_c[0] != EAP_REQUEST ||
			    load_be16(avp_c + 2) != avp_len ||
			    load_be32(avp_c + 4) != EXPANDED_JUNIPER ||
			    load_be32(avp_c + 8) != 2)
				goto auth_unknown;

			j2_found = 1;
			j2_code = avp_c[12];
			eap2_ident = avp_c[1];
		} else if (avp_flags & AVP_MANDATORY)
			goto auth_unknown;
	}

	/* We want it to be precisely one type of request, not a mixture. */
	if (realm_entry + !!realms_found + j2_found + cookie_found + !!old_sessions != 1) {
	auth_unknown:
		vpn_progress(vpninfo, PRG_ERR,
			     _("Unhandled Pulse authenticationb packet, or authentication failure\n"));
		goto bad_eap;
	}

	/* Prepare next response packet */
	buf_truncate(reqbuf);
	buf_append_ift_hdr(reqbuf, VENDOR_TCG, IFT_CLIENT_AUTH_RESPONSE);
	buf_append_be32(reqbuf, JUNIPER_1); /* IF-T/TLS Auth Type */
	eap_ofs = buf_append_eap_hdr(reqbuf, EAP_RESPONSE, eap_ident, EAP_TYPE_EXPANDED, 1);

	if (!cookie_found) {

		/* No user interaction when called from pulse_connect().
		 * We expect the cookie to work. */
		if (connecting) {
			vpn_progress(vpninfo, PRG_ERR,
				     _("Pulse authentication cookie not accepted\n"));
			ret = -EPERM;
			goto out;
		}

		if (realm_entry) {
			vpn_progress(vpninfo, PRG_TRACE, _("Pulse realm entry\n"));

			ret = pulse_request_realm_entry(vpninfo, reqbuf);
			if (ret)
				goto out;
		} else if (realms_found) {
			vpn_progress(vpninfo, PRG_TRACE, _("Pulse realm choice\n"));

			ret = pulse_request_realm_choice(vpninfo, reqbuf, realms_found, eap);
			if (ret)
				goto out;
		} else if (j2_found) {
			vpn_progress(vpninfo, PRG_TRACE,
				     _("Pulse password auth request, code 0x%02x\n"),
				     j2_code);

			/* Present user/password form to user */
			ret = pulse_request_user_auth(vpninfo, reqbuf, eap2_ident,
						      user_prompt, pass_prompt);
			if (ret)
				goto out;
		} else if (old_sessions) {
			vpn_progress(vpninfo, PRG_TRACE,
				     _("Pulse session limit, %d sessions\n"),
				     old_sessions);
			ret = pulse_request_session_kill(vpninfo, reqbuf, old_sessions, eap);
			if (ret)
				goto out;
		} else {
			vpn_progress(vpninfo, PRG_ERR,
				     _("Unhandled Pulse auth request\n"));
			goto bad_eap;
		}

		/* If we get here, something has filled in the next response */
		buf_fill_eap_len(reqbuf, eap_ofs);
		ret = send_eap_packet(vpninfo, ttls, reqbuf);
		if (ret)
			goto out;

		goto auth_response;
	}

	/* We're done, but need to send an empty response to the above information
	 * in order that the EAP session can complete with 'success'. Not quite
	 * sure why they didn't send it as payload on the success frame, mind you. */
	buf_fill_eap_len(reqbuf, eap_ofs);
	ret = send_eap_packet(vpninfo, ttls, reqbuf);
	if (ret)
		goto out;

	if (ttls) {
		/* Normally we don't actually send the EAP-TTLS frame until
		 * we're waiting for a response, which allows us to coalesce.
		 * This time, we need to flush the outbound frames. The empty
		 * EAP response (within EAP-TTLS) causes the server to close
		 * the EAP-TTLS session and the next response is plain IF-T/TLS
		 * IFT_CLIENT_AUTH_SUCCESS just like the non-certificate mode. */
		pulse_eap_ttls_recv(vpninfo, NULL, 0);
	}

	ret = recv_ift_packet(vpninfo, (void *)bytes, sizeof(bytes));
	if (ret < 0)
		goto out;

	if (!valid_ift_success(bytes, ret)) {
		vpn_progress(vpninfo, PRG_ERR,
			     _("Unexpected response instead of IF-T/TLS auth success:\n"));
		dump_buf_hex(vpninfo, PRG_ERR, '<', (void *)bytes, ret);
		ret = -EINVAL;
		goto out;
	}

	ret = 0;
 out:
	if (ret)
		openconnect_close_https(vpninfo, 0);

	buf_free(reqbuf);
	if (ttls)
		destroy_eap_ttls(vpninfo, ttls);
	buf_free(vpninfo->ttls_pushbuf);
	vpninfo->ttls_pushbuf = NULL;
	free(vpninfo->ttls_recvbuf);
	vpninfo->ttls_recvbuf = NULL;
	free(user_prompt);
	free(pass_prompt);
	return ret;
}

int pulse_eap_ttls_send(struct openconnect_info *vpninfo, const void *data, int len)
{
	struct oc_text_buf *buf = vpninfo->ttls_pushbuf;

	if (!buf) {
		buf = vpninfo->ttls_pushbuf = buf_alloc();
		if (!buf)
			return -ENOMEM;
	}

	/* We concatenate sent data into a single EAP-TTLS frame which is
	 * sent just before we actually need to read something. */
	if (!buf->pos) {
		buf_append_ift_hdr(buf, VENDOR_TCG, IFT_CLIENT_AUTH_RESPONSE);
		buf_append_be32(buf, JUNIPER_1); /* IF-T/TLS Auth Type */
		buf_append_eap_hdr(buf, EAP_RESPONSE, vpninfo->ttls_eap_ident,
				   EAP_TYPE_TTLS, 0);
		/* Flags byte for EAP-TTLS */
		buf_append_bytes(buf, "\0", 1);
	}
	buf_append_bytes(buf, data, len);
	return len;
}

int pulse_eap_ttls_recv(struct openconnect_info *vpninfo, void *data, int len)
{
	struct oc_text_buf *pushbuf= vpninfo->ttls_pushbuf;
	int ret;

	if (!vpninfo->ttls_recvlen) {
		uint8_t flags;

		if (pushbuf && !buf_error(pushbuf) && pushbuf->pos) {
			buf_fill_eap_len(pushbuf, 0x14);
			ret = send_ift_packet(vpninfo, pushbuf);
			if (ret)
				return ret;
			buf_truncate(pushbuf);
		} /* else send a continue? */
		if (!len)
			return 0;

		vpninfo->ttls_recvlen = vpninfo->ssl_read(vpninfo, (void *)vpninfo->ttls_recvbuf,
							  16384);
		if (vpninfo->ttls_recvlen > 0 && vpninfo->dump_http_traffic) {
			vpn_progress(vpninfo, PRG_TRACE,
				     _("Read %d bytes of IF-T/TLS EAP-TTLS record\n"),
				     vpninfo->ttls_recvlen);
			dump_buf_hex(vpninfo, PRG_TRACE, '<',
				     (void *)vpninfo->ttls_recvbuf,
				     vpninfo->ttls_recvlen);
		}
		if (!valid_ift_auth_eap(vpninfo->ttls_recvbuf, vpninfo->ttls_recvlen) ||
		    vpninfo->ttls_recvlen < 0x1a ||
		    vpninfo->ttls_recvbuf[0x18] != EAP_TYPE_TTLS) {
		bad_pkt:
			vpn_progress(vpninfo, PRG_ERR,
				     _("Bad EAP-TTLS packet\n"));
			return -EIO;
		}
		vpninfo->ttls_eap_ident = vpninfo->ttls_recvbuf[0x15];
		flags = vpninfo->ttls_recvbuf[0x19];
		if (flags & 0x7f)
			goto bad_pkt;
		if (flags & 0x80) {
			/* Length bit. */
			if (vpninfo->ttls_recvlen < 0x1e ||
			    load_be32(vpninfo->ttls_recvbuf + 0x1a) != vpninfo->ttls_recvlen - 0x1e)
				goto bad_pkt;
			vpninfo->ttls_recvpos = 0x1e;
			vpninfo->ttls_recvlen -= 0x1e;
		} else {
			vpninfo->ttls_recvpos = 0x1a;
			vpninfo->ttls_recvlen -= 0x1a;
		}
	}

	if (len > vpninfo->ttls_recvlen) {
		memcpy(data, vpninfo->ttls_recvbuf + vpninfo->ttls_recvpos,
		       vpninfo->ttls_recvlen);
		len = vpninfo->ttls_recvlen;
		vpninfo->ttls_recvlen = 0;
		return len;
	}
	memcpy(data, vpninfo->ttls_recvbuf + vpninfo->ttls_recvpos, len);
	vpninfo->ttls_recvpos += len;
	vpninfo->ttls_recvlen -= len;
	return len;

}

int pulse_obtain_cookie(struct openconnect_info *vpninfo)
{
	return pulse_authenticate(vpninfo, 0);
}

int pulse_connect(struct openconnect_info *vpninfo)
{
	unsigned char bytes[16384];
	int ret = 0, l;
	unsigned char *p;
	int routes_len = 0;

	/* If we already have a channel open, it's because we have just
	 * successfully authenticated on it from pulse_obtain_cookie(). */
	if (vpninfo->ssl_fd == -1) {
		ret = pulse_authenticate(vpninfo, 1);
		if (ret)
			return ret;
	}

	ret = recv_ift_packet(vpninfo, (void *)bytes, sizeof(bytes));
	if (ret < 0)
		return ret;


	/* Example config packet:

	   < 0000: 00 00 0a 4c 00 00 00 01  00 00 01 80 00 00 01 fb  |...L............|
	   < 0010: 00 00 00 00 00 00 00 00  00 00 00 00 00 00 00 00  |................|
	   < 0020: 2c 20 f0 00 00 00 00 00  00 00 01 70 2e 00 00 78  |, .........p...x|
	   < 0030: 07 00 00 00 07 00 00 10  00 00 ff ff 05 05 00 00  |................|
	   < 0040: 05 05 ff ff 07 00 00 10  00 00 ff ff 07 00 00 00  |................|
	   < 0050: 07 00 00 ff 07 00 00 10  00 00 ff ff 08 08 08 08  |................|
	   < 0060: 08 08 08 08 f1 00 00 10  00 00 ff ff 06 06 06 06  |................|
	   < 0070: 06 06 06 07 f1 00 00 10  00 00 ff ff 09 09 09 09  |................|
	   < 0080: 09 09 09 09 f1 00 00 10  00 00 ff ff 0a 0a 0a 0a  |................|
	   < 0090: 0a 0a 0a 0a f1 00 00 10  00 00 ff ff 0b 0b 0b 0b  |................|
	   < 00a0: 0b 0b 0b 0b 00 00 00 dc  03 00 00 00 40 00 00 01  |............@...|
	   < 00b0: 00 40 01 00 01 00 40 1f  00 01 00 40 20 00 01 00  |.@....@....@ ...|
	   < 00c0: 40 21 00 01 00 40 05 00  04 00 00 05 78 00 03 00  |@!...@......x...|
	   < 00d0: 04 08 08 08 08 00 03 00  04 08 08 04 04 40 06 00  |.............@..|
	   < 00e0: 0c 70 73 65 63 75 72 65  2e 6e 65 74 00 40 07 00  |.psecure.net.@..|
	   < 00f0: 04 00 00 00 00 00 04 00  04 01 01 01 01 40 19 00  |.............@..|
	   < 0100: 01 01 40 1a 00 01 00 40  0f 00 02 00 00 40 10 00  |..@....@.....@..|
	   < 0110: 02 00 05 40 11 00 02 00  02 40 12 00 04 00 00 04  |...@.....@......|
	   < 0120: b0 40 13 00 04 00 00 00  00 40 14 00 04 00 00 00  |.@.......@......|
	   < 0130: 01 40 15 00 04 00 00 00  00 40 16 00 02 11 94 40  |.@.......@.....@|
	   < 0140: 17 00 04 00 00 00 0f 40  18 00 04 00 00 00 3c 00  |.......@......<.|
	   < 0150: 01 00 04 0a 14 03 01 00  02 00 04 ff ff ff ff 40  |...............@|
	   < 0160: 0b 00 04 0a c8 c8 c8 40  0c 00 01 00 40 0d 00 01  |.......@....@...|
	   < 0170: 00 40 0e 00 01 00 40 1b  00 01 00 40 1c 00 01 00  |.@....@....@....|

	   It starts as an IF-T/TLS packet of type Juniper/1.

	   Lots of zeroes at the start, and at 0x20 there is a distinctive 0x2c20f000
	   signature which appears to be in all config packets.

	   At 0x28 it has the payload length (0x10 less than the full IF-T length).
	   0x2c is the start of the routing information. The 0x2e byte always
	   seems to be there, and in this example 0x78 is the length of the
	   routing information block. The number of entries is in byte 0x30.
	   In the absence of IPv6 perhaps, the length at 0x2c seems always to be
	   the number of entries (in 0x30) * 0x10 + 8.

	   Routing entries are 0x10 bytes each, starting at 0x34. The ones starting
	   with 0x07 are include, with 0xf1 are exclude. No idea what the following 7
	   bytes 0f 00 00 10 00 00 ff ff mean; perhaps the 0010 is a length? The IP
	   address range is in bytes 8-11 (starting address) and the highest address
	   of the range (traditionally a broadcast address) is in bytes 12-15.

	   After the routing inforamation (in this example at 0xa4) comes another
	   length field, this time for the information elements which comprise
	   the rest of the packet. Not sure what the 03 00 00 00 at 0xa8 means;
	   it *could* be an element type 0x3000 with payload length zero but if it
	   is, we don't know what it means. Following that, the elements all have
	   two bytes of type followed by two bytes length, then their payload.

	   There follows an attempt to parse the packet based on the above
	   understanding. Having more examples, especially with IPv6 split includes
	   and excludes, would be useful...
	*/

	if (ret < 0x50 ||
	    /* IF-T/TLS header */
	    load_be32(bytes) != VENDOR_JUNIPER ||
	    load_be32(bytes + 4) != 1 ||
	    load_be32(bytes + 8) != ret ||
	    /* This appears to indicate the packet type (vs. ESP config) */
	    load_be32(bytes + 0x20) != 0x2c20f000 ||
	    /* A length field */
	    load_be32(bytes + 0x28) != ret - 0x10 ||
	    /* Start of routing information */
	    load_be16(bytes + 0x2c) != 0x2e00 ||
	    /* Routing length makes sense */
	    (routes_len = load_be16(bytes + 0x2e)) != ((int)bytes[0x30] * 0x10 + 8) ||
	    /* Make sure the next length field is actually present... */
	    ret < 0x34 + 4 + routes_len ||
	    /* Another length field (and maybe some adjacent zeroes) */
	    load_be32(bytes + 0x2c + routes_len) + routes_len + 0x2c != ret) {
	bad_config:
		vpn_progress(vpninfo, PRG_ERR,
			     _("Unexpected Pulse config packet:\n"));
		dump_buf_hex(vpninfo, PRG_ERR, '<', (void *)bytes, ret);
		return -EINVAL;
	}
	p = bytes + 0x34;
	routes_len -= 8;
	/* We know it's a multiple of 0x10 now. We checked. */
	while (routes_len) {
		char buf[80];
		/* Probably not a whole be32 but let's see if anything ever changes */
		uint32_t type = load_be32(p);
		uint32_t ffff = load_be32(p+4);

		if (ffff != 0xffff)
			goto bad_config;

		/* Convert the range end into a netmask by xor. Mask out the
		 * bits in the network address, leaving only the low bits set,
		 * then invert what's left so that only the high bits are set
		 * as in a normal netmask.
		 *
		 * e.g.
		 * 10.0.0.0-10.0.63.255 becomes 0.0.63.255 becomes 255.255.192.0
		*/
		snprintf(buf, sizeof(buf), "%d.%d.%d.%d/%d.%d.%d.%d",
			 p[8], p[9], p[10], p[11],
			 255 ^ (p[8] ^ p[12]),  255 ^ (p[9] ^ p[13]),
			 255 ^ (p[10] ^ p[14]),  255 ^ (p[11] ^ p[15]));

		if (type == 0x07000010) {
			struct oc_split_include *inc;

			vpn_progress(vpninfo, PRG_DEBUG, _("Received split include route %s\n"), buf);
			inc = malloc(sizeof(*inc));
			if (inc) {
				inc->route = add_option(vpninfo, "split-include", buf, -1);
				if (inc->route) {
					inc->next = vpninfo->ip_info.split_includes;
					vpninfo->ip_info.split_includes = inc;
				} else
					free(inc);
			}
		} else if (type == 0xf1000010) {
			struct oc_split_include *exc;

			vpn_progress(vpninfo, PRG_DEBUG, _("Received split exclude route %s\n"), buf);
			exc = malloc(sizeof(*exc));
			if (exc) {
				exc->route = add_option(vpninfo, "split-exclude", buf, -1);
				if (exc->route) {
					exc->next = vpninfo->ip_info.split_excludes;
					vpninfo->ip_info.split_excludes = exc;
				} else
					free(exc);
			}
		} else
			goto bad_config;

		p += 0x10;
		routes_len -= 0x10;
	}

	/* p now points at the length field of the final elements, which
	   was already checked. */
	l = load_be32(p);
	/* No idea what this is */
	if (l < 8 || load_be32(p + 4) != 0x03000000)
		goto bad_config;
	p += 8;
	l -= 8;

	while (l) {
		uint16_t type = load_be16(p);
		uint16_t len = load_be16(p+2);

		if (len + 4 > l)
			goto bad_config;

		p += 4;
		l -= 4;
		process_attr(vpninfo, type, p, len);
		p += len;
		l -= len;
		if (l && l < 4)
			goto bad_config;
	}

	if (!vpninfo->ip_info.mtu ||
	    (!vpninfo->ip_info.addr && !vpninfo->ip_info.addr6)) {
		vpn_progress(vpninfo, PRG_ERR, "Insufficient configuration found\n");
		goto bad_config;
	}

	ret = 0;
	monitor_fd_new(vpninfo, ssl);
	monitor_read_fd(vpninfo, ssl);
	monitor_except_fd(vpninfo, ssl);

	free(vpninfo->cstp_pkt);
	vpninfo->cstp_pkt = NULL;

	return ret;
}


int pulse_mainloop(struct openconnect_info *vpninfo, int *timeout, int readable)
{
	int ret;
	int work_done = 0;

	if (vpninfo->ssl_fd == -1)
		goto do_reconnect;

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
		int receive_mtu = MAX(16384, vpninfo->deflate_pkt_size ? : vpninfo->ip_info.mtu);
		int len, payload_len;

		if (!vpninfo->cstp_pkt) {
			vpninfo->cstp_pkt = malloc(sizeof(struct pkt) + receive_mtu);
			if (!vpninfo->cstp_pkt) {
				vpn_progress(vpninfo, PRG_ERR, _("Allocation failed\n"));
				break;
			}
		}

		len = ssl_nonblock_read(vpninfo, &vpninfo->cstp_pkt->pulse.vendor, receive_mtu + 16);
		if (!len)
			break;
		if (len < 0)
			goto do_reconnect;
		if (len < 16) {
			vpn_progress(vpninfo, PRG_ERR, _("Short packet received (%d bytes)\n"), len);
			vpninfo->quit_reason = "Short packet received";
			return 1;
		}

		if (load_be32(&vpninfo->cstp_pkt->pulse.vendor) != VENDOR_JUNIPER ||
		    load_be32(&vpninfo->cstp_pkt->pulse.len) != len)
			goto unknown_pkt;

		vpninfo->ssl_times.last_rx = time(NULL);

		switch(load_be32(&vpninfo->cstp_pkt->pulse.type)) {
		case 4:
			payload_len = len - 16;
			vpn_progress(vpninfo, PRG_TRACE,
				     _("Received data packet of %d bytes\n"),
				     payload_len);
			vpninfo->cstp_pkt->len = payload_len;
			queue_packet(&vpninfo->incoming_queue, vpninfo->cstp_pkt);
			vpninfo->cstp_pkt = NULL;
			work_done = 1;
			continue;

		default:
		unknown_pkt:
			vpn_progress(vpninfo, PRG_ERR,
				     _("Unknown Pulse packet\n"));
			dump_buf_hex(vpninfo, PRG_TRACE, '<', (void *)&vpninfo->cstp_pkt->pulse.vendor, len);
			continue;
		}
	}


	/* If SSL_write() fails we are expected to try again. With exactly
	   the same data, at exactly the same location. So we keep the
	   packet we had before.... */
	if (vpninfo->current_ssl_pkt) {
	handle_outgoing:
		vpninfo->ssl_times.last_tx = time(NULL);
		unmonitor_write_fd(vpninfo, ssl);


		vpn_progress(vpninfo, PRG_TRACE, _("Packet outgoing:\n"));
		dump_buf_hex(vpninfo, PRG_TRACE, '>',
			     (void *)&vpninfo->current_ssl_pkt->pulse.vendor,
			     vpninfo->current_ssl_pkt->len + 16);

		ret = ssl_nonblock_write(vpninfo,
					 &vpninfo->current_ssl_pkt->pulse.vendor,
					 vpninfo->current_ssl_pkt->len + 16);
		if (ret < 0) {
			do_reconnect:
			/* XXX: Do we have to do this or can we leave it open?
			 * Perhaps we could even reconnect asynchronously while
			 * the ESP is still running? */
#ifdef HAVE_ESP
			esp_shutdown(vpninfo);
#endif
			ret = ssl_reconnect(vpninfo);
			if (ret) {
				vpn_progress(vpninfo, PRG_ERR, _("Reconnect failed\n"));
				vpninfo->quit_reason = "Pulse reconnect failed";
				return ret;
			}
			vpninfo->dtls_need_reconnect = 1;
			return 1;
		} else if (!ret) {
#if 0 /* Not for Pulse yet */
			/* -EAGAIN: ssl_nonblock_write() will have added the SSL
			   fd to ->select_wfds if appropriate, so we can just
			   return and wait. Unless it's been stalled for so long
			   that DPD kicks in and we kill the connection. */
			switch (ka_stalled_action(&vpninfo->ssl_times, timeout)) {
			case KA_DPD_DEAD:
				goto peer_dead;
			case KA_REKEY:
				goto do_rekey;
			case KA_NONE:
				return work_done;
			default:
				/* This should never happen */
				;
			}
#else
			return work_done;
#endif
		}

		if (ret != vpninfo->current_ssl_pkt->len + 16) {
			vpn_progress(vpninfo, PRG_ERR,
				     _("SSL wrote too few bytes! Asked for %d, sent %d\n"),
				     vpninfo->current_ssl_pkt->len + 8, ret);
			vpninfo->quit_reason = "Internal error";
			return 1;
		}
		/* Don't free the 'special' packets */
		if (vpninfo->current_ssl_pkt == vpninfo->deflate_pkt) {
			free(vpninfo->pending_deflated_pkt);
			vpninfo->pending_deflated_pkt = NULL;
		} else
			free(vpninfo->current_ssl_pkt);

		vpninfo->current_ssl_pkt = NULL;
	}

#if 0 /* Not understood for Pulse yet */
	if (vpninfo->owe_ssl_dpd_response) {
		vpninfo->owe_ssl_dpd_response = 0;
		vpninfo->current_ssl_pkt = (struct pkt *)&dpd_resp_pkt;
		goto handle_outgoing;
	}

	switch (keepalive_action(&vpninfo->ssl_times, timeout)) {
	case KA_REKEY:
	do_rekey:
		/* Not that this will ever happen; we don't even process
		   the setting when we're asked for it. */
		vpn_progress(vpninfo, PRG_INFO, _("CSTP rekey due\n"));
		if (vpninfo->ssl_times.rekey_method == REKEY_TUNNEL)
			goto do_reconnect;
		else if (vpninfo->ssl_times.rekey_method == REKEY_SSL) {
			ret = cstp_handshake(vpninfo, 0);
			if (ret) {
				/* if we failed rehandshake try establishing a new-tunnel instead of failing */
				vpn_progress(vpninfo, PRG_ERR, _("Rehandshake failed; attempting new-tunnel\n"));
				goto do_reconnect;
			}

			goto do_dtls_reconnect;
		}
		break;

	case KA_DPD_DEAD:
	peer_dead:
		vpn_progress(vpninfo, PRG_ERR,
			     _("CSTP Dead Peer Detection detected dead peer!\n"));
		goto do_reconnect;
	do_reconnect:
		ret = cstp_reconnect(vpninfo);
		if (ret) {
			vpn_progress(vpninfo, PRG_ERR, _("Reconnect failed\n"));
			vpninfo->quit_reason = "CSTP reconnect failed";
			return ret;
		}

	do_dtls_reconnect:
		/* succeeded, let's rekey DTLS, if it is not rekeying
		 * itself. */
		if (vpninfo->dtls_state > DTLS_SLEEPING &&
		    vpninfo->dtls_times.rekey_method == REKEY_NONE) {
			vpninfo->dtls_need_reconnect = 1;
		}

		return 1;

	case KA_DPD:
		vpn_progress(vpninfo, PRG_DEBUG, _("Send CSTP DPD\n"));

		vpninfo->current_ssl_pkt = (struct pkt *)&dpd_pkt;
		goto handle_outgoing;

	case KA_KEEPALIVE:
		/* No need to send an explicit keepalive
		   if we have real data to send */
		if (vpninfo->dtls_state != DTLS_CONNECTED &&
		    vpninfo->outgoing_queue.head)
			break;

		vpn_progress(vpninfo, PRG_DEBUG, _("Send CSTP Keepalive\n"));

		vpninfo->current_ssl_pkt = (struct pkt *)&keepalive_pkt;
		goto handle_outgoing;

	case KA_NONE:
		;
	}
#endif
	/* Service outgoing packet queue, if no DTLS */
	while (vpninfo->dtls_state != DTLS_CONNECTED &&
	       (vpninfo->current_ssl_pkt = dequeue_packet(&vpninfo->outgoing_queue))) {
		struct pkt *this = vpninfo->current_ssl_pkt;

		store_be32(&this->pulse.vendor, VENDOR_JUNIPER);
		store_be32(&this->pulse.type, 4);
		store_be32(&this->pulse.len, this->len + 16);
		store_be32(&this->pulse.ident, vpninfo->ift_seq++);

		vpn_progress(vpninfo, PRG_TRACE,
			     _("Sending IF-T/TLS data packet of %d bytes\n"),
			     this->len);

		vpninfo->current_ssl_pkt = this;
		goto handle_outgoing;
	}

	/* Work is not done if we just got rid of packets off the queue */
	return work_done;
}

int pulse_bye(struct openconnect_info *vpninfo, const char *reason)
{
	if (vpninfo->ssl_fd != -1) {
		struct oc_text_buf *buf = buf_alloc();
		buf_append_ift_hdr(buf, VENDOR_JUNIPER, 0x89);
		if (!buf_error(buf))
			send_ift_packet(vpninfo, buf);
		buf_free(buf);

		openconnect_close_https(vpninfo, 0);
	}
	return 0;
}

#ifdef HAVE_ESPx
void pulse_esp_close(struct openconnect_info *vpninfo)
{
	/* Tell server to stop sending on ESP channel */
	queue_esp_control(vpninfo, 0);
	esp_close(vpninfo);
}

int pulse_esp_send_probes(struct openconnect_info *vpninfo)
{
	struct pkt *pkt;
	int pktlen, seq;

	if (vpninfo->dtls_fd == -1) {
		int fd = udp_connect(vpninfo);
		if (fd < 0)
			return fd;

		/* We are not connected until we get an ESP packet back */
		vpninfo->dtls_state = DTLS_SLEEPING;
		vpninfo->dtls_fd = fd;
		monitor_fd_new(vpninfo, dtls);
		monitor_read_fd(vpninfo, dtls);
		monitor_except_fd(vpninfo, dtls);
	}

	pkt = malloc(sizeof(*pkt) + 1 + vpninfo->pkt_trailer);
	if (!pkt)
		return -ENOMEM;

	for (seq=1; seq <= (vpninfo->dtls_state==DTLS_CONNECTED ? 1 : 2); seq++) {
		pkt->len = 1;
		pkt->data[0] = 0;
		pktlen = encrypt_esp_packet(vpninfo, pkt);
		if (pktlen >= 0)
			send(vpninfo->dtls_fd, (void *)&pkt->esp, pktlen, 0);
	}
	free(pkt);

	vpninfo->dtls_times.last_tx = time(&vpninfo->new_dtls_started);

	return 0;
};

int pulse_esp_catch_probe(struct openconnect_info *vpninfo, struct pkt *pkt)
{
	return (pkt->len == 1 && pkt->data[0] == 0);
}
#endif /* HAVE_ESP */
