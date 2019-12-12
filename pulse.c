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
#define EAP_TYPE_GTC 6
#define EAP_TYPE_TLS 0x0d
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

/* Flags for prompt handling during authentication, based on the contents of the 0xd73 AVP (qv). */
#define PROMPT_PRIMARY		1
#define PROMPT_USERNAME		2
#define PROMPT_PASSWORD		4
#define PROMPT_GTC_NEXT		0x10000

/* Request codes for the Juniper Expanded/2 auth requests. */
#define J2_PASSCHANGE	0x43
#define J2_PASSREQ	0x01
#define J2_PASSRETRY	0x81
#define J2_PASSFAIL	0xc5

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

static void buf_append_avp_be32(struct oc_text_buf *buf, uint32_t type, uint32_t val)
{
	uint32_t val_be;

	store_be32(&val_be, val);
	buf_append_avp(buf, type, &val_be, sizeof(val_be));
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
	struct oc_split_include *xc;
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
		vpninfo->ip_info.addr6 = add_option(vpninfo, "ip6addr", buf, -1);

		i = strlen(buf);
		snprintf(buf + i, sizeof(buf) - i, "/%d", data[16]);
		vpninfo->ip_info.netmask6 = add_option(vpninfo, "ip6netmask", buf, -1);

		vpn_progress(vpninfo, PRG_DEBUG, _("Received internal IPv6 address %s\n"), buf);
		break;

	case 0x000a:
		if (attrlen != 16)
			goto badlen;
		if (!inet_ntop(AF_INET6, data, buf, sizeof(buf))) {
			vpn_progress(vpninfo, PRG_ERR,
				     _("Failed to handle IPv6 address\n"));
			return -EINVAL;
		}

		for (i = 0; i < 3; i++) {
			if (!vpninfo->ip_info.dns[i]) {
				vpninfo->ip_info.dns[i] = add_option(vpninfo, "DNS", buf, -1);
				break;
			}
		}

		vpn_progress(vpninfo, PRG_DEBUG, _("Received DNS server %s\n"), buf);
		break;

	case 0x000f:
		if (attrlen != 17)
			goto badlen;
		if (!inet_ntop(AF_INET6, data, buf, sizeof(buf))) {
			vpn_progress(vpninfo, PRG_ERR,
				     _("Failed to handle IPv6 address\n"));
			return -EINVAL;
		}
		i = strlen(buf);
		snprintf(buf + i, sizeof(buf) - i, "/%d", data[16]);

		xc = malloc(sizeof(*xc));
		if (xc) {
			xc->route =  add_option(vpninfo, "split-include6", buf, -1);
			if (xc->route) {
				xc->next = vpninfo->ip_info.split_includes;
				vpninfo->ip_info.split_includes = xc;
			} else
				free(xc);
		}
		vpn_progress(vpninfo, PRG_DEBUG, _("Received IPv6 split include %s\n"), buf);
		break;

	case 0x0010:
		if (attrlen != 17)
			goto badlen;
		if (!inet_ntop(AF_INET6, data, buf, sizeof(buf))) {
			vpn_progress(vpninfo, PRG_ERR,
				     _("Failed to handle IPv6 address\n"));
			return -EINVAL;
		}
		i = strlen(buf);
		snprintf(buf + i, sizeof(buf) - i, "/%d", data[16]);

		xc = malloc(sizeof(*xc));
		if (xc) {
			xc->route =  add_option(vpninfo, "split-exclude6", buf, -1);
			if (xc->route) {
				xc->next = vpninfo->ip_info.split_excludes;
				vpninfo->ip_info.split_excludes = xc;
			} else
				free(xc);
		}
		vpn_progress(vpninfo, PRG_DEBUG, _("Received IPv6 split exclude %s\n"), buf);
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

static int send_ift_bytes(struct openconnect_info *vpninfo, void *bytes, int len)
{
	int ret;

	store_be32(((char *)bytes) + 12, vpninfo->ift_seq++);

	dump_buf_hex(vpninfo, PRG_DEBUG, '>', (void *)bytes, len);
	ret = vpninfo->ssl_write(vpninfo, bytes, len);
	if (ret != len) {
		if (ret >= 0) {
			vpn_progress(vpninfo, PRG_ERR,
				     _("Short write to IF-T/TLS\n"));
			ret = -EIO;
		}
		return ret;
	}
	return 0;

}

static int send_ift_packet(struct openconnect_info *vpninfo, struct oc_text_buf *buf)
{
	if (buf_error(buf) || buf->pos < 16) {
		vpn_progress(vpninfo, PRG_ERR,
			     _("Error creating IF-T packet\n"));
		return buf_error(buf);
	}

	/* Fill in the length word in the header with the full length of the buffer.
	 * Also populate the sequence number. */
	store_be32(buf->data + 8, buf->pos);

	return send_ift_bytes(vpninfo, buf->data, buf->pos);
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
	if (!o.choices) {
		ret = -ENOMEM;
		goto out;
	}

	while (l) {
		char *from = NULL;
		time_t when = 0;
		char *sessid = NULL;

		if (parse_avp(vpninfo, &p, &l, &avp_p, &avp_len, &avp_flags,
			      &avp_vendor, &avp_code)) {
		badlist:
			free(from);
			free(sessid);
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
				free(sessid);
				sessid = strndup(avp_p2, avp_len2);
			} else if (avp_vendor == VENDOR_JUNIPER2 && avp_code == 0xd67) {
				free(from);
				from = strndup(avp_p2, avp_len2);
			} else if (avp_vendor == VENDOR_JUNIPER2 && avp_code == 0xd68 &&
				   avp_len2 == 8) {
				when = load_be32((char *)avp_p2 + 4);
				if (sizeof(time_t) > 4)
					when |= ((uint64_t)load_be32(avp_p2)) << 32;
			}
		}

		if (!from || !sessid || !when)
			goto badlist;

		if (0
#ifdef HAVE_LOCALTIME_S
		    || !localtime_s(&tm, &when)
#endif
#ifdef HAVE_LOCALTIME_R
		    || localtime_r(&when, &tm)
#endif
		    ) {
			strftime(tmbuf, sizeof(tmbuf), "%a, %d %b %Y %H:%M:%S %Z", &tm);
		} else
			snprintf(tmbuf, sizeof(tmbuf), "@%lu", (unsigned long)when);

		buf_append(form_msg, " - %s from %s at %s\n", sessid, from, tmbuf);

		free(from);
		from = NULL;

		o.choices[i] = malloc(sizeof(struct oc_choice));
		if (!o.choices[i]) {
			free(sessid);
			ret = -ENOMEM;
			goto out;
		}
		o.choices[i]->name = o.choices[i]->label = sessid;
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
				   uint8_t eap_ident, int prompt_flags, char *user_prompt, char *pass_prompt)
{
	struct oc_auth_form f;
	struct oc_form_opt o[2];
	unsigned char eap_avp[23];
	int l;
	int ret;

	memset(&f, 0, sizeof(f));
	memset(o, 0, sizeof(o));
	f.auth_id = (char *) ((prompt_flags & PROMPT_PRIMARY) ? "pulse_user" : "pulse_secondary");
	f.opts = &o[1]; /* Point to password prompt in case that's all we use */

	f.message = (prompt_flags & PROMPT_PRIMARY) ? _("Enter user credentials:") : _("Enter secondary credentials:");

	if (prompt_flags & PROMPT_USERNAME) {
		f.opts = &o[0];
		o[0].next = NULL; /* Again, for now */
		o[0].type = OC_FORM_OPT_TEXT;
		o[0].name = (char *)"username";
		if (user_prompt)
			o[0].label = user_prompt;
		else
			o[0].label = (char *) ((prompt_flags & PROMPT_PRIMARY) ? _("Username:") : _("Secondary username:"));
	}
	if (prompt_flags & PROMPT_PASSWORD) {
		/* Might be referenced from o[0] or directly from f.opts */
		o[0].next = &o[1];
		o[1].type = OC_FORM_OPT_PASSWORD;
		o[1].name = (char *)"password";
		if (pass_prompt)
			o[1].label = pass_prompt;
		else
			o[1].label = (char *) ((prompt_flags & PROMPT_PRIMARY) ? _("Password:") : _("Secondary password:"));
	}

	ret = process_auth_form(vpninfo, &f);
	if (ret)
		goto out;

	if (o[0]._value) {
		buf_append_avp_string(reqbuf, 0xd6d, o[0]._value);
		free_pass(&o[0]._value);
	}
	if (o[1]._value) {
		l = strlen(o[1]._value);
		if (l > 253) {
			free_pass(&o[1]._value);
			return -EINVAL;
		}
	} else {
		/* Their client actually resubmits the primary password when
		 * a secondary password is requested. But it doesn't seem to
		 * be necessary; might even just be a bug. */
		l = 0;
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
	if (o[1]._value) {
		buf_append_bytes(reqbuf, o[1]._value, l);
		free_pass(&o[1]._value);
	}

	/* Padding */
	if ((sizeof(eap_avp) + l) & 3) {
		uint32_t pad = 0;

		buf_append_bytes(reqbuf, &pad,
				 4 - ((sizeof(eap_avp) + l) & 3));
	}

	ret = 0;
 out:
	return ret;
}

static int pulse_request_pass_change(struct openconnect_info *vpninfo, struct oc_text_buf *reqbuf,
				     uint8_t eap_ident, int prompt_flags)
{
	struct oc_auth_form f;
	struct oc_form_opt o[3];
	unsigned char eap_avp[23];
	int l1, l2;
	int ret;

	memset(&f, 0, sizeof(f));
	memset(o, 0, sizeof(o));
	f.auth_id = (char *) ((prompt_flags & PROMPT_PRIMARY) ? "pulse_user_change" : "pulse_secondary_change");
	f.opts = &o[0];

	f.message = _("Password expired. Please change password:");

	o[0].type = OC_FORM_OPT_PASSWORD;
	o[0].name = (char *)"oldpass";
	o[0].label = (char *) _("Current password:");
	o[0].next = &o[1];

	o[1].type = OC_FORM_OPT_PASSWORD;
	o[1].name = (char *)"newpass1";
	o[1].label = (char *) _("New password:");
	o[1].next = &o[2];

	o[2].type = OC_FORM_OPT_PASSWORD;
	o[2].name = (char *)"newpass1";
	o[2].label = (char *) _("Verify new password:");

 retry:
	free_pass(&o[0]._value);
	free_pass(&o[1]._value);
	free_pass(&o[2]._value);

	ret = process_auth_form(vpninfo, &f);
	if (ret)
		goto out;

	if (!o[0]._value || !o[1]._value || !o[2]._value) {
		vpn_progress(vpninfo, PRG_DEBUG, _("Passwords not provided.\n"));
		ret = -EINVAL;
		goto out;
	}

	if (strcmp(o[1]._value, o[2]._value)) {
		vpn_progress(vpninfo, PRG_ERR, _("Passwords do not match.\n"));
		goto retry;
	}
	l1 = strlen(o[0]._value);
	if (l1 > 253) {
		vpn_progress(vpninfo, PRG_ERR, _("Current password too long.\n"));
		goto retry;
	}
	l2 = strlen(o[1]._value);
	if (l2 > 253) {
		vpn_progress(vpninfo, PRG_ERR, _("New password too long.\n"));
		goto retry;
	}

	/* AVP flags+mandatory+length */
	store_be32(eap_avp, AVP_CODE_EAP_MESSAGE);
	store_be32(eap_avp + 4, (AVP_MANDATORY << 24) + sizeof(eap_avp) + l1 + 2 + l2);

	/* EAP header: code/ident/len */
	eap_avp[8] = EAP_RESPONSE;
	eap_avp[9] = eap_ident;
	store_be16(eap_avp + 10, l1 + l2 + 17); /* EAP length */
	store_be32(eap_avp + 12, EXPANDED_JUNIPER);
	store_be32(eap_avp + 16, 2);

	/* EAP Juniper/2 payload: 02 02 <len> <password> */
	eap_avp[20] = eap_avp[21] = 0x02;
	eap_avp[22] = l1 + 2; /* Why 2? */
	buf_append_bytes(reqbuf, eap_avp, sizeof(eap_avp));
	buf_append_bytes(reqbuf, o[0]._value, l1);

	/* Reuse eap_avp to append the new password */
	eap_avp[0] = 0x03;
	eap_avp[1] = l2 + 2;
	buf_append_bytes(reqbuf, eap_avp, 2);
	buf_append_bytes(reqbuf, o[1]._value, l2);

	/* Padding */
	if ((sizeof(eap_avp) + l1 + 2 + l2) & 3) {
		uint32_t pad = 0;

		buf_append_bytes(reqbuf, &pad,
				 4 - ((sizeof(eap_avp) + l1 + 2 + l2) & 3));
	}

	ret = 0;
 out:
	free_pass(&o[0]._value);
	free_pass(&o[1]._value);
	free_pass(&o[2]._value);
	return ret;
}

static int pulse_request_gtc(struct openconnect_info *vpninfo, struct oc_text_buf *reqbuf,
			     uint8_t eap_ident, int prompt_flags, char *user_prompt, char *pass_prompt,
			     char *gtc_prompt)
{
	struct oc_auth_form f;
	struct oc_form_opt o[2];
	int ret;

	memset(&f, 0, sizeof(f));
	memset(o, 0, sizeof(o));
	f.auth_id = (char *)"pulse_gtc";

	/* The first prompt always seems to be 'Enter SecurID PASSCODE:' and is ignored. */
	if (gtc_prompt && (prompt_flags & PROMPT_GTC_NEXT))
		f.message = gtc_prompt;
	else
		f.message = _("Token code request:");

	if (prompt_flags & PROMPT_USERNAME) {
		f.opts = &o[0];
		o[0].next = &o[1];
		o[0].type = OC_FORM_OPT_TEXT;
		o[0].name = (char *)"username";
		if (user_prompt)
			o[0].label = user_prompt;
		else
			o[0].label = (char *) ((prompt_flags & PROMPT_PRIMARY) ? _("Username:") : _("Secondary username:"));
	} else {
		f.opts = &o[1];
	}

	o[1].type = OC_FORM_OPT_PASSWORD;
	o[1].name = (char *)"tokencode";

	/*
	 * For retries, we have a gtc_prompt and we just say 'Please enter response:'.
	 * Otherwise, use the pass_prompt if it exists, or create our own based
	 * on whether it's primary authentication or not.
	 */
	if (prompt_flags & PROMPT_GTC_NEXT) {
		o[1].label = _("Please enter response:");
	} else if (pass_prompt) {
		o[1].label = pass_prompt;
	} else if (prompt_flags & PROMPT_PRIMARY) {
		o[1].label = _("Please enter your passcode:");
	} else {
		o[1].label = _("Please enter your secondary token information:");
	}

	if (!can_gen_tokencode(vpninfo, &f, &o[1]))
		o[1].type = OC_FORM_OPT_TOKEN;

	ret = process_auth_form(vpninfo, &f);
	if (ret)
		goto out;

	ret = do_gen_tokencode(vpninfo, &f);
	if (ret)
		goto out;

	if (o[0]._value) {
		buf_append_avp_string(reqbuf, 0xd6d, o[0]._value);
		free_pass(&o[0]._value);
	}
	if (o[1]._value) {
		unsigned char eap_avp[13];
		int l = strlen(o[1]._value);
		if (l > 253) {
			free_pass(&o[1]._value);
			ret = -EINVAL;
			goto out;
		}

		/* AVP flags+mandatory+length */
		store_be32(eap_avp, AVP_CODE_EAP_MESSAGE);
		store_be32(eap_avp + 4, (AVP_MANDATORY << 24) + sizeof(eap_avp) + l);

		/* EAP header: code/ident/len */
		eap_avp[8] = EAP_RESPONSE;
		eap_avp[9] = eap_ident;
		store_be16(eap_avp + 10, l + 5); /* EAP length */
		eap_avp[12] = EAP_TYPE_GTC;
		buf_append_bytes(reqbuf, eap_avp, sizeof(eap_avp));
		buf_append_bytes(reqbuf, o[1]._value, l);

		/* Padding */
		if ((sizeof(eap_avp) + l) & 3) {
			uint32_t pad = 0;

			buf_append_bytes(reqbuf, &pad,
					 4 - ((sizeof(eap_avp) + l) & 3));
		}
		free_pass(&o[1]._value);
	} else {
		ret = -EINVAL;
		goto out;
	}
	ret = 0;
 out:
	return ret;
}

static int dup_prompt(char **p, uint8_t *avp_p, int avp_len)
{
	char *ret = NULL;

	free(*p);
	*p = NULL;

	if (!avp_len) {
		return 0;
	} else if (avp_p[avp_len - 1] == ':') {
		ret = strndup((char *)avp_p, avp_len);
	} else {
		ret = calloc(avp_len + 2, 1);
		if (ret) {
			memcpy(ret, avp_p, avp_len);
			ret[avp_len] = ':';
			ret[avp_len + 1] = 0;
		}
	}

	if (ret) {
		*p = ret;
		return 0;
	} else
		return -ENOMEM;
}

/*
 * There is complex client-side logic around when to (re)prompt for a password.
 * The first prompt always needs it, whether it's a TokenCode request (EAP-06)
 * or a normal password request (EAP-Expanded-Juniper/2). If a password request
 * fails (0x81) then we prompt for username again in case that's what was wrong.
 *
 * If there's a secondary password request, it might need a *secondary* username.
 * The first request comes with a 0xd73 AVP which has a single integer:
 *   1: prompt for both username and password.
 *   3: Prompt for password only.
 *   5: Prompt for username only.
 *
 */

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
	int j2_found = 0, realms_found = 0, realm_entry = 0, old_sessions = 0, gtc_found = 0;
	uint8_t j2_code = 0;
	void *ttls = NULL;
	char *user_prompt = NULL, *pass_prompt = NULL, *gtc_prompt = NULL, *signin_prompt = NULL;
	char *user2_prompt = NULL, *pass2_prompt = NULL;
	int prompt_flags = PROMPT_PRIMARY | PROMPT_USERNAME | PROMPT_PASSWORD;

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

#if 0
	/* Their client sends a lot of other stuff here, which we don't
	 * understand and which doesn't appear to be mandatory. So leave
	 * it out for now until/unless it becomes necessary. It seems that
	 * sending Pulse-Secure/4.0.0.0 or anything newer makes it do
	 * EAP-TLS *within* the EAP-TTLS session if you don't actually
	 * present a certificate. */
	buf_append_avp_be32(reqbuf, 0xd49, 3);
	buf_append_avp_be32(reqbuf, 0xd61, 0);
	buf_append_avp_string(reqbuf, 0xd5e, "Windows");
	buf_append_avp_string(reqbuf, 0xd70, "Pulse-Secure/9.0.3.1667 (Windows Server 2016) Pulse/9.0.3.1667");
	buf_append_avp_string(reqbuf, 0xd63, "\xac\x1e\x8a\x78\x2d\x96\x45\x69\xb7\x7b\x80\x0f\xb7\x39\x2e\x41");
	buf_append_avp_string(reqbuf, 0xd64, "\x1a\x3d\x9f\xa4\x07\xd9\xcb\x40\x9d\x61\x6a\x7a\x89\x24\x9b\x15");
	buf_append_avp_string(reqbuf, 0xd5f, "en-US");
	buf_append_avp_string(reqbuf, 0xd6c, "\x02\xe9\xa7\x51\x92\x4e");
	buf_append_avp_be32(reqbuf, 0xd84, 0);
#else
	buf_append_avp_string(reqbuf, 0xd70, vpninfo->useragent);
#endif
	if (vpninfo->cookie)
		buf_append_avp_string(reqbuf, 0xd53, vpninfo->cookie);
	buf_fill_eap_len(reqbuf, eap_ofs);
	ret = send_eap_packet(vpninfo, ttls, reqbuf);
	if (ret)
		goto out;


	/* Await start of auth negotiations */
 auth_response:
	free(signin_prompt);
	signin_prompt = NULL;

	/* If there's a follow-on GTC prompt, remember it's not the first */
	if (gtc_found)
		prompt_flags |= PROMPT_GTC_NEXT;
	else
		prompt_flags &= ~PROMPT_GTC_NEXT;

	realm_entry = realms_found = j2_found = old_sessions = 0, gtc_found = 0;
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
		} else if (avp_vendor == VENDOR_JUNIPER2 && avp_code == 0xd60) {
			uint32_t failcode;
			if (avp_len != 4)
				goto auth_unknown;

			failcode = load_be32(avp_p);
			if (failcode == 0x0d) {
				vpn_progress(vpninfo, PRG_ERR,
					     _("Authentication failure: Account locked out\n"));
			} else {
				vpn_progress(vpninfo, PRG_ERR,
					     _("Authentication failure: Code 0x%02x\n"),
					       failcode);
			}
			ret = -EPERM;
			goto out;
		} else if (avp_vendor == VENDOR_JUNIPER2 && avp_code == 0xd80) {
			dup_prompt(&user_prompt, avp_p, avp_len);
		} else if (avp_vendor == VENDOR_JUNIPER2 && avp_code == 0xd81) {
			dup_prompt(&pass_prompt, avp_p, avp_len);
		} else if (avp_vendor == VENDOR_JUNIPER2 && avp_code == 0xd82) {
			dup_prompt(&user2_prompt, avp_p, avp_len);
		} else if (avp_vendor == VENDOR_JUNIPER2 && avp_code == 0xd83) {
			dup_prompt(&pass2_prompt, avp_p, avp_len);
		} else if (avp_vendor == VENDOR_JUNIPER2 && avp_code == 0xd73) {
			uint32_t val;

			if (avp_len != 4)
				goto auth_unknown;
			val = load_be32(avp_p);

			switch (val) {
		case 1: /* Prompt for both username and password. */
			prompt_flags = PROMPT_PASSWORD | PROMPT_USERNAME;
			break;
		case 3: /* Prompt for password.*/
		case 15:
			prompt_flags = PROMPT_PASSWORD;
			break;
		case 5: /* Prompt for username.*/
			prompt_flags = PROMPT_USERNAME;
			break;

		default:
			/* It does no harm to submit both, as anything unwanted is ignored. */
			vpn_progress(vpninfo, PRG_ERR,
				     _("Unknown D73 prompt value 0x%x. Will prompt for both username and password.\n"),
				     val);
			vpn_progress(vpninfo, PRG_ERR,
				     _("Please report this value and the behaviour of the official client.\n"));
			prompt_flags = PROMPT_PASSWORD | PROMPT_USERNAME;
			break;
		}
		} else if (avp_vendor == VENDOR_JUNIPER2 && avp_code == 0xd7b) {
			free(signin_prompt);
			signin_prompt = strndup(avp_p, avp_len);
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

			/* EAP within AVP within EAP within IF-T/TLS. Chewck EAP header. */
			if (avp_len < 5 || avp_c[0] != EAP_REQUEST ||
			    load_be16(avp_c + 2) != avp_len)
				goto auth_unknown;

			eap2_ident = avp_c[1];

			if (avp_c[4] == EAP_TYPE_GTC) {
				gtc_found = 1;
				free(gtc_prompt);
				gtc_prompt = strndup(avp_c + 5, avp_len - 5);
			} else if (avp_len >= 13 && load_be32(avp_c + 4) == EXPANDED_JUNIPER) {
				switch (load_be32(avp_c + 8)) {
				case 2: /*  Expanded Juniper/2: password */
					j2_found = 1;
					j2_code = avp_c[12];
					if (j2_code == J2_PASSREQ || j2_code == J2_PASSRETRY || j2_code == J2_PASSCHANGE) {
						if (avp_len != 13)
							goto auth_unknown;
						/* Precisely one byte, which is j2_code. OK. */
					} else if (j2_code == J2_PASSFAIL) {
						/*
						  < 0000:  00 00 55 97 00 00 00 05  00 00 00 84 00 00 01 fa  |..U.............|
						  < 0010:  00 0a 4c 01 01 05 00 70  fe 00 0a 4c 00 00 00 01  |..L....p...L....|
						  < 0020:  00 00 00 4f 40 00 00 62  01 02 00 5a fe 00 0a 4c  |...O@..b...Z...L|
						  < 0030:  00 00 00 02 c5 01 4d 43  6f 75 6c 64 20 6e 6f 74  |......MCould not|
						  < 0040:  20 63 68 61 6e 67 65 20  70 61 73 73 77 6f 72 64  | change password|
						  < 0050:  2e 20 4e 65 77 20 70 61  73 73 77 6f 72 64 20 6d  |. New password m|
						  < 0060:  75 73 74 20 62 65 20 61  74 20 6c 65 61 73 74 20  |ust be at least |
						  < 0070:  34 20 63 68 61 72 61 63  74 65 72 73 20 6c 6f 6e  |4 characters lon|
						  < 0080:  67 2e 00 00                                       |g...|
						 */
						if (avp_len > 15 && avp_c[13] == 0x01 && avp_c[14] == avp_len - 13) {
							/* Failure message. */
							vpn_progress(vpninfo, PRG_ERR,
								     _("Authentication failure: %.*s\n"), avp_len - 15, avp_c + 15);
							ret = -EIO;
							goto out;
						} else
							goto auth_unknown;
					}
					break;

				default:
					goto auth_unknown;
				}
			} else {
				goto auth_unknown;
			}

		} else if (avp_flags & AVP_MANDATORY)
			goto auth_unknown;
	}

	/* We want it to be precisely one type of request, not a mixture. */
	if (realm_entry + !!realms_found + j2_found + gtc_found + cookie_found + !!old_sessions != 1 &&
	    !signin_prompt) {
	auth_unknown:
		vpn_progress(vpninfo, PRG_ERR,
			     _("Unhandled Pulse authentication packet, or authentication failure\n"));
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

			if (j2_code == J2_PASSCHANGE) {
				ret = pulse_request_pass_change(vpninfo, reqbuf, eap2_ident,
								prompt_flags);
			} else if (j2_code == J2_PASSREQ || j2_code == J2_PASSRETRY) {
				/* Present user/password form to user */
				ret = pulse_request_user_auth(vpninfo, reqbuf, eap2_ident, prompt_flags,
							      (prompt_flags & PROMPT_PRIMARY) ? user_prompt : user2_prompt,
							      (prompt_flags & PROMPT_PRIMARY) ? pass_prompt : pass2_prompt);
			} else {
				vpn_progress(vpninfo, PRG_ERR,
					     _("Pulse password request with unknown code 0x%02x. Please report.\n"),
					     j2_code);
				ret = -EINVAL;
			}

			if (ret)
				goto out;
		} else if (gtc_found) {
			vpn_progress(vpninfo, PRG_TRACE,
				     _("Pulse password general token code request\n"));

			/* Present user/password form to user */
			ret = pulse_request_gtc(vpninfo, reqbuf, eap2_ident, prompt_flags,
				(prompt_flags & PROMPT_PRIMARY) ? user_prompt : user2_prompt,
				(prompt_flags & PROMPT_PRIMARY) ? pass_prompt : pass2_prompt,
				gtc_prompt);
			if (ret)
				goto out;
		} else if (old_sessions) {
			vpn_progress(vpninfo, PRG_TRACE,
				     _("Pulse session limit, %d sessions\n"),
				     old_sessions);
			ret = pulse_request_session_kill(vpninfo, reqbuf, old_sessions, eap);
			if (ret)
				goto out;
		} else if (signin_prompt) {
			buf_append_avp_be32(reqbuf, 0xd7c, 1);
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
	free(user2_prompt);
	free(pass2_prompt);
	free(gtc_prompt);
	free(signin_prompt);
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
static int handle_main_config_packet(struct openconnect_info *vpninfo,
				     unsigned char *bytes, int len)
{
	int routes_len = 0;
	int l;
	unsigned char *p;

	/* First part of header, similar to ESP, has already been checked */
	if (len < 0x31 ||
	    /* Start of routing information */
	    load_be16(bytes + 0x2c) != 0x2e00 ||
	    /* Routing length at 0x2e makes sense */
	    (routes_len = load_be16(bytes + 0x2e)) != ((int)bytes[0x30] * 0x10 + 8) ||
	    /* Make sure the next length field (at 0xa4 in the above example) is present */
	    len < 0x2c + routes_len + 4||
	    /* Another length field, must match to end of packet */
	    load_be32(bytes + 0x2c + routes_len) + routes_len + 0x2c != len) {
	bad_config:
		vpn_progress(vpninfo, PRG_ERR,
			     _("Unexpected Pulse config packet:\n"));
		dump_buf_hex(vpninfo, PRG_ERR, '<', (void *)bytes, len);
		return -EINVAL;
	}
	p = bytes + 0x34;
	routes_len -= 8; /* The header including length and number of routes */

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
		} else {
			vpn_progress(vpninfo, PRG_ERR, _("Receive route of unknown type 0x%08x\n"),
				     type);
			goto bad_config;
		}

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
		uint16_t attrlen = load_be16(p+2);

		if (attrlen + 4 > l)
			goto bad_config;

		p += 4;
		l -= 4;
		process_attr(vpninfo, type, p, attrlen);
		p += attrlen;
		l -= attrlen;
		if (l && l < 4)
			goto bad_config;
	}
	return 0;
}

/* Example ESP config packet:
   < 0000:  00 00 0a 4c 00 00 00 01  00 00 00 80 00 00 01 fc  |...L............|
   < 0010:  00 00 00 00 00 00 00 00  00 00 00 00 00 00 00 00  |................|
   < 0020:  21 20 24 00 00 00 00 00  00 00 00 70 00 00 00 54  |! $........p...T|
   < 0030:  01 00 00 00 ec 52 1b 6c  00 40 11 9d c5 f6 85 f3  |.....R.l.@......|
   < 0040:  26 7d 70 75 44 45 63 eb  64 00 fb ba 89 4f 24 b2  |&}puDEc.d....O$.|
   < 0050:  81 42 ce 24 b8 0a f8 b6  71 39 78 f8 5e 6f 5f d6  |.B.$....q9x.^o_.|
   < 0060:  9e 5c 06 47 8d 1e f3 0e  5a 51 ae b2 3d 09 8d 27  |.\.G....ZQ..=..'|
   < 0070:  e0 50 76 6a 22 9a d1 20  86 78 00 00 00 00 00 00  |.Pvj".. .x......|

   First 0x2c bytes are like the main config packet header.

   At 0x2c there is another length field, covering the whole of the
   rest of this packet.  Then an unknown 0x01000000 at 0x30, followed
   by the server->client SPI in little-endian(!) form at 0x34.

   Then follows the secrets, with a 2-byte length field at 0x38 (which
   is always 0x40), followed by the secrets themselves. As with
   Juniper Network Connect, the HMAC secret immediately follows the
   encryption key, however large the latter is.
*/
static int handle_esp_config_packet(struct openconnect_info *vpninfo,
				    unsigned char *bytes, int len)
{
#ifdef HAVE_ESP
	struct esp *esp;
	int secretslen;
	uint32_t spi;
	int ret;

	if (len < 0x6a ||
	    load_be32(bytes + 0x2c) != len - 0x2c ||
	    load_be32(bytes + 0x30) != 0x01000000 ||
	    load_be16(bytes + 0x38) != 0x40) {
		vpn_progress(vpninfo, PRG_ERR,
			     _("Invalid ESP config packet:\n"));
		dump_buf_hex(vpninfo, PRG_ERR, '<', bytes, len);
		return -EINVAL;
	}

	/* We insist on this being 0x40 for now. But just in case it later changes... */
	secretslen = load_be16(bytes + 0x38);
	vpn_progress(vpninfo, PRG_DEBUG, _("%d bytes of ESP secrets\n"), secretslen);

	if (!vpninfo->enc_key_len || !vpninfo->hmac_key_len ||
	    vpninfo->enc_key_len + vpninfo->hmac_key_len > secretslen) {
		vpn_progress(vpninfo, PRG_ERR,
			     _("Invalid ESP setup\n"));
		return -EINVAL;
	}

	/* Yes, bizarrely this is little-endian on the wire. I have no idea
	 * what made them do this. */
	spi = load_le32(bytes + 0x34);
	vpn_progress(vpninfo, PRG_DEBUG, _("ESP SPI (outbound): %x\n"), spi);
	/* But we store it internally as big-endian because we never do any
	 * calculations on it; it's only set into outbound packets and matched
	 * on incoming ones... and we've NEVER had to see it in little-endian
	 * form ever before because that's insane! */
	store_be32(&vpninfo->esp_out.spi, spi);

	memcpy(vpninfo->esp_out.enc_key, bytes + 0x3a, vpninfo->enc_key_len);
	memcpy(vpninfo->esp_out.hmac_key, bytes + 0x3a + vpninfo->enc_key_len,
	       vpninfo->hmac_key_len);

	ret = openconnect_setup_esp_keys(vpninfo, 1);
	if (ret)
		return ret;

	esp = &vpninfo->esp_in[vpninfo->current_esp_in];

	/* Now, using the buffer in which we received the original packet (which
	 * we trust our caller made large enough), create an appropriate reply.
	 * A reply packet contains two sets of ESP information, as we are expected
	 * to send our own followed by a copy of what the server sent to us. */

	/* Adjust the length in the IF-T/TLS header */
	store_be32(bytes + 8, 0x40 + 2 * secretslen);

	/* Copy the server's own ESP information into place */
	memmove(bytes + secretslen + 0x3a, bytes + 0x34, secretslen + 0x06);

	/* Adjust other length fields. */
	store_be32(bytes + 0x28, 0x30 + 2 * secretslen);
	store_be32(bytes + 0x2c, 0x14 + 2 * secretslen);

	/* Store the SPI. Bizarrely little-endian again. */
	store_le32(bytes + 0x34, load_be32(&esp->spi));
	memcpy(bytes + 0x3a, esp->enc_key, vpninfo->enc_key_len);
	memcpy(bytes + 0x3a + vpninfo->enc_key_len, esp->hmac_key, vpninfo->hmac_key_len);
	memset(bytes + 0x3a + vpninfo->enc_key_len + vpninfo->hmac_key_len,
	       0, 0x40 - vpninfo->enc_key_len - vpninfo->hmac_key_len);

	return 0;
#else
	return -EINVAL;
#endif
}

int pulse_connect(struct openconnect_info *vpninfo)
{
	struct oc_text_buf *reqbuf;
	unsigned char bytes[16384];
	int ret;

	/* If we already have a channel open, it's because we have just
	 * successfully authenticated on it from pulse_obtain_cookie(). */
	if (vpninfo->ssl_fd == -1) {
		ret = pulse_authenticate(vpninfo, 1);
		if (ret)
			return ret;
	}

	while (1) {
		uint32_t pkt_type;

		ret = recv_ift_packet(vpninfo, (void *)bytes, sizeof(bytes));
		if (ret < 0)
			return ret;

		if (ret < 16 || load_be32(bytes + 8) != ret) {
			vpn_progress(vpninfo, PRG_ERR,
				     _("Bad IF-T/TLS packet when expecting configuration:\n"));
			dump_buf_hex(vpninfo, PRG_ERR, '<', bytes, ret);
			return -EINVAL;
		}

		if (load_be32(bytes) != VENDOR_JUNIPER) {
		bad_pkt:
			vpn_progress(vpninfo, PRG_INFO,
				     _("Unexpected IF-T/TLS packet when expecting configuration.\n"));
			dump_buf_hex(vpninfo, PRG_DEBUG, '<', bytes, ret);
			continue;
		}

		pkt_type = load_be32(bytes + 4);

		/* End of configuration? Seems to have a 4-byte payload of zeroes. */
		if (pkt_type == 0x8f)
			break;

		/* The main and ESP config packets both start like this. The word at
		 * 0x20 is 0x2c20f000 for config and 0x0x21202400 for ESP, and the word
		 * at 0x2c is the length of the payload (0x10 less than the overall
		 * length including (and in) the IF-T/TLS header. e.g 0x170 here:
		 *
		 * < 0000: 00 00 0a 4c 00 00 00 01  00 00 01 80 00 00 01 fb  |...L............|
		 * < 0010: 00 00 00 00 00 00 00 00  00 00 00 00 00 00 00 00  |................|
		 * < 0020: 2c 20 f0 00 00 00 00 00  00 00 01 70 ...          |, .........|
		 */

		if (pkt_type != 1 || ret < 0x2c || load_be32(bytes +  0x10) ||
		    load_be32(bytes + 0x14) || load_be32(bytes + 0x18) ||
		    load_be32(bytes + 0x1c) || load_be32(bytes + 0x24) ||
		    load_be32(bytes + 0x28) != ret - 0x10)
			goto bad_pkt;

		switch(load_be32(bytes + 0x20)) {
		case 0x2c20f000:
			ret = handle_main_config_packet(vpninfo, bytes, ret);
			if (ret)
				return ret;

			break;

		case 0x21202400:
			ret = handle_esp_config_packet(vpninfo, bytes, ret);
			if (ret) {
				vpninfo->dtls_state = DTLS_DISABLED;
				continue;
			}

			/* It has created a response packet to send. */
			ret = send_ift_bytes(vpninfo, bytes, load_be32(bytes + 8));
			if (ret)
				return ret;

			/* Tell server to enable ESP handling */
			reqbuf = buf_alloc();
			buf_append_ift_hdr(reqbuf, VENDOR_JUNIPER, 5);
			buf_append(reqbuf, "ncmo=1\n%c", 0);
			ret = send_ift_packet(vpninfo, reqbuf);
			buf_free(reqbuf);
			if (ret)
				return ret;

			break;

		default:
			goto bad_pkt;
		}
	}

	if (!vpninfo->ip_info.mtu ||
	    (!vpninfo->ip_info.addr && !vpninfo->ip_info.addr6)) {
		vpn_progress(vpninfo, PRG_ERR, "Insufficient configuration found\n");
		return -EINVAL;
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
		struct pkt *pkt = vpninfo->cstp_pkt;
		int len, payload_len;

		if (!pkt) {
			pkt = vpninfo->cstp_pkt = malloc(sizeof(struct pkt) + receive_mtu);
			if (!pkt) {
				vpn_progress(vpninfo, PRG_ERR, _("Allocation failed\n"));
				break;
			}
		}

		/* Receive packet header, if there's anything there... */
		len = ssl_nonblock_read(vpninfo, &pkt->pulse.vendor, 16);
		if (!len)
			break;
		if (len < 0)
			goto do_reconnect;
		if (len < 16) {
			vpn_progress(vpninfo, PRG_ERR, _("Short packet received (%d bytes)\n"), len);
			vpninfo->quit_reason = "Short packet received";
			return 1;
		}

		/* Packets shouldn't cross SSL record boundaries (we hope!), so if there
		 * was a header there, then rest of that packet should be there too. */
		if (load_be32(&pkt->pulse.len) > receive_mtu + 0x10) {
			/* This doesn't look right. Pull the rest of the SSL record
			 * and complain about it (which we will, since the length
			 * won't match the header */
			len = receive_mtu;
		} else
			len = load_be32(&pkt->pulse.len) - 0x10;

		payload_len = ssl_nonblock_read(vpninfo, &pkt->data, len);
		if (payload_len != load_be32(&pkt->pulse.len) - 0x10) {
			if (payload_len < 0)
				len = 0x10;
			else
				len = payload_len + 0x10;
			goto unknown_pkt;
		}

		if (load_be32(&pkt->pulse.vendor) != VENDOR_JUNIPER)
			goto unknown_pkt;

		vpninfo->ssl_times.last_rx = time(NULL);
		len = payload_len + 0x10;

		switch(load_be32(&pkt->pulse.type)) {
		case 4:
			vpn_progress(vpninfo, PRG_TRACE,
				     _("Received data packet of %d bytes\n"),
				     payload_len);
			dump_buf_hex(vpninfo, PRG_TRACE, '<', (void *)&vpninfo->cstp_pkt->pulse.vendor, len);
			vpninfo->cstp_pkt->len = payload_len;
			queue_packet(&vpninfo->incoming_queue, pkt);
			vpninfo->cstp_pkt = pkt = NULL;
			work_done = 1;
			continue;
		case 1:
			if (payload_len < 0x6a ||
			    load_be32(pkt->data + 0x10) != 0x21202400 ||
			    load_be32(pkt->data + 0x18) != payload_len ||
			    load_be32(pkt->data + 0x1c) != payload_len - 0x1c ||
			    load_be32(pkt->data + 0x20) != 0x01000000 ||
			    load_be16(pkt->data + 0x28) != 0x40)
				goto unknown_pkt;

			dump_buf_hex(vpninfo, PRG_ERR, '<', (void *)&vpninfo->cstp_pkt->pulse.vendor, len);

			ret = handle_esp_config_packet(vpninfo, (void *)&pkt->pulse.vendor, len);
			if (ret) {
				vpn_progress(vpninfo, PRG_ERR,
					     _("ESP rekey failed\n"));
				vpninfo->proto->udp_close(vpninfo);
				continue;
			}
			vpninfo->cstp_pkt = NULL;
			pkt->len = load_be32(&pkt->pulse.len) - 16;
			queue_packet(&vpninfo->oncp_control_queue, pkt);

			print_esp_keys(vpninfo, _("new incoming"), &vpninfo->esp_in[vpninfo->current_esp_in]);
			print_esp_keys(vpninfo, _("new outgoing"), &vpninfo->esp_out);
			continue;

		case 0x96:
			/* It sends the licence information once the connection is set up. For
			 * now, abuse this to deal with the race condition in ESP setup — it looks
			 * like the server doesn't process the ESP config until after we've sent
			 * the probes, in some cases. */
			if (vpninfo->dtls_state == DTLS_SLEEPING)
				vpninfo->proto->udp_send_probes(vpninfo);
			break;

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
	if (vpninfo->dtls_state == DTLS_CONNECTING) {
		/* We don't currently do anything to make the server start sending
		 * data packets in ESP instead of over IF-T/TLS. Just go straight
		 * to CONNECTED mode. */
		vpninfo->dtls_state = DTLS_CONNECTED;
		work_done = 1;
	}

	vpninfo->current_ssl_pkt = dequeue_packet(&vpninfo->oncp_control_queue);
	if (vpninfo->current_ssl_pkt) {
		/* Anything on the control queue will have the rest of its
		   header filled in already. */
		store_be32(&vpninfo->current_ssl_pkt->pulse.ident, vpninfo->ift_seq++);
		goto handle_outgoing;
	}

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
