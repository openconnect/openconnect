/*
 * OpenConnect (SSL + DTLS) VPN client
 *
 * Copyright © 2016-2017 Daniel Lenski
 *
 * Author: Daniel Lenski <dlenski@gmail.com>
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
#ifndef _WIN32
#include <sys/wait.h>
#endif
#include <stdarg.h>
#ifdef HAVE_LZ4
#include <lz4.h>
#endif

#ifdef _WIN32
#include "win32-ipicmp.h"
#else
/* The BSDs require the first two headers before netinet/ip.h
 * (Linux and macOS already #include them within netinet/ip.h)
 */
#include <sys/types.h>
#include <netinet/in_systm.h>
#include <netinet/in.h>
#include <netinet/ip.h>
#include <netinet/ip_icmp.h>
#endif

#if defined(__linux__)
/* For TCP_INFO */
# include <linux/tcp.h>
#endif

#include <assert.h>

#include "openconnect-internal.h"

/*
 * Data packets are encapsulated in the SSL stream as follows:
 *
 * 0000: Magic "\x1a\x2b\x3c\x4d"
 * 0004: Big-endian EtherType (0x0800 for IPv4)
 * 0006: Big-endian 16-bit length (not including 16-byte header)
 * 0008: Always "\x01\0\0\0\0\0\0\0"
 * 0010: data payload
 */

/* Strange initialisers here to work around GCC PR#10676 (which was
 * fixed in GCC 4.6 but it takes a while for some systems to catch
 * up. */
static const struct pkt dpd_pkt = {
	.next = NULL,
	{ .gpst.hdr = { 0x1a, 0x2b, 0x3c, 0x4d } }
};

/* We behave like CSTP — create a linked list in vpninfo->cstp_options
 * with the strings containing the information we got from the server,
 * and oc_ip_info contains const copies of those pointers.
 *
 * (unlike version in oncp.c, val is stolen rather than strdup'ed) */

static const char *add_option(struct openconnect_info *vpninfo, const char *opt, char **val)
{
	struct oc_vpn_option *new = malloc(sizeof(*new));
	if (!new)
		return NULL;

	new->option = strdup(opt);
	if (!new->option) {
		free(new);
		return NULL;
	}
	new->value = *val;
	*val = NULL;
	new->next = vpninfo->cstp_options;
	vpninfo->cstp_options = new;

	return new->value;
}

static int filter_opts(struct oc_text_buf *buf, const char *query, const char *incexc, int include)
{
	const char *f, *endf, *eq;
	const char *found, *comma;

	for (f = query; *f; f=(*endf) ? endf+1 : endf) {
		endf = strchr(f, '&') ? : f+strlen(f);
		eq = strchr(f, '=');
		if (!eq || eq > endf)
			eq = endf;

		for (found = incexc; *found; found=(*comma) ? comma+1 : comma) {
			comma = strchr(found, ',') ? : found+strlen(found);
			if (!strncmp(found, f, MAX(comma-found, eq-f)))
				break;
		}

		if ((include && *found) || (!include && !*found)) {
			if (buf->pos && buf->data[buf->pos-1] != '?' && buf->data[buf->pos-1] != '&')
				buf_append(buf, "&");
			buf_append_bytes(buf, f, (int)(endf-f));
		}
	}
	return buf_error(buf);
}

/* Parse this JavaScript-y mess:

	"var respStatus = \"Challenge|Error\";\n"
	"var respMsg = \"<prompt>\";\n"
	"thisForm.inputStr.value = "<inputStr>";\n"
*/
static int parse_javascript(char *buf, char **prompt, char **inputStr)
{
	const char *start, *end = buf;
	int status;

	const char *pre_status = "var respStatus = \"",
	           *pre_prompt = "var respMsg = \"",
	           *pre_inputStr = "thisForm.inputStr.value = \"";

	/* Status */
	while (isspace(*end))
		end++;
	if (strncmp(end, pre_status, strlen(pre_status)))
		goto err;

	start = end+strlen(pre_status);
	end = strchr(start, '\n');
	if (!end || end[-1] != ';' || end[-2] != '"')
		goto err;

	if (!strncmp(start, "Challenge", 8))    status = 0;
	else if (!strncmp(start, "Error", 5))   status = 1;
	else                                    goto err;

	/* Prompt */
	while (isspace(*end))
		end++;
	if (strncmp(end, pre_prompt, strlen(pre_prompt)))
		goto err;

	start = end+strlen(pre_prompt);
	end = strchr(start, '\n');
	if (!end || end[-1] != ';' || end[-2] != '"' || (end<start+2))
		goto err;

	if (prompt)
		*prompt = strndup(start, end-start-2);

	/* inputStr */
	while (isspace(*end))
		end++;
	if (strncmp(end, pre_inputStr, strlen(pre_inputStr)))
		goto err2;

	start = end+strlen(pre_inputStr);
	end = strchr(start, '\n');
	if (!end || end[-1] != ';' || end[-2] != '"' || (end<start+2))
		goto err2;

	if (inputStr)
		*inputStr = strndup(start, end-start-2);

	while (isspace(*end))
		end++;
	if (*end != '\0')
		goto err3;

	return status;

err3:
	if (inputStr) free(*inputStr);
err2:
	if (prompt) free(*prompt);
err:
	return -EINVAL;
}

int gpst_xml_or_error(struct openconnect_info *vpninfo, char *response,
					  int (*xml_cb)(struct openconnect_info *, xmlNode *xml_node, void *cb_data),
					  int (*challenge_cb)(struct openconnect_info *, char *prompt, char *inputStr, void *cb_data),
					  void *cb_data)
{
	xmlDocPtr xml_doc;
	xmlNode *xml_node;
	char *err = NULL;
	char *prompt = NULL, *inputStr = NULL;
	int result = -EINVAL;

	if (!response) {
		vpn_progress(vpninfo, PRG_ERR,
			     _("Empty response from server\n"));
		return -EINVAL;
	}

	/* is it XML? */
	xml_doc = xmlReadMemory(response, strlen(response), "noname.xml", NULL,
				XML_PARSE_NOERROR);
	if (!xml_doc) {
		/* is it Javascript? */
		result = parse_javascript(response, &prompt, &inputStr);
		switch (result) {
		case 1:
			vpn_progress(vpninfo, PRG_ERR, _("%s\n"), prompt);
			break;
		case 0:
			vpn_progress(vpninfo, PRG_INFO, _("Challenge: %s\n"), prompt);
			result = challenge_cb ? challenge_cb(vpninfo, prompt, inputStr, cb_data) : -EINVAL;
			break;
		default:
			goto bad_xml;
		}
		free(prompt);
		free(inputStr);
		goto bad_xml;
	}

	xml_node = xmlDocGetRootElement(xml_doc);

	/* is it <response status="error"><error>..</error></response> ? */
	if (xmlnode_is_named(xml_node, "response")
	    && !xmlnode_match_prop(xml_node, "status", "error")) {
		for (xml_node=xml_node->children; xml_node; xml_node=xml_node->next) {
			if (!xmlnode_get_val(xml_node, "error", &err))
				goto out;
		}
		goto bad_xml;
	}

	/* Is it <prelogin-response><status>Error</status><msg>..</msg></prelogin-response> ? */
	if (xmlnode_is_named(xml_node, "prelogin-response")) {
		char *s = NULL;
		int has_err = 0;
		xmlNode *x;
		for (x=xml_node->children; x; x=x->next) {
			if (!xmlnode_get_val(x, "status", &s))
				has_err = strcmp(s, "Success");
			else
				xmlnode_get_val(x, "msg", &err);
		}
		free(s);
		if (has_err)
			goto out;
		free(err);
		err = NULL;
	}

	/* is it <challenge><user>user.name</user><inputstr>...</inputstr><respmsg>...</respmsg></challenge> */
	if (xmlnode_is_named(xml_node, "challenge")) {
		for (xml_node=xml_node->children; xml_node; xml_node=xml_node->next) {
			xmlnode_get_val(xml_node, "inputstr", &inputStr);
			xmlnode_get_val(xml_node, "respmsg", &prompt);
			/* XXX: override the username passed to the next form from <user> ? */
		}
		result = challenge_cb ? challenge_cb(vpninfo, prompt, inputStr, cb_data) : -EINVAL;
		free(prompt);
		free(inputStr);
		goto bad_xml;
	}

	/* if it's XML, invoke callback (or default to success) */
	result = xml_cb ? xml_cb(vpninfo, xml_node, cb_data) : 0;

bad_xml:
	if (result == -EINVAL) {
		vpn_progress(vpninfo, PRG_ERR,
					 _("Failed to parse server response\n"));
		vpn_progress(vpninfo, PRG_DEBUG,
					 _("Response was:%s\n"), response);
	}

out:
	if (err) {
		if (!strcmp(err, "GlobalProtect gateway does not exist")
		    || !strcmp(err, "GlobalProtect portal does not exist")) {
			vpn_progress(vpninfo, PRG_DEBUG, "%s\n", err);
			result = -EEXIST;
		} else if (!strcmp(err, "Invalid authentication cookie")           /* equivalent to custom HTTP status 512 */
		           || !strcmp(err, "Valid client certificate is required") /* equivalent to custom HTTP status 513 */
		           || !strcmp(err, "Allow Automatic Restoration of SSL VPN is disabled")) {
			/* Any of these errors indicates that retrying won't help us reconnect (EPERM signals this to mainloop.) */
			vpn_progress(vpninfo, PRG_ERR, "%s\n", err);
			result = -EPERM;
		} else {
			vpn_progress(vpninfo, PRG_ERR, "%s\n", err);
			result = -EINVAL;
		}
		free(err);
	}
	if (xml_doc)
		xmlFreeDoc(xml_doc);
	return result;
}


#define ESP_HEADER_SIZE (4 /* SPI */ + 4 /* sequence number */)
#define ESP_FOOTER_SIZE (1 /* pad length */ + 1 /* next header */)
#define UDP_HEADER_SIZE 8
#define TCP_HEADER_SIZE 20 /* with no options */
#define IPV4_HEADER_SIZE 20
#define IPV6_HEADER_SIZE 40

/* Based on cstp.c's calculate_mtu().
 *
 * With HTTPS tunnel, there are 21 bytes of overhead beyond the
 * TCP MSS: 5 bytes for TLS and 16 for GPST.
 */
static int calculate_mtu(struct openconnect_info *vpninfo, int can_use_esp)
{
	int mtu = vpninfo->reqmtu, base_mtu = vpninfo->basemtu;
	int mss = 0;

#if defined(__linux__) && defined(TCP_INFO)
	if (!mtu) {
		struct tcp_info ti;
		socklen_t ti_size = sizeof(ti);

		if (!getsockopt(vpninfo->ssl_fd, IPPROTO_TCP, TCP_INFO,
				&ti, &ti_size)) {
			vpn_progress(vpninfo, PRG_DEBUG,
				     _("TCP_INFO rcv mss %d, snd mss %d, adv mss %d, pmtu %d\n"),
				     ti.tcpi_rcv_mss, ti.tcpi_snd_mss, ti.tcpi_advmss, ti.tcpi_pmtu);

			if (!base_mtu) {
				base_mtu = ti.tcpi_pmtu;
			}

			/* XXX: GlobalProtect has no mechanism to inform the server about the
			 * desired MTU, so could just ignore the "incoming" MSS (tcpi_rcv_mss).
			 */
			mss = MIN(ti.tcpi_rcv_mss, ti.tcpi_snd_mss);
		}
	}
#endif
#ifdef TCP_MAXSEG
	if (!mtu && !mss) {
		socklen_t mss_size = sizeof(mss);
		if (!getsockopt(vpninfo->ssl_fd, IPPROTO_TCP, TCP_MAXSEG,
				&mss, &mss_size)) {
			vpn_progress(vpninfo, PRG_DEBUG, _("TCP_MAXSEG %d\n"), mss);
		}
	}
#endif
	if (!base_mtu) {
		/* Default */
		base_mtu = 1406;
	}

	if (base_mtu < 1280)
		base_mtu = 1280;

#ifdef HAVE_ESP
	/* If we can use the ESP tunnel then we should pick the optimal MTU for ESP. */
	if (!mtu && can_use_esp) {
		/* remove ESP, UDP, IP headers from base (wire) MTU */
		mtu = ( base_mtu - UDP_HEADER_SIZE - ESP_HEADER_SIZE
		        - vpninfo->hmac_out_len
		        - MAX_IV_SIZE);
		if (vpninfo->peer_addr->sa_family == AF_INET6)
			mtu -= IPV6_HEADER_SIZE;
		else
			mtu -= IPV4_HEADER_SIZE;
		/* round down to a multiple of blocksize (16 bytes for both AES-128 and AES-256) */
		mtu -= mtu % 16;
		/* subtract ESP footer, which is included in the payload before padding to the blocksize */
		mtu -= ESP_FOOTER_SIZE;

	} else
#endif

    /* We are definitely using the TLS tunnel, so we should base our MTU on the TCP MSS. */
	if (!mtu) {
		if (mss)
			mtu = mss - 21;
		else {
			mtu = base_mtu - TCP_HEADER_SIZE - 21;
			if (vpninfo->peer_addr->sa_family == AF_INET6)
				mtu -= IPV6_HEADER_SIZE;
			else
				mtu -= IPV4_HEADER_SIZE;
		}
	}
	return mtu;
}

#ifdef HAVE_ESP
static int check_hmac_algo(struct openconnect_info *v, const char *s)
{
	if (!strcmp(s, "sha1"))	  return HMAC_SHA1;
	if (!strcmp(s, "md5"))    return HMAC_MD5;
	if (!strcmp(s, "sha256")) return HMAC_SHA256;
	vpn_progress(v, PRG_ERR, _("Unknown ESP MAC algorithm: %s"), s);
	return -ENOENT;
}

static int check_enc_algo(struct openconnect_info *v, const char *s)
{
	if (!strcmp(s, "aes128") || !strcmp(s, "aes-128-cbc")) return ENC_AES_128_CBC;
	if (!strcmp(s, "aes-256-cbc"))                         return ENC_AES_256_CBC;
	vpn_progress(v, PRG_ERR, _("Unknown ESP encryption algorithm: %s"), s);
	return -ENOENT;
}

/* Reads <KEYTAG/><bits>N</bits><val>hex digits</val></KEYTAG> and saves the
 * key in dest, returning its length in bytes.
 */
static int xml_to_key(xmlNode *xml_node, unsigned char *dest, int dest_size)
{
	int explen = -1, len = 0;
	xmlNode *child;
	char *p, *s = NULL;

	for (child = xml_node->children; child; child=child->next) {
		if (xmlnode_get_val(child, "bits", &s) == 0) {
			explen = atoi(s);
			if (explen & 0x07) goto out;
			explen >>= 3;
		} else if (xmlnode_get_val(child, "val", &s) == 0) {
			for (p=s; p[0] && p[1]; p+=2)
				if (len++ < dest_size)
					*dest++ = unhex(p);
		}
	}
out:
	free(s);
	return (len == explen) ? len : -EINVAL;
}
#endif

/* Return value:
 *  < 0, on error
 *  = 0, on success; *form is populated
 */
static int gpst_parse_config_xml(struct openconnect_info *vpninfo, xmlNode *xml_node, void *cb_data)
{
	xmlNode *member;
	char *s = NULL, *deferred_netmask = NULL;
	struct oc_split_include *inc;
	int split_route_is_default_route = 0;
	int n_dns = 0, got_ipv6 = 0, got_esp = 0;
	int ii;

	if (!xml_node || !xmlnode_is_named(xml_node, "response"))
		return -EINVAL;

	/* Clear old options which will be overwritten */
	vpninfo->ip_info.addr = vpninfo->ip_info.netmask = NULL;
	vpninfo->ip_info.addr6 = vpninfo->ip_info.netmask6 = NULL;
	vpninfo->ip_info.domain = NULL;
	vpninfo->ip_info.mtu = 0;
	vpninfo->esp_magic = inet_addr(vpninfo->ip_info.gateway_addr);
	vpninfo->esp_replay_protect = 1;
	vpninfo->ssl_times.rekey_method = REKEY_NONE;
	vpninfo->cstp_options = NULL;

	for (ii = 0; ii < 3; ii++)
		vpninfo->ip_info.dns[ii] = vpninfo->ip_info.nbns[ii] = NULL;
	free_split_routes(vpninfo);

	/* Parse config */
	for (xml_node = xml_node->children; xml_node; xml_node=xml_node->next) {
		if (!xmlnode_get_val(xml_node, "ip-address", &s))
			vpninfo->ip_info.addr = add_option(vpninfo, "ipaddr", &s);
		else if (!xmlnode_get_val(xml_node, "netmask", &deferred_netmask)) {
			/* XX: GlobalProtect servers always (almost always?) send 255.255.255.255 as their netmask
			 * (a /32 host route), and if they want to include an actual default route (0.0.0.0/0)
			 * they instead put it under <access-routes/>. We defer saving the netmask until later.
			 */
		} else if (!xmlnode_get_val(xml_node, "mtu", &s))
			vpninfo->ip_info.mtu = atoi(s);
		else if (!xmlnode_get_val(xml_node, "lifetime", &s))
			vpninfo->auth_expiration = time(NULL) + atol(s);
		else if (!xmlnode_get_val(xml_node, "disconnect-on-idle", &s)) {
			int sec = atoi(s);
			vpn_progress(vpninfo, PRG_INFO, _("Idle timeout is %d minutes.\n"), sec/60);
			vpninfo->idle_timeout = sec;
		} else if (!xmlnode_get_val(xml_node, "ssl-tunnel-url", &s)) {
			free(vpninfo->urlpath);
			vpninfo->urlpath = s;
			if (strcmp(s, "/ssl-tunnel-connect.sslvpn"))
				vpn_progress(vpninfo, PRG_INFO, _("Non-standard SSL tunnel path: %s\n"), s);
			s = NULL;
		} else if (!xmlnode_get_val(xml_node, "timeout", &s)) {
			int sec = atoi(s);
			vpn_progress(vpninfo, PRG_INFO, _("Tunnel timeout (rekey interval) is %d minutes.\n"), sec/60);
			vpninfo->ssl_times.last_rekey = time(NULL);
			vpninfo->ssl_times.rekey = sec - 60;
			vpninfo->ssl_times.rekey_method = REKEY_TUNNEL;
		} else if (!xmlnode_get_val(xml_node, "gw-address", &s)) {
			/* As remarked in oncp.c, "this is a tunnel; having a
			 * gateway is meaningless." See esp_send_probes_gp for the
			 * gory details of what this field actually means.
			 */
			if (strcmp(s, vpninfo->ip_info.gateway_addr))
				vpn_progress(vpninfo, PRG_DEBUG,
							 _("Gateway address in config XML (%s) differs from external gateway address (%s).\n"), s, vpninfo->ip_info.gateway_addr);
			vpninfo->esp_magic = inet_addr(s);
		} else if (!xmlnode_get_val(xml_node, "connected-gw-ip", &s)) {
			if (strcmp(s, vpninfo->ip_info.gateway_addr))
				vpn_progress(vpninfo, PRG_DEBUG, _("Config XML <connected-gw-ip> address (%s) differs from external\n"
				                                   "gateway address (%s). Please report any this to\n"
								   "<openconnect-devel@lists.infradead.org>, including any problems\n"
								   "with ESP or other apparent loss of connectivity or performance.\n"), s, vpninfo->ip_info.gateway_addr);
		} else if (xmlnode_is_named(xml_node, "dns-v6")) {
			got_ipv6 |= 1;
			goto handle_dns;
		} else if (xmlnode_is_named(xml_node, "dns")) {
		handle_dns:
			for (member = xml_node->children; member && n_dns<3; member=member->next) {
				if (!xmlnode_get_val(member, "member", &s)) {
					for (ii=0; ii<n_dns; ii++)
						/* XX: frequent duplicates between <dns> and <dns-v6> */
						if (!strcmp(s, vpninfo->ip_info.dns[ii]))
							break;
					if (ii==n_dns)
						vpninfo->ip_info.dns[n_dns++] = add_option(vpninfo, "DNS", &s);
				}
			}
		} else if (xmlnode_is_named(xml_node, "wins")) {
			for (ii=0, member = xml_node->children; member && ii<3; member=member->next)
				if (!xmlnode_get_val(member, "member", &s))
					vpninfo->ip_info.nbns[ii++] = add_option(vpninfo, "WINS", &s);
		} else if (xmlnode_is_named(xml_node, "dns-suffix")) {
			struct oc_text_buf *domains = buf_alloc();
			for (member = xml_node->children; member; member=member->next)
				if (!xmlnode_get_val(member, "member", &s))
					buf_append(domains, "%s ", s);
			if (buf_error(domains) == 0 && domains->pos > 0) {
				domains->data[domains->pos-1] = '\0';
				vpninfo->ip_info.domain = add_option(vpninfo, "search", &domains->data);
			}
			buf_free(domains);
		} else if (xmlnode_is_named(xml_node, "access-routes-v6") || xmlnode_is_named(xml_node, "exclude-access-routes-v6")) {
			got_ipv6 |= 1;
			goto handle_routes;
		} else if (xmlnode_is_named(xml_node, "access-routes") || xmlnode_is_named(xml_node, "exclude-access-routes")) {
		handle_routes:
			for (member = xml_node->children; member; member=member->next) {
				if (!xmlnode_get_val(member, "member", &s)) {
					int is_inc = (xml_node->name[0] == 'a');

					/* XX: if this is a default route jammed into the split-include
					 * routes, just mark it for now.
					 */
					if (is_inc && !strcmp(s, "0.0.0.0/0")) {
						split_route_is_default_route = 1;
						continue;
					}

					if ((inc = malloc(sizeof(*inc))) == NULL)
						return -ENOMEM;
					if (is_inc) {
						inc->route = add_option(vpninfo, "split-include", &s);
						inc->next = vpninfo->ip_info.split_includes;
						vpninfo->ip_info.split_includes = inc;
					} else {
						inc->route = add_option(vpninfo, "split-exclude", &s);
						inc->next = vpninfo->ip_info.split_excludes;
						vpninfo->ip_info.split_excludes = inc;
					}
				}
			}
		} else if (xmlnode_is_named(xml_node, "ipsec")) {
#ifdef HAVE_ESP
			if (vpninfo->dtls_state != DTLS_DISABLED) {
				int c = (vpninfo->current_esp_in ^= 1);
				struct esp *ei = &vpninfo->esp_in[c], *eo = &vpninfo->esp_out;
				vpninfo->old_esp_maxseq = vpninfo->esp_in[c^1].seq + 32;
				for (member = xml_node->children; member; member=member->next) {
					if (!xmlnode_get_val(member, "udp-port", &s))		udp_sockaddr(vpninfo, atoi(s));
					else if (!xmlnode_get_val(member, "enc-algo", &s)) 	vpninfo->esp_enc = check_enc_algo(vpninfo, s);
					else if (!xmlnode_get_val(member, "hmac-algo", &s))	vpninfo->esp_hmac = check_hmac_algo(vpninfo, s);
					else if (!xmlnode_get_val(member, "c2s-spi", &s))	eo->spi = htonl(strtoul(s, NULL, 16));
					else if (!xmlnode_get_val(member, "s2c-spi", &s))	ei->spi = htonl(strtoul(s, NULL, 16));
					else if (xmlnode_is_named(member, "ekey-c2s"))		vpninfo->enc_key_len = xml_to_key(member, eo->enc_key, sizeof(eo->enc_key));
					else if (xmlnode_is_named(member, "ekey-s2c"))		vpninfo->enc_key_len = xml_to_key(member, ei->enc_key, sizeof(ei->enc_key));
					else if (xmlnode_is_named(member, "akey-c2s"))		vpninfo->hmac_key_len = xml_to_key(member, eo->hmac_key, sizeof(eo->hmac_key));
					else if (xmlnode_is_named(member, "akey-s2c"))		vpninfo->hmac_key_len = xml_to_key(member, ei->hmac_key, sizeof(ei->hmac_key));
					else if (!xmlnode_get_val(member, "ipsec-mode", &s) && strcmp(s, "esp-tunnel"))
						vpn_progress(vpninfo, PRG_ERR, _("GlobalProtect config sent ipsec-mode=%s (expected esp-tunnel)\n"), s);
				}
				if (vpninfo->esp_enc <= 0 && vpninfo->esp_hmac <= 0 && vpninfo->enc_key_len <= 0 && vpninfo->hmac_key_len <= 0)
					vpn_progress(vpninfo, PRG_ERR, "Server's ESP configuration is incomplete or uses unknown algorithms.\n");
				else if (openconnect_setup_esp_keys(vpninfo, 0))
					vpn_progress(vpninfo, PRG_ERR, "Failed to setup ESP keys.\n");
				else {
					got_esp = 1;
					/* prevent race condition between esp_mainloop() and gpst_mainloop() timers */
					vpninfo->dtls_times.last_rekey = time(&vpninfo->new_dtls_started);
					vpninfo->delay_tunnel_reason = "awaiting GPST ESP connection";
				}
			}
#else
			vpn_progress(vpninfo, PRG_DEBUG, _("Ignoring ESP keys since ESP support not available in this build\n"));
#endif
		} else if (xmlnode_is_named(xml_node, "need-tunnel")
			   || xmlnode_is_named(xml_node, "bw-c2s")
			   || xmlnode_is_named(xml_node, "bw-s2c")
			   || xmlnode_is_named(xml_node, "default-gateway")
			   || xmlnode_is_named(xml_node, "no-direct-access-to-local-network")
			   || xmlnode_is_named(xml_node, "ip-address-preferred")
			   || xmlnode_is_named(xml_node, "portal")
			   || xmlnode_is_named(xml_node, "user")) {
			/* XX: Do these have any potential value at all for routing configuration or diagnostics? */
		} else if (xml_node->type == XML_ELEMENT_NODE) {
			/* XX: Don't know what tags are used for IPv6 addresses and networks, since
			 * we haven't yet seen a real GlobalProtect VPN with IPv6 internal addresses.
			 */
			free(s);
			s = (char *)xmlNodeGetContent(xml_node);
			if (strchr((char *)xml_node->name, '6')) {
				got_ipv6 |= 2;
				vpn_progress(vpninfo, PRG_ERR, _("Potential IPv6-related GlobalProtect config tag <%s>: %s\n"), xml_node->name, s);
			} else
				vpn_progress(vpninfo, PRG_DEBUG, _("Unknown GlobalProtect config tag <%s>: %s\n"), xml_node->name, s);
		}
	}

	/* Fix the issue of a 0.0.0.0/0 "split"-include route by swapping the "split" route with the default netmask. */
	if (split_route_is_default_route) {
		char *original_netmask = deferred_netmask;

		if ((deferred_netmask = strdup("0.0.0.0")) == NULL)
			return -ENOMEM;

		/* If the original netmask wasn't /32, add it as a split route */
		if (vpninfo->ip_info.addr && original_netmask) {
			uint32_t nm_bits = inet_addr(original_netmask);
			if (nm_bits != 0xffffffff) { /* 255.255.255.255 */
				struct in_addr net_addr;
				inet_aton(vpninfo->ip_info.addr, &net_addr);
				net_addr.s_addr &= nm_bits; /* clear host bits */

				if ((inc = malloc(sizeof(*inc))) == NULL ||
				    asprintf(&s, "%s/%s", inet_ntoa(net_addr), original_netmask) <= 0)
					return -ENOMEM;
				inc->route = add_option(vpninfo, "split-include", &s);
				inc->next = vpninfo->ip_info.split_includes;
				vpninfo->ip_info.split_includes = inc;
			}
		}
		free(original_netmask);
	}
	if (deferred_netmask)
		vpninfo->ip_info.netmask = add_option(vpninfo, "netmask", &deferred_netmask);

	/* Set 10-second DPD/keepalive (same as Windows client) unless
	 * overridden with --force-dpd */
	if (!vpninfo->ssl_times.dpd)
		vpninfo->ssl_times.dpd = 10;
	vpninfo->ssl_times.keepalive = vpninfo->esp_ssl_fallback = vpninfo->ssl_times.dpd;

	/* Warn about IPv6 config, if present, and ESP config, if absent */
	if (got_ipv6)
		vpn_progress(vpninfo, PRG_ERR, _("GlobalProtect config includes IPv6, but this build does not support\n"
						 "it IPv6 due to a lack of information on how GlobalProtect configures it.\n"
						 "Please report this to <openconnect-devel@lists.infradead.org>.\n"));
#ifdef HAVE_ESP
	if (!got_esp)
		vpn_progress(vpninfo, vpninfo->dtls_state != DTLS_DISABLED ? PRG_ERR : PRG_DEBUG,
			     _("Did not receive ESP keys in GlobalProtect config; tunnel will be TLS only. "));
#endif

	free(s);
	return 0;
}

static int gpst_get_config(struct openconnect_info *vpninfo)
{
	char *orig_path;
	int result;
	struct oc_text_buf *request_body = buf_alloc();
	struct oc_vpn_option *old_cstp_opts = vpninfo->cstp_options;
	const char *old_addr = vpninfo->ip_info.addr, *old_netmask = vpninfo->ip_info.netmask;
	const char *old_addr6 = vpninfo->ip_info.addr6, *old_netmask6 = vpninfo->ip_info.netmask6;
	const char *request_body_type = "application/x-www-form-urlencoded";
	const char *method = "POST";
	char *xml_buf=NULL;
	vpninfo->cstp_options = NULL;

	/* submit getconfig request */
	buf_append(request_body, "client-type=1&protocol-version=p1&app-version=5.1.5-8");
	append_opt(request_body, "clientos", gpst_os_name(vpninfo));
	append_opt(request_body, "os-version", vpninfo->platname);
	append_opt(request_body, "hmac-algo", "sha1,md5,sha256");
	append_opt(request_body, "enc-algo", "aes-128-cbc,aes-256-cbc");
	if (old_addr || old_addr6) {
		append_opt(request_body, "preferred-ip", old_addr);
		append_opt(request_body, "preferred-ipv6", old_addr6);
		filter_opts(request_body, vpninfo->cookie, "preferred-ip,preferred-ipv6", 0);
	} else
		buf_append(request_body, "&%s", vpninfo->cookie);
	if ((result = buf_error(request_body)))
		goto out;

	orig_path = vpninfo->urlpath;
	vpninfo->urlpath = strdup("ssl-vpn/getconfig.esp");
	result = do_https_request(vpninfo, method, request_body_type, request_body,
				  &xml_buf, 0);
	free(vpninfo->urlpath);
	vpninfo->urlpath = orig_path;

	/* parse getconfig result */
	if (result >= 0)
		result = gpst_xml_or_error(vpninfo, xml_buf, gpst_parse_config_xml, NULL, NULL);
	if (result)
		goto out;

	if (!vpninfo->ip_info.mtu) {
		/* FIXME: GP gateway config always seems to be <mtu>0</mtu> */
		char *no_esp_reason = NULL;
#ifdef HAVE_ESP
		if (vpninfo->dtls_state == DTLS_DISABLED)
			no_esp_reason = _("ESP disabled");
		else if (vpninfo->dtls_state == DTLS_NOSECRET)
			no_esp_reason = _("No ESP keys received");
#else
		no_esp_reason = _("ESP support not available in this build");
#endif
		vpninfo->ip_info.mtu = calculate_mtu(vpninfo, !no_esp_reason);
		vpn_progress(vpninfo, PRG_ERR,
			     _("No MTU received. Calculated %d for %s%s\n"), vpninfo->ip_info.mtu,
			     no_esp_reason ? "SSL tunnel. " : "ESP tunnel", no_esp_reason ? : "");
		/* return -EINVAL; */
	}
	if (!vpninfo->ip_info.addr && !vpninfo->ip_info.addr6 &&
	    !vpninfo->ip_info.netmask6) {
		vpn_progress(vpninfo, PRG_ERR,
			     _("No IP address received. Aborting\n"));
		result = -EINVAL;
		goto out;
	}

	result = check_address_sanity(vpninfo, old_addr, old_netmask, old_addr6, old_netmask6);

out:
	free_optlist(old_cstp_opts);
	buf_free(request_body);
	free(xml_buf);
	return result;
}

static int gpst_connect(struct openconnect_info *vpninfo)
{
	int ret;
	struct oc_text_buf *reqbuf;
	const char start_tunnel[12] = "START_TUNNEL"; /* NOT zero-terminated */
	char buf[256];

	/* We do NOT actually start the HTTPS tunnel if ESP is enabled and we received
	 * ESP keys, because the ESP keys become invalid as soon as the HTTPS tunnel
	 * is connected! >:-(
	 */
	if (vpninfo->dtls_state != DTLS_DISABLED && vpninfo->dtls_state != DTLS_NOSECRET)
		return 0;

	/* Connect to SSL VPN tunnel */
	vpn_progress(vpninfo, PRG_DEBUG,
		     _("Connecting to HTTPS tunnel endpoint ...\n"));

	ret = openconnect_open_https(vpninfo);
	if (ret)
		return ret;

	reqbuf = buf_alloc();
	buf_append(reqbuf, "GET %s?", vpninfo->urlpath);
	filter_opts(reqbuf, vpninfo->cookie, "user,authcookie", 1);
	buf_append(reqbuf, " HTTP/1.1\r\n\r\n");
	if ((ret = buf_error(reqbuf)))
		goto out;

	if (vpninfo->dump_http_traffic)
		dump_buf(vpninfo, '>', reqbuf->data);

	vpninfo->ssl_write(vpninfo, reqbuf->data, reqbuf->pos);

	if ((ret = vpninfo->ssl_read(vpninfo, buf, 12)) < 0) {
		if (ret == -EINTR)
			goto out;
		vpn_progress(vpninfo, PRG_ERR,
		             _("Error fetching GET-tunnel HTTPS response.\n"));
		ret = -EINVAL;
		goto out;
	}

	if (!strncmp(buf, start_tunnel, sizeof(start_tunnel))) {
		ret = 0;
	} else if (ret==0) {
		vpn_progress(vpninfo, PRG_ERR,
			     _("Gateway disconnected immediately after GET-tunnel request.\n"));
		ret = -EPIPE;
	} else {
		if (ret==sizeof(start_tunnel)) {
			ret = vpninfo->ssl_gets(vpninfo, buf+sizeof(start_tunnel), sizeof(buf)-sizeof(start_tunnel));
			ret = (ret>0 ? ret : 0) + sizeof(start_tunnel);
		}
		vpn_progress(vpninfo, PRG_ERR,
		             _("Got inappropriate HTTP GET-tunnel response: %.*s\n"), ret, buf);
		ret = -EINVAL;
	}

	if (ret < 0)
		openconnect_close_https(vpninfo, 0);
	else {
		monitor_fd_new(vpninfo, ssl);
		monitor_read_fd(vpninfo, ssl);
		monitor_except_fd(vpninfo, ssl);
		vpninfo->ssl_times.last_rx = vpninfo->ssl_times.last_tx = time(NULL);
		/* connecting the HTTPS tunnel totally invalidates the ESP keys,
		   hence shutdown */
		if (vpninfo->proto->udp_shutdown)
			vpninfo->proto->udp_shutdown(vpninfo);
	}

out:
	buf_free(reqbuf);
	return ret;
}

static int parse_hip_report_check(struct openconnect_info *vpninfo, xmlNode *xml_node, void *cb_data)
{
	char *s = NULL;
	int result = -EINVAL;

	if (!xml_node || !xmlnode_is_named(xml_node, "response"))
		goto out;

	for (xml_node = xml_node->children; xml_node; xml_node=xml_node->next) {
		if (!xmlnode_get_val(xml_node, "hip-report-needed", &s)) {
			if (!strcmp(s, "no"))
				result = 0;
			else if (!strcmp(s, "yes"))
				result = -EAGAIN;
			else
				result = -EINVAL;
			goto out;
		}
	}

out:
	free(s);
	return result;
}

/* Unlike CSD, the HIP security checker runs during the connection
 * phase, not during the authentication phase.
 *
 * The HIP security checker will (probably) ask us to resubmit the
 * HIP report if either of the following changes:
 *   - Client IP address
 *   - Client HIP report md5sum
 *
 * I'm not sure what the md5sum is computed over in the official
 * client, but it doesn't really matter.
 *
 * We just need an identifier for the combination of the local host
 * and the VPN gateway which won't change when our IP address
 * or authcookie are changed.
 */
static int build_csd_token(struct openconnect_info *vpninfo)
{
	struct oc_text_buf *buf;
	unsigned char md5[16];
	int i;

	if (vpninfo->csd_token)
		return 0;

	vpninfo->csd_token = malloc(MD5_SIZE * 2 + 1);
	if (!vpninfo->csd_token)
		return -ENOMEM;

	/* use cookie (excluding volatile authcookie and preferred-ip) to build md5sum */
	buf = buf_alloc();
	filter_opts(buf, vpninfo->cookie, "authcookie,preferred-ip", 0);
	if (buf_error(buf))
		goto out;

	/* save as csd_token */
	openconnect_md5(md5, buf->data, buf->pos);
	for (i=0; i < MD5_SIZE; i++)
		sprintf(&vpninfo->csd_token[i*2], "%02x", md5[i]);

out:
	return buf_free(buf);
}

/* check if HIP report is needed (to ssl-vpn/hipreportcheck.esp) or submit HIP report contents (to ssl-vpn/hipreport.esp) */
static int check_or_submit_hip_report(struct openconnect_info *vpninfo, const char *report)
{
	int result;

	struct oc_text_buf *request_body = buf_alloc();
	const char *request_body_type = "application/x-www-form-urlencoded";
	const char *method = "POST";
	char *xml_buf=NULL, *orig_path;

	/* cookie gives us these fields: authcookie, portal, user, domain, computer, and (maybe the unnecessary) preferred-ip */
	buf_append(request_body, "client-role=global-protect-full&%s", vpninfo->cookie);
	if (vpninfo->ip_info.addr)
		append_opt(request_body, "client-ip", vpninfo->ip_info.addr);
	if (vpninfo->ip_info.addr6)
		append_opt(request_body, "client-ipv6", vpninfo->ip_info.addr6);
	if (report) {
		/* XML report contains many characters requiring URL-encoding (%xx) */
		buf_ensure_space(request_body, strlen(report)*3);
		append_opt(request_body, "report", report);
	} else {
		result = build_csd_token(vpninfo);
		if (result)
			goto out;
		append_opt(request_body, "md5", vpninfo->csd_token);
	}
	if ((result = buf_error(request_body)))
		goto out;

	orig_path = vpninfo->urlpath;
	vpninfo->urlpath = strdup(report ? "ssl-vpn/hipreport.esp" : "ssl-vpn/hipreportcheck.esp");
	result = do_https_request(vpninfo, method, request_body_type, request_body,
				  &xml_buf, 0);
	free(vpninfo->urlpath);
	vpninfo->urlpath = orig_path;

	if (result >= 0)
		result = gpst_xml_or_error(vpninfo, xml_buf, report ? NULL : parse_hip_report_check, NULL, NULL);

out:
	buf_free(request_body);
	free(xml_buf);
	return result;
}

static int run_hip_script(struct openconnect_info *vpninfo)
{
#if !defined(_WIN32) && !defined(__native_client__)
	int pipefd[2];
	int ret;
	pid_t child;
#endif

	if (!vpninfo->csd_wrapper) {
		/* Only warn once */
		if (!vpninfo->last_trojan) {
			vpn_progress(vpninfo, PRG_ERR,
				     _("WARNING: Server asked us to submit HIP report with md5sum %s.\n"
				       "    VPN connectivity may be disabled or limited without HIP report submission.\n    %s\n"),
				     vpninfo->csd_token,
#if defined(_WIN32) || defined(__native_client__)
				     _("However, running the HIP report submission script on this platform is not yet implemented.")
#else
				     _("You need to provide a --csd-wrapper argument with the HIP report submission script.")
#endif
				);
			/* XXX: Many GlobalProtect VPNs work fine despite allegedly requiring HIP report submission */
		}
		return 0;
	}

#if defined(_WIN32) || defined(__native_client__)
	vpn_progress(vpninfo, PRG_ERR,
		     _("Error: Running the 'HIP Report' script on this platform is not yet implemented.\n"));
	return -EPERM;
#else

	vpn_progress(vpninfo, PRG_INFO,
		     _("Trying to run HIP Trojan script '%s'.\n"),
		     vpninfo->csd_wrapper);

#ifdef __linux__
	if (pipe2(pipefd, O_CLOEXEC))
#endif
	{
		if (pipe(pipefd)) {
			vpn_progress(vpninfo, PRG_ERR, _("Failed to create pipe for HIP script\n"));
			return -EPERM;
		}
		set_fd_cloexec(pipefd[0]);
		set_fd_cloexec(pipefd[1]);
	}
	child = fork();
	if (child == -1) {
		vpn_progress(vpninfo, PRG_ERR, _("Failed to fork for HIP script\n"));
		return -EPERM;
	} else if (child > 0) {
		/* in parent: read report from child */
		struct oc_text_buf *report_buf = buf_alloc();
		char b[256];
		int i, status;
		close(pipefd[1]);

		buf_truncate(report_buf);
		while ((i = read(pipefd[0], b, sizeof(b))) > 0)
			buf_append_bytes(report_buf, b, i);

		waitpid(child, &status, 0);
		if (!WIFEXITED(status)) {
			vpn_progress(vpninfo, PRG_ERR,
						 _("HIP script '%s' exited abnormally\n"),
						 vpninfo->csd_wrapper);
			ret = -EINVAL;
		} else if (WEXITSTATUS(status) != 0) {
			vpn_progress(vpninfo, PRG_ERR,
						 _("HIP script '%s' returned non-zero status: %d\n"),
						 vpninfo->csd_wrapper, WEXITSTATUS(status));
			ret = -EINVAL;
		} else {
			vpn_progress(vpninfo, PRG_INFO,
				     _("HIP script '%s' completed successfully (report is %d bytes).\n"),
				     vpninfo->csd_wrapper, report_buf->pos);

			ret = check_or_submit_hip_report(vpninfo, report_buf->data);
			if (ret < 0)
				vpn_progress(vpninfo, PRG_ERR, _("HIP report submission failed.\n"));
			else {
				vpn_progress(vpninfo, PRG_INFO, _("HIP report submitted successfully.\n"));
				ret = 0;
			}
		}
		buf_free(report_buf);
		return ret;
	} else {
		/* in child: run HIP script */
		const char *hip_argv[32];
		int i = 0;
		close(pipefd[0]);
		/* The duplicated fd does not have O_CLOEXEC */
		dup2(pipefd[1], 1);

		if (set_csd_user(vpninfo) < 0)
			exit(1);

		hip_argv[i++] = openconnect_utf8_to_legacy(vpninfo, vpninfo->csd_wrapper);
		hip_argv[i++] = "--cookie";
		hip_argv[i++] = vpninfo->cookie;
		if (vpninfo->ip_info.addr) {
			hip_argv[i++] = "--client-ip";
			hip_argv[i++] = vpninfo->ip_info.addr;
		}
		if (vpninfo->ip_info.addr6) {
			hip_argv[i++] = "--client-ipv6";
			hip_argv[i++] = vpninfo->ip_info.addr6;
		}
		hip_argv[i++] = "--md5";
		hip_argv[i++] = vpninfo->csd_token;
		hip_argv[i++] = "--client-os";
		hip_argv[i++] = gpst_os_name(vpninfo);
		hip_argv[i++] = NULL;
		execv(hip_argv[0], (char **)hip_argv);

		vpn_progress(vpninfo, PRG_ERR,
				 _("Failed to exec HIP script %s\n"), hip_argv[0]);
		exit(1);
	}

#endif /* !_WIN32 && !__native_client__ */
}

static int check_and_maybe_submit_hip_report(struct openconnect_info *vpninfo)
{
	int ret;

	ret = check_or_submit_hip_report(vpninfo, NULL);
	if (ret == -EAGAIN) {
		vpn_progress(vpninfo, PRG_DEBUG,
					 _("Gateway says HIP report submission is needed.\n"));
		ret = run_hip_script(vpninfo);
	} else if (ret == 0)
		vpn_progress(vpninfo, PRG_DEBUG,
					 _("Gateway says no HIP report submission is needed.\n"));

	return ret;
}

int gpst_setup(struct openconnect_info *vpninfo)
{
	int ret;

	/* ESP keys are invalid as soon as we (re-)fetch the configuration, hence shutdown */
	if (vpninfo->proto->udp_shutdown)
		vpninfo->proto->udp_shutdown(vpninfo);

	/* Get configuration */
	ret = gpst_get_config(vpninfo);
	if (ret)
		goto out;

	/* Always check HIP after getting configuration */
	ret = check_and_maybe_submit_hip_report(vpninfo);
	if (ret)
		goto out;

        /* XX: last_trojan is used both as a sentinel to detect the
         * first time we check/submit HIP, and for the mainloop to timeout
         * when periodic re-checking is required.
         */
	vpninfo->last_trojan = time(NULL);

	/* Default HIP re-checking to 3600 seconds unless already set by
	 * --force-trojan or portal config.
	 */
	if (!vpninfo->trojan_interval)
		vpninfo->trojan_interval = 3600;

	/* Connect tunnel immediately if ESP is not going to be used */
	ret = gpst_connect(vpninfo);

out:
	return ret;
}

int gpst_mainloop(struct openconnect_info *vpninfo, int *timeout, int readable)
{
	int ret;
	int work_done = 0;
	uint16_t ethertype;
	uint32_t one, zero, magic;

	/* Starting the HTTPS tunnel kills ESP, so we avoid starting
	 * it if the ESP tunnel is connected or connecting.
	 */
	switch (vpninfo->dtls_state) {
	case DTLS_CONNECTING:
		openconnect_close_https(vpninfo, 0); /* don't keep stale HTTPS socket */
		vpn_progress(vpninfo, PRG_INFO,
			     _("ESP tunnel connected; exiting HTTPS mainloop.\n"));
		vpninfo->dtls_state = DTLS_CONNECTED;
		/* Now that we are connected, let's ensure timeout is less than
		 * or equal to DTLS DPD/keepalive else we might over sleep, eg
		 * if timeout is set to DTLS attempt period from ESP mainloop,
		 * and falsely detect dead peer. */
		if (vpninfo->dtls_times.dpd)
			if (*timeout > vpninfo->dtls_times.dpd * 1000)
				*timeout = vpninfo->dtls_times.dpd * 1000;
		/* fall through */
	case DTLS_CONNECTED:
		/* Rekey or check-and-resubmit HIP if needed */
		if (keepalive_action(&vpninfo->ssl_times, timeout) == KA_REKEY)
			goto do_rekey;
		else if (trojan_check_deadline(vpninfo, timeout))
			goto do_recheck_hip;
		return 0;
	case DTLS_SECRET:
	case DTLS_SLEEPING:
		/* Allow 5 seconds after configuration for ESP to start */
		if (!ka_check_deadline(timeout, time(NULL), vpninfo->new_dtls_started + 5)) {
			vpninfo->delay_tunnel_reason = "awaiting GPST ESP connection";
			return 0;
		}

		/* ... before we switch to HTTPS instead */
		vpn_progress(vpninfo, PRG_ERR,
				     _("Failed to connect ESP tunnel; using HTTPS instead.\n"));
		/* XX: gpst_connect does nothing if ESP is enabled and has secrets */
		vpninfo->dtls_state = DTLS_NOSECRET;
		if (gpst_connect(vpninfo)) {
			vpninfo->quit_reason = "GPST connect failed";
			return 1;
		}
		break;
	case DTLS_NOSECRET:
		/* HTTPS tunnel already started, or getconfig.esp did not provide any ESP keys */
	case DTLS_DISABLED:
		/* ESP is disabled */
		;
	}

	if (vpninfo->ssl_fd == -1)
		goto do_reconnect;

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

		len = ssl_nonblock_read(vpninfo, vpninfo->cstp_pkt->gpst.hdr, receive_mtu + 16);
		if (!len)
			break;
		if (len < 0) {
			vpn_progress(vpninfo, PRG_ERR, _("Packet receive error: %s\n"), strerror(-len));
			goto do_reconnect;
		}
		if (len < 16) {
			vpn_progress(vpninfo, PRG_ERR, _("Short packet received (%d bytes)\n"), len);
			vpninfo->quit_reason = "Short packet received";
			return 1;
		}

		/* check packet header */
		magic = load_be32(vpninfo->cstp_pkt->gpst.hdr);
		ethertype = load_be16(vpninfo->cstp_pkt->gpst.hdr + 4);
		payload_len = load_be16(vpninfo->cstp_pkt->gpst.hdr + 6);
		one = load_le32(vpninfo->cstp_pkt->gpst.hdr + 8);
		zero = load_le32(vpninfo->cstp_pkt->gpst.hdr + 12);

		if (magic != 0x1a2b3c4d)
			goto unknown_pkt;

		if (len != 16 + payload_len) {
			vpn_progress(vpninfo, PRG_ERR,
				     _("Unexpected packet length. SSL_read returned %d (includes 16 header bytes) but header payload_len is %d\n"),
			             len, payload_len);
			dump_buf_hex(vpninfo, PRG_ERR, '<', vpninfo->cstp_pkt->gpst.hdr, 16);
			continue;
		}

		vpninfo->ssl_times.last_rx = time(NULL);
		switch (ethertype) {
		case 0:
			vpn_progress(vpninfo, PRG_DEBUG,
				     _("Got GPST DPD/keepalive response\n"));

			if (one != 0 || zero != 0) {
				vpn_progress(vpninfo, PRG_DEBUG,
					     _("Expected 0000000000000000 as last 8 bytes of DPD/keepalive packet header, but got:\n"));
				dump_buf_hex(vpninfo, PRG_DEBUG, '<', vpninfo->cstp_pkt->gpst.hdr + 8, 8);
			}
			continue;
		case 0x0800:
		case 0x86DD:
			vpn_progress(vpninfo, PRG_TRACE,
				     _("Received IPv%d data packet of %d bytes\n"),
				     ethertype == 0x86DD ? 6 : 4, payload_len);

			if (one != 1 || zero != 0) {
				vpn_progress(vpninfo, PRG_DEBUG,
					     _("Expected 0100000000000000 as last 8 bytes of data packet header, but got:\n"));
				dump_buf_hex(vpninfo, PRG_DEBUG, '<', vpninfo->cstp_pkt->gpst.hdr + 8, 8);
			}

			vpninfo->cstp_pkt->len = payload_len;
			queue_packet(&vpninfo->incoming_queue, vpninfo->cstp_pkt);
			vpninfo->cstp_pkt = NULL;
			work_done = 1;
			continue;
		}

	unknown_pkt:
		vpn_progress(vpninfo, PRG_ERR,
			     _("Unknown packet. Header dump follows:\n"));
		dump_buf_hex(vpninfo, PRG_ERR, '<', vpninfo->cstp_pkt->gpst.hdr, 16);
		vpninfo->quit_reason = "Unknown packet received";
		return 1;
	}


	/* If SSL_write() fails we are expected to try again. With exactly
	   the same data, at exactly the same location. So we keep the
	   packet we had before.... */
	if (vpninfo->current_ssl_pkt) {
	handle_outgoing:
		vpninfo->ssl_times.last_tx = time(NULL);
		unmonitor_write_fd(vpninfo, ssl);

		ret = ssl_nonblock_write(vpninfo,
					 vpninfo->current_ssl_pkt->gpst.hdr,
					 vpninfo->current_ssl_pkt->len + 16);
		if (ret < 0)
			goto do_reconnect;
		else if (!ret) {
			switch (ka_stalled_action(&vpninfo->ssl_times, timeout)) {
			case KA_REKEY:
				goto do_rekey;
			case KA_DPD_DEAD:
				goto peer_dead;
			case KA_NONE:
				return work_done;
			}
		}

		if (ret != vpninfo->current_ssl_pkt->len + 16) {
			vpn_progress(vpninfo, PRG_ERR,
				     _("SSL wrote too few bytes! Asked for %d, sent %d\n"),
				     vpninfo->current_ssl_pkt->len + 16, ret);
			vpninfo->quit_reason = "Internal error";
			return 1;
		}
		/* Don't free the 'special' packets */
		if (vpninfo->current_ssl_pkt != &dpd_pkt)
			free(vpninfo->current_ssl_pkt);

		vpninfo->current_ssl_pkt = NULL;
	}

	if (trojan_check_deadline(vpninfo, timeout)) {
	do_recheck_hip:
		vpn_progress(vpninfo, PRG_INFO, _("GlobalProtect HIP check due\n"));
		/* We could just be lazy and treat this as a reconnect, but that
		 * would require us to repull the routing configuration and new ESP
		 * keys, instead of just redoing the HIP check/submission.
		 *
		 * Therefore we'll just close the HTTPS tunnel (if up),
		 * redo the HIP check/submission, and reconnect the HTTPS tunnel
		 * if needed.
		 */
		openconnect_close_https(vpninfo, 0);
		ret = check_and_maybe_submit_hip_report(vpninfo);
		if (ret) {
			vpn_progress(vpninfo, PRG_ERR, _("HIP check or report failed\n"));
			vpninfo->quit_reason = "HIP check or report failed";
			return ret;
		}
		/* XX: no need to do_reconnect, since ESP doesn't need reconnection */
		if (gpst_connect(vpninfo))
			vpninfo->quit_reason = "GPST connect failed";
		return 1;
	}

	switch (keepalive_action(&vpninfo->ssl_times, timeout)) {
	case KA_REKEY:
	do_rekey:
		vpn_progress(vpninfo, PRG_INFO, _("GlobalProtect rekey due\n"));
		goto do_reconnect;
	case KA_DPD_DEAD:
	peer_dead:
		vpn_progress(vpninfo, PRG_ERR,
			     _("GPST Dead Peer Detection detected dead peer!\n"));
	do_reconnect:
		ret = ssl_reconnect(vpninfo);
		if (ret) {
			vpn_progress(vpninfo, PRG_ERR, _("Reconnect failed\n"));
			vpninfo->quit_reason = "GPST connect failed";
			return ret;
		}
		if (vpninfo->proto->udp_setup)
			vpninfo->proto->udp_setup(vpninfo, vpninfo->dtls_attempt_period);
		return 1;

	case KA_KEEPALIVE:
		/* No need to send an explicit keepalive
		   if we have real data to send */
		if (vpninfo->dtls_state != DTLS_CONNECTED &&
		    vpninfo->outgoing_queue.head)
			break;
		/* fall through */
	case KA_DPD:
		vpn_progress(vpninfo, PRG_DEBUG, _("Send GPST DPD/keepalive request\n"));

		vpninfo->current_ssl_pkt = (struct pkt *)&dpd_pkt;
		goto handle_outgoing;
	}


	/* Service outgoing packet queue */
	while (vpninfo->dtls_state != DTLS_CONNECTED &&
	       (vpninfo->current_ssl_pkt = dequeue_packet(&vpninfo->outgoing_queue))) {
		struct pkt *this = vpninfo->current_ssl_pkt;

		/* IPv4 or IPv6 EtherType */
		int ethertype = this->len && (this->data[0] & 0xF0) == 0x60 ? 0x86DD : 0x0800;

		/* store header */
		store_be32(this->gpst.hdr, 0x1a2b3c4d);
		store_be16(this->gpst.hdr + 4, ethertype);
		store_be16(this->gpst.hdr + 6, this->len);
		store_le32(this->gpst.hdr + 8, 1);
		store_le32(this->gpst.hdr + 12, 0);

		vpn_progress(vpninfo, PRG_TRACE,
			     _("Sending IPv%d data packet of %d bytes\n"),
			     (ethertype == 0x86DD ? 6 : 4), this->len);

		goto handle_outgoing;
	}

	/* Work is not done if we just got rid of packets off the queue */
	return work_done;
}

#ifdef HAVE_ESP
static uint16_t csum(uint16_t *buf, int nwords)
{
	uint32_t sum = 0;
	for(sum=0; nwords>0; nwords--)
		sum += ntohs(*buf++);
	sum = (sum >> 16) + (sum &0xffff);
	sum += (sum >> 16);
	return htons((uint16_t)(~sum));
}

static char magic_ping_payload[16] = "monitor\x00\x00pan ha ";

int gpst_esp_send_probes(struct openconnect_info *vpninfo)
{
	/* The GlobalProtect VPN initiates and maintains the ESP connection
	 * using specially-crafted ICMP ("ping") packets.
	 *
	 * 1) These ping packets have a special magic payload. It must
	 *    include at least the 16 bytes below. The Windows client actually
	 *    sends this 56-byte version, but the remaining bytes don't
	 *    seem to matter:
	 *
	 *    "monitor\x00\x00pan ha 0123456789:;<=>? !\"#$%&\'()*+,-./\x10\x11\x12\x13\x14\x15\x16\x18";
	 *
	 * 2) The ping packets are addressed to the IP supplied in the
	 *    config XML as as <gw-address>. In most cases, this is the
	 *    same as the *external* IP address of the VPN gateway
	 *    (vpninfo->ip_info.gateway_addr), but in some cases it is a
	 *    separate address.
	 *
	 *    Don't blame me. I didn't design this.
	 */
	int pktlen, seq;
	struct pkt *pkt = malloc(sizeof(*pkt) + sizeof(struct ip) + ICMP_MINLEN + sizeof(magic_ping_payload) + vpninfo->pkt_trailer);
	struct ip *iph = (void *)pkt->data;
	struct icmp *icmph = (void *)(pkt->data + sizeof(*iph));
	char *pmagic = (void *)(pkt->data + sizeof(*iph) + ICMP_MINLEN);
	if (!pkt)
		return -ENOMEM;

	if (vpninfo->dtls_fd == -1) {
		int fd = udp_connect(vpninfo);
		if (fd < 0) {
			free(pkt);
			return fd;
		}
		/* We are not connected until we get an ESP packet back */
		vpninfo->dtls_state = DTLS_SLEEPING;
		vpninfo->dtls_fd = fd;
		monitor_fd_new(vpninfo, dtls);
		monitor_read_fd(vpninfo, dtls);
		monitor_except_fd(vpninfo, dtls);
	}

	for (seq=1; seq <= (vpninfo->dtls_state==DTLS_CONNECTED ? 1 : 3); seq++) {
		memset(pkt, 0, sizeof(*pkt) + sizeof(*iph) + ICMP_MINLEN + sizeof(magic_ping_payload));
		pkt->len = sizeof(struct ip) + ICMP_MINLEN + sizeof(magic_ping_payload);

		/* IP Header */
		iph->ip_hl = 5;
		iph->ip_v = 4;
		iph->ip_len = htons(sizeof(*iph) + ICMP_MINLEN + sizeof(magic_ping_payload));
		iph->ip_id = htons(0x4747); /* what the Windows client uses */
		iph->ip_off = htons(IP_DF); /* don't fragment, frag offset = 0 */
		iph->ip_ttl = 64; /* hops */
		iph->ip_p = IPPROTO_ICMP;
		iph->ip_src.s_addr = inet_addr(vpninfo->ip_info.addr);
		iph->ip_dst.s_addr = vpninfo->esp_magic;
		iph->ip_sum = csum((uint16_t *)iph, sizeof(*iph)/2);

		/* ICMP echo request */
		icmph->icmp_type = ICMP_ECHO;
		icmph->icmp_hun.ih_idseq.icd_id = htons(0x4747);
		icmph->icmp_hun.ih_idseq.icd_seq = htons(seq);
		memcpy(pmagic, magic_ping_payload, sizeof(magic_ping_payload)); /* required to get gateway to respond */
		icmph->icmp_cksum = csum((uint16_t *)icmph, (ICMP_MINLEN+sizeof(magic_ping_payload))/2);

		pktlen = construct_esp_packet(vpninfo, pkt, IPPROTO_IPIP);
		if (pktlen < 0 ||
		    send(vpninfo->dtls_fd, (void *)&pkt->esp, pktlen, 0) < 0)
			vpn_progress(vpninfo, PRG_DEBUG, _("Failed to send ESP probe\n"));
	}

	free(pkt);

	vpninfo->dtls_times.last_tx = time(&vpninfo->new_dtls_started);

	return 0;
}

int gpst_esp_catch_probe(struct openconnect_info *vpninfo, struct pkt *pkt)
{
	struct ip *iph = (void *)(pkt->data);

	return ( pkt->len >= 21 && iph->ip_v==4 /* IPv4 header */
		 && iph->ip_p==IPPROTO_ICMP /* IPv4 protocol field == ICMP */
		 && iph->ip_src.s_addr == vpninfo->esp_magic /* source == magic address */
		 && pkt->len >= (iph->ip_hl<<2) + ICMP_MINLEN + sizeof(magic_ping_payload) /* No short-packet segfaults */
		 && pkt->data[iph->ip_hl<<2]==ICMP_ECHOREPLY /* ICMP reply */
		 && !memcmp(&pkt->data[(iph->ip_hl<<2) + ICMP_MINLEN], magic_ping_payload, sizeof(magic_ping_payload)) /* Same magic payload in response */
	       );
}
#endif /* HAVE_ESP */
