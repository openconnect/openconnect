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

#define XCAST(x) ((const xmlChar *)(x))

int f5_obtain_cookie(struct openconnect_info *vpninfo)
{
	return -EINVAL;
}

/*
 * Parse the 'favorites' profile information from
 * /vdesk/vpn/index.php3?outform=xml&client_version=2.0
 * which looks something like this:
 *
 *   <?xml version="1.0" encoding="utf-8"?>
 *     <favorites type="VPN" limited="YES">
 *       <favorite id="/Common/demo_vpn_resource">
 *         <caption>demo_vpn_resource</caption>
 *         <name>/Common/demo_vpn_resource</name>
 *         <params>resourcename=/Common/demo_vpn_resource</params>
 *       </favorite>
 *     </favorites>
 *
 * Extract the content of the "params" node which is needed for the
 * next request.
 */
static int parse_profile(struct openconnect_info *vpninfo, struct oc_text_buf *buf,
			 char **params)
{
	xmlDocPtr xml_doc;
	xmlNode *xml_node, *xml_node2, *xml_node3;
	char *type = NULL;
	int ret;

	if (buf_error(buf))
		return buf_error(buf);

	xml_doc = xmlReadMemory(buf->data, buf->pos, "noname.xml", NULL,
				XML_PARSE_NOERROR|XML_PARSE_RECOVER);
	if (!xml_doc) {
		vpn_progress(vpninfo, PRG_ERR,
			     _("Failed to parse F5 profile response\n"));
		vpn_progress(vpninfo, PRG_DEBUG,
			     _("Response was:%s\n"), buf->data);
		return -EINVAL;
	}
	xml_node = xmlDocGetRootElement(xml_doc);
	for (; xml_node; xml_node = xml_node->next) {
		if (xml_node->type != XML_ELEMENT_NODE)
			continue;

		if (!xmlnode_is_named(xml_node, "favorites"))
			continue;

		type = (char *)xmlGetProp(xml_node, XCAST("type"));
		if (!type)
			continue;

		if (strcmp(type, "VPN")) {
			free(type);
			continue;
		}
		free(type);

		for (xml_node2 = xmlFirstElementChild(xml_node);
		     xml_node2;
		     xml_node2 = xmlNextElementSibling(xml_node2)) {
			if (!xmlnode_is_named(xml_node2, "favorite"))
				continue;

			for (xml_node3 = xmlFirstElementChild(xml_node2);
			     xml_node3;
			     xml_node3 = xmlNextElementSibling(xml_node3)) {
				if (!xmlnode_is_named(xml_node3, "params"))
					continue;
				*params = (char *)xmlNodeGetContent(xml_node3);
				ret = 0;
				goto out;
			}
		}
	}

	vpn_progress(vpninfo, PRG_ERR,
		     _("Failed to find VPN profile parameters\n"));
	vpn_progress(vpninfo, PRG_DEBUG,
		     _("Response was:%s\n"), buf->data);
	ret = -EINVAL;
 out:
	xmlFreeDoc(xml_doc);
	return ret;
}

static int xmlnode_bool_or_int_value(struct openconnect_info *vpninfo, xmlNode *node)
{
	int ret = -1;
	char *content = (char *)xmlNodeGetContent(node);
	if (!content)
		return -1;

	if (isdigit(content[0]))
		ret = atoi(content);
	if (!strcasecmp(content, "yes") || !strcasecmp(content, "on"))
		ret = 1;
	if (!strcasecmp(content, "no") || !strcasecmp(content, "off"))
		ret = 0;

	free(content);
	return ret;
}

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

static int parse_options(struct openconnect_info *vpninfo, struct oc_text_buf *buf,
			 char **session_id, char **ur_z, int *ipv4, int *ipv6, int *hdlc)
{
	xmlNode *fav_node, *obj_node, *xml_node;
	xmlDocPtr xml_doc;
	int ret = 0, ii, n_dns = 0, n_nbns = 0, default_route = 0;
	char *s = NULL;
	struct oc_text_buf *domains = NULL;

	if (buf_error(buf))
		return buf_error(buf);

	xml_doc = xmlReadMemory(buf->data, buf->pos, "noname.xml", NULL,
				XML_PARSE_NOERROR|XML_PARSE_RECOVER);
	if (!xml_doc) {
		vpn_progress(vpninfo, PRG_ERR,
			     _("Failed to parse F5 options response\n"));
		vpn_progress(vpninfo, PRG_DEBUG,
			     _("Response was:%s\n"), buf->data);
		return -EINVAL;
	}
	fav_node = xmlDocGetRootElement(xml_doc);
	if (!xmlnode_is_named(fav_node, "favorite"))
		goto err;

	obj_node = xmlFirstElementChild(fav_node);
	if (!xmlnode_is_named(obj_node, "object"))
		goto err;

	/* Clear old options which will be overwritten */
	vpninfo->ip_info.addr = vpninfo->ip_info.netmask = NULL;
	vpninfo->ip_info.addr6 = vpninfo->ip_info.netmask6 = NULL;
	vpninfo->ip_info.domain = NULL;
	vpninfo->cstp_options = NULL;
	for (ii = 0; ii < 3; ii++)
		vpninfo->ip_info.dns[ii] = vpninfo->ip_info.nbns[ii] = NULL;
	free_split_routes(vpninfo);

	domains = buf_alloc();

	for (xml_node = xmlFirstElementChild(obj_node);
	     xml_node;
	     xml_node = xmlNextElementSibling(xml_node)) {
		if (xmlnode_is_named(xml_node, "ur_Z"))
			*ur_z = (char *)xmlNodeGetContent(xml_node);
		else if (xmlnode_is_named(xml_node, "Session_ID"))
			*session_id = (char *)xmlNodeGetContent(xml_node);
		else if (xmlnode_is_named(xml_node, "IPV4_0"))
			*ipv4 = xmlnode_bool_or_int_value(vpninfo, xml_node);
		else if (xmlnode_is_named(xml_node, "IPV6_0")) {
			if (!vpninfo->disable_ipv6)
				*ipv6 = xmlnode_bool_or_int_value(vpninfo, xml_node);
		} else if (xmlnode_is_named(xml_node, "hdlc_framing"))
			*hdlc = xmlnode_bool_or_int_value(vpninfo, xml_node);
		else if (xmlnode_is_named(xml_node, "idle_session_timeout")) {
			int sec = vpninfo->idle_timeout = xmlnode_bool_or_int_value(vpninfo, xml_node);
			vpn_progress(vpninfo, PRG_INFO, _("Idle timeout is %d minutes.\n"), sec/60);
		} else if (xmlnode_is_named(xml_node, "tunnel_port_dtls")) {
			int port = xmlnode_bool_or_int_value(vpninfo, xml_node);
			udp_sockaddr(vpninfo, port);
			vpn_progress(vpninfo, PRG_INFO, _("DTLS port is %d.\n"), port);
		} else if (xmlnode_is_named(xml_node, "UseDefaultGateway0")) {
			default_route = xmlnode_bool_or_int_value(vpninfo, xml_node);
			vpn_progress(vpninfo, PRG_INFO, _("Got UseDefaultGateway0 value of %d.\n"), default_route);
		} else if (xmlnode_is_named(xml_node, "SplitTunneling0")) {
			int st = xmlnode_bool_or_int_value(vpninfo, xml_node);
			vpn_progress(vpninfo, PRG_INFO, _("Got SplitTunneling0 value of %d.\n"), st);
                }
		/* XX: This is an objectively stupid way to use XML, a hierarchical data format. */
		else if (   (!strncmp((char *)xml_node->name, "DNS", 3) && isdigit(xml_node->name[3]))
			 || (!strncmp((char *)xml_node->name, "DNS6_", 5) && isdigit(xml_node->name[5])) ) {
			s = (char *)xmlNodeGetContent(xml_node);
			if (s && *s) {
				vpn_progress(vpninfo, PRG_INFO, _("Got IPv%d DNS server %s.\n"),
					     xml_node->name[4]=='_' ? 6 : 4, s);
				if (n_dns < 3) vpninfo->ip_info.dns[n_dns++] = add_option(vpninfo, "DNS", &s);
			}
		} else if (!strncmp((char *)xml_node->name, "WINS", 4) && isdigit(xml_node->name[4])) {
			s = (char *)xmlNodeGetContent(xml_node);
			if (s && *s) {
				vpn_progress(vpninfo, PRG_INFO, _("Got WINS/NBNS server %s.\n"), s);
				if (n_nbns < 3) vpninfo->ip_info.dns[n_nbns++] = add_option(vpninfo, "WINS", &s);
			}
		} else if (!strncmp((char *)xml_node->name, "DNSSuffix", 9) && isdigit(xml_node->name[9])) {
			s = (char *)xmlNodeGetContent(xml_node);
			if (s && *s) {
				vpn_progress(vpninfo, PRG_INFO, _("Got search domain %s.\n"), s);
				buf_append(domains, "%s ", s);
			}
		} else if (   (!strncmp((char *)xml_node->name, "LAN", 3) && isdigit((char)xml_node->name[3]))
			   || (!strncmp((char *)xml_node->name, "LAN6_", 5) && isdigit((char)xml_node->name[5]))) {
			s = (char *)xmlNodeGetContent(xml_node);
			if (s && *s) {
				char *word, *next;
				struct oc_split_include *inc;

				for (word = (char *)add_option(vpninfo, "route-list", &s);
				     *word; word = next) {
					for (next = word; *next && !isspace(*next); next++);
					if (*next)
						*next++ = 0;
					if (next == word + 1)
						continue;

					inc = malloc(sizeof(*inc));
					inc->route = word;
					inc->next = vpninfo->ip_info.split_includes;
					vpninfo->ip_info.split_includes = inc;
					vpn_progress(vpninfo, PRG_INFO, _("Got IPv%d route %s.\n"),
						     xml_node->name[4]=='_' ? 6 : 4, word);
				}
			}
		}
	}

	if (default_route && ipv4)
		vpninfo->ip_info.netmask = strdup("0.0.0.0");
	if (default_route && ipv6)
		vpninfo->ip_info.netmask6 = strdup("::");
	if (buf_error(domains) == 0 && domains->pos > 0) {
		domains->data[domains->pos-1] = '\0';
		vpninfo->ip_info.domain = add_option(vpninfo, "search", &domains->data);
	}
	buf_free(domains);

	if ( (*ipv4 < 1 && *ipv6 < 1) || !*ur_z || !*session_id) {
	err:
		vpn_progress(vpninfo, PRG_ERR,
			     _("Failed to find VPN options\n"));
		vpn_progress(vpninfo, PRG_DEBUG,
			     _("Response was:%s\n"), buf->data);
		ret = -EINVAL;
	}
 	xmlFreeDoc(xml_doc);
	free(s);
	return ret;
}

static int get_ip_address(struct openconnect_info *vpninfo, char *header, char *val) {
	char *s;
	if (!strcasecmp(header, "X-VPN-client-IP")) {
		vpn_progress(vpninfo, PRG_INFO,
			     _("Got legacy IP address %s\n"), val);
		vpninfo->ip_info.addr = s = strdup(val);
		if (!s) return -ENOMEM;
	} else if (!strcasecmp(header, "X-VPN-client-IPv6")) {
		vpn_progress(vpninfo, PRG_INFO,
			     _("Got IPv6 address %s\n"), val);
		vpninfo->ip_info.addr6 = s = strdup(val);
		if (!s) return -ENOMEM;
	}
        /* XX: The server's IP address(es) X-VPN-server-{IP,IPv6} are also
         * sent, but the utility of these is unclear. */
	return 0;
}

int f5_connect(struct openconnect_info *vpninfo)
{
	int ret;
	struct oc_text_buf *reqbuf;
	char *profile_params = NULL;
	char *sid = NULL, *ur_z = NULL;
	int ipv4 = -1, ipv6 = -1, hdlc = -1;

	/* XXX: We should do what cstp_connect() does to check that configuration
	   hasn't changed on a reconnect. */

	if (!vpninfo->cookies && vpninfo->cookie)
		http_add_cookie(vpninfo, "MRHSession", vpninfo->cookie, 1);

	ret = openconnect_open_https(vpninfo);
	if (ret)
		return ret;

	reqbuf = buf_alloc();

	buf_append(reqbuf, "GET /vdesk/vpn/index.php3?outform=xml&client_version=2.0 HTTP/1.1\r\n");
	http_common_headers(vpninfo, reqbuf);
	buf_append(reqbuf, "\r\n");

	if (buf_error(reqbuf)) {
		vpn_progress(vpninfo, PRG_ERR,
			     _("Error creating f5 profile request\n"));
		ret = buf_error(reqbuf);
		goto out;
	}
	if (vpninfo->dump_http_traffic)
		dump_buf(vpninfo, '>', reqbuf->data);

	ret = vpninfo->ssl_write(vpninfo, reqbuf->data, reqbuf->pos);
	if (ret < 0)
		goto out;

	ret = process_http_response(vpninfo, 0, NULL, reqbuf);
	if (ret < 0)
		goto out;

	if (ret != 201 && ret != 200) {
		vpn_progress(vpninfo, PRG_ERR,
			     _("Unexpected %d result from server\n"),
			     ret);
		ret = -EINVAL;
		goto out;
	}

	if (vpninfo->dump_http_traffic)
		dump_buf(vpninfo, '<', reqbuf->data);
	ret = parse_profile(vpninfo, reqbuf, &profile_params);
	if (ret)
		goto out;

	vpn_progress(vpninfo, PRG_DEBUG,
		     _("Got profile parameters '%s'\n"), profile_params);
	buf_truncate(reqbuf);

	/* Now fetch the connection options */
	ret = openconnect_open_https(vpninfo);
	if (ret)
		goto out;
	buf_append(reqbuf, "GET /vdesk/vpn/connect.php3?%s&outform=xml&client_version=2.0 HTTP/1.1\r\n",
		   profile_params);
	http_common_headers(vpninfo, reqbuf);
	buf_append(reqbuf, "\r\n");

	if (buf_error(reqbuf)) {
		vpn_progress(vpninfo, PRG_ERR,
			     _("Error creating f5 options request\n"));
		ret = buf_error(reqbuf);
		goto out;
	}
	if (vpninfo->dump_http_traffic)
		dump_buf(vpninfo, '>', reqbuf->data);
	ret = vpninfo->ssl_write(vpninfo, reqbuf->data, reqbuf->pos);
	if (ret < 0)
		goto out;

	ret = process_http_response(vpninfo, 0, NULL, reqbuf);
	if (ret < 0)
		goto out;

	if (ret != 201 && ret != 200) {
		vpn_progress(vpninfo, PRG_ERR,
			     _("Unexpected %d result from server\n"),
			     ret);
		ret = -EINVAL;
		goto out;
	}

	if (vpninfo->dump_http_traffic)
		dump_buf(vpninfo, '<', reqbuf->data);
	ret = parse_options(vpninfo, reqbuf, &sid, &ur_z, &ipv4, &ipv6, &hdlc);
	if (ret)
		goto out;

	vpn_progress(vpninfo, PRG_DEBUG,
		     _("Got ipv4 %d ipv6 %d hdlc %d ur_Z '%s'\n"), ipv4, ipv6, hdlc, ur_z);
	buf_truncate(reqbuf);

	if (ipv4 == -1)
		ipv4 = 0;
	if (ipv6 == -1)
		ipv6 = 0;
	if (hdlc != 0) {
		vpn_progress(vpninfo, PRG_ERR,
			     _("PPP with HDLC framing is not supported yet\n"));
		ret = -EINVAL;
		goto out;
	}
	/* Now fetch the connection options */
	ret = openconnect_open_https(vpninfo);
	if (ret)
		goto out;
	buf_append(reqbuf, "GET /myvpn?sess=%s&hdlc_framing=%s&ipv4=%s&ipv6=%s&Z=%s&hostname=",
		   sid, hdlc?"yes":"no", ipv4?"yes":"no", ipv6?"yes":"no", ur_z);
	buf_append_base64(reqbuf, vpninfo->localname, strlen(vpninfo->localname));
	buf_append(reqbuf, " HTTP/1.1\r\n");
	http_common_headers(vpninfo, reqbuf);
	buf_append(reqbuf, "\r\n");

	if (buf_error(reqbuf)) {
		vpn_progress(vpninfo, PRG_ERR,
			     _("Error creating f5 options request\n"));
		ret = buf_error(reqbuf);
		goto out;
	}
	if (vpninfo->dump_http_traffic)
		dump_buf(vpninfo, '>', reqbuf->data);
	ret = vpninfo->ssl_write(vpninfo, reqbuf->data, reqbuf->pos);
	if (ret < 0)
		goto out;

	ret = process_http_response(vpninfo, 1, get_ip_address, reqbuf);
	if (ret < 0)
		goto out;

	if (ret != 201 && ret != 200) {
		vpn_progress(vpninfo, PRG_ERR,
			     _("Unexpected %d result from server\n"),
			     ret);
		ret = -EINVAL;
		goto out;
	}

	if (!(vpninfo->ppp = openconnect_ppp_new(hdlc, ipv4, ipv6, 0 /* we_go_first */))) {
		ret = -ENOMEM;
		goto out;
	}

	ppp_negotiate_config(vpninfo);
	ppp_print_state(vpninfo);
	ret = -EIO; /* success */
 out:
	free(profile_params);
	free(sid);
	free(ur_z);
	if (ret)
		openconnect_close_https(vpninfo, 0);
	else {
		monitor_fd_new(vpninfo, ssl);
		monitor_read_fd(vpninfo, ssl);
		monitor_except_fd(vpninfo, ssl);
	}
	buf_free(reqbuf);

	free(vpninfo->cstp_pkt);
	vpninfo->cstp_pkt = NULL;

	vpninfo->ip_info.mtu = 1400;

	return ret;
}

int f5_mainloop(struct openconnect_info *vpninfo, int *timeout, int readable)
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
		int len;

		if (!vpninfo->cstp_pkt) {
			vpninfo->cstp_pkt = malloc(sizeof(struct pkt) + receive_mtu);
			if (!vpninfo->cstp_pkt) {
				vpn_progress(vpninfo, PRG_ERR, _("Allocation failed\n"));
				break;
			}
		}

		len = ssl_nonblock_read(vpninfo, vpninfo->cstp_pkt->data, receive_mtu);
		if (!len)
			break;
		if (len < 0)
			goto do_reconnect;
		if (len < 8) {
			vpn_progress(vpninfo, PRG_ERR, _("Short packet received (%d bytes)\n"), len);
			vpninfo->quit_reason = "Short packet received";
			return 1;
		}

		/* Check it looks like a valid IP packet, and then check for the special
		 * IP protocol 255 that is used for control stuff. Maybe also look at length
		 * and be prepared to *split* IP packets received in the same read() call. */

		vpninfo->ssl_times.last_rx = time(NULL);

		vpn_progress(vpninfo, PRG_TRACE,
			     _("Received uncompressed data packet of %d bytes\n"),
			     len);
		vpninfo->cstp_pkt->len = len;
		queue_packet(&vpninfo->incoming_queue, vpninfo->cstp_pkt);
		vpninfo->cstp_pkt = NULL;
		work_done = 1;
		continue;
	}


	/* If SSL_write() fails we are expected to try again. With exactly
	   the same data, at exactly the same location. So we keep the
	   packet we had before.... */
	if (vpninfo->current_ssl_pkt) {
	handle_outgoing:
		vpninfo->ssl_times.last_tx = time(NULL);
		unmonitor_write_fd(vpninfo, ssl);

		ret = ssl_nonblock_write(vpninfo,
					 vpninfo->current_ssl_pkt->data,
					 vpninfo->current_ssl_pkt->len);
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
				goto do_rekey;
			case KA_NONE:
				return work_done;
			default:
				/* This should never happen */
				;
			}
		}

		if (ret != vpninfo->current_ssl_pkt->len) {
			vpn_progress(vpninfo, PRG_ERR,
				     _("SSL wrote too few bytes! Asked for %d, sent %d\n"),
				     vpninfo->current_ssl_pkt->len + 8, ret);
			vpninfo->quit_reason = "Internal error";
			return 1;
		}

		vpninfo->current_ssl_pkt = NULL;
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
	do_reconnect:
		ret = -EINVAL; // Not implemented yet f5_reconnect(vpninfo);
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

		//vpninfo->current_ssl_pkt = (struct pkt *)&dpd_pkt;
		//goto handle_outgoing;
		break;

	case KA_KEEPALIVE:
		/* No need to send an explicit keepalive
		   if we have real data to send */
		if (vpninfo->dtls_state != DTLS_CONNECTED &&
		    vpninfo->outgoing_queue.head)
			break;

		vpn_progress(vpninfo, PRG_DEBUG, _("Send CSTP Keepalive\n"));

		//vpninfo->current_ssl_pkt = (struct pkt *)&keepalive_pkt;
		//goto handle_outgoing;
		break;

	case KA_NONE:
		;
	}

	/* Service outgoing packet queue, if no DTLS */
	while (vpninfo->dtls_state != DTLS_CONNECTED &&
	       (vpninfo->current_ssl_pkt = dequeue_packet(&vpninfo->outgoing_queue))) {
		struct pkt *this = vpninfo->current_ssl_pkt;

		vpn_progress(vpninfo, PRG_TRACE,
			     _("Sending uncompressed data packet of %d bytes\n"),
			     this->len);

		vpninfo->current_ssl_pkt = this;
		goto handle_outgoing;
	}

	/* Work is not done if we just got rid of packets off the queue */
	return work_done;
}

int f5_bye(struct openconnect_info *vpninfo, const char *reason)
{
	char *orig_path;
	char *res_buf=NULL;
	int ret;

	/* We need to close and reopen the HTTPS connection (to kill
	 * the f5 tunnel) and submit a new HTTPS request to logout.
	 */
	openconnect_close_https(vpninfo, 0);

	orig_path = vpninfo->urlpath;
	vpninfo->urlpath = strdup("vdesk/hangup.php3?hangup_error=1"); /* redirect segfaults without strdup */
	ret = do_https_request(vpninfo, "GET", NULL, NULL, &res_buf, 0);
	free(vpninfo->urlpath);
	vpninfo->urlpath = orig_path;

	if (ret < 0)
		vpn_progress(vpninfo, PRG_ERR, _("Logout failed.\n"));
	else
		vpn_progress(vpninfo, PRG_INFO, _("Logout successful.\n"));

	free(res_buf);
	return ret;
}
