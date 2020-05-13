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

int fortinet_obtain_cookie(struct openconnect_info *vpninfo)
{
	return -EINVAL;
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

static int parse_fortinet_xml_config(struct openconnect_info *vpninfo, char *buf, int len,
				     int *ipv4, int *ipv6)
{
	xmlNode *fav_node, *obj_node, *xml_node;
	xmlDocPtr xml_doc;
	int ret = 0, ii, n_dns = 0, n_nbns = 0, default_route = 0;
	char *s = NULL;
	struct oc_text_buf *domains = NULL;

	if (!buf || !len)
		return -EINVAL;

	xml_doc = xmlReadMemory(buf, len, "noname.xml", NULL,
				XML_PARSE_NOERROR|XML_PARSE_RECOVER);
	if (!xml_doc) {
		vpn_progress(vpninfo, PRG_ERR,
			     _("Failed to parse Fortinet config XML\n"));
		vpn_progress(vpninfo, PRG_DEBUG,
			     _("Response was:%s\n"), buf);
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
		if (xmlnode_is_named(xml_node, "IPV4_0"))
			*ipv4 = xmlnode_bool_or_int_value(vpninfo, xml_node);
		else if (xmlnode_is_named(xml_node, "IPV6_0")) {
			if (!vpninfo->disable_ipv6)
				*ipv6 = xmlnode_bool_or_int_value(vpninfo, xml_node);
		} else if (xmlnode_is_named(xml_node, "idle_session_timeout")) {
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

	if (*ipv4 < 1 && *ipv6 < 1) {
	err:
		vpn_progress(vpninfo, PRG_ERR,
			     _("Failed to find VPN options\n"));
		vpn_progress(vpninfo, PRG_DEBUG,
			     _("Response was:%s\n"), buf);
		ret = -EINVAL;
	}
 	xmlFreeDoc(xml_doc);
	free(s);
	return ret;
}

int fortinet_connect(struct openconnect_info *vpninfo)
{
	char *res_buf = NULL;
	struct oc_text_buf *reqbuf = NULL;
	int ret, ipv4 = -1, ipv6 = -1;

	/* XXX: We should do what cstp_connect() does to check that configuration
	   hasn't changed on a reconnect. */

	if (!vpninfo->cookies && vpninfo->cookie)
		http_add_cookie(vpninfo, "SVPNCOOKIE", vpninfo->cookie, 1);

	ret = openconnect_open_https(vpninfo);
	if (ret)
		return ret;

	reqbuf = buf_alloc();

	/* Request VPN allocation
	 *
	 * XXX: Should this be done on every reconnect, or should it have
	 * been part of fortinet_obtain_cookie(). For the moment while
	 * we're letting the auth happen externally for now, let's do it
	 * here...
	 */
	free(vpninfo->urlpath);
	vpninfo->urlpath = strdup("remote/index");
	ret = do_https_request(vpninfo, "GET", NULL, NULL, &res_buf, 0);
	if (ret < 0)
		goto out;
	/* We don't care what it returned as long as it was successful */
	free(res_buf);
	res_buf = NULL;

	/* XXX: Why was auth_request_vpn_allocation() doing this anyway?
	 * It's fetching the legacy non-XML configuration, isn't it?
	 * Do we *actually* have to do this, before fetching the XML config?
	 */
	free(vpninfo->urlpath);
	vpninfo->urlpath = strdup("remote/fortisslvpn");
	ret = do_https_request(vpninfo, "GET", NULL, NULL, &res_buf, 0);
	if (ret < 0)
		goto out;
	/* We don't care what it returned as long as it was successful */
	free(res_buf);
	res_buf = NULL;

	free(vpninfo->urlpath);
	vpninfo->urlpath = strdup("remote/fortisslvpn_xml");
	ret = do_https_request(vpninfo, "GET", NULL, NULL, &res_buf, 0);
	if (ret < 0)
		goto out;

	ret = parse_fortinet_xml_config(vpninfo, res_buf, ret, &ipv4, &ipv6);
	if (ret)
		goto out;

	if (ipv4 == -1)
		ipv4 = 0;
	if (ipv6 == -1)
		ipv6 = 0;

	/* Now fetch the connection options */
	ret = openconnect_open_https(vpninfo);
	if (ret)
		goto out;
	reqbuf = buf_alloc();
	buf_append(reqbuf, "GET /remote/sslvpn-tunnel HTTP/1.1\r\n");
	http_common_headers(vpninfo, reqbuf);
	buf_append(reqbuf, "\r\n");

	if (buf_error(reqbuf)) {
		vpn_progress(vpninfo, PRG_ERR,
			     _("Error creating fortinet connection request\n"));
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

	if (ret != 201 && ret != 200) {
		vpn_progress(vpninfo, PRG_ERR,
			     _("Unexpected %d result from server\n"),
			     ret);
		ret = -EINVAL;
		goto out;
	}

	vpninfo->ppp = openconnect_ppp_new(PPP_ENCAP_FORTINET_HDLC, ipv4, ipv6);
	if (!vpninfo->ppp) {
		ret = -ENOMEM;
		goto out;
	}

	ret = 0; /* success */
 out:
	if (ret)
		openconnect_close_https(vpninfo, 0);
	else {
		monitor_fd_new(vpninfo, ssl);
		monitor_read_fd(vpninfo, ssl);
		monitor_except_fd(vpninfo, ssl);
	}
	buf_free(reqbuf);
	free(res_buf);

	free(vpninfo->cstp_pkt);
	vpninfo->cstp_pkt = NULL;

	vpninfo->ip_info.mtu = 1400;

	return ret;
}

int fortinet_bye(struct openconnect_info *vpninfo, const char *reason)
{
	char *orig_path;
	char *res_buf=NULL;
	int ret;

	/* XX: handle clean PPP termination?
	   ppp_bye(vpninfo); */

	/* We need to close and reopen the HTTPS connection (to kill
	 * the fortinet tunnel) and submit a new HTTPS request to logout.
	 */
	openconnect_close_https(vpninfo, 0);

	orig_path = vpninfo->urlpath;
	vpninfo->urlpath = strdup("remote/logout");
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
