/*
 * OpenConnect (SSL + DTLS) VPN client
 *
 * Copyright © 2020 Andreas Gnau
 *
 * Author: Andreas Gnau <rondom@rondom.de>
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

int nx_obtain_cookie(struct openconnect_info *vpninfo)
{
	vpn_progress(
		vpninfo, PRG_ERR,
		_("Authentication for Net Extender not implemented yet.\n"));
	return -EINVAL;
}

void nx_common_headers(struct openconnect_info *vpninfo,
		       struct oc_text_buf *buf)
{
	http_common_headers(vpninfo, buf);
	dump_buf(vpninfo, PRG_ERR, buf->data); // TODO: XXX
	// TODO: Is this the place to manipulate user agent (NX requires the UA to contain netextender)
}

int nx_connect(struct openconnect_info *vpninfo)
{
	int ret = -EINVAL;
	struct oc_text_buf *reqbuf = NULL;
	char *auth_token = NULL;
	int auth_token_len = -1;
	int ipv4 = 1; // TODO: get from info
	int ipv6 = 0;

	// TODO: check for correct swap-cookie
	if (!vpninfo->cookie) {
		vpn_progress(vpninfo, PRG_ERR,
			     _("Malformed cookie or no cookie given\n"));
		return -EINVAL;
	}
	// TODO: get auth_token and other info from /cgi-bin/sslvpnclient?launchplatform=mac&neProto=3&supportipv6=yes
	auth_token = openconnect_base64_decode(&auth_token_len, vpninfo->cookie);
	if (!auth_token)
		return auth_token_len;
	// TODO: get ECP (trojan) info from /cgi-bin/sslvpnclient?epcversionquery=nxx
	ret = openconnect_open_https(vpninfo);
	if (ret)
		return ret;

	reqbuf = buf_alloc();
	if (!reqbuf)
		return -errno;

	buf_append(reqbuf, "CONNECT localhost:0 HTTP/1.0\r\n");
	buf_append(reqbuf, "X-SSLVPN-PROTOCOL: 2.0\r\n");
	buf_append(reqbuf, "X-SSLVPN-SERVICE: NETEXTENDER\r\n");
	buf_append(reqbuf, "Connection-Medium: MacOS\r\n");
	buf_append(reqbuf, "Frame-Encode: off\r\n");
	buf_append(reqbuf, "X-NE-PROTOCOL: 2.0\r\n");
	buf_append(reqbuf, "Proxy-Authorization: %.*s\r\n", auth_token_len,
		   auth_token);
	// TODO: use set string for nx in openconnect_set_reported_os
	buf_append(reqbuf, "X-NX-Client-Platform: Linux\r\n");
	buf_append(reqbuf, "User-Agent: %s\r\n", vpninfo->useragent);
	buf_append(reqbuf, "\r\n");
	if ((ret = buf_error(reqbuf) != 0)) {
		vpn_progress(vpninfo, PRG_ERR,
			     _("Error creating HTTPS CONNECT request\n"));
		goto out;
	}
	if (vpninfo->dump_http_traffic)
		dump_buf(vpninfo, '>', reqbuf->data);
	vpninfo->ssl_write(vpninfo, reqbuf->data, reqbuf->pos);

	// In case of success, there won't be a HTTP 200, data will start straight away
	// TODO: refactor process_http_response to handle this, so we can use it and do proper error handling
	// We expect either a HTTP response (failure) or a size (BE, 4b) (success).
	// The size will be smaller than 0x01000000 for sure, so we can use the
	// first byte as an indicator of success and don't need to check for "HTTP"
	// TODO: actually handle errors as described above
	vpn_progress(vpninfo, PRG_DEBUG, _("Connection established\n"));
	vpninfo->ppp = openconnect_ppp_new(PPP_ENCAP_NX_HDLC, ipv4, ipv6);
	if (!vpninfo->ppp) {
		ret = -ENOMEM;
		goto out;
	}

	ret = 0;

out:
	if (ret < 0)
		openconnect_close_https(vpninfo, 0);
	else {
		monitor_fd_new(vpninfo, ssl);
		monitor_read_fd(vpninfo, ssl);
		monitor_except_fd(vpninfo, ssl);
	}

	buf_free(reqbuf);
	free(auth_token);
	return ret;
}

int nx_bye(struct openconnect_info *vpninfo, const char *reason)
{
	//ppp_bye(vpninfo);
	// TODO: implement
	return -EINVAL;
}