/*
 * OpenConnect (SSL + DTLS) VPN client
 *
 * Copyright © 2008-2015 Microsoft Corp
 *
 * Author: Alan Jowett <alan.jowett@microsoft.com>
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

#include <ctype.h>
#include <errno.h>
#include <stdlib.h>
#include <string.h>

#include "openconnect-internal.h"

int set_oidc_token(struct openconnect_info *vpninfo, const char *token_str)
{
	int ret;
	char *file_token = NULL;

	if (token_str) {
		switch(token_str[0]) {
		case '@':
			token_str++;
			/* fall through */
		case '/':
			ret = openconnect_read_file(vpninfo, token_str, &file_token);
			if (ret < 0)
				return ret;
		}
	}
	
	if (!file_token) {
		vpninfo->bearer_token = strdup(token_str);
		if (!vpninfo->bearer_token) {
			return 1;
		}
	}
	else {
		vpninfo->bearer_token = file_token;
	}
	vpninfo->token_mode = OC_TOKEN_MODE_OIDC;
	return 0;
}


