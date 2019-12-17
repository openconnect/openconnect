/*
 * OpenConnect (SSL + DTLS) VPN client
 *
 * Copyright © 2008-2015 Intel Corporation.
 * Copyright © 2008 Nick Andrew <nick@nick-andrew.net>
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

#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <fcntl.h>
#include <sys/types.h>
#include <libxml/parser.h>
#include <libxml/tree.h>
#include <string.h>
#include <ctype.h>
#include <errno.h>

#include "openconnect-internal.h"

static char *fetch_and_trim(xmlNode *node)
{
	char *str = (char *)xmlNodeGetContent(node), *p;
	int i, len;

	if (!str)
		return NULL;

	len = strlen(str);
	for (i = len-1; i >= 0; i--) {
		if (isspace((int)(unsigned char)str[i]))
			str[i] = 0;
		else
			break;
	}

	for (p = str; isspace((int)(unsigned char)*p); p++)
		;

	if (p == str)
		return str;

	p = strdup(p);
	free(str);
	return p;
}

int config_lookup_host(struct openconnect_info *vpninfo, const char *host)
{
	int i;
	ssize_t size;
	char *xmlfile;
	unsigned char sha1[SHA1_SIZE];
	xmlDocPtr xml_doc;
	xmlNode *xml_node, *xml_node2;

	if (!vpninfo->xmlconfig)
		return 0;

	size = openconnect_read_file(vpninfo, vpninfo->xmlconfig, &xmlfile);
	if (size == -ENOENT) {
		fprintf(stderr, _("Treating host \"%s\" as a raw hostname\n"), host);
		return 0;
	} else if (size <= 0) {
		return size;
	}

	if (openconnect_sha1(sha1, xmlfile, size)) {
		fprintf(stderr, _("Failed to SHA1 existing file\n"));
		free(xmlfile);
		return -1;
	}

	for (i = 0; i < SHA1_SIZE; i++)
		snprintf(&vpninfo->xmlsha1[i*2], 3, "%02x", sha1[i]);

	vpn_progress(vpninfo, PRG_DEBUG, _("XML config file SHA1: %s\n"),
		     vpninfo->xmlsha1);

	xml_doc = xmlReadMemory(xmlfile, size, "noname.xml", NULL, 0);

	free(xmlfile);

	if (!xml_doc) {
		fprintf(stderr, _("Failed to parse XML config file %s\n"),
			vpninfo->xmlconfig);
		fprintf(stderr, _("Treating host \"%s\" as a raw hostname\n"),
			host);
		return 0;
	}
	xml_node = xmlDocGetRootElement(xml_doc);

	for (xml_node = xml_node->children; xml_node; xml_node = xml_node->next) {
		if (xml_node->type == XML_ELEMENT_NODE &&
		    !strcmp((char *)xml_node->name, "ServerList")) {

			for (xml_node = xml_node->children; xml_node && !vpninfo->hostname;
			     xml_node = xml_node->next) {

				if (xml_node->type == XML_ELEMENT_NODE &&
				    !strcmp((char *)xml_node->name, "HostEntry")) {
					int match = 0;

					for (xml_node2 = xml_node->children;
					     match >= 0 && xml_node2; xml_node2 = xml_node2->next) {

						if (xml_node2->type != XML_ELEMENT_NODE)
							continue;

						if (!match && !strcmp((char *)xml_node2->name, "HostName")) {
							char *content = fetch_and_trim(xml_node2);
							if (content && !strcmp(content, host))
								match = 1;
							else
								match = -1;
							free(content);
						} else if (match &&
							   !strcmp((char *)xml_node2->name, "HostAddress")) {
							char *content = fetch_and_trim(xml_node2);
							if (content &&
							    !openconnect_parse_url(vpninfo, content)) {
								printf(_("Host \"%s\" has address \"%s\"\n"),
								       host, content);
							}
							free(content);
						} else if (match &&
							   !strcmp((char *)xml_node2->name, "UserGroup")) {
							char *content = fetch_and_trim(xml_node2);
							if (content) {
								free(vpninfo->urlpath);
								vpninfo->urlpath = content;
								printf(_("Host \"%s\" has UserGroup \"%s\"\n"),
								       host, content);
							}
						}
					}
				}

			}
			break;
		}
	}
	xmlFreeDoc(xml_doc);

	if (!vpninfo->hostname) {
		fprintf(stderr, _("Host \"%s\" not listed in config; treating as raw hostname\n"),
			host);
	}

	return 0;
}
