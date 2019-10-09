/*
 * OpenConnect (SSL + DTLS) VPN client
 *
 * Copyright © 2008-2016 Intel Corporation.
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

#include <errno.h>
#include <sys/types.h>
#include <unistd.h>
#include <fcntl.h>
#include <string.h>
#include <errno.h>
#include <stdlib.h>
#include <stdio.h>
#ifndef _WIN32
#include <netinet/in.h>
#include <sys/socket.h>
#endif

#include "openconnect-internal.h"

/* In the very early days there were cases where this wasn't found in
 * the header files but it did still work somehow. I forget the details
 * now but I was definitely avoiding using the macro. Let's just define
 * it for ourselves instead.*/
#ifndef DTLS1_BAD_VER
#define DTLS1_BAD_VER 0x100
#endif

#ifdef HAVE_DTLS1_STOP_TIMER
/* OpenSSL doesn't deliberately export this, but we need it to
   workaround a DTLS bug in versions < 1.0.0e */
extern void dtls1_stop_timer(SSL *);
#endif

#ifndef DTLS_get_data_mtu
/* This equivalent functionality was submitted for OpenSSL 1.1.1+ in
 * https://github.com/openssl/openssl/pull/1666 */
static int dtls_get_data_mtu(struct openconnect_info *vpninfo, int mtu)
{
	int ivlen, maclen, blocksize = 0, pad = 0;
#if OPENSSL_VERSION_NUMBER >= 0x10100000L && !defined(LIBRESSL_VERSION_NUMBER)
	const SSL_CIPHER *s_ciph = SSL_get_current_cipher(vpninfo->dtls_ssl);
	int cipher_nid;
	const EVP_CIPHER *e_ciph;
	const EVP_MD *e_md;
	char wtf[128];

	cipher_nid = SSL_CIPHER_get_cipher_nid(s_ciph);
	if (cipher_nid == NID_chacha20_poly1305) {
		ivlen = 0; /* Automatically derived from handshake and seqno */
		maclen = 16; /* Poly1305 */
	} else {
		e_ciph = EVP_get_cipherbynid(cipher_nid);
		switch (EVP_CIPHER_mode(e_ciph)) {
		case EVP_CIPH_GCM_MODE:
			ivlen = EVP_GCM_TLS_EXPLICIT_IV_LEN;
			maclen = EVP_GCM_TLS_TAG_LEN;
			break;

		case EVP_CIPH_CCM_MODE:
			ivlen = EVP_CCM_TLS_EXPLICIT_IV_LEN;
			SSL_CIPHER_description(s_ciph, wtf, sizeof(wtf));
			if (strstr(wtf, "CCM8"))
				maclen = 8;
			else
				maclen = 16;
			break;

		case EVP_CIPH_CBC_MODE:
			blocksize = EVP_CIPHER_block_size(e_ciph);
			ivlen = EVP_CIPHER_iv_length(e_ciph);
			pad = 1;

			e_md = EVP_get_digestbynid(SSL_CIPHER_get_digest_nid(s_ciph));
			maclen = EVP_MD_size(e_md);
			break;

		default:
			vpn_progress(vpninfo, PRG_ERR,
				     _("Unable to calculate DTLS overhead for %s\n"),
				     SSL_CIPHER_get_name(s_ciph));
			ivlen = 0;
			maclen = DTLS_OVERHEAD;
			break;
		}
	}
#else
	/* OpenSSL <= 1.0.2 only supports CBC ciphers with PSK */
	ivlen = EVP_CIPHER_iv_length(EVP_CIPHER_CTX_cipher(vpninfo->dtls_ssl->enc_read_ctx));
	maclen = EVP_MD_CTX_size(vpninfo->dtls_ssl->read_hash);
	blocksize = ivlen;
	pad = 1;
#endif

	/* Even when it pretended to, OpenSSL never did encrypt-then-mac.
	 * So the MAC is *inside* the encryption, unconditionally.
	 * https://github.com/openssl/openssl/pull/1705 */
	if (mtu < DTLS1_RT_HEADER_LENGTH + ivlen)
		return 0;
	mtu -= DTLS1_RT_HEADER_LENGTH + ivlen;

	/* For CBC mode round down to blocksize */
	if (blocksize)
		mtu -= mtu % blocksize;

	/* Finally, CBC modes require at least one byte to indicate
	 * padding length, as well as the MAC. */
	if (mtu < pad + maclen)
		return 0;
	mtu -= pad + maclen;
	return mtu;
}
#endif /* !DTLS_get_data_mtu */

/* sets the DTLS MTU and returns the actual tunnel MTU */
unsigned dtls_set_mtu(struct openconnect_info *vpninfo, unsigned mtu)
{
	/* This is the record MTU (not the link MTU, which includes
	 * IP+UDP headers, and not the payload MTU */
	SSL_set_mtu(vpninfo->dtls_ssl, mtu);

#ifdef DTLS_get_data_mtu
	return DTLS_get_data_mtu(vpninfo->dtls_ssl);
#else
	return dtls_get_data_mtu(vpninfo, mtu);
#endif
}

#if OPENSSL_VERSION_NUMBER >= 0x10100000L && !defined(LIBRESSL_VERSION_NUMBER)
/* Since OpenSSL 1.1, the SSL_SESSION structure is opaque and we can't
 * just fill it in directly. So we have to generate the OpenSSL ASN.1
 * representation of the SSL_SESSION, and use d2i_SSL_SESSION() to
 * create the SSL_SESSION from that. */

static void buf_append_INTEGER(struct oc_text_buf *buf, uint32_t datum)
{
	int l;

	/* We only handle positive integers up to INT_MAX */
	if (datum < 0x80)
		l = 1;
	else if (datum < 0x8000)
		l = 2;
	else if (datum < 0x800000)
		l = 3;
	else
		l = 4;

	if (buf_ensure_space(buf, 2 + l))
		return;

	buf->data[buf->pos++] = 0x02;
	buf->data[buf->pos++] = l;
	while (l--)
		buf->data[buf->pos++] = datum >> (l * 8);
}

static void buf_append_OCTET_STRING(struct oc_text_buf *buf, void *data, int len)
{
	/* We only (need to) cope with length < 0x80 for now */
	if (len >= 0x80) {
		buf->error = -EINVAL;
		return;
	}

	if (buf_ensure_space(buf, 2 + len))
		return;

	buf->data[buf->pos++] = 0x04;
	buf->data[buf->pos++] = len;
	memcpy(buf->data + buf->pos, data, len);
	buf->pos += len;
}

static SSL_SESSION *generate_dtls_session(struct openconnect_info *vpninfo,
					  int dtlsver, const SSL_CIPHER *cipher,
					  unsigned rnd_key)
{
	struct oc_text_buf *buf = buf_alloc();
	SSL_SESSION *dtls_session;
	const unsigned char *asn;
	uint16_t cid;
	uint8_t rnd_secret[TLS_MASTER_KEY_SIZE];

	buf_append_bytes(buf, "\x30\x80", 2); // SEQUENCE, indeterminate length
	buf_append_INTEGER(buf, 1 /* SSL_SESSION_ASN1_VERSION */);
	buf_append_INTEGER(buf, dtlsver);
	store_be16(&cid, SSL_CIPHER_get_id(cipher) & 0xffff);
	buf_append_OCTET_STRING(buf, &cid, 2);
	if (rnd_key) {
		buf_append_OCTET_STRING(buf, vpninfo->dtls_app_id,
					vpninfo->dtls_app_id_size);

		if (openconnect_random(rnd_secret, sizeof(rnd_secret))) {
			vpn_progress(vpninfo, PRG_ERR,
				     _("Failed to generate random key\n"));
			buf_free(buf);
			return NULL;
		}
		buf_append_OCTET_STRING(buf, rnd_secret, sizeof(rnd_secret));
	} else {
		buf_append_OCTET_STRING(buf, vpninfo->dtls_session_id,
					sizeof(vpninfo->dtls_session_id));

		buf_append_OCTET_STRING(buf, vpninfo->dtls_secret,
					sizeof(vpninfo->dtls_secret));
	}
	/* If the length actually fits in one byte (which it should), do
	 * it that way.  Else, leave it indeterminate and add two
	 * end-of-contents octets to mark the end of the SEQUENCE. */
	if (!buf_error(buf) && buf->pos <= 0x80)
		buf->data[1] = buf->pos - 2;
	else
		buf_append_bytes(buf, "\0\0", 2);

	if (buf_error(buf)) {
		vpn_progress(vpninfo, PRG_ERR,
			     _("Failed to create SSL_SESSION ASN.1 for OpenSSL: %s\n"),
			     strerror(-buf_error(buf)));
		buf_free(buf);
		return NULL;
	}

	asn = (void *)buf->data;
	dtls_session = d2i_SSL_SESSION(NULL, &asn, buf->pos);
	buf_free(buf);
	if (!dtls_session) {
		vpn_progress(vpninfo, PRG_ERR,
			     _("OpenSSL failed to parse SSL_SESSION ASN.1\n"));
		openconnect_report_ssl_errors(vpninfo);
		return NULL;
	}

	return dtls_session;
}
#else /* OpenSSL before 1.1 */
static SSL_SESSION *generate_dtls_session(struct openconnect_info *vpninfo,
					  int dtlsver, const SSL_CIPHER *cipher,
					  unsigned rnd_key)
{
	SSL_SESSION *dtls_session = SSL_SESSION_new();

	if (!dtls_session) {
		vpn_progress(vpninfo, PRG_ERR,
			     _("Initialise DTLSv1 session failed\n"));
		return NULL;
	}

	dtls_session->ssl_version = dtlsver;
	dtls_session->master_key_length = TLS_MASTER_KEY_SIZE;

	if (rnd_key) {
		if (openconnect_random(dtls_session->master_key, TLS_MASTER_KEY_SIZE)) {
			vpn_progress(vpninfo, PRG_ERR,
				     _("Failed to generate random key\n"));
			return NULL;
		}

		if (vpninfo->dtls_app_id_size > sizeof(dtls_session->session_id)) {
			vpn_progress(vpninfo, PRG_ERR,
				     _("Too large application ID size\n"));
			return NULL;
		}

		dtls_session->session_id_length = vpninfo->dtls_app_id_size;
		memcpy(dtls_session->session_id, vpninfo->dtls_app_id,
		       vpninfo->dtls_app_id_size);
	} else {
		memcpy(dtls_session->master_key, vpninfo->dtls_secret,
		       sizeof(vpninfo->dtls_secret));

		dtls_session->session_id_length = sizeof(vpninfo->dtls_session_id);
		memcpy(dtls_session->session_id, vpninfo->dtls_session_id,
		       sizeof(vpninfo->dtls_session_id));
	}


	dtls_session->cipher = (SSL_CIPHER *)cipher;
	dtls_session->cipher_id = cipher->id;

	return dtls_session;
}
#endif

#if defined (HAVE_DTLS12) && !defined(OPENSSL_NO_PSK)
static unsigned int psk_callback(SSL *ssl, const char *hint, char *identity,
				 unsigned int max_identity_len, unsigned char *psk,
				 unsigned int max_psk_len)
{
	struct openconnect_info *vpninfo = SSL_get_app_data(ssl);

	if (!vpninfo || max_identity_len < 4 || max_psk_len < PSK_KEY_SIZE)
		return 0;
	vpn_progress(vpninfo, PRG_TRACE, _("PSK callback\n"));

	snprintf(identity, max_psk_len, "psk");

	memcpy(psk, vpninfo->dtls_secret, PSK_KEY_SIZE);
	return PSK_KEY_SIZE;
}

#endif

#ifndef HAVE_SSL_CIPHER_FIND
static const SSL_CIPHER *SSL_CIPHER_find(SSL *ssl, const unsigned char *ptr)
{
    return ssl->method->get_cipher_by_char(ptr);
}
#endif

int start_dtls_handshake(struct openconnect_info *vpninfo, int dtls_fd)
{
	method_const SSL_METHOD *dtls_method;
	SSL_SESSION *dtls_session;
	SSL *dtls_ssl;
	BIO *dtls_bio;
	int dtlsver = DTLS1_BAD_VER;
	const char *cipher = vpninfo->dtls_cipher;

#ifdef HAVE_DTLS12
	/* These things should never happen unless they're supported */
	if (vpninfo->cisco_dtls12) {
		dtlsver = DTLS1_2_VERSION;
	} else if (!strcmp(cipher, "OC-DTLS1_2-AES128-GCM")) {
		dtlsver = DTLS1_2_VERSION;
		cipher = "AES128-GCM-SHA256";
	} else if (!strcmp(cipher, "OC-DTLS1_2-AES256-GCM")) {
		dtlsver = DTLS1_2_VERSION;
		cipher = "AES256-GCM-SHA384";
#ifndef OPENSSL_NO_PSK
	} else if (!strcmp(cipher, "PSK-NEGOTIATE")) {
		dtlsver = 0; /* Let it negotiate */
#endif
	}
#endif

	if (!vpninfo->dtls_ctx) {
#ifdef HAVE_DTLS12
		/* If we can use SSL_CTX_set_min_proto_version, do so. */
		dtls_method = DTLS_client_method();
#endif
#ifndef HAVE_SSL_CTX_PROTOVER
		/* If !HAVE_DTLS12, dtlsver *MUST* be DTLS1_BAD_VER because it's set
		 * at the top of the function and nothing can change it. */
		if (dtlsver == DTLS1_BAD_VER)
			dtls_method = DTLSv1_client_method();
#endif

		vpninfo->dtls_ctx = SSL_CTX_new(dtls_method);
		if (!vpninfo->dtls_ctx) {
			vpn_progress(vpninfo, PRG_ERR,
				     _("Initialise DTLSv1 CTX failed\n"));
			openconnect_report_ssl_errors(vpninfo);
			vpninfo->dtls_attempt_period = 0;
			return -EINVAL;
		}
#ifdef HAVE_SSL_CTX_PROTOVER
		if (dtlsver &&
		    (!SSL_CTX_set_min_proto_version(vpninfo->dtls_ctx, dtlsver) ||
		     !SSL_CTX_set_max_proto_version(vpninfo->dtls_ctx, dtlsver))) {
			vpn_progress(vpninfo, PRG_ERR,
				     _("Set DTLS CTX version failed\n"));
			openconnect_report_ssl_errors(vpninfo);
			SSL_CTX_free(vpninfo->dtls_ctx);
			vpninfo->dtls_ctx = NULL;
			vpninfo->dtls_attempt_period = 0;
			return -EINVAL;
		}
#else /* !HAVE_SSL_CTX_PROTOVER */
		/* If we used the legacy version-specific methods, we need the special
		 * way to make TLSv1_client_method() do DTLS1_BAD_VER. */
		if (dtlsver == DTLS1_BAD_VER)
			SSL_CTX_set_options(vpninfo->dtls_ctx, SSL_OP_CISCO_ANYCONNECT);
#endif
#if defined (HAVE_DTLS12) && !defined(OPENSSL_NO_PSK)
		if (!dtlsver) {
			SSL_CTX_set_psk_client_callback(vpninfo->dtls_ctx, psk_callback);
			/* For PSK we override the DTLS master secret with one derived
			 * from the HTTPS session. */
			if (!SSL_export_keying_material(vpninfo->https_ssl,
							vpninfo->dtls_secret, PSK_KEY_SIZE,
							PSK_LABEL, PSK_LABEL_SIZE, NULL, 0, 0)) {
				vpn_progress(vpninfo, PRG_ERR,
					     _("Failed to generate DTLS key\n"));
				openconnect_report_ssl_errors(vpninfo);
				SSL_CTX_free(vpninfo->dtls_ctx);
				vpninfo->dtls_ctx = NULL;
				vpninfo->dtls_attempt_period = 0;
				return -EINVAL;
			}
			/* For SSL_CTX_set_cipher_list() */
			cipher = "PSK";
		}
#endif /* OPENSSL_NO_PSK */
#ifdef SSL_OP_NO_ENCRYPT_THEN_MAC
		/*
		 * I'm fairly sure I wasn't lying when I said I had tested
		 * https://github.com/openssl/openssl/commit/e23d5071ec4c7aa6bb2b
		 * against GnuTLS both with and without EtM in 2016.
		 *
		 * Nevertheless, in 2019 it seems to be failing to negotiate
		 * at least for DTLS1_BAD_VER against ocserv with GnuTLS 3.6.7:
		 * https://gitlab.com/gnutls/gnutls/issues/139 — I think because
		 * GnuTLS isn't actually doing EtM after negotiating it (like
		 * OpenSSL 1.1.0 used to).
		 *
		 * Just turn it off. Real Cisco servers don't do it for
		 * DTLS1_BAD_VER, and against ocserv (and newer Cisco) we should
		 * be using DTLSv1.2 with AEAD ciphersuites anyway so EtM is
		 * irrelevant.
		 */
		SSL_CTX_set_options(vpninfo->dtls_ctx, SSL_OP_NO_ENCRYPT_THEN_MAC);
#endif
#ifdef SSL_OP_NO_EXTENDED_MASTER_SECRET
		/* RFC7627 says:
		 *
		 *   If the original session did not use the "extended_master_secret"
		 *   extension but the new ClientHello contains the extension, then the
		 *   server MUST NOT perform the abbreviated handshake.  Instead, it
		 *   SHOULD continue with a full handshake (as described in
		 *   Section 5.2) to negotiate a new session.
		 *
		 * Now that would be distinctly suboptimal, since we have no way to do
		 * a full handshake (we even explicitly protect against it, in case a
		 * MITM server attempts to hijack our deliberately-resumed session).
		 *
		 * So where OpenSSL provides the choice, tell it not to use extms on
		 * resumed sessions.
		 */
		if (dtlsver)
			SSL_CTX_set_options(vpninfo->dtls_ctx, SSL_OP_NO_EXTENDED_MASTER_SECRET);
#endif
		/* If we don't readahead, then we do short reads and throw
		   away the tail of data packets. */
		SSL_CTX_set_read_ahead(vpninfo->dtls_ctx, 1);

		if (!SSL_CTX_set_cipher_list(vpninfo->dtls_ctx, cipher)) {
			vpn_progress(vpninfo, PRG_ERR,
				     _("Set DTLS cipher list failed\n"));
			SSL_CTX_free(vpninfo->dtls_ctx);
			vpninfo->dtls_ctx = NULL;
			vpninfo->dtls_attempt_period = 0;
			return -EINVAL;
		}
	}

	dtls_ssl = SSL_new(vpninfo->dtls_ctx);
	SSL_set_connect_state(dtls_ssl);
	SSL_set_app_data(dtls_ssl, vpninfo);


	if (dtlsver) {
		STACK_OF(SSL_CIPHER) *ciphers = SSL_get_ciphers(dtls_ssl);
		const SSL_CIPHER *ssl_ciph = NULL;
		int i;

		for (i = 0; i < sk_SSL_CIPHER_num(ciphers); i++) {
			ssl_ciph = sk_SSL_CIPHER_value(ciphers, i);
			/* For PSK-NEGOTIATE just use the first one we find */
			if (!dtlsver || !strcmp(SSL_CIPHER_get_name(ssl_ciph), cipher))
				break;
		}

		if (i == sk_SSL_CIPHER_num(ciphers)) {
			vpn_progress(vpninfo, PRG_ERR, _("DTLS cipher '%s' not found\n"),
				     cipher);
			SSL_CTX_free(vpninfo->dtls_ctx);
			SSL_free(dtls_ssl);
			vpninfo->dtls_ctx = NULL;
			vpninfo->dtls_attempt_period = 0;
			return -EINVAL;
		}

		/* We're going to "resume" a session which never existed. Fake it... */
		dtls_session = generate_dtls_session(vpninfo, dtlsver, ssl_ciph, 0);
		if (!dtls_session) {
			SSL_CTX_free(vpninfo->dtls_ctx);
			SSL_free(dtls_ssl);
			vpninfo->dtls_ctx = NULL;
			vpninfo->dtls_attempt_period = 0;
			return -EINVAL;
		}

		if (!SSL_set_session(dtls_ssl, dtls_session)) {
			vpn_progress(vpninfo, PRG_ERR,
				     _("SSL_set_session() failed with old protocol version 0x%x\n"
				       "Are you using a version of OpenSSL older than 0.9.8m?\n"
				       "See http://rt.openssl.org/Ticket/Display.html?id=1751\n"
				       "Use the --no-dtls command line option to avoid this message\n"),
				     DTLS1_BAD_VER);
			SSL_CTX_free(vpninfo->dtls_ctx);
			SSL_free(dtls_ssl);
			vpninfo->dtls_ctx = NULL;
			vpninfo->dtls_attempt_period = 0;
			SSL_SESSION_free(dtls_session);
			return -EINVAL;
		}
		/* We don't need our own refcount on it any more */
		SSL_SESSION_free(dtls_session);

	} else if (vpninfo->dtls_app_id_size > 0) {
		const uint8_t cs[2] = {0x00, 0x2F}; /* RSA-AES-128 */
		/* we generate a session with a random key which cannot be resumed;
		 * we want to set the client identifier we received from the server
		 * as a session ID. */
		dtls_session = generate_dtls_session(vpninfo, DTLS1_VERSION,
						     SSL_CIPHER_find(dtls_ssl, cs),
						     1);
		if (!dtls_session) {
			SSL_CTX_free(vpninfo->dtls_ctx);
			SSL_free(dtls_ssl);
			vpninfo->dtls_ctx = NULL;
			vpninfo->dtls_attempt_period = 0;
			return -EINVAL;
		}
	
		if (!SSL_set_session(dtls_ssl, dtls_session)) {
			vpn_progress(vpninfo, PRG_ERR,
				     _("SSL_set_session() failed\n"));
			SSL_CTX_free(vpninfo->dtls_ctx);
			SSL_free(dtls_ssl);
			vpninfo->dtls_ctx = NULL;
			vpninfo->dtls_attempt_period = 0;
			SSL_SESSION_free(dtls_session);
			return -EINVAL;
		}
		/* We don't need our own refcount on it any more */
		SSL_SESSION_free(dtls_session);
	}


	dtls_bio = BIO_new_socket(dtls_fd, BIO_NOCLOSE);
	/* Set non-blocking */
	BIO_set_nbio(dtls_bio, 1);
	SSL_set_bio(dtls_ssl, dtls_bio, dtls_bio);

	vpninfo->dtls_ssl = dtls_ssl;

	return 0;
}

int dtls_try_handshake(struct openconnect_info *vpninfo)
{
	int ret = SSL_do_handshake(vpninfo->dtls_ssl);

	if (ret == 1) {
		const char *c;

		if (!strcmp(vpninfo->dtls_cipher, "PSK-NEGOTIATE")) {
			/* For PSK-NEGOTIATE, we have to determine the tunnel MTU
			 * for ourselves based on the base MTU */
			int data_mtu = vpninfo->cstp_basemtu;
			if (vpninfo->peer_addr->sa_family == AF_INET6)
				data_mtu -= 40; /* IPv6 header */
			else
				data_mtu -= 20; /* Legacy IP header */
			data_mtu -= 8; /* UDP header */
			if (data_mtu < 0) {
				vpn_progress(vpninfo, PRG_ERR,
					     _("Peer MTU %d too small to allow DTLS\n"),
					     vpninfo->cstp_basemtu);
				goto nodtls;
			}
			/* Reduce it by one because that's the payload header *inside*
			 * the encryption */
			data_mtu = dtls_set_mtu(vpninfo, data_mtu) - 1;
			if (data_mtu < 0)
				goto nodtls;
			if (data_mtu < vpninfo->ip_info.mtu) {
				vpn_progress(vpninfo, PRG_INFO,
					     _("DTLS MTU reduced to %d\n"),
					     data_mtu);
				vpninfo->ip_info.mtu = data_mtu;
			}
		} else if (!SSL_session_reused(vpninfo->dtls_ssl)) {
			/* Someone attempting to hijack the DTLS session?
			 * A real server would never allow a full session
			 * establishment instead of the agreed resume. */
			vpn_progress(vpninfo, PRG_ERR,
				     _("DTLS session resume failed; possible MITM attack. Disabling DTLS.\n"));
		nodtls:
			dtls_close(vpninfo);
			SSL_CTX_free(vpninfo->dtls_ctx);
			vpninfo->dtls_ctx = NULL;
			vpninfo->dtls_attempt_period = 0;
			vpninfo->dtls_state = DTLS_DISABLED;
			return -EIO;
		}

		vpninfo->dtls_state = DTLS_CONNECTED;
		vpn_progress(vpninfo, PRG_INFO,
			     _("Established DTLS connection (using OpenSSL). Ciphersuite %s.\n"),
			     SSL_get_cipher(vpninfo->dtls_ssl));

		c = openconnect_get_dtls_compression(vpninfo);
		if (c) {
			vpn_progress(vpninfo, PRG_INFO,
				     _("DTLS connection compression using %s.\n"), c);
		}

		vpninfo->dtls_times.last_rekey = vpninfo->dtls_times.last_rx = 
			vpninfo->dtls_times.last_tx = time(NULL);

		/* From about 8.4.1(11) onwards, the ASA seems to get
		   very unhappy if we resend ChangeCipherSpec messages
		   after the initial setup. This was "fixed" in OpenSSL
		   1.0.0e for RT#2505, but it's not clear if that was
		   the right fix. What happens if the original packet
		   *does* get lost? Surely we *wanted* the retransmits,
		   because without them the server will never be able
		   to decrypt anything we send?
		   Oh well, our retransmitted packets upset the server
		   because we don't get the Cisco-compatibility right
		   (this is one of the areas in which Cisco's DTLS differs
		   from the RFC4347 spec), and DPD should help us notice
		   if *nothing* is getting through. */
#if OPENSSL_VERSION_NUMBER >= 0x10100000L
		/* OpenSSL 1.1.0 or above. Do nothing. The SSLeay() function
		   got renamed, and it's a pointless check in this case
		   anyway because there's *no* chance that we linked against
		   1.1.0 and are running against something older than 1.0.0e. */
#elif OPENSSL_VERSION_NUMBER >= 0x1000005fL
		/* OpenSSL 1.0.0e or above doesn't resend anyway; do nothing.
		   However, if we were *built* against 1.0.0e or newer, but at
		   runtime we find that we are being run against an older
		   version, warn about it. */
		if (SSLeay() < 0x1000005fL) {
			vpn_progress(vpninfo, PRG_ERR,
				     _("Your OpenSSL is older than the one you built against, so DTLS may fail!"));
		}
#elif defined(HAVE_DTLS1_STOP_TIMER)
		/*
		 * This works for any normal OpenSSL that supports
		 * Cisco DTLS compatibility (0.9.8m to 1.0.0d inclusive,
		 * and even later versions although it isn't needed there.
		 */
		dtls1_stop_timer(vpninfo->dtls_ssl);
#elif defined(BIO_CTRL_DGRAM_SET_NEXT_TIMEOUT)
		/*
		 * Debian restricts visibility of dtls1_stop_timer()
		 * so do it manually. This version also works on all
		 * sane versions of OpenSSL:
		 */
		memset(&(vpninfo->dtls_ssl->d1->next_timeout), 0,
		       sizeof((vpninfo->dtls_ssl->d1->next_timeout)));
		vpninfo->dtls_ssl->d1->timeout_duration = 1;
		BIO_ctrl(SSL_get_rbio(vpninfo->dtls_ssl),
			 BIO_CTRL_DGRAM_SET_NEXT_TIMEOUT, 0,
			 &(vpninfo->dtls_ssl->d1->next_timeout));
#elif defined(BIO_CTRL_DGRAM_SET_TIMEOUT)
		/*
		 * OK, here it gets more fun... this shoul handle the case
		 * of older OpenSSL which has the Cisco DTLS compatibility
		 * backported, but *not* the fix for RT#1922.
		 */
		BIO_ctrl(SSL_get_rbio(vpninfo->dtls_ssl),
			 BIO_CTRL_DGRAM_SET_TIMEOUT, 0, NULL);
#else
		/*
		 * And if they don't have any of the above, they probably
		 * don't have RT#1829 fixed either, but that's OK because
		 * that's the "fix" that *introduces* the timeout we're
		 * trying to disable. So do nothing...
		 */
#endif
		dtls_detect_mtu(vpninfo);
		return 0;
	}

	ret = SSL_get_error(vpninfo->dtls_ssl, ret);
	if (ret == SSL_ERROR_WANT_WRITE || ret == SSL_ERROR_WANT_READ) {
		static int badossl_bitched = 0;
		if (time(NULL) < vpninfo->new_dtls_started + 12)
			return 0;
		if (((OPENSSL_VERSION_NUMBER >= 0x100000b0L && OPENSSL_VERSION_NUMBER <= 0x100000c0L) || \
		     (OPENSSL_VERSION_NUMBER >= 0x10001040L && OPENSSL_VERSION_NUMBER <= 0x10001060L) || \
		     OPENSSL_VERSION_NUMBER == 0x10002000L) && !badossl_bitched) {
			badossl_bitched = 1;
			vpn_progress(vpninfo, PRG_ERR, _("DTLS handshake timed out\n"));
			vpn_progress(vpninfo, PRG_ERR, _("This is probably because your OpenSSL is broken\n"
				"See http://rt.openssl.org/Ticket/Display.html?id=2984\n"));
		} else {
			vpn_progress(vpninfo, PRG_DEBUG, _("DTLS handshake timed out\n"));
		}
	}

	vpn_progress(vpninfo, PRG_ERR, _("DTLS handshake failed: %d\n"), ret);
	openconnect_report_ssl_errors(vpninfo);

	dtls_close(vpninfo);

	vpninfo->dtls_state = DTLS_SLEEPING;
	time(&vpninfo->new_dtls_started);
	return -EINVAL;
}

void dtls_shutdown(struct openconnect_info *vpninfo)
{
	dtls_close(vpninfo);
	SSL_CTX_free(vpninfo->dtls_ctx);
}

void dtls_ssl_free(struct openconnect_info *vpninfo)
{
	/* We are only ever called when this is non-NULL */
	SSL_free(vpninfo->dtls_ssl);
}

#if OPENSSL_VERSION_NUMBER < 0x10100000L || defined(LIBRESSL_VERSION_NUMBER)
void gather_dtls_ciphers(struct openconnect_info *vpninfo, struct oc_text_buf *buf,
			 struct oc_text_buf *buf12)
{
#ifdef HAVE_DTLS12
#ifndef OPENSSL_NO_PSK
	buf_append(buf, "PSK-NEGOTIATE:");
#endif
	buf_append(buf, "OC-DTLS1_2-AES256-GCM:OC-DTLS1_2-AES128-GCM:");
	buf_append(buf12, "ECDHE-RSA-AES256-GCM-SHA384:ECDHE-RSA-AES128-GCM-SHA256:AES128-GCM-SHA256:AES256-GCM-SHA384\r\n");
#endif
	buf_append(buf, "DHE-RSA-AES256-SHA:DHE-RSA-AES128-SHA:");
	buf_append(buf, "AES256-SHA:AES128-SHA:DES-CBC3-SHA:DES-CBC-SHA");
}
#else
void gather_dtls_ciphers(struct openconnect_info *vpninfo, struct oc_text_buf *buf,
			 struct oc_text_buf *buf12)
{
	method_const SSL_METHOD *dtls_method;
	SSL_CTX *ctx;
	SSL *ssl;
	STACK_OF(SSL_CIPHER) *ciphers;
	int i;

	dtls_method = DTLS_client_method();
	ctx = SSL_CTX_new(dtls_method);
	if (!ctx)
		return;
	ssl = SSL_new(ctx);
	if (!ssl) {
		SSL_CTX_free(ctx);
		return;
	}

	ciphers = SSL_get1_supported_ciphers(ssl);
	for (i = 0; i < sk_SSL_CIPHER_num(ciphers); i++) {
		const SSL_CIPHER *ciph = sk_SSL_CIPHER_value(ciphers, i);
		const char *name = SSL_CIPHER_get_name(ciph);
		const char *vers = SSL_CIPHER_get_version(ciph);

		if (!strcmp(vers, "SSLv3") || !strcmp(vers, "TLSv1.0") ||
		    !strcmp(vers, "TLSv1/SSLv3")) {
			buf_append(buf, "%s%s",
				   (buf_error(buf) || !buf->pos) ? "" : ":",
				   name);
		} else if (!strcmp(vers, "TLSv1.2")) {
			buf_append(buf12, "%s%s:",
				   (buf_error(buf12) || !buf12->pos) ? "" : ":",
				   name);
		}
	}
	sk_SSL_CIPHER_free(ciphers);
	SSL_free(ssl);
	SSL_CTX_free(ctx);

	/* All DTLSv1 suites are also supported in DTLSv1.2 */
	if (!buf_error(buf))
		buf_append(buf12, ":%s", buf->data);
#ifndef OPENSSL_NO_PSK
	buf_append(buf, ":PSK-NEGOTIATE");
#endif
}
#endif
