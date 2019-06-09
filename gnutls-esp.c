/*
 * OpenConnect (SSL + DTLS) VPN client
 *
 * Copyright © 2008-2015 Intel Corporation.
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
#include <string.h>
#include <stdlib.h>
#include <errno.h>

#include <gnutls/gnutls.h>
#include <gnutls/crypto.h>

#include "openconnect-internal.h"

void destroy_esp_ciphers(struct esp *esp)
{
	if (esp->cipher) {
		gnutls_cipher_deinit(esp->cipher);
		esp->cipher = NULL;
	}
	if (esp->hmac) {
		gnutls_hmac_deinit(esp->hmac, NULL);
		esp->hmac = NULL;
	}
}

static int init_esp_cipher(struct openconnect_info *vpninfo, struct esp *esp,
			   gnutls_mac_algorithm_t macalg, gnutls_cipher_algorithm_t encalg)
{
	gnutls_datum_t enc_key;
	int err;

	destroy_esp_ciphers(esp);

	enc_key.size = gnutls_cipher_get_key_size(encalg);
	enc_key.data = esp->enc_key;

	err = gnutls_cipher_init(&esp->cipher, encalg, &enc_key, NULL);
	if (err) {
		vpn_progress(vpninfo, PRG_ERR,
			     _("Failed to initialise ESP cipher: %s\n"),
			     gnutls_strerror(err));
		return -EIO;
	}

	err = gnutls_hmac_init(&esp->hmac, macalg,
			       esp->hmac_key,
			       gnutls_hmac_get_len(macalg));
	if (err) {
		vpn_progress(vpninfo, PRG_ERR,
			     _("Failed to initialize ESP HMAC: %s\n"),
			     gnutls_strerror(err));
		destroy_esp_ciphers(esp);
	}
	return 0;
}

int init_esp_ciphers(struct openconnect_info *vpninfo, struct esp *esp_out, struct esp *esp_in)
{
	gnutls_mac_algorithm_t macalg;
	gnutls_cipher_algorithm_t encalg;
	int ret;

	switch (vpninfo->esp_enc) {
	case ENC_AES_128_CBC:
		encalg = GNUTLS_CIPHER_AES_128_CBC;
		break;
	case ENC_AES_256_CBC:
		encalg = GNUTLS_CIPHER_AES_256_CBC;
		break;
	default:
		return -EINVAL;
	}

	switch (vpninfo->esp_hmac) {
	case HMAC_MD5:
		macalg = GNUTLS_MAC_MD5;
		break;
	case HMAC_SHA1:
		macalg = GNUTLS_MAC_SHA1;
		break;
	case HMAC_SHA256:
		macalg = GNUTLS_MAC_SHA256;
		break;
	default:
		return -EINVAL;
	}

	ret = init_esp_cipher(vpninfo, esp_out, macalg, encalg);
	if (ret)
		return ret;

	gnutls_cipher_set_iv(esp_out->cipher, esp_out->iv, sizeof(esp_out->iv));

	ret = init_esp_cipher(vpninfo, esp_in, macalg, encalg);
	if (ret) {
		destroy_esp_ciphers(esp_out);
		return ret;
	}

	return 0;
}

/* pkt->len shall be the *payload* length. Omitting the header and the 12-byte HMAC */
int decrypt_esp_packet(struct openconnect_info *vpninfo, struct esp *esp, struct pkt *pkt)
{
	unsigned char hmac_buf[MAX_HMAC_SIZE];
	int err;

	err = gnutls_hmac(esp->hmac, &pkt->esp, sizeof(pkt->esp) + pkt->len);
	if (err) {
		vpn_progress(vpninfo, PRG_ERR,
			     _("Failed to calculate HMAC for ESP packet: %s\n"),
			     gnutls_strerror(err));
		return -EIO;
	}
	gnutls_hmac_output(esp->hmac, hmac_buf);
	if (memcmp(hmac_buf, pkt->data + pkt->len, vpninfo->hmac_out_len)) {
		vpn_progress(vpninfo, PRG_DEBUG,
			     _("Received ESP packet with invalid HMAC\n"));
		return -EINVAL;
	}

	if (verify_packet_seqno(vpninfo, esp, ntohl(pkt->esp.seq)))
		return -EINVAL;

	gnutls_cipher_set_iv(esp->cipher, pkt->esp.iv, sizeof(pkt->esp.iv));

	err = gnutls_cipher_decrypt(esp->cipher, pkt->data, pkt->len);
	if (err) {
		vpn_progress(vpninfo, PRG_ERR,
			     _("Decrypting ESP packet failed: %s\n"),
			     gnutls_strerror(err));
		return -EINVAL;
	}

	return 0;
}

int encrypt_esp_packet(struct openconnect_info *vpninfo, struct pkt *pkt, int crypt_len)
{
	const int blksize = 16;
	int err;

	err = gnutls_cipher_encrypt(vpninfo->esp_out.cipher, pkt->data, crypt_len);
	if (err) {
		vpn_progress(vpninfo, PRG_ERR,
			     _("Failed to encrypt ESP packet: %s\n"),
			     gnutls_strerror(err));
		return -EIO;
	}

	err = gnutls_hmac(vpninfo->esp_out.hmac, &pkt->esp, sizeof(pkt->esp) + crypt_len);
	if (err) {
		vpn_progress(vpninfo, PRG_ERR,
			     _("Failed to calculate HMAC for ESP packet: %s\n"),
			     gnutls_strerror(err));
		return -EIO;
	}
	gnutls_hmac_output(vpninfo->esp_out.hmac, pkt->data + crypt_len);

	memcpy(vpninfo->esp_out.iv, pkt->data + crypt_len, blksize);
	gnutls_cipher_encrypt(vpninfo->esp_out.cipher, vpninfo->esp_out.iv, blksize);
	return 0;
}
