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

#include "openconnect-internal.h"

#include <openssl/evp.h>
#include <openssl/rand.h>

#if OPENSSL_VERSION_NUMBER < 0x10100000L || defined(LIBRESSL_VERSION_NUMBER)

#define EVP_CIPHER_CTX_free(c) do {				\
				    EVP_CIPHER_CTX_cleanup(c);	\
				    free(c); } while (0)
#define HMAC_CTX_free(c) do {					\
				    HMAC_CTX_cleanup(c);	\
				    free(c); } while (0)

static inline HMAC_CTX *HMAC_CTX_new(void)
{
	HMAC_CTX *ret = malloc(sizeof(*ret));
	if (ret)
		HMAC_CTX_init(ret);
	return ret;
}
#endif

void destroy_esp_ciphers(struct esp *esp)
{
	if (esp->cipher) {
		EVP_CIPHER_CTX_free(esp->cipher);
		esp->cipher = NULL;
	}
	if (esp->hmac) {
		HMAC_CTX_free(esp->hmac);
		esp->hmac = NULL;
	}
}

static int init_esp_cipher(struct openconnect_info *vpninfo, struct esp *esp,
			    const EVP_MD *macalg, const EVP_CIPHER *encalg, int decrypt)
{
	int ret;

	destroy_esp_ciphers(esp);

#if OPENSSL_VERSION_NUMBER < 0x10100000L || defined(LIBRESSL_VERSION_NUMBER)
	esp->cipher = malloc(sizeof(*esp->cipher));
	if (!esp->cipher)
		return -ENOMEM;
	EVP_CIPHER_CTX_init(esp->cipher);
#else
	esp->cipher = EVP_CIPHER_CTX_new();
	if (!esp->cipher)
		return -ENOMEM;
#endif

	if (decrypt)
		ret = EVP_DecryptInit_ex(esp->cipher, encalg, NULL, esp->enc_key, NULL);
	else {
		ret = EVP_EncryptInit_ex(esp->cipher, encalg, NULL, esp->enc_key, esp->iv);
	}

	if (!ret) {
		vpn_progress(vpninfo, PRG_ERR,
			     _("Failed to initialise ESP cipher:\n"));
		openconnect_report_ssl_errors(vpninfo);
		return -EIO;
	}
	EVP_CIPHER_CTX_set_padding(esp->cipher, 0);

	esp->hmac = HMAC_CTX_new();
	if (!esp->hmac) {
		destroy_esp_ciphers(esp);
		return -ENOMEM;
	}
	if (!HMAC_Init_ex(esp->hmac, esp->hmac_key,
			  EVP_MD_size(macalg), macalg, NULL)) {
		vpn_progress(vpninfo, PRG_ERR,
			     _("Failed to initialize ESP HMAC\n"));

		openconnect_report_ssl_errors(vpninfo);
		destroy_esp_ciphers(esp);
	}

	return 0;
}

int init_esp_ciphers(struct openconnect_info *vpninfo, struct esp *esp_out, struct esp *esp_in)
{
	const EVP_CIPHER *encalg;
	const EVP_MD *macalg;
	int ret;

	switch (vpninfo->esp_enc) {
	case ENC_AES_128_CBC:
		encalg = EVP_aes_128_cbc();
		break;
	case ENC_AES_256_CBC:
		encalg = EVP_aes_256_cbc();
		break;
	default:
		return -EINVAL;
	}

	switch (vpninfo->esp_hmac) {
	case HMAC_MD5:
		macalg = EVP_md5();
		break;
	case HMAC_SHA1:
		macalg = EVP_sha1();
		break;
	default:
		return -EINVAL;
	}

	ret = init_esp_cipher(vpninfo, &vpninfo->esp_out, macalg, encalg, 0);
	if (ret)
		return ret;

	ret = init_esp_cipher(vpninfo, esp_in, macalg, encalg, 1);
	if (ret) {
		destroy_esp_ciphers(&vpninfo->esp_out);
		return ret;
	}

	return 0;
}

/* pkt->len shall be the *payload* length. Omitting the header and the 12-byte HMAC */
int decrypt_esp_packet(struct openconnect_info *vpninfo, struct esp *esp, struct pkt *pkt)
{
	unsigned char hmac_buf[20];
	unsigned int hmac_len = sizeof(hmac_buf);
	int crypt_len = pkt->len;

	HMAC_Init_ex(esp->hmac, NULL, 0, NULL, NULL);
	HMAC_Update(esp->hmac, (void *)&pkt->esp, sizeof(pkt->esp) + pkt->len);
	HMAC_Final(esp->hmac, hmac_buf, &hmac_len);

	if (memcmp(hmac_buf, pkt->data + pkt->len, 12)) {
		vpn_progress(vpninfo, PRG_DEBUG,
			     _("Received ESP packet with invalid HMAC\n"));
		return -EINVAL;
	}

	if (verify_packet_seqno(vpninfo, esp, ntohl(pkt->esp.seq)))
		return -EINVAL;

	if (!EVP_DecryptInit_ex(esp->cipher, NULL, NULL, NULL,
				pkt->esp.iv)) {
		vpn_progress(vpninfo, PRG_ERR,
			     _("Failed to set up decryption context for ESP packet:\n"));
		openconnect_report_ssl_errors(vpninfo);
		return -EINVAL;
	}

	if (!EVP_DecryptUpdate(esp->cipher, pkt->data, &crypt_len,
			       pkt->data, pkt->len)) {
		vpn_progress(vpninfo, PRG_ERR,
			     _("Failed to decrypt ESP packet:\n"));
		openconnect_report_ssl_errors(vpninfo);
		return -EINVAL;
	}

	return 0;
}

int encrypt_esp_packet(struct openconnect_info *vpninfo, struct pkt *pkt)
{
	int i, padlen;
	int blksize = 16;
	unsigned int hmac_len = 20;
	int crypt_len;

	/* This gets much more fun if the IV is variable-length */
	pkt->esp.spi = vpninfo->esp_out.spi;
	pkt->esp.seq = htonl(vpninfo->esp_out.seq++);

	padlen = blksize - 1 - ((pkt->len + 1) % blksize);
	for (i=0; i<padlen; i++)
		pkt->data[pkt->len + i] = i + 1;
	pkt->data[pkt->len + padlen] = padlen;
	pkt->data[pkt->len + padlen + 1] = 0x04; /* Legacy IP */

	memcpy(pkt->esp.iv, vpninfo->esp_out.iv, 16);

	crypt_len = pkt->len + padlen + 2;
	if (!EVP_EncryptUpdate(vpninfo->esp_out.cipher, pkt->data, &crypt_len,
			       pkt->data, crypt_len)) {
		vpn_progress(vpninfo, PRG_ERR,
			     _("Failed to encrypt ESP packet:\n"));
		openconnect_report_ssl_errors(vpninfo);
		return -EINVAL;
	}

	HMAC_Init_ex(vpninfo->esp_out.hmac, NULL, 0, NULL, NULL);
	HMAC_Update(vpninfo->esp_out.hmac, (void *)&pkt->esp, sizeof(pkt->esp) + crypt_len);
	HMAC_Final(vpninfo->esp_out.hmac, pkt->data + crypt_len, &hmac_len);

	EVP_EncryptUpdate(vpninfo->esp_out.cipher, vpninfo->esp_out.iv, &blksize,
			  pkt->data + crypt_len + hmac_len - blksize, blksize);
	return sizeof(pkt->esp) + crypt_len + 12;
}
