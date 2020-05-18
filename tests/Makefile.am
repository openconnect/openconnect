
certsdir=$(srcdir)/certs

USER_KEYS = \
	$(certsdir)/user-key-pkcs1.pem $(certsdir)/user-key-pkcs1.der \
	$(certsdir)/user-key-pkcs1-aes128.pem \
	$(certsdir)/user-key-pkcs8.pem $(certsdir)/user-key-pkcs8.der \
	$(certsdir)/user-key-pkcs8-pbes1-sha1-3des.pem $(certsdir)/user-key-pkcs8-pbes1-sha1-3des.der \
	$(certsdir)/user-key-pkcs8-pbes2-sha1.pem $(certsdir)/user-key-pkcs8-pbes2-sha1.der \
	$(certsdir)/user-key-sha1-3des-sha1.p12 $(certsdir)/user-key-sha1-3des-sha256.p12 \
	$(certsdir)/user-key-aes256-cbc-sha256.p12

# We know GnuTLS doesn't support these for now. https://bugzilla.redhat.com/1369484
OSSL_KEYS = \
	$(certsdir)/user-key-md5-des-sha1.p12 $(certsdir)/user-key-aes256-cbc-md5-des-sha256.p12 \
	$(certsdir)/user-key-pkcs8-pbes2-sha256.pem $(certsdir)/user-key-pkcs8-pbes2-sha256.der \
	$(certsdir)/user-key-pkcs8-pbes1-md5-des.pem $(certsdir)/user-key-pkcs8-pbes1-md5-des.der
if OPENCONNECT_OPENSSL
USER_KEYS += $(OSSL_KEYS)
endif

DSA_KEYS = \
	$(certsdir)/dsa-key-pkcs1.pem $(certsdir)/dsa-key-pkcs1.der \
	$(certsdir)/dsa-key-pkcs1-aes128.pem \
	$(certsdir)/dsa-key-pkcs8.pem $(certsdir)/dsa-key-pkcs8.der \
	$(certsdir)/dsa-key-pkcs8-pbes2-sha1.pem $(certsdir)/dsa-key-pkcs8-pbes2-sha1.der \
	$(certsdir)/dsa-key-aes256-cbc-sha256.p12
if TEST_DSA
USER_KEYS += $(DSA_KEYS)
endif

USER_KEYS += $(certsdir)/ec-key-pkcs1.pem $(certsdir)/ec-key-pkcs1.der \
	$(certsdir)/ec-key-pkcs1-aes128.pem \
	$(certsdir)/ec-key-pkcs8.pem $(certsdir)/ec-key-pkcs8.der \
	$(certsdir)/ec-key-pkcs8-pbes2-sha1.pem $(certsdir)/ec-key-pkcs8-pbes2-sha1.der \
	$(certsdir)/ec-key-aes256-cbc-sha256.p12

USER_CERTS = $(certsdir)/user-cert.pem $(certsdir)/dsa-cert.pem $(certsdir)/ec-cert.pem

EXTRA_DIST = certs/ca.pem certs/ca-key.pem certs/user-cert.pem $(USER_KEYS) $(USER_CERTS) \
	$(OSSL_KEYS) $(DSA_KEYS) $(certsdir)/user-key-nonascii-password.p12 \
	pass-UTF-8 pass-ISO8859-2 \
	certs/server-cert.pem certs/server-key.pem configs/test1.passwd \
	common.sh configs/test-user-cert.config configs/test-user-pass.config \
	configs/test-obsolete-server-crypto.config \
	configs/user-cert.prm configs/server-cert.prm \
	softhsm2.conf.in softhsm ns.sh configs/test-dtls-psk.config \
	scripts/vpnc-script scripts/vpnc-script-detect-disconnect

dist_check_SCRIPTS = autocompletion

if HAVE_NETNS
dist_check_SCRIPTS += dtls-psk sigterm
endif

if HAVE_CWRAP
dist_check_SCRIPTS += auth-username-pass auth-certificate auth-nonascii cert-fingerprint id-test obsolete-server-crypto pfs

if TEST_PKCS11
dist_check_SCRIPTS += auth-pkcs11

PKCS11_TOKENS = openconnect-test openconnect-test1

PKCS11_KEYS = object=RSA id=%01
# Neither GnuTLS or libp11 support this
#PKCS11_KEYS += object=DSA id=%02
PKCS11_KEYS += object=EC id=%03

if OPENCONNECT_GNUTLS
# We fail test2 because PKCS11_enumerate_certs() still doesn't seem to return
# the certs after we log in. Perhaps it's cached the results?
PKCS11_TOKENS += openconnect-test2
endif # OPENCONNECT_GNUTLS
if OPENCONNECT_OPENSSL
# GnuTLS build fails this one: https://gitlab.com/gnutls/gnutls/-/issues/977
PKCS11_TOKENS += openconnect-test3
endif # OPENCONNECT_OPENSSL
endif # TEST_PKCS11
endif # HAVE_CWRAP

TESTS_ENVIRONMENT = srcdir="$(srcdir)" \
	top_builddir="$(top_builddir)" \
	key_list="$(USER_KEYS)" \
	pkcs11_keys="$(PKCS11_KEYS)" \
	pkcs11_tokens="$(PKCS11_TOKENS)"


C_TESTS = lzstest seqtest

if OPENCONNECT_WIN32
C_TESTS += list-taps
endif

if CHECK_DTLS
C_TESTS += bad_dtls_test
bad_dtls_test_SOURCES = bad_dtls_test.c
bad_dtls_test_CFLAGS = $(OPENSSL_CFLAGS)
bad_dtls_test_LDADD = $(OPENSSL_LIBS)

if DTLS_XFAIL
XFAIL_TESTS = bad_dtls_test
endif
endif

TESTS = $(dist_check_SCRIPTS) $(C_TESTS)

noinst_PROGRAMS = $(C_TESTS) serverhash

serverhash_SOURCES = serverhash.c
serverhash_LDADD = ../libopenconnect.la $(SSL_LIBS)

# Nothing actually *depends* on the cert files; they are created manually
# and considered part of the sources, committed to the git tree. But for
# reference, the commands used to generate them are here...

keyfiles: $(USER_KEYS) $(USER_CERTS) $(certsdir)/server-cert.pem


OPENSSL = openssl
OSSLARGS = -in $< -out $@ -passout pass:password
OSSLARGSP12 = -inkey $< -out $@ -in $${KEYFILE%-key-pkcs8.pem}-cert.pem -passout pass:$${PASSWORD%-password}

# Strictly speaking this is only PKCS#1 for RSA. For EC it's probably
# best described as RFC5915§4, and no idea what defines it for DSA.
$(certsdir)/user-key-pkcs1.pem:
	$(OPENSSL) genrsa -out $@ 2432

$(certsdir)/dsa-key-pkcs1.pem:
	$(OPENSSL) dsaparam -genkey 1024 -out $@

$(certsdir)/ec-key-pkcs1.pem:
	$(OPENSSL) ecparam -genkey -out $@ -name prime256v1

# Even in OpenSSL 1.1, this creates the old encrypted PEM format.
$(certsdir)/user-key-pkcs1-aes128.pem: certs/user-key-pkcs1.pem
	$(OPENSSL) rsa $(OSSLARGS) -aes128

$(certsdir)/dsa-key-pkcs1-aes128.pem: certs/dsa-key-pkcs1.pem
	$(OPENSSL) dsa $(OSSLARGS) -aes128

$(certsdir)/ec-key-pkcs1-aes128.pem: certs/ec-key-pkcs1.pem
	$(OPENSSL) ec $(OSSLARGS) -aes128

# Plain unencrypted PKCS#8
%-key-pkcs8.pem: %-key-pkcs1.pem
	$(OPENSSL) pkcs8 $(OSSLARGS) -topk8 -nocrypt

%-key-pkcs8-pbes1-sha1-3des.pem: %-key-pkcs8.pem
	$(OPENSSL) pkcs8 $(OSSLARGS) -topk8 -v1 pbeWithSHA1And3-KeyTripleDES-CBC

# This is the default created by OpenSSL 1.0.2 with -topk8
%-key-pkcs8-pbes1-md5-des.pem: %-key-pkcs8.pem
	$(OPENSSL) pkcs8 $(OSSLARGS) -topk8 -v1 pbeWithMD5AndDES-CBC

%-key-pkcs8-pbes2-sha1.pem: %-key-pkcs8.pem
	$(OPENSSL) pkcs8 $(OSSLARGS) -topk8 -v2 aes256 -v2prf hmacWithSHA1

# This is the default created by OpenSSL 1.1 with -topk8
%-key-pkcs8-pbes2-sha256.pem: %-key-pkcs8.pem
	$(OPENSSL) pkcs8 $(OSSLARGS) -topk8 -v2 aes256 -v2prf hmacWithSHA256

%-key-sha1-3des-sha1.p12: %-key-pkcs8.pem %-cert.pem
	KEYFILE="$<"; $(OPENSSL) pkcs12 $(OSSLARGSP12) -export -macalg SHA1 \
		-certpbe pbeWithSHA1And3-KeyTripleDES-CBC -keypbe pbeWithSHA1And3-KeyTripleDES-CBC

%-key-sha1-3des-sha256.p12: %-key-pkcs8.pem %-cert.pem
	KEYFILE="$<"; $(OPENSSL) pkcs12 $(OSSLARGSP12) -export -macalg SHA256 \
		-certpbe pbeWithSHA1And3-KeyTripleDES-CBC -keypbe pbeWithSHA1And3-KeyTripleDES-CBC

%-key-md5-des-sha1.p12: %-key-pkcs8.pem %-cert.pem
	KEYFILE="$<"; $(OPENSSL) pkcs12 $(OSSLARGSP12) -export -macalg SHA1 \
		-certpbe pbeWithMD5AndDES-CBC -keypbe pbeWithMD5AndDES-CBC

%-key-aes256-cbc-sha256.p12: %-key-pkcs8.pem %-cert.pem
	KEYFILE="$<"; $(OPENSSL) pkcs12 $(OSSLARGSP12) -export -macalg SHA256 \
		-certpbe AES-256-CBC -keypbe AES-256-CBC

# NB: Needs OpenSSL 1.1 or newer
%-key-nonascii-password.p12: %-key-pkcs8.pem %-cert.pem
	LC_ALL=en_GB.UTF-8 PASSWORD="$$(cat $(srcdir)/pass-UTF-8)" KEYFILE="$<" ; \
	$(OPENSSL) pkcs12 $(OSSLARGSP12) -export -macalg SHA256 \
		-certpbe AES-256-CBC -keypbe AES-256-CBC

# This one makes GnuTLS behave strangely...
%-key-aes256-cbc-md5-des-sha256.p12: %-key-pkcs8.pem %-cert.pem
	KEYFILE="$<"; $(OPENSSL) pkcs12 $(OSSLARGSP12) -export -macalg SHA256 \
		-certpbe AES-256-CBC -keypbe pbeWithMD5AndDES-CBC

%.der: %.pem
	sed -e '0,/^-----BEGIN.*KEY-----/d' -e '/^-----END.*KEY-----/,$$d' $< | base64 -d > $@

$(certsdir)/server-cert.pem:
	$(OPENSSL) req -new -config $(srcdir)/configs/server-cert.prm -key $(certsdir)/server-key.pem -out $@.csr
	$(OPENSSL) x509 -days 3650 -CA $(certsdir)/ca.pem -CAkey $(certsdir)/ca-key.pem \
		-extfile $(srcdir)/configs/server-cert.prm -extensions req_EXT \
		-set_serial $(shell date +%s) -req -out $@ -in $@.csr

%-cert.csr: %-key-pkcs8.pem
	$(OPENSSL) req -new -config $(srcdir)/configs/user-cert.prm -key $< -out $@

%.pem: %.csr
	$(OPENSSL) x509 -days 3650 -CA $(certsdir)/ca.pem -CAkey $(certsdir)/ca-key.pem \
		-set_serial $(shell date +%s) -req -out $@ -in $<

SHM2_UTIL=SOFTHSM2_CONF=softhsm2.conf softhsm2-util
P11TOOL=SOFTHSM2_CONF=softhsm2.conf p11tool

# Nice and simple: Certs visible without login, public keys present in token
softhsm-setup0:
	$(SHM2_UTIL) --show-slots
	$(SHM2_UTIL) --init-token --free --label openconnect-test \
		--so-pin 12345678 --pin 1234

	$(SHM2_UTIL) --token openconnect-test --pin 1234 --import $(certsdir)/user-key-pkcs8.pem \
		--label RSA --id 01
	$(P11TOOL) --load-certificate $(certsdir)/user-cert.pem --no-mark-private \
		   --label RSA --id 01 --set-pin 1234 --login \
		   --write "pkcs11:token=openconnect-test;pin-value=1234"

	$(SHM2_UTIL) --token openconnect-test --pin 1234 --import $(certsdir)/dsa-key-pkcs8.pem \
		--label DSA --id 02
	$(P11TOOL) --load-certificate $(certsdir)/dsa-cert.pem --no-mark-private \
		   --label DSA --id 02 --set-pin 1234 --login \
		   --write "pkcs11:token=openconnect-test;pin-value=1234"

	$(SHM2_UTIL) --token openconnect-test --pin 1234 --import $(certsdir)/ec-key-pkcs8.pem \
			--label EC --id 03
	$(P11TOOL) --load-certificate $(certsdir)/ec-cert.pem --no-mark-private \
		   --label EC --id 03 --set-pin 1234 --login \
		   --write "pkcs11:token=openconnect-test;pin-value=1234"

# Second test: Import keys with GnuTLS so public key is absent
softhsm-setup1:
	$(SHM2_UTIL) --show-slots
	$(SHM2_UTIL) --init-token --free --label openconnect-test1 \
		--so-pin 12345678 --pin 1234

	$(P11TOOL) --load-certificate $(certsdir)/user-cert.pem --no-mark-private \
		   --load-privkey $(certsdir)/user-key-pkcs8.pem \
		   --label RSA --id 01 --login \
		   --write "pkcs11:token=openconnect-test1;pin-value=1234"

	$(P11TOOL) --load-certificate $(certsdir)/dsa-cert.pem --no-mark-private \
		   --load-privkey $(certsdir)/dsa-key-pkcs8.pem \
		   --label DSA --id 02 --login \
		   --write "pkcs11:token=openconnect-test1;pin-value=1234"

	$(P11TOOL) --load-certificate $(certsdir)/ec-cert.pem --no-mark-private \
		   --load-privkey $(certsdir)/ec-key-pkcs8.pem \
		   --label EC --id 03 --login \
		   --write "pkcs11:token=openconnect-test1;pin-value=1234"

# Third test: CKA_PRIVATE on certificates
softhsm-setup2:
	$(SHM2_UTIL) --show-slots
	$(SHM2_UTIL) --init-token --free --label openconnect-test2 \
		--so-pin 12345678 --pin 1234

	$(P11TOOL) --load-certificate $(certsdir)/user-cert.pem \
		   --load-privkey $(certsdir)/user-key-pkcs8.pem \
		   --label RSA --id 01 --login \
		   --write "pkcs11:token=openconnect-test2;pin-value=1234"

	$(P11TOOL) --load-certificate $(certsdir)/dsa-cert.pem \
		   --load-privkey $(certsdir)/dsa-key-pkcs8.pem \
		   --label DSA --id 02 --login \
		   --write "pkcs11:token=openconnect-test2;pin-value=1234"

	$(P11TOOL) --load-certificate $(certsdir)/ec-cert.pem \
		   --load-privkey $(certsdir)/ec-key-pkcs8.pem \
		   --label EC --id 03 --login \
		   --write "pkcs11:token=openconnect-test2;pin-value=1234"

# Fourth test: token lacks CKF_LOGIN_REQUIRED (#123)
softhsm-setup3:
	$(SHM2_UTIL) --show-slots
	$(SHM2_UTIL) --init-token --free --label openconnect-test3 \
		--so-pin 12345678 --pin 1234

# Remove the CKF_LOGIN_REQUIRED flag
	TOKOBJ=$$(grep -l openconnect-test3 $(srcdir)/softhsm/*/token.object); \
	if [ -n "$$TOKOBJ" ] && od -t x1 $$TOKOBJ | grep -q '^0000160.* 04 2d$$'; then \
		echo -en \\x29 | dd bs=1 count=1 conv=notrunc seek=127 of=$$TOKOBJ; \
	else \
		echo "Token file not understood"; \
		exit 1; \
	fi

	$(P11TOOL) --load-certificate $(certsdir)/user-cert.pem \
		   --load-privkey $(certsdir)/user-key-pkcs8.pem \
		   --label RSA --id 01 --login \
		   --write "pkcs11:token=openconnect-test3;pin-value=1234"

	$(P11TOOL) --load-certificate $(certsdir)/dsa-cert.pem \
		   --load-privkey $(certsdir)/dsa-key-pkcs8.pem \
		   --label DSA --id 02 --login \
		   --write "pkcs11:token=openconnect-test3;pin-value=1234"

	$(P11TOOL) --load-certificate $(certsdir)/ec-cert.pem \
		   --load-privkey $(certsdir)/ec-key-pkcs8.pem \
		   --label EC --id 03 --login \
		   --write "pkcs11:token=openconnect-test3;pin-value=1234"
