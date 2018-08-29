#ifndef _SKAE_H
#define _SKAE_H

#include <openssl/pem.h>
#include <openssl/x509.h>

#if OPENSSL_VERSION_NUMBER < 0x10100000
#define ASN1_STRING_get0_data(obj) ASN1_STRING_data(obj)
#endif

#include "ctx.h"

enum skae_versions { SKAE_VER_1_2, SKAE_VER_2_0 };

int skae_verify_x509(attest_ctx_data *d_ctx,
		     attest_ctx_verifier *v_ctx, X509 *cert);
int skae_callback(int preverify, X509_STORE_CTX* x509_ctx);

int skae_create(enum skae_versions version,
		size_t tpms_attest_len, unsigned char *tpms_attest,
		size_t sig_len, unsigned char *sig,
		size_t *skae_bin_len, unsigned char **skae_bin);

#endif /*_SKAE_H*/
