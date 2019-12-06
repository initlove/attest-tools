/*
 * Copyright (C) 2019 Huawei Technologies Duesseldorf GmbH
 *
 * Author: Roberto Sassu <roberto.sassu@huawei.com>
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public License as
 * published by the Free Software Foundation, version 2 of the
 * License.
 *
 * File: attest_tls_common.c
 *      Common functions for TLS client/server.
 */

/* Code taken from https://wiki.openssl.org/index.php/Simple_TLS_Server */

#include <openssl/ssl.h>
#include <openssl/err.h>
#include <openssl/engine.h>
#include <openssl/engine.h>

#include <ibmtss/Implementation.h>

#include "skae.h"
#include "attest_tls_common.h"

void init_openssl()
{
	SSL_load_error_strings();
	OpenSSL_add_ssl_algorithms();
}

void cleanup_openssl()
{
	EVP_cleanup();
	OPENSSL_cleanup();
}

SSL_CTX *create_context(int context_type)
{
	const SSL_METHOD *method;
	SSL_CTX *ctx;

	if (context_type == CONTEXT_CLIENT)
		method = SSLv23_client_method();
	else
		method = SSLv23_server_method();

	ctx = SSL_CTX_new(method);
	if (!ctx) {
		perror("Unable to create SSL context");
		ERR_print_errors_fp(stderr);
	}

	return ctx;
}

int configure_context(SSL_CTX *ctx, int engine, int verify_skae, char *key_path,
		      char *cert_path, char *ca_path)
{
	STACK_OF(X509) *chain = sk_X509_new(NULL);
	EVP_PKEY *pk = NULL;
	ENGINE *e = NULL;
	const char *engine_id = "tpm2";
	FILE *fp;
	X509 *cert = NULL, *ca_cert = NULL;
	int rc = -EINVAL;

	if (engine) {
		ENGINE_load_builtin_engines();

		if ((e = ENGINE_by_id(engine_id)) == NULL) {
			ERR_print_errors_fp(stderr);
			goto out;
		}

		if (!ENGINE_init(e)) {
			ERR_print_errors_fp(stderr);
			goto out;
		}

		if (!ENGINE_set_default(e, ENGINE_METHOD_ALL)) {
			ERR_print_errors_fp(stderr);
			goto out;
		}

		pk = ENGINE_load_private_key(e, key_path, NULL, NULL);
		if (!pk) {
			ERR_print_errors_fp(stderr);
			goto out;
		}
	} else {
		fp = fopen(key_path, "r");
		if (!fp)
			goto out;

		pk = PEM_read_PrivateKey(fp, &pk, NULL, NULL);
		fclose(fp);

		if (!pk)
			goto out;
	}

	fp = fopen(cert_path, "r");
	if (!fp)
		goto out;

	cert = PEM_read_X509(fp, &cert, NULL, NULL);
	fclose(fp);

	if (!cert)
		goto out;

	if (ca_path) {
		fp = fopen(ca_path, "r");
		if (!fp)
			goto out;

		ca_cert = PEM_read_X509(fp, &ca_cert, NULL, NULL);
		fclose(fp);

		if (!ca_cert)
			goto out;

		sk_X509_push(chain, ca_cert);

		SSL_CTX_load_verify_locations(ctx, ca_path, NULL);
	}

	SSL_CTX_set_ecdh_auto(ctx, 1);

	if (SSL_CTX_use_cert_and_key(ctx, cert, pk, chain, 0) <= 0) {
		ERR_print_errors_fp(stderr);
		goto out;
	}

	if (verify_skae)
		 SSL_CTX_set_verify(ctx, SSL_VERIFY_PEER, skae_callback);

	rc = 0;
out:
	if (rc)
		printf("Cannot configure the SSL context\n");

	if (pk)
		EVP_PKEY_free(pk);

	if (e) {
		ENGINE_finish(e);
		ENGINE_free(e);
	}

	X509_free(cert);
	X509_free(ca_cert);
	sk_X509_free(chain);

	return rc;
}

static int configure_pcr(char *pcr_list_str)
{
	unsigned char pcr_mask[] = { 0x00, 0x00, 0x00 };
	int pcr_list[IMPLEMENTATION_PCR];
	int rc, i;

	if (!pcr_list_str)
		return 0;

	rc = attest_util_parse_pcr_list(pcr_list_str,
					sizeof(pcr_list) / sizeof(*pcr_list),
					pcr_list);
	if (rc < 0)
		return rc;

	for (i = 0; i < IMPLEMENTATION_PCR; i++) {
		if (pcr_list[i] == -1)
			continue;

		pcr_mask[pcr_list[i] / 8] |= 1 << (pcr_list[i] % 8);
	}

	attest_ctx_verifier_set_pcr_mask(attest_ctx_verifier_get_global(),
					 sizeof(pcr_mask), pcr_mask);

	return 0;
}

int configure_attest(int fd, size_t recv_data_size,
		     unsigned char *recv_attest_data, char *pcr_list_str,
		     char *req_path)
{
	int rc;

	rc = configure_pcr(pcr_list_str);
	if (rc < 0)
		return rc;

	attest_ctx_verifier_req_add_json_file(attest_ctx_verifier_get_global(),
					      req_path);

	return attest_ctx_data_add_json_data(attest_ctx_data_get_global(),
					     (char *)recv_attest_data,
					     recv_data_size);
}
