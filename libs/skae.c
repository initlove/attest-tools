/*
 * Copyright (C) 2018-2019 Huawei Technologies Duesseldorf GmbH
 *
 * Author: Roberto Sassu <roberto.sassu@huawei.com>
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public License as
 * published by the Free Software Foundation, version 2 of the
 * License.
 *
 * File: skae.c
 *      SKAE functions.
 */

/**
 * @defgroup skae-api SKAE API
 * @ingroup app-api
 * @brief
 * Functions to create or verify a SKAE extension in a X.509 certificate or CSR.
 */

/**
 * \addtogroup skae-api
 *  @{
 */

#include <stdio.h>
#include <errno.h>
#include <unistd.h>
#include <stdint.h>
#include <string.h>

#include "skae.h"
#include "util.h"
#include "ctx_json.h"
#include "verifier.h"

static int skae_check_ext(attest_ctx_data *d_ctx, attest_ctx_verifier *v_ctx,
			  ASN1_OCTET_STRING *data, EVP_PKEY *key)
{
	const unsigned char *data_ptr = data->data;
	uint16_t tpms_attest_len, sig_len;
	unsigned char *tpms_attest, *sig;
	SUBJECTKEYATTESTATIONEVIDENCE *skae = NULL;
	KEYATTESTATIONEVIDENCE *k;
	TPMCERTIFYINFO *c;
	int rc = 0;

	current_log(v_ctx);

	skae = d2i_SUBJECTKEYATTESTATIONEVIDENCE(NULL, &data_ptr, data->length);
	check_goto(!skae, -EINVAL, out, v_ctx,
		   "SKAE der -> internal conversion failed");

	k = skae->KeyAttestationEvidence;
	check_goto(k->type != KEYATTESTATIONEVIDENCE_TYPE_NOT_ENVELOPED,
		   -ENOTSUP, out, v_ctx,
		   "attestation evidence type not supported");

	c = k->attestEvidence->TPMCertifyInfo;

	tpms_attest_len = ASN1_STRING_length(c->tpmCertifyInfo);
	tpms_attest = (unsigned char *)ASN1_STRING_get0_data(c->tpmCertifyInfo);
	sig_len = ASN1_STRING_length(c->signature);
	sig = (unsigned char *)ASN1_STRING_get0_data(c->signature);

	rc = attest_verifier_check_tpms_attest(d_ctx, v_ctx, tpms_attest_len,
					       tpms_attest, sig_len, sig, key);
out:
	SUBJECTKEYATTESTATIONEVIDENCE_free(skae);
	return rc;
}

static X509_EXTENSION *skae_get_ext(X509 *cert, X509_REQ *req,
				    const char *ext_name)
{
	ASN1_OBJECT *obj;
	X509_EXTENSION *ext = NULL, *cur_ext;
	STACK_OF(X509_EXTENSION) *exts = NULL;
	int rc = -1, i;

	obj = OBJ_txt2obj(ext_name, 1);
	if (!obj)
		return NULL;

	if (cert) {
		rc = X509_get_ext_by_OBJ(cert, obj, -1);
	} else if (req) {
		exts = X509_REQ_get_extensions(req);
		if (exts)
			rc = X509v3_get_ext_by_OBJ(exts, obj, -1);
	}
	ASN1_OBJECT_free(obj);

	if (rc == -1)
		goto out;

	if (cert)
		ext = X509_get_ext(cert, rc);
	else
		ext = sk_X509_EXTENSION_value(exts, rc);
out:
	if (exts) {
		for (i = 0; i < sk_X509_EXTENSION_num(exts); i++) {
			if (i == rc)
				continue;

			cur_ext = sk_X509_EXTENSION_value(exts, i);
			X509_EXTENSION_free(cur_ext);
		}

		sk_X509_EXTENSION_free(exts);
	}

	return ext;
}

static int skae_verify_common(attest_ctx_data *d_ctx,
			      attest_ctx_verifier *v_ctx, X509 *cert,
			      X509_REQ *req)
{
	char data_path_template[MAX_PATH_LENGTH];
	X509_EXTENSION *skae_ext = NULL, *skae_url_ext = NULL;
	ASN1_OCTET_STRING *skae_data = NULL, *skae_url_data = NULL;
	struct verification_log *log;
	EVP_PKEY *pk = NULL;
	const char *data;
	int rc = 0, fd;

	log = attest_ctx_verifier_add_log(v_ctx, "verify SKAE extension");

	check_goto(!d_ctx || !v_ctx, -EINVAL, err, v_ctx,
		   "%s context not provided", !d_ctx ? "data" : "verifier");

	check_goto(!cert && !req, -EINVAL, err, v_ctx,
		   "certificate not provided");
 
	skae_ext = skae_get_ext(cert, req, OID_SKAE);
	check_goto(!skae_ext, -ENOENT, err, v_ctx, "SKAE extension not found");

	skae_url_ext = skae_get_ext(cert, req, OID_SKAE_DATA_URL);
	if (skae_url_ext) {
		skae_url_data = X509_EXTENSION_get_data(skae_url_ext);
		data = (const char *)skae_url_data->data + 2;

		snprintf(data_path_template, sizeof(data_path_template),
			 "%s/skae-temp-file-XXXXXX", d_ctx->data_dir);

		fd = mkstemp(data_path_template);
		check_goto(fd < 0, -EACCES, err, v_ctx,
			   "mkstemp() error: %s", strerror(errno));

		rc = attest_util_download_data(data, fd);
		close(fd);

		check_goto(rc, -ENOENT, out, v_ctx, "%s download error", data);

		rc = attest_ctx_data_add_json_file(d_ctx, data_path_template);
		unlink(data_path_template);

		if (rc)
			goto out;
	}

	if (cert)
		pk = X509_get_pubkey(cert);
	else if (req)
		pk = X509_REQ_get_pubkey(req);

	check_goto(!pk, -ENOENT, err, v_ctx, "X509_get_pubkey() error");

	skae_data = X509_EXTENSION_get_data(skae_ext);

	rc = skae_check_ext(d_ctx, v_ctx, skae_data, pk);
	if (rc)
		goto err;

	rc = 1;
out:
	EVP_PKEY_free(pk);

	attest_ctx_verifier_end_log(v_ctx, log, !rc);
	return rc;
err:
	rc = 0;
	goto out;
}

/**
 * Verify provided X.509 certificate
 * @param[in] d_ctx	data context
 * @param[in] v_ctx	verifier context
 * @param[in] cert	X.509 certificate
 *
 * @returns 0 on success, a negative value on error
 */
int skae_verify_x509(attest_ctx_data *d_ctx,
		     attest_ctx_verifier *v_ctx, X509 *cert)
{
	return skae_verify_common(d_ctx, v_ctx, cert, NULL);
}

/**
 * Verify provided X.509 CSR
 * @param[in] d_ctx	data context
 * @param[in] v_ctx	verifier context
 * @param[in] req	X.509 CSR
 *
 * @returns 0 on success, a negative value on error
 */
int skae_verify_x509_req(attest_ctx_data *d_ctx,
			 attest_ctx_verifier *v_ctx, X509_REQ *req)
{
	return skae_verify_common(d_ctx, v_ctx, NULL, req);
}

/**
 * Callback function to be passed to SSL_CTX_set_verify()
 * @param[in] preverify	result of X509 verification
 * @param[in] x509_ctx	context for certificate chain verification
 *
 * @returns 1 on success, 0 on error
 */
int skae_callback(int preverify, X509_STORE_CTX* x509_ctx)
{
	X509* cert = X509_STORE_CTX_get_current_cert(x509_ctx);
	STACK_OF(X509) *certs = X509_STORE_CTX_get_chain(x509_ctx);

	if (cert != sk_X509_value(certs, 0))
		return 1;

	return skae_verify_x509(attest_ctx_data_get_global(),
				attest_ctx_verifier_get_global(), cert);
}

/**
 * Create SKAE extension
 * @param[in] version	T	CG version
 * @param[in] tpms_attest_len	length of marshalled TPMS_ATTEST
 * @param[in] tpms_attest	marshalled TPMS_ATTEST
 * @param[in] sig_len		length of marshalled TPMT_SIGNATURE
 * @param[in] sig		marshalled TPMT_SIGNATURE
 * @param[in,out] skae_bin_len	length of marshalled SKAE
 * @param[in,out] skae_bin	marshalled SKAE
 * @param[in,out] skae_obj	SKAE object
 *
 * @returns 0 on success, a negative value on error
 */
int skae_create(enum skae_versions version,
		size_t tpms_attest_len, unsigned char *tpms_attest,
		size_t sig_len, unsigned char *sig,
		size_t *skae_bin_len, unsigned char **skae_bin,
		SUBJECTKEYATTESTATIONEVIDENCE **skae_obj)
{
	SUBJECTKEYATTESTATIONEVIDENCE *skae;
	KEYATTESTATIONEVIDENCE *k;
	int rc = -ENOMEM, major, minor;

	skae = SUBJECTKEYATTESTATIONEVIDENCE_new();
	if (!skae) {
		fprintf(stderr, "Cannot create SKAE\n");
		goto out;
	}

	skae->type = OBJ_txt2obj(OID_SKAE, 1);
	if (!skae->type) {
		fprintf(stderr, "Cannot create SKAE\n");
		goto out_skae;
	}

	switch (version) {
	case SKAE_VER_1_2:
		major = 1;
		minor = 2;
		break;
	case SKAE_VER_2_0:
		major = 2;
		minor = 0;
		break;
	default:
		fprintf(stderr, "Invalid SKAE version\n");
		return -EINVAL;
	}

	ASN1_INTEGER_set(skae->TCGSpecVersion->major, major);
	ASN1_INTEGER_set(skae->TCGSpecVersion->minor, minor);

	k = skae->KeyAttestationEvidence;
	k->type = KEYATTESTATIONEVIDENCE_TYPE_NOT_ENVELOPED;
	k->attestEvidence = ATTESTATIONEVIDENCE_new();
	if (!k->attestEvidence) {
		fprintf(stderr, "Cannot create SKAE\n");
		goto out_skae;
	}

	ASN1_STRING_set(k->attestEvidence->TPMCertifyInfo->tpmCertifyInfo,
			tpms_attest, tpms_attest_len);
	ASN1_STRING_set(k->attestEvidence->TPMCertifyInfo->signature,
			sig, sig_len);

	rc = i2d_SUBJECTKEYATTESTATIONEVIDENCE(skae, skae_bin);
	if (rc > 0)
		*skae_bin_len = rc;

out_skae:
	if (!skae_obj)
		SUBJECTKEYATTESTATIONEVIDENCE_free(skae);
	else
		*skae_obj = skae;
out:
	return rc > 0 ? 0 : -EINVAL;
}
/** @}*/
