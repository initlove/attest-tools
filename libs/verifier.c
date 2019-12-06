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
 * File: verifier.c
 *      Verifier functions.
 */

/**
 * @defgroup verifier-api Verifier API
 * @ingroup app-api
 * @brief
 * Functions to verify TPM specific data structures (e.g. quote or certify
 * info).
 */

/**
 * @addtogroup verifier-api
 *  @{
 */

#include <stdio.h>
#include <fcntl.h>
#include <string.h>
#include <unistd.h>
#include <stdlib.h>
#include <errno.h>

#include "ctx.h"
#include "util.h"
#include "event_log.h"
#include "verifier.h"
#include "crypto.h"

#include "tpm2-common.h"

static int attest_verifier_check_signature(attest_ctx_data *d_ctx,
					   attest_ctx_verifier *v_ctx,
					   INT32 tpms_attest_len,
					   BYTE *tpms_attest,
					   INT32 signature_len,
					   BYTE *signature)
{
	struct verification_log *log;
	TPMT_SIGNATURE tpmtSignature;
	TPMT_HA digest;
	X509 *x509 = NULL;
	int rc;

	log = attest_ctx_verifier_add_log(v_ctx,
					  "verify signature of attest data");

	rc = TPMT_SIGNATURE_Unmarshal(&tpmtSignature,
				      &signature, &signature_len, TRUE);
	check_goto(rc, -EINVAL, out, v_ctx,
		   "TPMT_SIGNATURE_Unmarshal() error: %d", rc);

	digest.hashAlg = TPM_ALG_NULL;
	if (tpmtSignature.sigAlg != TPM_ALG_NULL)
		digest.hashAlg = tpmtSignature.signature.any.hashAlg;

	rc = TSS_Hash_Generate(&digest, tpms_attest_len, tpms_attest,
			       0, NULL);
	check_goto(rc, -EINVAL, out, v_ctx,
		   "TSS_Hash_Generate() error: %d", rc);

	rc = attest_crypto_verify_cert(d_ctx, v_ctx, CTX_AIK_CERT,
				       CTX_PRIVACY_CA_CERT, &x509);
	if (rc)
		goto out;

	rc = attest_crypto_verify_sig(v_ctx, &tpmtSignature, &digest, x509);
out:
	attest_ctx_verifier_end_log(v_ctx, log, rc);
	X509_free(x509);
	return rc;
}


static int attest_verifier_check_object_name(attest_ctx_data *d_ctx,
					     attest_ctx_verifier *v_ctx,
					     TPMS_CERTIFY_INFO *certify_info)
{
	INT32 alg_len;
	BYTE *alg_ptr;
	TPMT_HA digest;
	TPM_ALG_ID algID;
	struct data_item *pkey;
	struct verification_log *log;
	int rc;

	log = attest_ctx_verifier_add_log(v_ctx, "check object name");

	alg_len = sizeof(TPM_ALG_ID);
	alg_ptr = certify_info->name.t.name;

	rc = TPM_ALG_ID_Unmarshal(&algID, &alg_ptr, &alg_len);
	check_goto(rc, -EINVAL, out, v_ctx,
		   "TPM_ALG_ID_Unmarshal() error: %d", rc);

	digest.hashAlg = algID;

	pkey = attest_ctx_data_get(d_ctx, CTX_TPM_KEY_TEMPLATE);
	check_goto(!pkey, -ENOENT, out, v_ctx, "TPM public key not provided");

	rc = TSS_Hash_Generate(&digest,
			       pkey->len - sizeof(((TPM2B_DIGEST *)0)->b.size),
			       pkey->data + sizeof(((TPM2B_DIGEST *)0)->b.size),
			       0, NULL);
	check_goto(rc, -EINVAL, out, v_ctx,
		   "TSS_Hash_Generate() error: %d", rc);

	rc = memcmp((unsigned char *)&digest.digest,
		    certify_info->name.t.name + sizeof(algID),
		    TSS_GetDigestSize(algID));
	check_goto(rc, -EINVAL, out, v_ctx, "attested key != provided key");
out:
	attest_ctx_verifier_end_log(v_ctx, log, rc);
	return rc;
}

static int attest_verifier_check_policy_digest(attest_ctx_data *d_ctx,
					       attest_ctx_verifier *v_ctx,
					       enum ctx_fields policy_field,
					       TPM_ALG_ID algID,
					       UINT32 policy_digest_len,
					       BYTE *policy_digest)
{
	TPMT_HA digest;
	struct list_head *head;
	struct data_item *policy;
	BYTE *policy_bin;
	int rc = 0;

	current_log(v_ctx);

	digest.hashAlg = algID;
	memset((BYTE *)&digest.digest, 0, TSS_GetDigestSize(digest.hashAlg));
	head = &d_ctx->ctx_data[policy_field];

	list_for_each_entry(policy, head, list) {
		policy_bin = malloc(policy->len / 2);
		check_goto(!policy_bin, -ENOMEM, out, v_ctx, "out of memory");
		rc = hex2bin(policy_bin, (const char *)policy->data,
			     policy->len / 2);
		check_goto(rc, -ENOMEM, out, v_ctx,
			   "policy hex -> bin conversion error");

		rc = TSS_Hash_Generate(&digest,
				       TSS_GetDigestSize(digest.hashAlg),
				       (BYTE *)&digest.digest,
				       policy->len / 2, policy_bin, 0, NULL);

		free(policy_bin);
		check_goto(rc, -EINVAL, out, v_ctx,
			   "TSS_Hash_Generate() error: %d", rc);
	}

	rc = memcmp((BYTE *)&digest.digest, policy_digest, policy_digest_len);
	check_goto(rc, -EINVAL, out, v_ctx,
		   "attested policy != provided policy");
out:
	return rc;
}

static int attest_verifier_check_public_key(attest_ctx_data *d_ctx,
					    attest_ctx_verifier *v_ctx,
					    TPM_ALG_ID *nameAlg,
					    EVP_PKEY *key)
{
	TPMT_PUBLIC p;
	INT32 pubkey_len;
	EVP_PKEY *key_tpm;
	struct data_item *pkey;
	BYTE *pubkey_ptr;
	struct verification_log *log;
	UINT32 req_mask = (TPMA_OBJECT_FIXEDTPM | TPMA_OBJECT_FIXEDPARENT |
			   TPMA_OBJECT_SENSITIVEDATAORIGIN);
	int rc = 0;

	log = attest_ctx_verifier_add_log(v_ctx, "check TPM public key");

	pkey = attest_ctx_data_get(d_ctx, CTX_TPM_KEY_TEMPLATE);
	check_goto(!pkey, -ENOENT, out, v_ctx, "TPM public key not provided");

	pubkey_len = pkey->len - sizeof(((TPM2B_PUBLIC *)0)->size);
	pubkey_ptr = pkey->data + sizeof(((TPM2B_PUBLIC *)0)->size);

	rc = TPMT_PUBLIC_Unmarshal(&p, &pubkey_ptr, &pubkey_len, 0);
	check_goto(rc, -EINVAL, out, v_ctx,
		   "TPMT_PUBLIC_Unmarshal() error: %d", rc);

	*nameAlg = p.nameAlg;

	key_tpm = tpm2_to_openssl_public(&p);
	check_goto(!key_tpm, -EINVAL, out, v_ctx,
		   "tpm2_to_openssl_public() error");

	rc = !EVP_PKEY_cmp(key, key_tpm);
	EVP_PKEY_free(key_tpm);

	check_goto(rc, -EINVAL, out, v_ctx, "attested key != provided key");
	check_goto((p.objectAttributes.val & TPMA_OBJECT_USERWITHAUTH) &&
		   p.authPolicy.b.size, -EINVAL, out, v_ctx,
		   "USERWITHAUTH flag set and policy specified");
	check_goto((p.objectAttributes.val & req_mask) != req_mask,
		   -EINVAL, out, v_ctx,
		   "key migratable or not generated inside the TPM");

	rc = attest_verifier_check_policy_digest(d_ctx, v_ctx,
				CTX_TPM_KEY_POLICY, p.nameAlg,
				p.authPolicy.b.size, p.authPolicy.b.buffer);
out:
	attest_ctx_verifier_end_log(v_ctx, log, rc);
	return rc;
}

static int attest_verifier_check_pcrs(attest_ctx_data *d_ctx,
				      attest_ctx_verifier *v_ctx,
				      TPM_ALG_ID hashAlg,
				      TPML_PCR_SELECTION *pcr_selection,
				      BYTE *pcr_digest, int parse_logs)
{
	struct verification_log *log;
	int rc;

	log = attest_ctx_verifier_add_log(v_ctx, "check PCR policy");

	if (!parse_logs) {
		rc = attest_pcr_verify(v_ctx, pcr_selection, hashAlg,
				       pcr_digest);
		goto out;
	}

	rc = attest_pcr_init(v_ctx);
	if (rc)
		goto out;

	rc = attest_event_log_parse_verify(d_ctx, v_ctx, 1);
	if (rc)
		goto out_cleanup;

	rc = attest_pcr_verify(v_ctx, pcr_selection, hashAlg, pcr_digest);
out_cleanup:
	attest_pcr_cleanup(v_ctx);
out:
	attest_ctx_verifier_end_log(v_ctx, log, rc);
	return rc;
}

/**
 * Check key policy
 * @param[in] d_ctx		data context
 * @param[in] v_ctx		verifier context
 * @param[in] parse_logs	Parse or not logs
 * @param[in] policy_field	Type of policy to check
 * @param[in] pcr_mask_len	Length of selected PCRs
 * @param[in] pcr_mask		Selected PCRs
 *
 * @returns 0 on success, a negative value on error
 */
int attest_verifier_check_key_policy(attest_ctx_data *d_ctx,
				     attest_ctx_verifier *v_ctx,
				     TPM_ALG_ID hashAlg,
				     int parse_logs,
				     enum ctx_fields policy_field,
				     int pcr_mask_len, uint8_t *pcr_mask)
{
	struct list_head *head = &d_ctx->ctx_data[policy_field];
	BYTE *policy_bin = NULL, *policy_bin_ptr;
	struct verification_log *log;
	TPML_PCR_SELECTION pcrs;
	INT32 policy_bin_len;
	struct data_item *policy;
	TPM_CC code;
	int rc = 0;

	log = attest_ctx_verifier_add_log(v_ctx, "check key policy");

	list_for_each_entry(policy, head, list) {
		policy_bin_len = policy->len / 2;
		policy_bin_ptr = policy_bin = malloc(policy_bin_len);
		check_goto(!policy_bin, -ENOMEM, out, v_ctx, "out of memory");

		rc = hex2bin(policy_bin, (const char *)policy->data,
			     policy_bin_len);
		check_goto(rc, -EINVAL, out_free, v_ctx,
			   "policy hex -> bin conversion error");

		rc = TPM_CC_Unmarshal(&code, &policy_bin_ptr, &policy_bin_len);
		check_goto(rc, -EINVAL, out_free, v_ctx,
			   "TPM_CC_Unmarshal() error: %d", rc);

		if (code != TPM_CC_PolicyPCR) {
			free(policy_bin);
			continue;
		}

		rc = TPML_PCR_SELECTION_Unmarshal(&pcrs, &policy_bin_ptr,
						  &policy_bin_len);
		check_goto(rc, -EINVAL, out_free, v_ctx,
			   "TPML_PCR_SELECTION_Unmarshal() error: %d", rc);

		rc = attest_util_check_mask(pcrs.pcrSelections[0].sizeofSelect,
				pcrs.pcrSelections[0].pcrSelect,
			        pcr_mask_len ?
				pcr_mask_len : sizeof(v_ctx->pcr_mask),
				pcr_mask_len ? pcr_mask : v_ctx->pcr_mask);
		check_goto(rc, rc, out_free, v_ctx,
			   "PCR mask requirement not satisfied");

		check_goto(policy_bin_len < TSS_GetDigestSize(hashAlg), -EINVAL,
			   out_free, v_ctx,
			   "insufficient data, expected: %d, current: %d",
			   TSS_GetDigestSize(hashAlg), policy_bin_len);

		rc = attest_verifier_check_pcrs(d_ctx, v_ctx, hashAlg, &pcrs,
						policy_bin_ptr, parse_logs);
		break;
	}
out_free:
	free(policy_bin);
out:
	attest_ctx_verifier_end_log(v_ctx, log, rc);
	return rc;
}

static int attest_verifier_check_certify_info(attest_ctx_data *d_ctx,
					      attest_ctx_verifier *v_ctx,
					      TPMS_CERTIFY_INFO *certify_info,
					      EVP_PKEY *key)
{
	TPM_ALG_ID nameAlg;
	int rc;

	rc = attest_verifier_check_object_name(d_ctx, v_ctx, certify_info);
	if (rc)
		return rc;

	rc = attest_verifier_check_public_key(d_ctx, v_ctx, &nameAlg, key);
	if (rc)
		return rc;

	return attest_verifier_check_key_policy(d_ctx, v_ctx, nameAlg, 1,
						CTX_TPM_KEY_POLICY, 0, NULL);
}

static int attest_verifier_check_quote_info(attest_ctx_data *d_ctx,
					    attest_ctx_verifier *v_ctx,
					    TPMS_QUOTE_INFO *quote_info,
					    TPMT_SIGNATURE *signature)
{
	return attest_verifier_check_pcrs(d_ctx, v_ctx,
					  signature->signature.any.hashAlg,
					  &quote_info->pcrSelect,
					  quote_info->pcrDigest.b.buffer, 1);
}

static int attest_verifier_check_extra_data(attest_ctx_data *d_ctx,
					    attest_ctx_verifier *v_ctx,
					    TPM2B_DATA *extraData)
{
	struct verification_log *log;
	struct data_item *nonce;
	int rc;

	log = attest_ctx_verifier_add_log(v_ctx, "check extra data");

	nonce = attest_ctx_data_get(d_ctx, CTX_NONCE);
	check_goto(!nonce, -ENOENT, out, v_ctx, "Nonce not provided");

	check_goto(nonce->len != extraData->t.size, -EINVAL, out, v_ctx,
		   "extra data length mismatch");

	rc = memcmp(nonce->data, extraData->t.buffer, nonce->len);
	check_goto(rc, -EINVAL, out, v_ctx, "extra data mismatch");
out:
	attest_ctx_verifier_end_log(v_ctx, log, rc);
	return rc;
}

/**
 * check TPMS_ATTEST data structure
 * @param[in] d_ctx		data context
 * @param[in] v_ctx		verifier context
 * @param[in] tpms_attest_len	length of marshalled TPMS_ATTEST
 * @param[in] tpms_attest	marshalled TPMS_ATTEST
 * @param[in] sig_len		length of marshalled TPMT_SIGNATURE
 * @param[in] sig		marshalled TPMT_SIGNATURE
 * @param[in] key		OpenSSL key for verification of CERTIFY_INFO
 *
 * @returns 0 on success, a negative value on error
 */
int attest_verifier_check_tpms_attest(attest_ctx_data *d_ctx,
				      attest_ctx_verifier *v_ctx,
				      INT32 tpms_attest_len,
				      BYTE *tpms_attest,
				      INT32 sig_len, BYTE *sig,
				      EVP_PKEY *key)
{
	TPMS_ATTEST a;
	TPMT_SIGNATURE s;
	int rc;

	if (!d_ctx || !v_ctx)
		return -EINVAL;

	rc = attest_verifier_check_signature(d_ctx, v_ctx, tpms_attest_len,
					     tpms_attest, sig_len, sig);
	if (rc)
		return rc;

	rc = TPMS_ATTEST_Unmarshal(&a, &tpms_attest, &tpms_attest_len);
	if (rc)
		return rc;

	rc = TPMT_SIGNATURE_Unmarshal(&s, &sig, &sig_len, TRUE);
	if (rc)
		return rc;

	switch (a.type) {
	case TPM_ST_ATTEST_CERTIFY:
		rc = attest_verifier_check_certify_info(d_ctx, v_ctx,
					(TPMS_CERTIFY_INFO *)&a.attested, key);
		break;
	case TPM_ST_ATTEST_QUOTE:
		rc = attest_verifier_check_extra_data(d_ctx, v_ctx,
					&a.extraData);
		if (rc)
			break;

		rc = attest_verifier_check_quote_info(d_ctx, v_ctx,
					(TPMS_QUOTE_INFO *)&a.attested, &s);
		break;
	default:
		rc = -ENOTSUP;
	}

	return rc;
}

/**
 * check TPM2B_PUBLIC data structure
 * @param[in] d_ctx		data context
 * @param[in] v_ctx		verifier context
 * @param[in] buffer_len	buffer length
 * @param[in] buffer		buffer containing TPM2B_PRIVATE and TPM2B_PUBLIC
 * @param[in] private		buffer contains TPM2B_PRIVATE
 * @param[in] req_mask		mask of flags to check in TPM2B_PUBLIC
 * @param[in] policy_field	policy field to verify policy digest
 * @param[in,out] nameAlg	hash algorithm of name
 * @param[in,out] name		calculated object name
 *
 * @returns 0 on success, a negative value on error
 */
int attest_verifier_check_tpm2b_public(attest_ctx_data *d_ctx,
			attest_ctx_verifier *v_ctx, INT32 buffer_len,
			BYTE *buffer, int private, UINT32 req_mask,
			enum ctx_fields policy_field, TPM_ALG_ID *nameAlg,
			TPM2B_NAME *name)
{
	TPMT_HA digest;
	TPM2B_PRIVATE priv;
	TPM2B_PUBLIC pub;
	struct verification_log *log;
	BYTE *buffer_ptr = buffer;
	int rc, len = buffer_len;

	log = attest_ctx_verifier_add_log(v_ctx, "validate TPM2B_PUBLIC");

	if (private) {
		rc = TPM2B_PRIVATE_Unmarshal(&priv, &buffer_ptr, &len);
		check_goto(rc, -EINVAL, out, v_ctx,
			   "TPM2B_PRIVATE_Unmarshal() error: %d", rc);
	}

	rc = TPM2B_PUBLIC_Unmarshal(&pub, &buffer_ptr, &len, 0);
	check_goto(rc, -EINVAL, out, v_ctx,
		   "TPM2B_PUBLIC_Unmarshal() error: %d", rc);

	check_goto((pub.publicArea.objectAttributes.val & req_mask) != req_mask,
		   -EINVAL, out, v_ctx, "Invalid flags");

	if (pub.publicArea.authPolicy.b.size) {
		check_goto(policy_field == CTX__LAST, -ENOENT, out, vctx,
			   "policy not provided\n");

		rc = attest_verifier_check_policy_digest(d_ctx, v_ctx,
					policy_field, pub.publicArea.nameAlg,
					pub.publicArea.authPolicy.b.size,
					pub.publicArea.authPolicy.b.buffer);
		check_goto(rc, rc, out, v_ctx,
			   "attest_verifier_check_policy_digest failed\n");
	}

	digest.hashAlg = *nameAlg = pub.publicArea.nameAlg;

	rc = TSS_Hash_Generate(&digest,
			       buffer_len - sizeof(((TPM2B_DIGEST *)0)->b.size),
			       buffer + sizeof(((TPM2B_DIGEST *)0)->b.size), 0,
			       NULL);
	check_goto(rc, -EINVAL, out, v_ctx,
		   "TSS_Hash_Generate() error: %d", rc);

	buffer_ptr = name->b.buffer;
	name->b.size = 0;

	rc = TSS_TPMT_HA_Marshal(&digest, &name->b.size, &buffer_ptr, NULL);
	check_goto(rc, -EINVAL, out, v_ctx,
		   "TSS_TPMT_HA_Marshal() error: %d", rc);

out:
	attest_ctx_verifier_end_log(v_ctx, log, rc);
	return rc;
}
/** @}*/
