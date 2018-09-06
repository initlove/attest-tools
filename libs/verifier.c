/**
 * @name Attestation Data Verifier Function
 * \addtogroup user-api
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

	v_ctx->pcr_algo = digest.hashAlg;

	rc = TSS_Hash_Generate(&digest, tpms_attest_len, tpms_attest,
			       0, NULL);
	check_goto(rc, -EINVAL, out, v_ctx,
		   "TSS_Hash_Generate() error: %d", rc);

	rc = attest_crypto_verify_cert(d_ctx, v_ctx, &x509);
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

	rc = TSS_Hash_Generate(&digest, pkey->len - sizeof(UINT16),
			       pkey->data + sizeof(UINT16), 0, NULL);
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

static int attest_verifier_check_public_key(attest_ctx_data *d_ctx,
					    attest_ctx_verifier *v_ctx,
					    EVP_PKEY *key)
{
	TPMT_PUBLIC p;
	TPMT_HA digest;
	INT32 pubkey_len;
	EVP_PKEY *key_tpm;
	struct list_head *head;
	struct data_item *pkey, *policy;
	BYTE *pubkey_ptr, *policy_bin;
	struct verification_log *log;
	int rc = 0;

	log = attest_ctx_verifier_add_log(v_ctx, "check TPM public key");

	pkey = attest_ctx_data_get(d_ctx, CTX_TPM_KEY_TEMPLATE);
	check_goto(!pkey, -ENOENT, out, v_ctx, "TPM public key not provided");

	pubkey_len = pkey->len - sizeof(UINT16);
	pubkey_ptr = pkey->data + sizeof(UINT16);

	rc = TPMT_PUBLIC_Unmarshal(&p, &pubkey_ptr, &pubkey_len, 0);
	check_goto(rc, -EINVAL, out, v_ctx,
		   "TPMT_PUBLIC_Unmarshal() error: %d", rc);

	v_ctx->pcr_algo = p.nameAlg;

	key_tpm = tpm2_to_openssl_public(&p);
	check_goto(!key_tpm, -EINVAL, out, v_ctx,
		   "tpm2_to_openssl_public() error");

	rc = !EVP_PKEY_cmp(key, key_tpm);
	EVP_PKEY_free(key_tpm);

	check_goto(rc, -EINVAL, out, v_ctx, "attested key != provided key");
	check_goto((p.objectAttributes.val & TPMA_OBJECT_USERWITHAUTH) &&
		   p.authPolicy.b.size, -EINVAL, out, v_ctx,
		   "USERWITHAUTH flag set and policy specified");
	check_goto(!(p.objectAttributes.val & TPMA_OBJECT_SENSITIVEDATAORIGIN),
		   -EINVAL, out, v_ctx,
		   "USERWITHAUTH flag set and policy specified");

	digest.hashAlg = p.nameAlg;
	memset((BYTE *)&digest.digest, 0, TSS_GetDigestSize(digest.hashAlg));
	head = &d_ctx->ctx_data[CTX_TPM_KEY_POLICY];

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

	rc = memcmp((BYTE *)&digest.digest,
		    p.authPolicy.b.buffer, p.authPolicy.b.size);
	check_goto(rc, -EINVAL, out, v_ctx,
		   "attested policy != provided policy");
out:
	attest_ctx_verifier_end_log(v_ctx, log, rc);
	return rc;
}

static int attest_verifier_check_pcrs(attest_ctx_data *d_ctx,
				      attest_ctx_verifier *v_ctx,
				      TPML_PCR_SELECTION *pcr_selection,
				      BYTE *pcr_digest)
{
	struct verification_log *log;
	int rc;

	log = attest_ctx_verifier_add_log(v_ctx, "check PCR policy");

	rc = attest_pcr_init(v_ctx);
	if (rc)
		goto out;

	rc = attest_event_log_verify(d_ctx, v_ctx);
	if (rc)
		goto out_cleanup;

	rc = attest_pcr_verify(v_ctx, pcr_selection, pcr_digest);
out_cleanup:
	attest_pcr_cleanup(v_ctx);
out:
	attest_ctx_verifier_end_log(v_ctx, log, rc);
	return rc;
}

static int attest_verifier_check_key_policy(attest_ctx_data *d_ctx,
					    attest_ctx_verifier *v_ctx)
{
	struct list_head *head = &d_ctx->ctx_data[CTX_TPM_KEY_POLICY];
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

		rc = attest_verifier_check_pcrs(d_ctx, v_ctx, &pcrs,
						policy_bin_ptr);
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
	int rc;

	rc = attest_verifier_check_object_name(d_ctx, v_ctx, certify_info);
	if (rc)
		return rc;

	rc = attest_verifier_check_public_key(d_ctx, v_ctx, key);
	if (rc)
		return rc;

	return attest_verifier_check_key_policy(d_ctx, v_ctx);
}


static int attest_verifier_check_quote_info(attest_ctx_data *d_ctx,
					    attest_ctx_verifier *v_ctx,
					    TPMS_QUOTE_INFO *quote_info)
{
	return attest_verifier_check_pcrs(d_ctx, v_ctx, &quote_info->pcrSelect,
					  quote_info->pcrDigest.b.buffer);
}

/**
 * check TPMS_ATTEST data structure
 *
 * @param[in] d_ctx	data context
 * @param[in] v_ctx	verifier context
 * @param[in] tpms_attest_len	length of marshalled TPMS_ATTEST
 * @param[in] tpms_attest	marshalled TPMS_ATTEST
 * @param[in] sig_len	length of marshalled TPMT_SIGNATURE
 * @param[in] sig	marshalled TPMT_SIGNATURE
 * @param[in] key	OpenSSL key for verification of CERTIFY_INFO
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

	switch (a.type) {
	case TPM_ST_ATTEST_CERTIFY:
		rc = attest_verifier_check_certify_info(d_ctx, v_ctx,
					(TPMS_CERTIFY_INFO *)&a.attested, key);
		break;
	case TPM_ST_ATTEST_QUOTE:
		rc = attest_verifier_check_quote_info(d_ctx, v_ctx,
					(TPMS_QUOTE_INFO *)&a.attested);
		break;
	default:
		rc = -ENOTSUP;
	}

	return rc;
}
/** @}*/
