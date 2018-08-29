/**
 * @name Subject Key Attestation Evidence (SKAE) Functions
 * \addtogroup user-api
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
#include "skae-asn.h"

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

static ASN1_OCTET_STRING *skae_get_ext_data(X509 *cert, const char *ext_name)
{
	ASN1_OBJECT *obj;
	X509_EXTENSION *ext;
	ASN1_OCTET_STRING *ext_data = NULL;
	int rc;

	obj = OBJ_txt2obj(ext_name, 1);
	rc = X509_get_ext_by_OBJ(cert, obj, -1);
	ASN1_OBJECT_free(obj);

	if (rc == -1)
		return NULL;

	ext = X509_get_ext(cert, rc);
	if (!ext)
		return NULL;

	ext_data = X509_EXTENSION_get_data(ext);
	if (!ext_data)
		return NULL;

	return ext_data;
}

/**
 * Verify provided X.509 certificate
 *
 * @param[in] d_ctx	data context
 * @param[in] v_ctx	verifier context
 * @param[in] cert	X.509 certificate
 *
 * @returns 0 on success, a negative value on error
 */
int skae_verify_x509(attest_ctx_data *d_ctx,
		     attest_ctx_verifier *v_ctx, X509 *cert)
{
	char data_path_template[MAX_PATH_LENGTH];
	ASN1_OCTET_STRING *skae_data = NULL, *skae_data_url = NULL;
	struct verification_log *log;
	EVP_PKEY *pk = NULL;
	const char *data;
	int rc = 0, fd;

	log = attest_ctx_verifier_add_log(v_ctx, "verify SKAE extension");

	check_goto(!d_ctx || !v_ctx, -EINVAL, err, v_ctx,
		   "%s context not provided", !d_ctx ? "data" : "verifier");

	check_goto(!cert, -EINVAL, err, v_ctx, "certificate not provided");

	skae_data = skae_get_ext_data(cert, OID_SKAE);
	check_goto(!skae_data, -ENOENT, err, v_ctx, "SKAE extension not found");

	skae_data_url = skae_get_ext_data(cert, OID_SKAE_DATA_URL);
	if (skae_data_url) {
		data = (const char *)skae_data_url->data + 2;

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

	pk = X509_get_pubkey(cert);
	check_goto(!pk, -ENOENT, err, v_ctx, "X509_get_pubkey() error");

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

	return skae_verify_x509(NULL, NULL, cert);
}

/**
 * Create SKAE extension
 * @param[in] version	TCG version
 * @param[in] tpms_attest_len	length of marshalled TPMS_ATTEST
 * @param[in] tpms_attest	marshalled TPMS_ATTEST
 * @param[in] sig_len	length of marshalled TPMT_SIGNATURE
 * @param[in,out] skae_bin_len	length of marshalled SKAE
 * @param[in,out] skae_bin	marshalled SKAE
 *
 * @returns 0 on success, a negative value on error
 */
int skae_create(enum skae_versions version,
		size_t tpms_attest_len, unsigned char *tpms_attest,
		size_t sig_len, unsigned char *sig,
		size_t *skae_bin_len, unsigned char **skae_bin)
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
	SUBJECTKEYATTESTATIONEVIDENCE_free(skae);
out:
	return rc > 0 ? 0 : -EINVAL;
}
/** @}*/
