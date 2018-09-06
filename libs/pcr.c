/** @defgroup pcr-api PCR API
 *  @ingroup developer-api
 *  Event Log API
 */

/**
 * @name PCR Functions
 * \addtogroup pcr-api
 *  @{
 */

#include <stdio.h>
#include <string.h>
#include <errno.h>

#include "pcr.h"

static TPMI_ALG_HASH supported_algorithms[PCR_BANK__LAST] = {
	[PCR_BANK_SHA1] = TPM_ALG_SHA1,
	[PCR_BANK_SHA256] = TPM_ALG_SHA256,
};

static enum pcr_banks attest_pcr_lookup_bank(TPMI_ALG_HASH alg)
{
	int i;

	for (i = 0; i < PCR_BANK__LAST; i++)
		if (supported_algorithms[i] == alg)
			return i;

	return PCR_BANK__LAST;
}

/// @private
int attest_pcr_init(attest_ctx_verifier *ctx)
{
	TPMT_HA *pcr, *pcr_item;
	int rc = 0, i, j;

	current_log(ctx);

	pcr = malloc(sizeof(TPMT_HA) * PCR_BANK__LAST * IMPLEMENTATION_PCR);
	check_goto(!pcr, -ENOMEM, out, ctx, "out of memory");

	for (i = 0; i < PCR_BANK__LAST; i++) {
		for (j = 0; j < IMPLEMENTATION_PCR; j++) {
			pcr_item = pcr + i * IMPLEMENTATION_PCR + j;
			pcr_item->hashAlg = supported_algorithms[i];
			memset((uint8_t *)&pcr_item->digest, 0,
			       TSS_GetDigestSize(supported_algorithms[i]));
		}
	}

	ctx->pcr = pcr;
out:
	return rc;
}

/// @private
void attest_pcr_cleanup(attest_ctx_verifier *ctx)
{
	free(ctx->pcr);
}

/**
 * Retrieve current value of a PCR
 * @param[in] v_ctx	verifier context
 * @param[in] pcr_num	PCR number
 * @param[in] alg	PCR bank
 *
 * @returns TPMT_HA structure on success, NULL if not found
 */
TPMT_HA *attest_pcr_get(attest_ctx_verifier *ctx, int pcr_num,
			TPMI_ALG_HASH alg)
{
	enum pcr_banks pcr_bank;

	pcr_bank = attest_pcr_lookup_bank(alg);
	if (pcr_bank == PCR_BANK__LAST)
		return NULL;

	return (TPMT_HA *)ctx->pcr + pcr_bank * IMPLEMENTATION_PCR + pcr_num;
}

/**
 * Extend a PCR
 * @param[in] v_ctx	verifier context
 * @param[in] pcr_num	PCR number
 * @param[in] alg	PCR bank
 * @param[in] digest	digest to extend the PCR
 *
 * @returns 0 on success, a negative value on error
 */
int attest_pcr_extend(attest_ctx_verifier *ctx, unsigned int pcr_num,
		      TPMI_ALG_HASH alg, unsigned char *digest)
{
	TPMT_HA *selected_pcr;
	int rc, digest_len = TSS_GetDigestSize(alg);

	current_log(ctx);

	selected_pcr = attest_pcr_get(ctx, pcr_num, alg);
	check_goto(!selected_pcr, -ENOENT, out, ctx, "PCR not found");

	rc = TSS_Hash_Generate(selected_pcr, digest_len, &selected_pcr->digest,
			       digest_len, digest, 0, NULL);
	check_goto(!selected_pcr, -ENOENT, out, ctx,
		   "TSS_Hash_Generate() error: %d", rc);
out:
	return 0;
}

/// @private
int attest_pcr_verify(attest_ctx_verifier *ctx, TPML_PCR_SELECTION *pcrs,
		      unsigned char *digest)
{
	UINT16 pcrLength = 0;
	TPMT_HA *selected_pcr, calculated_digest;
	TPMI_ALG_HASH alg = pcrs->pcrSelections[0].hash;
	int d_len = TSS_GetDigestSize(alg);
	unsigned char buffer[IMPLEMENTATION_PCR * d_len];
	unsigned char *buffer_ptr = buffer;
	int rc, i, size = sizeof(buffer);

	for (i = 0; i < IMPLEMENTATION_PCR; i++) {
		if (!(pcrs->pcrSelections[0].pcrSelect[i / 8] & (1 << (i % 8))))
			continue;

		selected_pcr = attest_pcr_get(ctx, i, alg);
		if (!selected_pcr)
			return -ENOENT;

		rc = TSS_Array_Marshal((uint8_t *)&selected_pcr->digest,
				       d_len, &pcrLength, &buffer_ptr, &size);
		if (rc)
			return rc;
	}

	calculated_digest.hashAlg = ctx->pcr_algo;

	rc = TSS_Hash_Generate(&calculated_digest, pcrLength, buffer, 0, NULL);
	if (rc)
		return rc;

	return memcmp(digest, (uint8_t *)&calculated_digest.digest, d_len);
}
/** @}*/
