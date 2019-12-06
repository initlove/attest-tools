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
 * File: pcr.c
 *      PCR functions.
 */

/**
 * @defgroup pcr-api PCR API
 * @ingroup developer-api
 * @brief
 * Functions to extend or verify software PCRs
 */

/**
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
	[PCR_BANK_SHA384] = TPM_ALG_SHA384,
	[PCR_BANK_SHA512] = TPM_ALG_SHA512,
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
int attest_pcr_init(attest_ctx_verifier *v_ctx)
{
	TPMT_HA *pcr_item;
	int rc = 0, i, j;
	unsigned char *pcr;

	current_log(v_ctx);

	pcr = malloc(sizeof(TPMT_HA) * PCR_BANK__LAST * IMPLEMENTATION_PCR);
	check_goto(!pcr, -ENOMEM, out, ctx, "out of memory");

	for (i = 0; i < PCR_BANK__LAST; i++) {
		for (j = 0; j < IMPLEMENTATION_PCR; j++) {
			pcr_item = (TPMT_HA *)(pcr + sizeof(TPMT_HA) *
				   (i * IMPLEMENTATION_PCR + j));
			pcr_item->hashAlg = supported_algorithms[i];
			memset((uint8_t *)&pcr_item->digest, 0,
			       TSS_GetDigestSize(supported_algorithms[i]));
		}
	}

	v_ctx->pcr = pcr;
out:
	return rc;
}

/// @private
void attest_pcr_cleanup(attest_ctx_verifier *v_ctx)
{
	free(v_ctx->pcr);
}

/**
 * Retrieve current value of a PCR
 * @param[in] v_ctx	verifier context
 * @param[in] pcr_num	PCR number
 * @param[in] alg	PCR bank
 *
 * @returns TPMT_HA structure on success, NULL if not found
 */
TPMT_HA *attest_pcr_get(attest_ctx_verifier *v_ctx, int pcr_num,
			TPMI_ALG_HASH alg)
{
	enum pcr_banks pcr_bank;

	pcr_bank = attest_pcr_lookup_bank(alg);
	if (pcr_bank == PCR_BANK__LAST)
		return NULL;

	return v_ctx->pcr + sizeof(TPMT_HA) *
	       (pcr_bank * IMPLEMENTATION_PCR + pcr_num);
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
int attest_pcr_extend(attest_ctx_verifier *v_ctx, unsigned int pcr_num,
		      TPMI_ALG_HASH alg, unsigned char *digest)
{
	TPMT_HA *selected_pcr;
	int rc, digest_len = TSS_GetDigestSize(alg);

	current_log(v_ctx);

	selected_pcr = attest_pcr_get(v_ctx, pcr_num, alg);
	check_goto(!selected_pcr, -ENOENT, out, v_ctx, "PCR not found");

	rc = TSS_Hash_Generate(selected_pcr, digest_len, &selected_pcr->digest,
			       digest_len, digest, 0, NULL);
	check_goto(rc, -EINVAL, out, v_ctx, "TSS_Hash_Generate() error: %d",
		   rc);
out:
	return rc;
}

/**
 * Calculate PCR digest
 * @param[in] v_ctx	verifier context
 * @param[in] digest	PCR array
 * @param[in] pcrs	PCR selection
 *
 * @returns 0 on success, a negative value on error
 */
int attest_pcr_calc_digest(attest_ctx_verifier *v_ctx, TPMT_HA *digest,
			   TPML_PCR_SELECTION *pcrs)
{
	UINT16 pcrLength = 0;
	TPMT_HA *selected_pcr;
	TPMI_ALG_HASH alg = pcrs->pcrSelections[0].hash;
	int d_len = TSS_GetDigestSize(alg);
	unsigned char buffer[IMPLEMENTATION_PCR * d_len];
	unsigned char *buffer_ptr = buffer;
	int rc, i, size = sizeof(buffer);

	for (i = 0; i < IMPLEMENTATION_PCR; i++) {
		if (!(pcrs->pcrSelections[0].pcrSelect[i / 8] & (1 << (i % 8))))
			continue;

		selected_pcr = attest_pcr_get(v_ctx, i, alg);
		if (!selected_pcr)
			return -ENOENT;

		rc = TSS_Array_Marshal((uint8_t *)&selected_pcr->digest,
				       d_len, &pcrLength, &buffer_ptr, &size);
		if (rc)
			return rc;
	}

	return TSS_Hash_Generate(digest, pcrLength, buffer, 0, NULL);
}

/**
 * Verify PCR digest
 * @param[in] v_ctx	verifier context
 * @param[in] pcrs	PCR selection
 * @param[in] digest	PCR digest to compare
 *
 * @returns 0 on success, a negative value on error
 */
int attest_pcr_verify(attest_ctx_verifier *v_ctx, TPML_PCR_SELECTION *pcrs,
		      TPM_ALG_ID hashAlg, unsigned char *digest)
{
	TPMT_HA calculated_digest;
	int rc;

	calculated_digest.hashAlg = hashAlg;

	rc = attest_pcr_calc_digest(v_ctx, &calculated_digest, pcrs);
	if (rc)
		return rc;

	return memcmp(digest, (uint8_t *)&calculated_digest.digest,
		      TSS_GetDigestSize(calculated_digest.hashAlg));
}
/** @}*/
