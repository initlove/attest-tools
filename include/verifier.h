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
 * File: verifier.h
 *      Header of verifier.c.
 */

#ifndef _VERIFIER_H
#define _VERIFIER_H

#include <ibmtss/tss.h>
#include <ibmtss/tssutils.h>
#include <ibmtss/tsscryptoh.h>
#include <ibmtss/tssresponsecode.h>
#include <ibmtss/tssmarshal.h>
#include <ibmtss/Unmarshal_fp.h>

#include <openssl/evp.h>
#include <openssl/rsa.h>
#include <openssl/pem.h>

#include "ctx.h"

int attest_verifier_check_key_policy(attest_ctx_data *d_ctx,
				     attest_ctx_verifier *v_ctx,
				     TPM_ALG_ID hashAlg,
				     int parse_logs,
				     enum ctx_fields policy_field,
				     int pcr_mask_len, uint8_t *pcr_mask);
int attest_verifier_check_tpms_attest(attest_ctx_data *d_ctx,
				      attest_ctx_verifier *v_ctx,
				      INT32 tpms_attest_len,
				      BYTE *tpms_attest,
				      INT32 sig_len, BYTE *sig,
				      EVP_PKEY *key);
int attest_verifier_check_tpm2b_public(attest_ctx_data *d_ctx,
			attest_ctx_verifier *v_ctx, INT32 buffer_len,
			BYTE *buffer, int private, UINT32 req_mask,
			enum ctx_fields policy_field, TPM_ALG_ID *nameAlg,
			TPM2B_NAME *name);

#endif /*_VERIFIER_H*/
