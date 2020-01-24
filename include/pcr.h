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
 * File: pcr.h
 *      Header of pcr.c.
 */

#ifndef _PCR_H
#define _PCR_H

#include <ibmtss/tsscrypto.h>
#include <ibmtss/tsscryptoh.h>
#include <ibmtss/tssmarshal.h>
#include <ibmtss/Implementation.h>

#include "ctx.h"

enum pcr_banks { PCR_BANK_SHA1, PCR_BANK_SHA256, PCR_BANK_SHA384,
		 PCR_BANK_SHA512, PCR_BANK__LAST };

TPM_ALG_ID attest_pcr_bank_alg(enum pcr_banks bank_id);
TPM_ALG_ID attest_pcr_bank_alg_from_name(char *alg_name, int alg_name_len);
int attest_pcr_init(attest_ctx_verifier *v_ctx);
void attest_pcr_cleanup(attest_ctx_verifier *v_ctx);
TPMT_HA *attest_pcr_get(attest_ctx_verifier *v_ctx, int pcr_num,
			TPMI_ALG_HASH alg);
int attest_pcr_extend(attest_ctx_verifier *v_ctx, unsigned int pcr_num,
		      TPMI_ALG_HASH alg, unsigned char *digest);
int attest_pcr_calc_digest(attest_ctx_verifier *v_ctx, TPMT_HA *digest,
			   TPML_PCR_SELECTION *pcrs);
int attest_pcr_verify(attest_ctx_verifier *v_ctx, TPML_PCR_SELECTION *pcrs,
		      TPM_ALG_ID hashAlg, unsigned char *digest);

#endif /*_PCR_H*/
