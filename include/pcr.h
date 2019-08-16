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

#define TSSINCLUDE(x) < TSS_INCLUDE/x >
#include TSSINCLUDE(tsscrypto.h)
#include TSSINCLUDE(tsscryptoh.h)
#include TSSINCLUDE(tssmarshal.h)

#include "ctx.h"

enum pcr_banks { PCR_BANK_SHA1, PCR_BANK_SHA256, PCR_BANK__LAST };

int attest_pcr_init(attest_ctx_verifier *ctx);
void attest_pcr_cleanup(attest_ctx_verifier *ctx);
TPMT_HA *attest_pcr_get(attest_ctx_verifier *ctx, int pcr_num,
			TPMI_ALG_HASH alg);
int attest_pcr_extend(attest_ctx_verifier *ctx, unsigned int pcr_num,
		      TPMI_ALG_HASH alg, unsigned char *digest);
int attest_pcr_verify(attest_ctx_verifier *ctx, TPML_PCR_SELECTION *pcrs,
		      unsigned char *digest);

#endif /*_PCR_H*/
