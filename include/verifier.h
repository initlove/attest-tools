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

#include <tss2/tss.h>
#include <tss2/tssutils.h>
#include <tss2/tsscryptoh.h>
#include <tss2/tssresponsecode.h>
#include <tss2/tssmarshal.h>
#include <tss2/Unmarshal_fp.h>

#include <openssl/evp.h>
#include <openssl/rsa.h>
#include <openssl/pem.h>

int attest_verifier_check_tpms_attest(attest_ctx_data *d_ctx,
				      attest_ctx_verifier *v_ctx,
				      INT32 tpms_attest_len,
				      BYTE *tpms_attest,
				      INT32 sig_len, BYTE *sig,
				      EVP_PKEY *key);

#endif /*_VERIFIER_H*/
