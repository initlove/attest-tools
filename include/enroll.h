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
 * File: enroll.h
 *      Header of enroll.h
 */

#ifndef _ENROLL_H
#define _ENROLL_H

#include <tss2/tss.h>
#include <tss2/tsscryptoh.h>
#include <tss2/tssresponsecode.h>

#include "ctx.h"

int attest_enroll_make_credential(attest_ctx_data *d_ctx_in,
				  attest_ctx_data *d_ctx_out,
				  attest_ctx_verifier *v_ctx);

int attest_enroll_make_cert(attest_ctx_data *d_ctx_in,
			    attest_ctx_data *d_ctx_out,
			    attest_ctx_verifier *v_ctx,
			    char *pcaKeyPath, char *pcaKeyPassword,
			    char *pcaCertPath, char *hostname);

#endif /*_CRYPTO_H*/
