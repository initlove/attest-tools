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
 * File: crypto.h
 *      Header of crypto.c.
 */
#ifndef _CRYPTO_H
#define _CRYPTO_H

#include <ibmtss/tss.h>
#include <ibmtss/tsscryptoh.h>
#include <ibmtss/tssresponsecode.h>

#include <openssl/err.h>
#include <openssl/pem.h>
#include <openssl/x509.h>

#include "ctx.h"

int attest_crypto_verify_sig(attest_ctx_verifier *v_ctx,
			     TPMT_SIGNATURE *tpmtsig, TPMT_HA *digest,
			     X509 *x509);
int attest_crypto_verify_cert(attest_ctx_data *d_ctx,
			      attest_ctx_verifier *v_ctx,
			      enum ctx_fields cert, enum ctx_fields ca,
			      X509 **x509);

#endif /*_CRYPTO_H*/
