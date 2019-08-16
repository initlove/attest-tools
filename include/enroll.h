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
