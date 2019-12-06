/*
 * Copyright (C) 2019 Huawei Technologies Duesseldorf GmbH
 *
 * Author: Roberto Sassu <roberto.sassu@huawei.com>
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public License as
 * published by the Free Software Foundation, version 2 of the
 * License.
 *
 * File: attest_tls_common.h
 *      Header of attest_tls_common.c
 */

/* Code taken from https://wiki.openssl.org/index.php/Simple_TLS_Server */

#ifndef _ATTEST_TLS_COMMON_H
#define _ATTEST_TLS_COMMON_H

#include "ctx_json.h"
#include "util.h"

void init_openssl();
void cleanup_openssl();

#define CONTEXT_CLIENT 0
#define CONTEXT_SERVER 1

SSL_CTX *create_context(int context_type);

int configure_context(SSL_CTX *ctx, int engine, int verify_skae, char *key_path,
		      char *cert_path, char *ca_path);
int configure_attest(int fd, size_t recv_data_size,
		     unsigned char *recv_attest_data, char *pcr_list_str,
		     char *req_path);

#endif /*_ATTEST_TLS_COMMON_H*/
