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
 * File: test_client.c
 *      Client for enrollment.
 */

#include <stdio.h>
#include <fcntl.h>
#include <string.h>
#include <unistd.h>
#include <stdlib.h>
#include <errno.h>

#include <sys/types.h>
#include <sys/stat.h>
#include <sys/mman.h>
#include <sys/wait.h>
#include <sys/socket.h>
#include <sys/un.h>

#include "enroll.h"
#include "ctx_json.h"
#include "util.h"
#include "tss.h"

#include <tss2/tss.h>
#include <tss2/tssmarshal.h>
#include <tss2/Unmarshal_fp.h>

#include <openssl/evp.h>

int verbose;

static int send_receive(int fd, int op, char *message_in, char **message_out)
{
	size_t len, cur_len;
	int rc = -EIO;

	len = strlen(message_in);
	len += sizeof(len) * 2;

	cur_len = write(fd, &len, sizeof(len));
	cur_len = write(fd, &op, sizeof(op));
	cur_len = write(fd, message_in, len - sizeof(len) * 2);

	if (cur_len != len - sizeof(len) * 2)
		return -EIO;

	cur_len = read(fd, &len, sizeof(len));
	if (cur_len != sizeof(len))
		return -EIO;

	if (len == 0)
		return -EINVAL;

	*message_out = malloc(len);
	if (!*message_out)
		return -ENOMEM;

	len -= sizeof(len);

	cur_len = read(fd, *message_out, len);
	if (cur_len != len) {
		rc = -EIO;
		free(*message_out);
		goto out;
	}

	rc = 0;
out:
	return rc;
}

int add_ek_cert(attest_ctx_data *d_ctx, TSS_CONTEXT *tssContext)
{
	size_t nvdata_len;
	BYTE *nvdata, *nvdata_ptr;
	X509 *ek_cert;
	char *ek_cert_pem;
	int rc;

	rc = tss_getekcert(tssContext, TPM_ALG_RSA, &nvdata_len, &nvdata);
	if (rc)
		return rc;

	nvdata_ptr = nvdata;

	ek_cert = d2i_X509(NULL, (const unsigned char **)&nvdata_ptr,
			   nvdata_len);
	if (!ek_cert) {
		printf("Cannot parse EK cert\n");
		rc = -EINVAL;
		goto out;
	}

	rc = convertX509ToPemMem(&ek_cert_pem, ek_cert);
	if (rc) {
		printf("Cannot convert EK cert\n");
		rc = -EINVAL;
	}

	rc = attest_ctx_data_add(d_ctx, CTX_EK_CERT, strlen(ek_cert_pem),
				 (unsigned char *)ek_cert_pem, NULL);
	X509_free(ek_cert);
out:
	free(nvdata);
	return rc;
}

int add_ak(attest_ctx_data *d_ctx, TSS_CONTEXT *tssContext, char *akPrivPath,
	   char *akPubPath)
{
	UINT16 private_len, public_len;
	BYTE *private, *public;
	int rc;

	rc = tss_create(tssContext, TPM_ALG_RSA, TPM_ECC_NONE, TPM_ALG_SHA256,
			TPM_ALG_SHA256, 1, &private_len, &private, &public_len,
			&public);
	if (rc)
		return rc;

	rc = attest_util_write_file(akPrivPath, private_len, private);
	if (rc < 0)
		goto out;

	rc = attest_util_write_file(akPubPath, public_len, public);
	if (rc < 0) {
		unlink(akPrivPath);
		goto out;
	}

	rc = attest_ctx_data_add(d_ctx, CTX_TPM_AK_KEY, public_len, public,
				 NULL);
out:
	if (rc) {
		free(private);
		free(public);
	}

	return rc;
}

int add_cred(attest_ctx_data *d_ctx, TSS_CONTEXT *tssContext, char *akPrivPath,
	     char *akPubPath)
{
	TPM_HANDLE activateHandle, keyHandle;
	BYTE *private, *public, *cred;
	size_t private_len, public_len;
	struct data_item *credblob, *secret;
	UINT16 cred_len;
	int rc;

	rc = tss_createek(tssContext, TPM_ALG_RSA, &activateHandle);
	if (rc)
		return rc;

	rc = attest_util_read_file(akPrivPath, &private_len, &private);
	if (rc)
		goto out_flush_ek;

	rc = attest_util_read_file(akPubPath, &public_len, &public);
	if (rc)
		goto out_munmap_priv;

	rc = attest_ctx_data_add_copy(d_ctx, CTX_TPM_AK_KEY, public_len,
				      public, NULL);
	if (rc)
		goto out_munmap_pub;

	rc = tss_load(tssContext, private_len, private, public_len, public,
		      &keyHandle);
	if (rc)
		goto out_munmap_pub;

	credblob = attest_ctx_data_get(d_ctx, CTX_CREDBLOB);
	if (!credblob)
		goto out_flush_ak;

	secret = attest_ctx_data_get(d_ctx, CTX_SECRET);
	if (!secret)
		goto out_flush_ak;

	rc = tss_activatecredential(tssContext, keyHandle, activateHandle,
				    credblob->len, credblob->data, secret->len,
				    secret->data, (UINT16 *)&cred_len, &cred);
	if (rc)
		goto out_flush_ak;

	rc = attest_ctx_data_add(d_ctx, CTX_CRED, cred_len, cred, NULL);
out_flush_ak:
	tss_flushcontext(tssContext, keyHandle);
out_munmap_pub:
	munmap(public, public_len);
out_munmap_priv:
	munmap(private, private_len);
out_flush_ek:
	tss_flushcontext(tssContext, activateHandle);
	return rc;
}

int print_ak_cert(attest_ctx_data *d_ctx)
{
	struct data_item *ak_cert;
	X509 *cert;
	int rc = 0;

	ak_cert = attest_ctx_data_get(d_ctx, CTX_AIK_CERT);
	if (!ak_cert) {
		printf("AK certificate not found\n");
		return -ENOENT;
	}

	rc = convertPemMemToX509(&cert, (char *)ak_cert->data);
        if (rc) {
		printf("Cannot parse AK cert\n");
		rc = -EINVAL;
		goto out;
	}

	X509_print_fp(stdout, cert);
out:
	X509_free(cert);
	return rc;
}

int main()
{
	struct sockaddr_un addr;
	attest_ctx_data *d_ctx = NULL;
	void *tssContext;
	char *message_in, *message_out;
	int rc, fd = -1;

	attest_ctx_data_init(&d_ctx);

	rc = TSS_Create((TSS_CONTEXT **)&tssContext);
	if (rc)
		return -EINVAL;

	rc = add_ek_cert(d_ctx, tssContext);
	if (rc)
		goto out;

	rc = attest_ctx_data_add_file(d_ctx, CTX_EK_CA_CERT,
				      "ek_ca_cert.pem", NULL);
	if (rc)
		goto out;

	rc = add_ak(d_ctx, tssContext, "akpriv.bin", "akpub.bin");
	if (rc)
		goto out;

	attest_ctx_data_print_json(d_ctx, &message_in);

	fd = socket(AF_UNIX, SOCK_STREAM, 0);
	memset(&addr, 0, sizeof(addr));
	addr.sun_family = AF_UNIX;
	strncpy(addr.sun_path, "socket", sizeof(addr.sun_path)-1);
	connect(fd, (struct sockaddr*)&addr, sizeof(addr));

	rc = send_receive(fd, 0, message_in, &message_out);
	free(message_in);

	if (rc < 0)
		goto out;

	close(fd);

	attest_ctx_data_cleanup(d_ctx);
	attest_ctx_data_init(&d_ctx);

	rc = attest_ctx_data_add_json_data(d_ctx, message_out,
					   strlen(message_out));
	free(message_out);

	if (rc < 0)
		goto out;

	rc = add_cred(d_ctx, tssContext, "akpriv.bin", "akpub.bin");
	if (rc < 0)
		goto out;

	attest_ctx_data_print_json(d_ctx, &message_in);

	fd = socket(AF_UNIX, SOCK_STREAM, 0);
	connect(fd, (struct sockaddr*)&addr, sizeof(addr));

	rc = send_receive(fd, 1, message_in, &message_out);
	if (rc < 0)
		goto out;

	attest_ctx_data_cleanup(d_ctx);
	attest_ctx_data_init(&d_ctx);

	rc = attest_ctx_data_add_json_data(d_ctx, message_out,
					   strlen(message_out));
        free(message_out);
	if (rc < 0)
		goto out;

	print_ak_cert(d_ctx);

out:
	close(fd);

	TSS_Delete(tssContext);
	attest_ctx_data_cleanup(d_ctx);
	return rc;
}
