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
 * File: attest_ra_server.c
 *      Server for enrollment and TPM key certificate request.
 */

#include <stdio.h>
#include <fcntl.h>
#include <string.h>
#include <unistd.h>
#include <stdlib.h>
#include <errno.h>
#include <getopt.h>

#include <sys/types.h>
#include <sys/stat.h>
#include <sys/socket.h>
#include <sys/wait.h>
#include <sys/un.h>

#include "enroll_server.h"
#include "util.h"

#include <ibmtss/tss.h>
#include <ibmtss/tssmarshal.h>
#include <ibmtss/Unmarshal_fp.h>

#include <openssl/evp.h>
#include <openssl/pem.h>
#include <openssl/rand.h>

#define CAKEY_PATH "cakey.pem"
#define CACERT_PATH "cacert.pem"
#define CAKEY_PASSWORD "1234"

static struct option long_options[] = {
	{"pcr-list", 0, 0, 'p'},
	{"requirements", 1, 0, 'r'},
	{"ima-violations", 0, 0, 'i'},
	{"help", 0, 0, 'h'},
	{"version", 0, 0, 'v'},
	{0, 0, 0, 0}
};

static void usage(char *argv0)
{
	fprintf(stdout, "Usage: %s [options] <filename>\n\n"
		"Options:\n"
		"\t-p, --pcr-list                PCR list\n"
		"\t-r, --requirements            verifier requirements\n"
		"\t-i, --ima-violations          allow IMA violations\n"
		"\t-h, --help                    print this help message\n"
		"\t-v, --version                 print package version\n"
		"\n"
		"Report bugs to " PACKAGE_BUGREPORT "\n",
		argv0);
	exit(-1);
}

int main(int argc, char *argv[])
{
	char *message_in = NULL, *message_out = NULL, *req_path = NULL;
	char *csr_str = NULL, *cert_str = NULL, *ca_cert_str = NULL;
	char *pcr_list_str = NULL;
	size_t len, ca_cert_str_len;
	struct sockaddr_in addr;
	BYTE hmac_key[64];
	uint8_t pcr_mask[3] = { 0 };
	int pcr_list[IMPLEMENTATION_PCR];
	int ima_violations = 0;
	int rc, option_index, c, fd, fd_socket, op, reuse_addr = 1;

	while (1) {
		option_index = 0;
		c = getopt_long(argc, argv, "p:r:ihv",
				long_options, &option_index);
		if (c == -1)
			break;

		switch (c) {
			case 'p':
				pcr_list_str = optarg;
				break;
			case 'r':
				req_path = optarg;
				break;
			case 'i':
				ima_violations = 1;
				break;
			case 'h':
				usage(argv[0]);
				break;
			case 'v':
				fprintf(stdout, "%s " VERSION "\n"
					"Copyright 2019 by Roberto Sassu\n"
					"License GPLv2: GNU GPL version 2\n"
					"Written by Roberto Sassu <roberto.sassu@huawei.com>\n",
					argv[0]);
				exit(0);
			default:
				printf("Unknown option '%c'\n", c);
				usage(argv[0]);
				break;
		}
	}

	if (pcr_list_str) {
		rc = attest_util_parse_pcr_list(pcr_list_str,
					sizeof(pcr_list) / sizeof(*pcr_list),
					pcr_list);
		if (rc < 0)
			return rc;
	}

	OpenSSL_add_all_algorithms();

	rc = RAND_bytes(hmac_key, sizeof(hmac_key));
	if (!rc) {
		printf("Cannot generate HMAC key\n");
		return 1;
	}

	fd_socket = socket(AF_INET, SOCK_STREAM, 0);
	setsockopt(fd_socket, SOL_SOCKET, SO_REUSEADDR, &reuse_addr,
		   sizeof(reuse_addr));

	memset(&addr, 0, sizeof(addr));

	addr.sin_family = AF_INET;
	addr.sin_addr.s_addr = htonl(INADDR_ANY);
	addr.sin_port = htons(3000);

	rc = bind(fd_socket, (struct sockaddr *)&addr, sizeof(addr));
	if (rc) {
		printf("%s\n", strerror(errno));
		goto out;
	}

	rc = listen(fd_socket, 5);
	if (rc) {
		printf("%s\n", strerror(errno));
		goto out;
	}

	while (1) {
		fd = accept(fd_socket, NULL, NULL);
		if (fd < 0)
			continue;

		rc = attest_util_read_buf(fd, (uint8_t *)&len, sizeof(len));
		if (rc)
			goto out_free;

		rc = attest_util_read_buf(fd, (uint8_t *)&op, sizeof(op));
		if (rc)
			goto out_free;

		len -= 2 * sizeof(len);
		message_in = malloc(len + 1);

		if (!message_in) {
			len = 0;
			goto response;
		}

		message_in[len] = '\0';

		rc = attest_util_read_buf(fd, (uint8_t *)message_in, len);
		if (rc)
			goto out_free;

		len = 0;

		message_out = NULL;

		csr_str = NULL;
		cert_str = NULL;
		ca_cert_str = NULL;

		switch (op) {
		case 0:
			rc = attest_enroll_msg_make_credential(hmac_key,
						sizeof(hmac_key), CAKEY_PATH,
						CAKEY_PASSWORD, CACERT_PATH,
						message_in, &message_out);
			break;
		case 1:
			rc = attest_enroll_msg_make_cert(hmac_key,
					sizeof(hmac_key), CAKEY_PATH,
					CAKEY_PASSWORD, CACERT_PATH,
					message_in, &message_out);
			break;
		case 2:
			rc = attest_enroll_msg_process_csr(sizeof(pcr_mask),
							pcr_mask, req_path,
							ima_violations,
							message_in, &csr_str);
			if (rc < 0)
				break;

			rc = attest_enroll_sign_csr(CAKEY_PATH,
						    CAKEY_PASSWORD, CACERT_PATH,
						    csr_str, &cert_str);
			if (rc < 0)
				break;

			rc = attest_util_read_seq_file(CACERT_PATH,
						&ca_cert_str_len,
						(uint8_t **)&ca_cert_str);
			if (rc < 0)
				break;

			rc = attest_enroll_msg_return_cert(cert_str,
							   ca_cert_str,
							   &message_out);
			break;
		case 3:
			rc = attest_enroll_msg_gen_quote_nonce(sizeof(hmac_key),
							       hmac_key,
							       message_in,
							       &message_out);
			break;
		case 4:
			rc = attest_enroll_msg_process_quote(sizeof(hmac_key),
							     hmac_key,
							     sizeof(pcr_mask),
							     pcr_mask, req_path,
							     ima_violations,
							     message_in,
							     &message_out);
			break;
		default:
			rc = -EINVAL;
			break;
		}

		if (!rc)
			len = strlen(message_out) + sizeof(len) + 1;
response:
		if (!len)
			printf("error\n");

		rc = attest_util_write_buf(fd, (uint8_t *)&len, sizeof(len));
		if (rc)
			goto out;

		if (len)
			rc = attest_util_write_buf(fd, (uint8_t *)message_out,
						   len - sizeof(len));
out_free:
		free(message_in);
		free(message_out);
		free(csr_str);
		free(cert_str);
		free(ca_cert_str);

		close(fd);

		if (rc)
			break;
	}
out:
	EVP_cleanup();
	close(fd_socket);
	return 0;
}
