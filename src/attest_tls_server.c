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
 * File: attest_tls_server.c
 *      TLS server.
 */

/* Code taken from https://wiki.openssl.org/index.php/Simple_TLS_Server */

#include <stdio.h>
#include <unistd.h>
#include <string.h>
#include <getopt.h>
#include <malloc.h>
#include <sys/socket.h>
#include <sys/mman.h>
#include <arpa/inet.h>
#include <openssl/ssl.h>
#include <openssl/err.h>
#include <openssl/engine.h>

#include "attest_tls_common.h"

#define SERVER_PORT 4433
#define BUFLEN 1024

int create_socket(void)
{
	int s = -1;
	int reuse_addr = 1;
	struct sockaddr_in addr;

	addr.sin_family = AF_INET;
	addr.sin_port = htons(SERVER_PORT);
	addr.sin_addr.s_addr = htonl(INADDR_ANY);

	s = socket(AF_INET, SOCK_STREAM, 0);
	if (s < 0) {
		perror("Unable to create socket");
		goto out;
	}

	setsockopt(s, SOL_SOCKET, SO_REUSEADDR, &reuse_addr,
		   sizeof(reuse_addr));

	if (bind(s, (struct sockaddr *)&addr, sizeof(addr)) < 0) {
		perror("Unable to bind");
		goto out;
	}

	if (listen(s, 1) < 0) {
		perror("Unable to listen");
		goto out;
	}
out:
	return s;
}

static struct option long_options[] = {
	{"key", 1, 0, 'k'},
	{"cert", 1, 0, 'c'},
	{"ca-certs", 1, 0, 'd'},
	{"attest-data", 1, 0, 'a'},
	{"engine", 0, 0, 'e'},
	{"pcr-list", 0, 0, 'p'},
	{"requirements", 1, 0, 'r'},
	{"verify-skae", 0, 0, 'S'},
	{"verbose", 0, 0, 'V'},
	{"help", 0, 0, 'h'},
	{"version", 0, 0, 'v'},
	{0, 0, 0, 0}
};

static void usage(char *argv0)
{
	fprintf(stdout, "Usage: %s [options] <filename>\n\n"
		"Options:\n"
		"\t-k, --key                     server private key\n"
		"\t-c, --cert                    server certificate\n"
		"\t-d, --ca-certs                CA certificates\n"
		"\t-a, --attest-data             attestation data\n"
		"\t-e, --engine                  use tpm2 engine\n"
		"\t-p, --pcr-list                PCR list\n"
		"\t-r, --requirements            verifier requirements\n"
		"\t-S, --verify-skae             verify peer's SKAE\n"
		"\t-V, --verbose                 verbose mode\n"
		"\t-h, --help                    print this help message\n"
		"\t-v, --version                 print package version\n"
		"\n"
		"Report bugs to " PACKAGE_BUGREPORT "\n",
		argv0);
	exit(-1);
}

int main(int argc, char **argv)
{
	SSL_CTX *ctx;
	char *key_path = NULL, *cert_path = NULL, *ca_path = NULL;
	char *attest_data_path = NULL, *req_path = NULL;
	char *pcr_list_str = NULL, *logs;
	unsigned char *client_attest_data, *server_attest_data;
	size_t file_size, data_size;
	int sock, option_index, c;
	int rc = -EINVAL, engine = 0, verify_skae = 0, verbose = 0;

	while (1) {
		option_index = 0;
		c = getopt_long(argc, argv, "k:c:d:a:ep:r:SVhv", long_options,
				&option_index);
		if (c == -1)
			break;

		switch (c) {
			case 'k':
				key_path = optarg;
				break;
			case 'c':
				cert_path = optarg;
				break;
			case 'd':
				ca_path = optarg;
				break;
			case 'a':
				attest_data_path = optarg;
				break;
			case 'e':
				engine = 1;
				break;
			case 'p':
				pcr_list_str = optarg;
				break;
			case 'r':
				req_path = optarg;
				break;
			case 'S':
				verify_skae = 1;
				break;
			case 'V':
				verbose = 1;
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

	if (!key_path || !cert_path) {
		printf("Missing key or certificate\n");
		return -EINVAL;
	}

	if (verify_skae && !req_path) {
		printf("Missing requirements\n");
		return -EINVAL;
	}

	init_openssl();

	ctx = create_context(CONTEXT_SERVER);
	if (!ctx)
		goto cleanup;

	rc = SSL_CTX_set_max_early_data(ctx, BUFLEN);
	if (rc <= 0) {
		ERR_print_errors_fp(stderr);
		goto cleanup;
	}

	rc = configure_context(ctx, engine, verify_skae, key_path, cert_path,
			       ca_path);
	if (rc < 0)
		goto free;

	sock = create_socket();

	while(1) {
		struct sockaddr_in addr;
		uint len = sizeof(addr);
		SSL *ssl;
		const char reply[] = "test\n";

		int client = accept(sock, (struct sockaddr*)&addr, &len);
		if (client < 0) {
			perror("Unable to accept");
			goto close;
		}

		attest_ctx_data_init(NULL);
		attest_ctx_verifier_init(NULL);

		client_attest_data = NULL;
		server_attest_data = NULL;

		rc = attest_util_read_buf(client, (unsigned char *)&data_size,
					  sizeof(data_size));
		if (rc < 0)
			goto error;

		data_size = ntohl(data_size);
		if (data_size) {
			client_attest_data = malloc(data_size);
			if (!client_attest_data) {
				rc = -ENOMEM;
				goto error;
			}

			rc = attest_util_read_buf(client, client_attest_data,
						  data_size);
			if (rc < 0)
				goto error;

			if (verify_skae) {
				rc = configure_attest(client, data_size,
						      client_attest_data,
						      pcr_list_str, req_path);
				if (rc < 0)
					goto error;
			}
		}

		data_size = 0;

		if (attest_data_path) {
			rc = attest_util_read_file(attest_data_path, &file_size,
						   &server_attest_data);
			if (!rc)
				data_size = file_size;
		}

		data_size = htonl(data_size);

		rc = attest_util_write_buf(client, (unsigned char *)&data_size,
					   sizeof(data_size));
		if (rc < 0)
			goto error;

		if (data_size) {
			rc = attest_util_write_buf(client, server_attest_data,
						   file_size);
			if (rc < 0)
				goto error;
		}

		ssl = SSL_new(ctx);
		SSL_set_fd(ssl, client);

		rc = SSL_accept(ssl);

		if (verify_skae && verbose) {
			logs = attest_ctx_verifier_result_print_json(
					attest_ctx_verifier_get_global());
			printf("%s\n", logs);
			free(logs);
		}

		if (rc <= 0) {
			ERR_print_errors_fp(stderr);
			rc = -EIO;
			goto error_ssl;
		}

		if (SSL_get_verify_result(ssl) == X509_V_OK) {
			printf("good client cert\n");
			SSL_write(ssl, reply, strlen(reply));
		} else {
			ERR_print_errors_fp(stderr);
			printf("bad client cert\n");
		}
error_ssl:
		SSL_shutdown(ssl);
		SSL_free(ssl);
error:
		close(client);
		free(client_attest_data);

		if (server_attest_data)
			munmap(server_attest_data, file_size);

		attest_ctx_data_cleanup(NULL);
		attest_ctx_verifier_cleanup(NULL);
	}
close:
	close(sock);
free:
	SSL_CTX_free(ctx);
cleanup:
	cleanup_openssl();

	return rc;
}
