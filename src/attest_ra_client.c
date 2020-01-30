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
 * File: attest_ra_client.c
 *      Client for enrollment and TPM key certificate request.
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
#include <sys/mman.h>
#include <sys/wait.h>
#include <sys/socket.h>
#include <netdb.h>

#include "enroll_client.h"
#include "util.h"

#define SERVER_HOSTNAME "test-server"
#define SERVER_PORT "3000"

static int send_receive(char *test_server_fqdn, int op, char *message_in,
			char **message_out)
{
	struct addrinfo hints, *result = NULL, *rp;
	size_t len;
	int rc, fd = -1;

	memset(&hints, 0, sizeof(struct addrinfo));
	hints.ai_family = AF_INET;
	hints.ai_socktype = SOCK_STREAM;
	hints.ai_flags = 0;
	hints.ai_protocol = 0;

	rc = getaddrinfo(test_server_fqdn, SERVER_PORT, &hints, &result);
	if (rc)
		goto out;

	for (rp = result; rp != NULL; rp = rp->ai_next) {
		fd = socket(rp->ai_family, rp->ai_socktype,
				rp->ai_protocol);
		if (fd == -1)
			continue;

		if (connect(fd, rp->ai_addr, rp->ai_addrlen) != -1)
			break;

		close(fd);
	}

	freeaddrinfo(result);

	if (!rp) {
		rc = -EIO;
		goto out;
	}

	len = strlen(message_in);
	len += sizeof(len) * 2;

	rc = attest_util_write_buf(fd, (uint8_t *)&len, sizeof(len));
	if (rc)
		goto out;

	rc = attest_util_write_buf(fd, (uint8_t *)&op, sizeof(op));
	if (rc)
		goto out;

	rc = attest_util_write_buf(fd, (uint8_t *)message_in,
				   len - sizeof(len) * 2);
	if (rc)
		goto out;

	rc = attest_util_read_buf(fd, (uint8_t *)&len, sizeof(len));
	if (rc)
		goto out;

	if (len == 0) {
		rc = -EINVAL;
		goto out;
	}

	*message_out = malloc(len);
	if (!*message_out) {
		rc = -ENOMEM;
		goto out;
	}

	len -= sizeof(len);

	rc = attest_util_read_buf(fd, (uint8_t *)*message_out, len);
out:
	close(fd);
	return rc;
}

static struct option long_options[] = {
	{"request-ak-cert", 0, 0, 'a'},
	{"request-key-cert", 0, 0, 'k'},
	{"create-sym-key", 0, 0, 'y'},
	{"send-quote", 0, 0, 'q'},
	{"skip-sig-ver", 0, 0, 'S'},
	{"test-server-fqdn", 1, 0, 's'},
	{"kernel-bios-log", 0, 0, 'b'},
	{"kernel-ima-log", 0, 0, 'i'},
	{"pcr-list", 0, 0, 'p'},
	{"save-attest-data", 1, 0, 'r'},
	{"help", 0, 0, 'h'},
	{"version", 0, 0, 'v'},
	{0, 0, 0, 0}
};

static void usage(char *argv0)
{
	fprintf(stdout, "Usage: %s [options] <filename>\n\n"
		"Options:\n"
		"\t-a, --request-ak-cert         request AK cert\n"
		"\t-k, --request-key-cert        request TLS Key cert\n"
		"\t-y, --create-sym-key          create symmetric key\n"
		"\t-q, --send-quote              send quote\n"
		"\t-S, --skip-sig-ver            skip signature verification\n"
		"\t-s, --test-server-fqdn        server FQDN\n"
		"\t-b, --kernel-bios-log         use kernel BIOS log\n"
		"\t-i, --kernel-ima-log          use kernel IMA log\n"
		"\t-p, --pcr-list                PCR list\n"
		"\t-r, --save-attest-data <file> save attest data\n"
		"\t-h, --help                    print this help message\n"
		"\t-v, --version                 print package version\n"
		"\n"
		"Report bugs to " PACKAGE_BUGREPORT "\n",
		argv0);
	exit(-1);
}

enum request_types { REQUEST_AK_CERT, REQUEST_KEY_CERT, CREATE_SYM_KEY,
		     SEND_QUOTE, REQUEST__LAST };

int main(int argc, char **argv)
{
	enum request_types type = REQUEST__LAST;
	char *message_in = NULL, *message_out = NULL;
	char *test_server_fqdn = SERVER_HOSTNAME, *pcr_list_str = NULL;
	char **attest_data_ptr = NULL, *attest_data, *attest_data_path;
	char *pcr_alg_name = "sha1";
	int skip_sig_ver = 0;
	int rc = 0, option_index, c, kernel_bios_log = 0, kernel_ima_log = 0;

	while (1) {
		option_index = 0;
		c = getopt_long(argc, argv, "akyqSs:bip:P:r:hv",
				long_options, &option_index);
		if (c == -1)
			break;

		switch (c) {
			case 'a':
				type = REQUEST_AK_CERT;
				break;
			case 'k':
				type = REQUEST_KEY_CERT;
				break;
			case 'y':
				type = CREATE_SYM_KEY;
				break;
			case 'q':
				type = SEND_QUOTE;
				break;
			case 'S':
				skip_sig_ver = 1;
				break;
			case 's':
				test_server_fqdn = optarg;
				break;
			case 'b':
				kernel_bios_log = 1;
				break;
			case 'i':
				kernel_ima_log = 1;
				break;
			case 'p':
				pcr_list_str = optarg;
				break;
			case 'P':
				pcr_alg_name = optarg;
				break;
			case 'r':
				attest_data_path = optarg;
				attest_data_ptr = &attest_data;
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

	switch (type) {
	case REQUEST_AK_CERT:
		rc = attest_enroll_msg_ak_challenge_request("list",
							    &message_in);
		if (rc < 0)
			break;

		if (attest_data_ptr)
			rc = attest_util_write_file(attest_data_path,
					strlen(message_in),
					(unsigned char *)message_in, 0);

		rc = send_receive(test_server_fqdn, 0, message_in,
				  &message_out);
		if (rc < 0)
			break;

		free(message_in);
		message_in = message_out;
		message_out = NULL;

		rc = attest_enroll_msg_ak_cert_request(message_in,
						       &message_out);
		if (rc < 0)
			break;

		free(message_in);
		message_in = message_out;
		message_out = NULL;

		rc = send_receive(test_server_fqdn, 1, message_in,
				  &message_out);
		if (rc < 0)
			break;

		rc = attest_enroll_msg_ak_cert_response(message_out);
		break;
	case REQUEST_KEY_CERT:
		rc = attest_enroll_msg_key_cert_request(kernel_bios_log,
							kernel_ima_log,
							pcr_alg_name,
							pcr_list_str,
							attest_data_ptr,
							&message_in);
		if (rc < 0)
			break;

		rc = send_receive(test_server_fqdn, 2, message_in,
				  &message_out);
		if (rc < 0)
			break;

		rc = attest_enroll_msg_key_cert_response(message_out);
		if (rc < 0)
			break;

		if (attest_data_ptr)
			rc = attest_util_write_file(attest_data_path,
					strlen(attest_data),
					(unsigned char *)attest_data, 0);
		break;
	case CREATE_SYM_KEY:
		rc = attest_enroll_create_sym_key(kernel_bios_log,
						  kernel_ima_log,
						  pcr_alg_name,
						  pcr_list_str);
		break;
	case SEND_QUOTE:
		rc = attest_enroll_msg_quote_nonce_request(&message_out);
		if (rc < 0)
			break;

		rc = send_receive(test_server_fqdn, 3, message_out,
				  &message_in);
		if (rc < 0)
			break;

		free(message_out);
		message_out = NULL;

		rc = attest_enroll_msg_quote_request("list_privacy_ca",
						kernel_bios_log, kernel_ima_log,
						pcr_alg_name, pcr_list_str,
						skip_sig_ver, message_in,
						&message_out);
		if (rc < 0)
			break;

		free(message_in);
		message_in = NULL;

		rc = send_receive(test_server_fqdn, 4, message_out,
				  &message_in);
		if (!rc)
			printf("successful verification\n");
		else
			printf("failed verification\n");
		break;
	default:
		printf("Request not provided\n");
		return 1;
	}

	if (message_in)
		free(message_in);
	if (message_out)
		free(message_out);

	return rc;
}
