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
 * File: attest_create_skae.c
 *      Tool for creating the SKAE.
 */

#include <stdio.h>
#include <getopt.h>
#include <string.h>
#include <errno.h>

#include <sys/stat.h>
#include <sys/mman.h>

#include "skae.h"
#include "util.h"

#define MAX_LABEL_LENGTH 256
#define MAX_REQ_LENGTH 256

static struct option long_options[] = {
	{"tpms-attest", 1, 0, 'a'},
	{"tpmt-signature", 1, 0, 's'},
	{"tpm-version", 1, 0, 'e'},
	{"help", 0, 0, 'h'},
	{"version", 0, 0, 'v'},
	{0, 0, 0, 0}
};

static void usage(char *argv0)
{
	fprintf(stdout, "Usage: %s [options] <filename>\n\n"
		"Options:\n"
		"\t-a, --tpms-attest <path>      path of marshalled TPMS_ATTEST\n"
		"\t-s, --tpmt-signature <path>   path of marshalled TPMT_SIGNATURE\n"
		"\t-e, --tpm-version <version>   TPM version\n"
		"\t-h, --help                    print this help message\n"
		"\t-v, --version                 print package version\n"
		"\n"
		"Report bugs to " PACKAGE_BUGREPORT "\n",
		argv0);
	exit(-1);
}

int main(int argc, char **argv)
{
	char *tpms_attest_path = NULL, *sig_path = NULL, *skae_path;
	size_t tpms_attest_len = 0, sig_len = 0, skae_len;
	unsigned char *tpms_attest, *sig, *skae = NULL;
	enum skae_versions version = SKAE_VER_2_0;
	int option_index, c;
	int rc = 0;

	while (1) {
		option_index = 0;
		c = getopt_long(argc, argv, "a:s:e:hv",
				long_options, &option_index);
		if (c == -1)
			break;

		switch (c) {
			case 'a':
				tpms_attest_path = optarg;
				break;
			case 's':
				sig_path = optarg;
				break;
			case 'e':
				if (!strcmp(optarg, "1.2")) {
					version = SKAE_VER_1_2;
				} else if (!strcmp(optarg, "2.0")) {
					version = SKAE_VER_2_0;
				} else {
					fprintf(stderr,
						"Unsupported TPM version\n");
					return EXIT_FAILURE;
				}
				break;
			case 'h':
				usage(argv[0]);
				break;
			case 'v':
				fprintf(stdout, "%s " VERSION "\n"
					"Copyright 2018 by Roberto Sassu\n"
					"License GPLv2: GNU GPL version 2\n"
					"Written by Roberto Sassu <roberto.sassu@huawei.com>\n",
				       argv[0]);
				exit(0);
			default:
				fprintf(stderr, "Unknown option '%c'\n", c);
				usage(argv[0]);
				break;
		}
	}

	if (!tpms_attest_path || !sig_path) {
		fprintf(stderr, "Missing attestation data/signature\n");
		usage(argv[0]);
	}

	if (optind >= argc) {
		fprintf(stderr, "Too few arguments: Expected file name as last argument\n");
		usage(argv[0]);
	}

	skae_path = argv[argc - 1];

	if (optind < argc - 1) {
		fprintf(stderr, "Unexpected additional arguments\n");
		usage(argv[0]);
	}

	rc = attest_util_read_file(tpms_attest_path,
				   &tpms_attest_len, &tpms_attest);
	if (rc) {
		fprintf(stderr, "Cannot read %s\n", tpms_attest_path);
		goto out;
	}

	rc = attest_util_read_file(sig_path, &sig_len, &sig);
	if (rc) {
		fprintf(stderr, "Cannot read %s\n", sig_path);
		goto out;
	}

	rc = skae_create(version, tpms_attest_len, tpms_attest,
			 sig_len, sig, &skae_len, &skae);
	if (rc) {
		fprintf(stderr, "Cannot create SKAE, rc: %d\n", rc);
		goto out;
	}

	rc = attest_util_write_file(skae_path, skae_len, skae);
	if (rc) {
		fprintf(stderr, "Cannot write SKAE, rc: %d\n", rc);
		goto out;
	}
out:
	free(skae);

	if (tpms_attest_len)
		munmap(tpms_attest, tpms_attest_len);
	if (sig_len)
		munmap(sig, sig_len);

	return rc;
}
