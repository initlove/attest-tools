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
 * File: attest_parse_json.c
 *      Tool for parsing a JSON file with data for verifying the SKAE.
 */

#include <stdio.h>
#include <getopt.h>
#include <string.h>
#include <errno.h>
#include <stdarg.h>

#include <linux/limits.h>

#include "ctx_json.h"
#include "ctx.h"
#include "util.h"

#define MAX_LABEL_LENGTH 256
#define MAX_REQ_LENGTH 256

static struct option long_options[] = {
	{"interactive", 0, 0, 'i'},
	{"json", 1, 0, 'j'},
	{"help", 0, 0, 'h'},
	{"version", 0, 0, 'v'},
	{0, 0, 0, 0}
};

static void usage(char *argv0)
{
	fprintf(stdout, "Usage: %s [options] <filename>\n\n"
		"Options:\n"
		"\t-i, --interactive             interactive mode\n"
		"\t-j, --json <file>             JSON input file\n"
		"\t-h, --help                    print this help message\n"
		"\t-v, --version                 print package version\n"
		"\n"
		"Report bugs to " PACKAGE_BUGREPORT "\n",
		argv0);
	exit(-1);
}

static char *ask_question(int max_answer_len, char *answer,
			  char *question_fmt, ...)
{
	va_list list;

	va_start(list, question_fmt);
	vprintf(question_fmt, list);
	if (!fgets(answer, max_answer_len, stdin))
		return NULL;

	answer[strlen(answer) - 1] = '\0';
	return strlen(answer) ? answer : NULL;
}

int main(int argc, char **argv)
{
	char filename[FILENAME_MAX];
	char path[PATH_MAX], *path_ptr = filename, *data_sep;
	char *json_path = NULL;
	const char *key, *output_str;
	unsigned char *output;
	size_t output_len;
	int option_index, c;
	struct json_object_iterator l_it, l_itEnd;
	json_object *root, *output_obj;
	enum data_formats fmt;
	int rc = 0, interactive = 0;

	while (1) {
		option_index = 0;
		c = getopt_long(argc, argv, "ij:hv",
				long_options, &option_index);
		if (c == -1)
			break;

		switch (c) {
			case 'i':
				interactive = 1;
				break;
			case 'j':
				json_path = optarg;
				break;

			case 'h':
				usage(argv[0]);
				break;
			case 'v':
				fprintf(stdout, "%s " VERSION "\n"
					"Copyright 2018-2019 by Roberto Sassu\n"
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

	if (!json_path) {
		printf("Input file not specified\n");
		usage(argv[0]);
	}

	root = attest_ctx_parse_json_file(json_path);
	if (!root) {
		printf("Unable to parse %s\n", json_path);
		return -EINVAL;
	}

	l_it = json_object_iter_begin(root);
	l_itEnd = json_object_iter_end(root);

	while (!json_object_iter_equal(&l_it, &l_itEnd)) {
		key = json_object_iter_peek_name(&l_it);

		json_object_object_get_ex(root, key, &output_obj);

		snprintf(filename, sizeof(filename), "%s.bin", key);
		if (interactive) {
			path_ptr = ask_question(sizeof(path), path,
						"Enter path [%s]: ", path);
			if (!path_ptr)
				path_ptr = filename;
		}

		output_str = json_object_get_string(output_obj);

		data_sep = strchr(output_str, ':');
		if (data_sep) {
			fmt = attest_ctx_data_lookup_format(output_str,
						    data_sep - output_str);
			if (fmt != DATA_FMT_BASE64) {
				printf("Invalid data format %d for key %s\n",
				       fmt, key);
				json_object_iter_next(&l_it);
				continue;
			}

			rc = attest_util_decode_data(strlen(output_str),
					output_str, data_sep - output_str + 1,
					&output_len, &output);
			if (rc < 0) {
				printf("Cannot decode data for key %s\n", key);
				json_object_iter_next(&l_it);
				continue;
			}
		} else {
			output = (unsigned char *)output_str;
			output_len = strlen(output_str);
		}

		rc = attest_util_write_file(path_ptr, output_len, output);

		if (output != (unsigned char *)output_str)
			free(output);

		if (rc < 0)
			printf("Cannot write data to file %s\n", path_ptr);

		json_object_iter_next(&l_it);
	}

	json_object_put(root);
	return rc;
}
