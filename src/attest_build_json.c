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
 * File: attest_build_json.c
 *      Tool for building a JSON file for verifying the SKAE.
 */

#include <stdio.h>
#include <getopt.h>
#include <string.h>
#include <errno.h>
#include <stdarg.h>
#include <dirent.h>

#include <sys/stat.h>
#include <sys/mman.h>

#include "ctx_json.h"
#include "ctx.h"
#include "util.h"

#define MAX_LABEL_LENGTH 256
#define MAX_REQ_LENGTH 256

static struct option long_options[] = {
	{"data-type", 1, 0, 't'},
	{"data-path", 1, 0, 'p'},
	{"data-label", 1, 0, 'l'},
	{"default-label", 0, 0, 'u'},
	{"data-format", 1, 0, 'f'},
	{"req-key", 1, 0, 'k'},
	{"req-value", 1, 0, 'q'},
	{"delete", 0, 0, 'd'},
	{"append", 0, 0, 'a'},
	{"newline", 0, 0, 'n'},
	{"interactive", 0, 0, 'i'},
	{"json-type", 1, 0, 'j'},
	{"help", 0, 0, 'h'},
	{"version", 0, 0, 'v'},
	{0, 0, 0, 0}
};

static void usage(char *argv0)
{
	fprintf(stdout, "Usage: %s [options] <filename>\n\n"
		"Options:\n"
		"\t-t, --data-type <type>        data type\n"
		"\t-p, --data-path <file>        data path\n"
		"\t-l, --data-label <label>      data label\n"
		"\t-u, --default-label           use file name as data label\n"
		"\t-f, --data-format <format>    data format\n"
		"\t-k, --req-key                 requirement key\n"
		"\t-q, --req-value               requirement value\n"
		"\t-d, --delete                  delete entry\n"
		"\t-a, --append                  append entry\n"
		"\t-n, --newline                 add element for each line\n"
		"\t-i, --interactive             interactive mode\n"
		"\t-j, --json-type               type of JSON to build\n"
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

static void add_json(json_object *parent, int append,
		     const char *key, const char *value)
{
	json_object *object;
	int index = 0;

	if (!key) {
		object = json_object_new_string((char *)value);
	} else {
		object = json_object_new_object();
		json_object_object_add(object, key,
			json_object_new_string((char *)value));
	}

	if (json_object_is_type(parent, json_type_array)) {
		if (append)
			index = json_object_array_length(parent);

		json_object_array_put_idx(parent, index, object);
	} else {
		json_object_object_add(parent, key, object);
	}
}

static int add_file_base64(json_object *parent, enum ctx_fields field,
			   const char *data_location, const char *data_label,
			   int append, int newline)
{
	size_t line_len, input_len;
	char *input_ptr, *newline_ptr, *output;
	unsigned char *input;
	int rc;

	rc = attest_util_read_file(data_location, &input_len, &input);
	if (rc) {
		printf("Unable to read %s\n", data_location);
		goto out;
	}

	input_ptr = (char *)input;

	while (input_len > 0) {
		line_len = input_len;
		newline_ptr = NULL;

		if (newline) {
			newline_ptr = strchr(input_ptr, '\n');
			line_len = newline_ptr - input_ptr;
		}

		rc = attest_ctx_data_new_string(DATA_FMT_BASE64, line_len,
						(unsigned char *)input_ptr,
						&output);
		if (rc) {
			printf("Unable to encode data\n");
			goto out_munmap;

		}

		input_ptr += line_len + 1;
		input_len -= (line_len + (newline_ptr ? 1 : 0));

		add_json(parent, append, data_label, output);

		free(output);
		output = NULL;
	}
out_munmap:
	munmap(input, input_len);
out:
	return rc;
}

static int add_file_uri(json_object *parent, enum ctx_fields field,
			const char *data_location, const char *data_label,
			int append)
{
	char *output;
	int rc;

	rc = attest_ctx_data_new_string(DATA_FMT_URI, strlen(data_location),
					(unsigned char *)data_location,
					&output);
	if (rc)
		return rc;

	add_json(parent, append, data_label, output);
	return 0;
}

static int add_file(json_object *root, enum ctx_fields field,
		    char *data_location, const char *data_label,
		    enum data_formats fmt, int append, int newline,
		    int default_label)
{
	char data_label_buf[MAX_LABEL_LENGTH];
	const char *field_str = attest_ctx_data_get_field(field);
	json_object *parent;
	int rc = -ENOENT;

	if (field == CTX__LAST || !data_location) {
		printf("Data type/location not specified\n");
		return rc;
	}

	if (field == CTX_EVENT_LOG || field == CTX_AUX_DATA) {
		if (!default_label && !data_label) {
			data_label = ask_question(sizeof(data_label_buf),
				data_label_buf, "Enter label for %s: ",
				field_str);
		} else if (default_label) {
			data_label = strrchr(data_location, '/');
			if (!data_label)
				data_label = data_location;
			else
				data_label++;
		}

		if (!data_label) {
			printf("Data label not specified\n");
			return rc;
		}
	}

	json_object_object_get_ex(root, field_str, &parent);
	if (!parent) {
		if (field == CTX_EVENT_LOG || field == CTX_AUX_DATA)
			parent = json_object_new_object();
		else
			parent = json_object_new_array();

		json_object_object_add(root, field_str, parent);
	}

	switch (fmt) {
	case DATA_FMT_BASE64:
		rc = add_file_base64(parent, field, data_location, data_label,
				     append, newline);
		break;
	case DATA_FMT_URI:
		rc = add_file_uri(parent, field, data_location, data_label,
				  append);
		break;
	default:
		break;
	}

	return rc;
}

static int add_dir(json_object *root, enum ctx_fields field, int location_len,
		   char *data_location, enum data_formats fmt, int append,
		   int newline, int default_label)
{
	int data_len;
	struct dirent *d_entry;
	DIR *dir;

	data_len = strlen(data_location);
	if (data_len < location_len - 1)
		data_location[data_len++] = '/';

	dir = opendir(data_location);

	while ((d_entry = readdir(dir))) {
		if (!strcmp(d_entry->d_name, ".") ||
		    !strcmp(d_entry->d_name, ".."))
			continue;

		if (data_len + strlen(d_entry->d_name) + 1 > location_len) {
			printf("path too long\n");
			continue;
		}

		snprintf(data_location + data_len, location_len - data_len,
			 "%s", d_entry->d_name);
		add_file(root, field, data_location, d_entry->d_name,
			 fmt, append, newline, default_label);
		append = 1;
	}

	return 0;
}

static int add_file_interactive(json_object *root, int append)
{
	char data_location_buf[MAX_PATH_LENGTH];
	char data_format_buf[MAX_LABEL_LENGTH], yesno_buf[3];
	char *data_location = NULL, *data_format, *answer;
	enum data_formats fmt = DATA_FMT_BASE64;
	const char *field_str;
	int field, newline, default_label;
	struct stat st;

	for (field = 0; field < CTX__LAST; field++) {
		field_str = attest_ctx_data_get_field(field);

		answer = ask_question(sizeof(yesno_buf), yesno_buf,
				      "Add data for %s [y/N]: ", field_str);
		if (!answer || *answer != 'y') {
			printf("====\n");
			continue;
		}
again:
		data_format = ask_question(sizeof(data_format_buf),
			data_format_buf, "Enter data format for %s [%s]: ",
			field_str, attest_ctx_data_get_format(fmt));
		if (data_format) {
			fmt = attest_ctx_data_lookup_format(data_format,
							strlen(data_format));
			if (fmt == DATA_FMT__LAST) {
				printf("Invalid data format\n");
				return -EINVAL;
			}
		}

		data_location = ask_question(sizeof(data_location_buf),
			data_location_buf, "Enter location for %s: ",
			field_str);

		answer = ask_question(sizeof(yesno_buf), yesno_buf,
			"Separate input lines for %s [y/N]: ", field_str);
		newline = (answer && *answer == 'y') ? 1 : 0;

		answer = ask_question(sizeof(yesno_buf), yesno_buf,
			"Use default data label [y/N]: ", field_str);
		default_label = (answer && *answer == 'y') ? 1 : 0;

		if (!stat(data_location, &st) && S_ISDIR(st.st_mode))
			add_dir(root, field, sizeof(data_location_buf),
				data_location, fmt, append, newline,
				default_label);
		else
			add_file(root, field, data_location, NULL,
				 fmt, append, newline, default_label);

		answer = ask_question(sizeof(yesno_buf), yesno_buf,
			"Add more data for %s [y/N]: ", field_str);
		if (answer && *answer == 'y') {
			printf("==\n");
			goto again;
		}

		printf("====\n");
	}

	return 0;
}

static int delete_data(json_object *root, enum ctx_fields field,
		       const char *data_label)
{
	const char *field_str = attest_ctx_data_get_field(field);
	json_object *parent, *parent_new, *object;
	long int array_index;
	int i;

	if (!data_label) {
		json_object_object_del(root, field_str);
		return 0;
	}

	json_object_object_get_ex(root, field_str, &parent);
	if (json_object_is_type(parent, json_type_array)) {
		array_index = strtoul(data_label, NULL, 10);
		if (array_index < 0 ||
		    array_index >= json_object_array_length(parent)) {
			printf("Invalid array index %s\n", data_label);
			return -EINVAL;
		}

		parent_new = json_object_new_array();

		for (i = 0; i < json_object_array_length(parent); i++) {
			if (i == array_index)
				continue;

			object = json_object_array_get_idx(parent, i);
			json_object_array_add(parent_new, object);
		}
		json_object_object_del(root, field_str);
		json_object_object_add(root, field_str, parent_new);
	} else {
		json_object_object_del(parent, data_label);
	}

	return 0;
}

static int delete_data_interactive(json_object *root)
{
	char data_label_buf[MAX_LABEL_LENGTH], yesno_buf[3];
	char *data_label = NULL, *answer;
	enum ctx_fields field;
	const char *field_str;

	for (field = 0; field < CTX__LAST; field++) {
		field_str = attest_ctx_data_get_field(field);

		answer = ask_question(sizeof(yesno_buf), yesno_buf,
				      "Delete data from %s [y/N]: ", field_str);
		if (!answer || *answer != 'y') {
			printf("====\n");
			continue;
		}
again:
		data_label = ask_question(sizeof(data_label_buf),
			data_label_buf,
			"Enter array index/label for %s [ALL]: ", field_str);

		delete_data(root, field, data_label);

		answer = ask_question(sizeof(yesno_buf), yesno_buf,
			"Delete more data from %s [y/N]: ", field_str);
		if (answer && *answer == 'y') {
			printf("==\n");
			goto again;
		}
	}

	return 0;
}

static int add_req_interactive(json_object *root)
{
	char req_key_buf[MAX_REQ_LENGTH], req_value_buf[MAX_REQ_LENGTH];
	char yesno_buf[3];
	char *req_key, *req_value, *answer;
	json_object *req_obj;

	json_object_object_get_ex(root, JSON_REQS_OBJECT_KEY, &req_obj);
again:
	req_key = ask_question(sizeof(req_key_buf), req_key_buf,
			       "Enter verifier ID: ");
	if (!req_key) {
		printf("Requirement key/value must be specified\n");
		goto out;
	}

	req_value = ask_question(sizeof(req_value_buf), req_value_buf,
			         "Enter requirement: ");
	if (!req_value)
		req_value = "";

	json_object_object_add(req_obj, req_key,
			       json_object_new_string(req_value));
out:
	answer = ask_question(sizeof(yesno_buf), yesno_buf,
			      "Add more requirements [y/N]: ");
	if (answer && *answer == 'y')
		goto again;

	return 0;
}

static void delete_req(json_object *root, const char *req_key)
{
	json_object *req_obj;

	json_object_object_get_ex(root, JSON_REQS_OBJECT_KEY, &req_obj);
	json_object_object_del(req_obj, req_key);
}

static int delete_req_interactive(json_object *root)
{
	char req_key_buf[MAX_REQ_LENGTH], yesno_buf[3];
	char *req_key, *answer;
again:
	req_key = ask_question(sizeof(req_key_buf), req_key_buf,
			       "Enter verifier ID: ");
	if (!req_key) {
		printf("Requirement key must be specified\n");
		goto out;
	}

	delete_req(root, req_key);
out:
	answer = ask_question(sizeof(yesno_buf), yesno_buf,
			      "Delete more requirements [y/N]: ");
	if (answer && *answer == 'y')
		goto again;

	return 0;
}

int main(int argc, char **argv)
{
	char *data_label = NULL, *data_location = NULL, *json_path;
	char *req_key = NULL, *req_value = NULL;
	int option_index, c, newline = 0, append = 0;
	int default_label = 0, build_req = 0, interactive = 0, delete = 0;
	enum ctx_fields field = CTX__LAST;
	enum data_formats fmt = DATA_FMT_BASE64;
	const char *json_str;
	json_object *root, *req_array;
	struct stat st;
	int rc = 0;

	while (1) {
		option_index = 0;
		c = getopt_long(argc, argv, "t:p:l:uf:k:q:danij:hv",
				long_options, &option_index);
		if (c == -1)
			break;

		switch (c) {
			case 't':
				field = attest_ctx_data_lookup_field(optarg);
				if (field == CTX__LAST) {
					printf("Unknown data type %s\n",
					       optarg);
					return -EINVAL;
				}
				break;
			case 'p':
				data_location = optarg;
				break;
			case 'l':
				data_label = optarg;
				break;
			case 'u':
				default_label = 1;
				break;
			case 'f':
				fmt = attest_ctx_data_lookup_format(optarg,
								strlen(optarg));
				if (fmt == DATA_FMT__LAST) {
					printf("Unknown data format %s\n",
					       optarg);
					return -EINVAL;
				}
				break;
			case 'k':
				req_key = optarg;
				break;
			case 'q':
				req_value = optarg;
				break;
			case 'd':
				delete = 1;
				break;
			case 'a':
				append = 1;
				break;
			case 'n':
				newline = 1;
				break;
			case 'i':
				interactive = 1;
				break;
			case 'j':
				if (!strcmp(optarg, "data"))
					build_req = 0;
				else if (!strcmp(optarg, JSON_REQS_OBJECT_KEY))
					build_req = 1;
				else {
					printf("unknown JSON type\n");
					return -EINVAL;
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
				printf("Unknown option '%c'\n", c);
				usage(argv[0]);
				break;
		}
	}

	if (!interactive) {
		if (!build_req && !delete && !data_location) {
			printf("Missing data location\n");
			usage(argv[0]);
		}

		if (build_req && (!req_key || (!delete && !req_value))) {
			printf("Missing req key/value\n");
			usage(argv[0]);
		}
	}

	if (optind >= argc) {
		printf("Too few arguments: Expected file name as last argument\n");
		usage(argv[0]);
	}

	json_path = argv[argc - 1];

	if (optind < argc - 1) {
		printf("Unexpected additional arguments\n");
		usage(argv[0]);
	}


	if (stat(json_path, &st) != -1) {
		root = attest_ctx_parse_json_file(json_path);
		if (!root) {
			printf("Unable to parse %s\n", json_path);
			return -EINVAL;
		}
	} else {
		root = json_object_new_object();
	}

	if (!build_req) {
		if (!delete && interactive)
			rc = add_file_interactive(root, append);
		else if (!delete && !interactive)
			rc = add_file(root, field, data_location, data_label,
				      fmt, append, newline, default_label);
		else if (interactive)
			rc = delete_data_interactive(root);
		else
			rc = delete_data(root, field, data_label);

	} else {
		json_object_object_get_ex(root, JSON_REQS_OBJECT_KEY,
					  &req_array);
		if (!req_array) {
			req_array = json_object_new_object();
			json_object_object_add(root, JSON_REQS_OBJECT_KEY,
					       req_array);
		}

		if (!delete && interactive) {
			rc = add_req_interactive(root);
		} else if (!delete && !interactive) {
			json_object_object_add(req_array, req_key,
					json_object_new_string(req_value));
			rc = 0;
		} else if (interactive) {
			rc = delete_req_interactive(root);
		} else {
			delete_req(root, req_key);
			rc = 0;
		}
	}

	if (rc)
		goto out;

	json_str = json_object_to_json_string_ext(root,
						  JSON_C_TO_STRING_PRETTY);
	rc = attest_util_write_file(json_path, strlen(json_str),
				    (unsigned char *)json_str);
out:
	json_object_put(root);
	return rc;
}
