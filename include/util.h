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
 * File: util.h
 *      Header of util.c.
 */

#ifndef _UTIL_H
#define _UTIL_H

int attest_util_read_file(const char *path, size_t *len, unsigned char **data);
int attest_util_read_seq_file(const char *path, size_t *len,
			      unsigned char **data);
int attest_util_write_file(const char *path, size_t len, unsigned char *data,
			   int append);
int attest_util_copy_file(const char *path_source, const char *path_dest);
int attest_util_read_buf(int fd, unsigned char *buf, size_t buf_len);
int attest_util_write_buf(int fd, unsigned char *buf, size_t buf_len);
int attest_util_calc_digest(const char *algo, int *digest_len,
			    unsigned char *digest, int len, void *data);
int attest_util_decode_data(size_t input_len, const char *input, int offset,
			    size_t *output_len, unsigned char **output);
int attest_util_encode_data(size_t input_len, const unsigned char *input,
			    int offset, size_t *output_len, char **output);
int attest_util_download_data(const char *url, int fd);
int attest_util_check_mask(int mask_in_len, uint8_t *mask_in,
			   int mask_ref_len, uint8_t *mask_ref);
int attest_util_parse_pcr_list(const char *pcr_list_str, int pcr_list_num,
			       int *pcr_list);

int hex2bin(unsigned char *dst, const char *src, size_t count);
char *bin2hex(char *dst, const void *src, size_t count);

#endif /*_UTIL_H*/
