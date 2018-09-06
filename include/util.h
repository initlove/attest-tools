#ifndef _UTIL_H
#define _UTIL_H

int attest_util_read_file(const char *path, size_t *len, unsigned char **data);
int attest_util_write_file(const char *path, size_t len, unsigned char *data);
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
int hex2bin(unsigned char *dst, const char *src, size_t count);

#endif /*_UTIL_H*/
