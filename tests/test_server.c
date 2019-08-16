#include <stdio.h>
#include <fcntl.h>
#include <string.h>
#include <unistd.h>
#include <stdlib.h>
#include <errno.h>

#include <sys/types.h>
#include <sys/stat.h>
#include <sys/socket.h>
#include <sys/un.h>

#include "enroll.h"
#include "ctx_json.h"

#include <tss2/tss.h>
#include <tss2/tssmarshal.h>
#include <tss2/Unmarshal_fp.h>

#include <openssl/evp.h>
#include <openssl/rand.h>

#define CAKEY_PATH "cakey.pem"
#define CACERT_PATH "cacert.pem"
#define CAKEY_PASSWORD "1234"

int main()
{
	attest_ctx_data *d_ctx_in = NULL, *d_ctx_out = NULL;
	attest_ctx_verifier *v_ctx = NULL;
	char *input, *output;
	size_t len, cur_len;
	struct sockaddr_un addr;
	BYTE hmac_key[64];
	int rc, fd, fd_socket, op;

	OpenSSL_add_all_algorithms();

	rc = RAND_bytes(hmac_key, sizeof(hmac_key));
	if (!rc) {
		printf("Cannot generate HMAC key\n");
		return 1;
	}

	unlink("socket");
	fd_socket = socket(AF_UNIX, SOCK_STREAM, 0);
	memset(&addr, 0, sizeof(addr));
	addr.sun_family = AF_UNIX;
	strncpy(addr.sun_path, "socket", sizeof(addr.sun_path)-1);
	bind(fd_socket, (struct sockaddr*)&addr, sizeof(addr));
	listen(fd_socket, 5);

	while (1) {
		fd = accept(fd_socket, NULL, NULL);
		if (fd < 0)
			continue;

		cur_len = read(fd, &len, sizeof(len));
		cur_len = read(fd, &op, sizeof(op));

		len -= 2 * sizeof(len);
		input = malloc(len + 1);

		if (!input) {
			len = 0;
			goto response;
		}

		cur_len = read(fd, input, len);
		if (cur_len != len) {
			len = 0;
			goto response;
		}

		input[len] = '\0';

		len = 0;
#ifdef DEBUG
		printf("-> %s\n", input);
#endif
		attest_ctx_data_init(&d_ctx_in);
		attest_ctx_data_init(&d_ctx_out);
		attest_ctx_verifier_init(&v_ctx);
		attest_ctx_verifier_set_key(v_ctx, hmac_key, sizeof(hmac_key));

		rc = attest_ctx_data_add_json_data(d_ctx_in, input, cur_len);
		if (rc < 0)
			goto response;

		free(input);

		switch (op) {
		case 0:
			rc = attest_enroll_make_credential(d_ctx_in, d_ctx_out,
							   v_ctx);
			break;
		case 1:
			rc = attest_enroll_make_cert(d_ctx_in, d_ctx_out, v_ctx,
						     CAKEY_PATH, CAKEY_PASSWORD,
						     CACERT_PATH, "desktop");
			break;
		default:
			printf("Undefined operation\n");
			rc = -EINVAL;
			break;
		}

		if (rc < 0)
			goto response;

		rc = attest_ctx_data_print_json(d_ctx_out, &output);
		if (rc)
			goto response;

		len = strlen(output) + sizeof(len) + 1;
#ifdef DEBUG
		printf("<- %s\n", output);
#endif
response:
		cur_len = write(fd, &len, sizeof(len));
		if (len) {
			len = write(fd, output, len - sizeof(len));
			if (len != len - sizeof(len)) {
				rc = -EIO;
				break;
			}

			free(output);
		}

		attest_ctx_data_cleanup(d_ctx_in);
		attest_ctx_data_cleanup(d_ctx_out);
		attest_ctx_verifier_cleanup(v_ctx);
	}

	EVP_cleanup();
	return 0;
}
