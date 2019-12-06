bin_PROGRAMS=attest_build_json attest_parse_json attest_create_skae \
	     attest_ra_client attest_ra_server attest_tls_client \
	     attest_tls_server

attest_build_json_SOURCES=attest_build_json.c
attest_build_json_LDADD=${DEPS_LIBS} -ljson-c ../libs/libattest.la
attest_build_json_CFLAGS=${DEPS_CFLAGS} -I$(top_srcdir)/include

attest_parse_json_SOURCES=attest_parse_json.c
attest_parse_json_LDADD=${DEPS_LIBS} -ljson-c ../libs/libattest.la
attest_parse_json_CFLAGS=${DEPS_CFLAGS} -I$(top_srcdir)/include

attest_create_skae_SOURCES=attest_create_skae.c
attest_create_skae_LDADD=${DEPS_LIBS} -ljson-c ../libs/libattest.la \
			 ../libs/libskae.la
attest_create_skae_CFLAGS=${DEPS_CFLAGS} -I$(top_srcdir)/include

attest_ra_client_SOURCES=attest_ra_client.c
attest_ra_client_LDADD=${DEPS_LIBS} ../libs/libattest.la \
		       ../libs/libenroll_client.la
attest_ra_client_CFLAGS=${DEPS_CFLAGS} -I$(top_srcdir)/include

attest_ra_server_SOURCES=attest_ra_server.c
attest_ra_server_LDADD=${DEPS_LIBS} ../libs/libattest.la \
		       ../libs/libenroll_server.la
attest_ra_server_CFLAGS=${DEPS_CFLAGS} -I$(top_srcdir)/include

attest_tls_client_SOURCES=attest_tls_common.c attest_tls_client.c
attest_tls_client_LDADD=${DEPS_LIBS} ../libs/libattest.la ../libs/libskae.la \
			-lssl -lcrypto
attest_tls_client_CFLAGS=${DEPS_CFLAGS} -I$(top_srcdir)/include

attest_tls_server_SOURCES=attest_tls_common.c attest_tls_server.c
attest_tls_server_LDADD=${DEPS_LIBS} ../libs/libattest.la ../libs/libskae.la \
			-lssl -lcrypto
attest_tls_server_CFLAGS=${DEPS_CFLAGS} -I$(top_srcdir)/include
