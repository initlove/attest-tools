bin_PROGRAMS=attest_build_json attest_create_skae

attest_build_json_SOURCES=attest_build_json.c
attest_build_json_LDADD=${DEPS_LIBS} -ljson-c ../libs/libattest.la
attest_build_json_CFLAGS=${DEPS_CFLAGS} -Werror -I$(top_srcdir)/include

attest_create_skae_SOURCES=attest_create_skae.c
attest_create_skae_LDADD=${DEPS_LIBS} -ljson-c ../libs/libattest.la \
			 ../libs/libskae.la
attest_create_skae_CFLAGS=${DEPS_CFLAGS} -Werror -I$(top_srcdir)/include
