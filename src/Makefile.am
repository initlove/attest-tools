bin_PROGRAMS=attest_build_json

attest_build_json_SOURCES=attest_build_json.c
attest_build_json_LDADD=${DEPS_LIBS} -ljson-c ../libs/libattest.la
attest_build_json_CFLAGS=${DEPS_CFLAGS} -Werror -I$(top_srcdir)/include
