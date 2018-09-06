lib_LTLIBRARIES=libattest.la

libattest_la_LDFLAGS= -no-undefined -avoid-version
libattest_la_LIBADD=${DEPS_LIBS}
libattest_la_SOURCES=util.c ctx.c ctx_json.c
libattest_la_CFLAGS=${DEPS_CFLAGS} -Werror -I$(top_srcdir)/include
