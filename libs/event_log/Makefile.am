lib_LTLIBRARIES=libeventlog_bios.la

libeventlog_bios_la_LDFLAGS= -no-undefined -avoid-version
libeventlog_bios_la_LIBADD=${DEPS_LIBS} -ltss -lcrypto
libeventlog_bios_la_SOURCES=bios.c
libeventlog_bios_la_CFLAGS=${DEPS_CFLAGS} -Werror -I$(top_srcdir)/include
