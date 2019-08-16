bin_PROGRAMS=test_client test_server

test_client_SOURCES=test_client.c
test_client_LDADD=-ltssutils ../libs/libclient.la
test_client_CFLAGS=${DEPS_CFLAGS} -I$(top_srcdir)/include

test_server_SOURCES=test_server.c
test_server_LDADD=../libs/libenroll.la
test_server_CFLAGS=${DEPS_CFLAGS} -I$(top_srcdir)/include
