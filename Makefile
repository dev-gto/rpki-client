include Makefile.configure

# If set to zero, privilege-dropping is disabled and RPKI_PRIVDROP_USER
# is not used.  Otherwise, privileges are dropped.

RPKI_PRIVDROP		= 1
RPKI_PRIVDROP_USER	= "_rpki-client"

# Command to invoke for rsync.  Must be in user's path.

RPKI_RSYNC_COMMAND	= "openrsync"

# Where to place output files.

RPKI_PATH_OUT_DIR	= "/var/db/rpki-client"

# Where repositories are stored.

RPKI_PATH_BASE_DIR	= "/var/cache/rpki-client"

# Where TAL files are found.

RPKI_TAL_DIR		= "/etc/rpki"

OBJS = as.o \
	   asn1.o \
	   cert.o \
	   cms.o \
	   compats.o \
	   crl.o \
	   encoding.o \
	   hash.o \
	   io.o \
	   ip.o \
	   log.o \
	   mft.o \
	   mkdir.o \
	   output.o \
	   output-bgpd.o \
	   output-bird.o \
	   output-csv.o \
	   output-json.o \
	   roa.o \
	   rsync.o \
	   tal.o \
	   test-core.o \
	   validate.o \
	   x509.o
ALLOBJS	= $(OBJS) \
	   main.o \
	   test-cert.o \
	   test-crl.o \
	   test-mft.o \
	   test-roa.o \
	   test-rpki.o \
	   test-tal.o
BINS = rpki-client \
	   test-rpki

ARCH=$(shell uname -s|tr A-Z a-z)
ifeq ($(ARCH), linux)
	# Linux.
	LDADD += `pkg-config --libs openssl` -lresolv 
	CFLAGS += -Wno-discarded-qualifiers -Wno-pointer-sign -fomit-frame-pointer -fstrict-aliasing -fstack-protector `pkg-config --cflags openssl` -D_LINUX
else ifeq ($(ARCH), freebsd)
	CFLAGS += -I/usr/include/openssl -Wno-strict-prototypes -Wno-implicit-function-declaration -Wno-incompatible-pointer-types-discards-qualifiers -Wno-ignored-qualifiers -Wno-pointer-sign -fomit-frame-pointer -fstrict-aliasing -fstack-protector -D_NSIG=NSIG -D_FREEBSD
	LDADD += -lssl -lcrypto
else
	# OpenBSD.
	CFLAGS += -I/usr/local/include/eopenssl -Wno-incompatible-pointer-types-discards-qualifiers
	LDADD += /usr/local/lib/eopenssl/libssl.a /usr/local/lib/eopenssl/libcrypto.a
endif

all: $(BINS) rpki-client.install.8

site.h: Makefile
	@(echo "#define RPKI_RSYNC_COMMAND \"${RPKI_RSYNC_COMMAND}\"" ; \
	 echo "#define RPKI_PATH_OUT_DIR \"${RPKI_PATH_OUT_DIR}\"" ; \
	 echo "#define RPKI_PATH_BASE_DIR \"${RPKI_PATH_BASE_DIR}\"" ; \
	 echo "#define RPKI_PRIVDROP ${RPKI_PRIVDROP}" ; \
	 echo "#define RPKI_PRIVDROP_USER \"${RPKI_PRIVDROP_USER}\"" ; \
	 echo "#define RPKI_TAL_DIR \"${RPKI_TAL_DIR}\"" ; ) >$@

site.sed: Makefile
	@(echo "s!@RPKI_RSYNC_COMMAND@!${RPKI_RSYNC_COMMAND}!g" ; \
	 echo "s!@RPKI_PATH_OUT_DIR@!${RPKI_PATH_OUT_DIR}!g" ; \
	 echo "s!@RPKI_PATH_BASE_DIR@!${RPKI_PATH_BASE_DIR}!g" ; \
	 echo "s!@RPKI_PRIVDROP_USER@!${RPKI_PRIVDROP_USER}!g" ; \
	 echo "s!@RPKI_TAL_DIR@!${RPKI_TAL_DIR}!g" ; ) >$@

install: all
	mkdir -p $(DESTDIR)$(BINDIR)
	mkdir -p $(DESTDIR)$(MANDIR)/man8
	$(INSTALL_PROGRAM) rpki-client $(DESTDIR)$(BINDIR)
	$(INSTALL_MAN) rpki-client.install.8 $(DESTDIR)$(MANDIR)/man8/rpki-client.8

uninstall:
	rm -f $(DESTDIR)$(BINDIR)/rpki-client
	rm -f $(DESTDIR)$(MANDIR)/man8/rpki-client.8

rpki-client: main.o $(OBJS)
	$(CC) -o $@ $^ $(LDFLAGS) $(LDADD)

test-%: test-%.o $(OBJS)
	$(CC) -o $@ $^ $(LDFLAGS) $(LDADD)

clean:
	rm -f $(BINS) $(ALLOBJS) rpki-client.install.8 site.sed site.h

distclean: clean
	rm -f config.h config.log Makefile.configure

distcheck:
	mandoc -Tlint -Werror rpki-client.8
	rm -rf .distcheck
	mkdir .distcheck
	cp *.c extern.h rpki-client.8 configure Makefile .distcheck
	( cd .distcheck && ./configure PREFIX=prefix )
	( cd .distcheck && $(MAKE) )
	( cd .distcheck && $(MAKE) install )
	rm -rf .distcheck

regress:
	# Do nothing.

$(ALLOBJS): extern.h config.h site.h

rpki-client.install.8: rpki-client.8 site.sed
	sed -f site.sed rpki-client.8 >$@
