#
# @configure_input@
#
# Copyright (c) 1994-2008 Carnegie Mellon University.  All rights reserved.
#
# Redistribution and use in source and binary forms, with or without
# modification, are permitted provided that the following conditions
# are met:
#
# 1. Redistributions of source code must retain the above copyright
#    notice, this list of conditions and the following disclaimer.
#
# 2. Redistributions in binary form must reproduce the above copyright
#    notice, this list of conditions and the following disclaimer in
#    the documentation and/or other materials provided with the
#    distribution.
#
# 3. The name "Carnegie Mellon University" must not be used to
#    endorse or promote products derived from this software without
#    prior written permission. For permission or any legal
#    details, please contact
#      Carnegie Mellon University
#      Center for Technology Transfer and Enterprise Creation
#      4615 Forbes Avenue
#      Suite 302
#      Pittsburgh, PA  15213
#      (412) 268-7393, fax: (412) 268-7395
#      innovation@andrew.cmu.edu
#
# 4. Redistributions of any form whatsoever must retain the following
#    acknowledgment:
#    "This product includes software developed by Computing Services
#     at Carnegie Mellon University (http://www.cmu.edu/computing/)."
#
# CARNEGIE MELLON UNIVERSITY DISCLAIMS ALL WARRANTIES WITH REGARD TO
# THIS SOFTWARE, INCLUDING ALL IMPLIED WARRANTIES OF MERCHANTABILITY
# AND FITNESS, IN NO EVENT SHALL CARNEGIE MELLON UNIVERSITY BE LIABLE
# FOR ANY SPECIAL, INDIRECT OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES
# WHATSOEVER RESULTING FROM LOSS OF USE, DATA OR PROFITS, WHETHER IN
# AN ACTION OF CONTRACT, NEGLIGENCE OR OTHER TORTIOUS ACTION, ARISING
# OUT OF OR IN CONNECTION WITH THE USE OR PERFORMANCE OF THIS SOFTWARE.
#

ACLOCAL_AMFLAGS = -I cmulocal
AM_CFLAGS = @PERL_CCCDLFLAGS@ $(GCOV_CFLAGS)
AM_CXXFLAGS = $(GCOV_CXXFLAGS)

AM_CPPFLAGS = \
	$(COM_ERR_CPPFLAGS) \
	-I${top_builddir} \
	-I${top_builddir}/lib \
	-I${top_srcdir} \
	-I${top_srcdir}/lib \
	-DLIBEXEC_DIR=\"$(libexecdir)\" \
	-DSBIN_DIR=\"$(sbindir)\" \
	-DSYSCONF_DIR=\"$(sysconfdir)\" \
	${DEFS} \
	${LOCALDEFS} \
	$(SASLFLAGS) \
	$(SSL_CPPFLAGS) \
	$(ICU_CFLAGS)

if HAVE_LDAP
AM_CPPFLAGS += $(LDAP_CPPFLAGS)
endif # HAVE_LDAP

AM_LDFLAGS = $(COV_LDFLAGS) $(ICU_LIBS)

# have distcheck try to build with all optional components enabled, to aid
# detection of missing files for these components
AM_DISTCHECK_CONFIGURE_FLAGS = \
    --enable-http \
    --enable-calalarmd \
    --enable-replication \
    --with-openssl=yes \
    --enable-nntp \
    --enable-murder \
    --enable-idled \
    --enable-sieve \
    --enable-autocreate \
    --enable-backup \
    --enable-xapian \
    --enable-jmap \
    --with-ldap

BUILT_SOURCES = \
	lib/imapopts.c \
	lib/imapopts.h

CLEANFILES = \
	lib/chartable.c \
	lib/imapopts.c \
	lib/imapopts.h

DISTCLEANFILES = \
	com_err/et/compile_et \
	imap/http_caldav_js.h \
	imap/http_carddav_js.h \
	imap/http_err.c \
	imap/http_err.h \
	imap/imap_err.c \
	imap/imap_err.h \
	imap/jmap_err.c \
	imap/jmap_err.h \
	imap/lmtp_err.c \
	imap/lmtp_err.h \
	imap/mupdate_err.c \
	imap/mupdate_err.h \
	imap/nntp_err.c \
	imap/nntp_err.h \
	imap/promdata.c \
	imap/promdata.h \
	imap/tz_err.c \
	imap/tz_err.h \
	perl/sieve/scripts/installsieve \
	perl/sieve/scripts/sieveshell \
	sieve/sieve_err.c \
	sieve/sieve_err.h

MAINTAINERCLEANFILES = \
	doc/legacy/murder.png \
	doc/legacy/netnews.png \
	man/imapd.conf.5 \
	man/sieveshell.1 \
	sieve/addr.h \
	sieve/sieve.h

SUBDIRS = .
DIST_SUBDIRS = . perl/annotator perl/imap perl/sieve/managesieve
dist_sysconf_DATA =
lib_LTLIBRARIES = lib/libcyrus_min.la lib/libcyrus.la
check_PROGRAMS =
libexec_PROGRAMS =
sbin_PROGRAMS =
noinst_HEADERS =
noinst_LTLIBRARIES =
noinst_PROGRAMS =

if COM_ERR
COMPILE_ET_DEP = com_err/et/compile_et
BUILT_SOURCES += com_err/et/compile_et com_err/et/libcyrus_com_err.la
lib_LTLIBRARIES += com_err/et/libcyrus_com_err.la
endif # COM_ERR

bin_PROGRAMS = imtest/imtest

if SERVER
BUILT_SOURCES += \
	imap/http_err.c \
	imap/http_err.h \
	imap/imap_err.c \
	imap/imap_err.h \
	imap/lmtp_err.c \
	imap/lmtp_err.h \
	imap/mupdate_err.c \
	imap/mupdate_err.h \
	imap/promdata.c \
	imap/promdata.h \
	lib/htmlchar.c \
	lib/htmlchar.h \
	imap/rfc822_header.c \
	imap/rfc822_header.h \
	imap/mailbox_header_cache.h

lib_LTLIBRARIES += imap/libcyrus_imap.la

libexec_PROGRAMS += \
	master/master \
	imap/imapd \
	imap/lmtpd \
	imap/pop3d \
	imap/promstatsd \
	imap/smmapd

sbin_PROGRAMS += \
	imap/arbitron \
	imap/chk_cyrus \
	imap/ctl_conversationsdb \
	imap/ctl_cyrusdb \
	imap/ctl_deliver \
	imap/ctl_mboxlist \
	imap/cvt_cyrusdb \
	imap/cyr_df \
	imap/cyrdump \
	imap/cyr_dbtool \
	imap/cyr_deny \
	imap/cyr_expire \
	imap/cyr_info \
	imap/cyr_buildinfo \
	imap/cyr_sequence \
	imap/cyr_synclog \
	imap/cyr_userseen \
	imap/cyr_virusscan \
	imap/deliver \
	imap/ipurge \
	imap/mbexamine \
	imap/mbpath \
	imap/mbtool \
	imap/quota \
	imap/reconstruct \
	imap/cvt_xlist_specialuse

noinst_PROGRAMS += \
	imap/message_test \
	imap/search_test

if USE_SQUAT
noinst_PROGRAMS += imap/squat_dump
endif
if SQUATTER
# Despite the name, the squatter program handles any search engine
sbin_PROGRAMS += imap/squatter
endif

if NNTPD
libexec_PROGRAMS += imap/nntpd
sbin_PROGRAMS += imap/fetchnews
BUILT_SOURCES += imap/nntp_err.c
endif # NNTPD

libexec_PROGRAMS += imap/fud

if IDLED
libexec_PROGRAMS += imap/idled
endif # IDLED

if MURDER
libexec_PROGRAMS += imap/mupdate
endif # MURDER

if CALALARMD
libexec_PROGRAMS += imap/calalarmd
endif

if HTTPD

AM_CPPFLAGS += $(HTTP_CPPFLAGS)

AM_LDFLAGS += $(HTTP_LIBS)

BUILT_SOURCES += \
	imap/http_caldav_js.h \
	imap/http_carddav_js.h \
	imap/tz_err.c \
	imap/tz_err.h

libexec_PROGRAMS += imap/httpd
check_PROGRAMS += imap/ical_apply_patch
sbin_PROGRAMS += \
	imap/ctl_zoneinfo \
	imap/dav_reconstruct

endif # HTTPD

if REPLICATION
libexec_PROGRAMS += imap/sync_server
sbin_PROGRAMS += imap/sync_client imap/sync_reset
endif # REPLICATION

if BACKUP
noinst_LTLIBRARIES += backup/libcyrus_backup.la
noinst_HEADERS += backup/backup.h
libexec_PROGRAMS += backup/backupd
sbin_PROGRAMS += backup/ctl_backups backup/cyr_backup backup/restore
endif # BACKUP

if HAVE_SSL
sbin_PROGRAMS += imap/tls_prune
endif # HAVE_SSL

sbin_PROGRAMS += imap/unexpunge

if SIEVE
check_PROGRAMS += notifyd/notifytest
libexec_PROGRAMS += notifyd/notifyd
endif # SIEVE
endif # SERVER

if CMULOCAL
dist_sysconf_DATA += depot/rc.local.imap depot/rc.local.ptclient
sbin_PROGRAMS += netnews/remotepurge
endif # CMULOCAL

if PTCLIENT
sbin_PROGRAMS += ptclient/ptdump ptclient/ptexpire
libexec_PROGRAMS += \
	ptclient/ptloader
endif # PTCLIENT

if PERL
SUBDIRS += perl/annotator perl/imap
noinst_LTLIBRARIES += perl/libcyrus.la perl/libcyrus_min.la
endif # PERL

if SIEVE

if PERL
SUBDIRS += perl/sieve/managesieve
noinst_LTLIBRARIES += perl/sieve/lib/libisieve.la
endif # PERL

BUILT_SOURCES += sieve/addr.c sieve/sieve.c sieve/sieve_err.c
noinst_LTLIBRARIES += sieve/libcyrus_sieve_lex.la
lib_LTLIBRARIES += sieve/libcyrus_sieve.la
check_PROGRAMS += sieve/test sieve/test_mailbox
sbin_PROGRAMS += sieve/sievec sieve/sieved

if SERVER
libexec_PROGRAMS += timsieved/timsieved
endif # SERVER

endif # SIEVE

EXTRA_DIST = \
	COPYING \
	README.md \
	VERSION \
	com_err/et/et_c.awk \
	com_err/et/et_h.awk \
	com_err/et/test1.et \
	com_err/et/test2.et \
	com_err/et/test_et.c \
	contrib/sieve-spamassassin \
	contrib/fud-client.c \
	contrib/deliver-notify-zephyr.patch \
	contrib/add-cyrus-user \
	contrib/README \
	contrib/cyrusv2.mc \
	contrib/dkim_canon_ischedule.patch \
	contrib/notify_unix/notify \
	contrib/notify_unix/net-server-prefork-0.01.tgz \
	contrib/notify_unix/README \
	contrib/notify_unix/sql_notify.pl \
	contrib/notify_unix/simple_notify.pl \
	contrib/squatrunner.pl \
	contrib/mupdate-test.pl \
	contrib/squatrunner.txt \
	cunit/cacert.pem \
	cunit/cert.pem \
	cunit/cunit.pl \
	cunit/cunit-to-junit.pl \
	cunit/key.pem \
	cunit/vg.supp \
	doc/legacy/murder.png \
	doc/legacy/netnews.png \
	doc \
	docsrc \
	imap/http_caldav.js \
	imap/http_carddav.js \
	imap/http_err.et \
	imap/imap_err.et \
	imap/jmap_err.et \
	imap/lmtp_err.et \
	imap/mailbox_header_cache.gperf \
	imap/mupdate_err.et \
	imap/nntp_err.et \
	imap/promdata.p \
	imap/rfc822_header.st \
	imap/tz_err.et \
	lib/charset/aliases.txt \
	lib/charset/UnicodeData.txt \
	lib/charset/unifix.txt \
	lib/charset/us-ascii.t \
	lib/htmlchar.st \
	lib/imapoptions \
	lib/test/cyrusdb.c \
	lib/test/cyrusdb.INPUT \
	lib/test/cyrusdblong.INPUT \
	lib/test/cyrusdblong.OUTPUT \
	lib/test/cyrusdb.OUTPUT \
	lib/test/cyrusdbtxn.INPUT \
	lib/test/cyrusdbtxn.OUTPUT \
	lib/test/pool.c \
	lib/test/rnddb.c \
	master/README \
	netnews/inn.diffs \
	perl/annotator/Daemon.pm \
	perl/annotator/Makefile.PL \
	perl/annotator/Makefile.PL.in \
	perl/annotator/MANIFEST \
	perl/annotator/MANIFEST.in \
	perl/annotator/Message.pm \
	perl/annotator/README \
	perl/imap/Changes \
	perl/imap/cyradm.sh \
	perl/imap/cyrperl.h \
	perl/imap/examples/auditmbox.pl \
	perl/imap/examples/imapcollate.pl \
	perl/imap/examples/imapdu.pl \
	perl/imap/examples/test-imsp.pl \
	perl/imap/IMAP/Admin.pm \
	perl/imap/IMAP/IMSP.pm \
	perl/imap/IMAP/Shell.pm \
	perl/imap/IMAP.pm \
	perl/imap/IMAP.xs \
	perl/imap/Makefile.PL \
	perl/imap/Makefile.PL.in \
	perl/imap/MANIFEST \
	perl/imap/MANIFEST.in \
	perl/imap/README \
	perl/imap/t/01-imclient.t \
	perl/imap/t/02-admin.t \
	perl/imap/typemap \
	perl/imap/xsutil.c \
	perl/sieve/managesieve/Makefile.PL \
	perl/sieve/managesieve/Makefile.PL.in \
	perl/sieve/managesieve/managesieve.h \
	perl/sieve/managesieve/managesieve.pm \
	perl/sieve/managesieve/managesieve.xs \
	perl/sieve/managesieve/MANIFEST \
	perl/sieve/managesieve/MANIFEST.in \
	perl/sieve/managesieve/typemap \
	ptclient/README \
	ptclient/test.c \
	ptclient/test2.c \
	sieve/addr.h \
	sieve/sieve.h \
	sieve/sieve_err.et \
	sieve/tests/testExtension \
	sieve/tests/testExtension/uberExtensionTestScript.key \
	sieve/tests/testExtension/testm \
	sieve/tests/testExtension/testm/uetest-envelope \
	sieve/tests/testExtension/testm/uetest-asub \
	sieve/tests/testExtension/testm/uetest-areg \
	sieve/tests/testExtension/testm/uetest-count \
	sieve/tests/testExtension/testm/uetest-value \
	sieve/tests/testExtension/testm/uetest-hreg \
	sieve/tests/testExtension/serverm \
	sieve/tests/testExtension/serverm/uetmail-hreg \
	sieve/tests/testExtension/serverm/uetmail-value \
	sieve/tests/testExtension/serverm/uetmail-count2 \
	sieve/tests/testExtension/serverm/uetmail-envelope \
	sieve/tests/testExtension/serverm/uetmail-asub \
	sieve/tests/testExtension/serverm/uetmail-value2 \
	sieve/tests/testExtension/serverm/uetmail-areg \
	sieve/tests/testExtension/serverm/uetmail-count \
	sieve/tests/testExtension/uberExtensionTestScript.s \
	sieve/tests/README \
	sieve/tests/action \
	sieve/tests/action/testm \
	sieve/tests/action/testm/uatest-keep \
	sieve/tests/action/testm/uatest-redirect \
	sieve/tests/action/testm/uatest-discard \
	sieve/tests/action/testm/uatest-stop2 \
	sieve/tests/action/testm/uatest-stop \
	sieve/tests/action/serverm \
	sieve/tests/action/serverm/uamail-stop2 \
	sieve/tests/action/serverm/uamail-redirect \
	sieve/tests/action/serverm/uamail-stop \
	sieve/tests/action/serverm/uamail-keep \
	sieve/tests/action/serverm/uamail-discard \
	sieve/tests/action/uberActionScript.key \
	sieve/tests/action/uberActionScript.s \
	sieve/tests/test \
	sieve/tests/test/uberTestScript.key \
	sieve/tests/test/testm \
	sieve/tests/test/testm/utest-header \
	sieve/tests/test/testm/utest-address \
	sieve/tests/test/serverm \
	sieve/tests/test/serverm/utmail-address \
	sieve/tests/test/serverm/utmail-header \
	sieve/tests/test/uberTestScript.s \
	sieve/tests/actionExtensions \
	sieve/tests/actionExtensions/uberExtensionActionScript.s \
	sieve/tests/actionExtensions/testm \
	sieve/tests/actionExtensions/testm/ueatest-flag4 \
	sieve/tests/actionExtensions/testm/ueatest-flag2 \
	sieve/tests/actionExtensions/testm/ueatest-fileinto \
	sieve/tests/actionExtensions/testm/ueatest-denotify \
	sieve/tests/actionExtensions/testm/ueatest-vacation \
	sieve/tests/actionExtensions/testm/ueatest-reject \
	sieve/tests/actionExtensions/testm/ueatest-mark \
	sieve/tests/actionExtensions/testm/ueatest-denotify2 \
	sieve/tests/actionExtensions/testm/ueatest-flag5 \
	sieve/tests/actionExtensions/testm/ueatest-notify2 \
	sieve/tests/actionExtensions/testm/ueatest-notify \
	sieve/tests/actionExtensions/testm/ueatest-flag1 \
	sieve/tests/actionExtensions/testm/ueatest-flag3 \
	sieve/tests/actionExtensions/testm/ueatest-unmark \
	sieve/tests/actionExtensions/uberExtensionActionScript.key \
	sieve/tests/actionExtensions/serverm \
	sieve/tests/actionExtensions/serverm/ueamail-flag4 \
	sieve/tests/actionExtensions/serverm/ueamail-denotify \
	sieve/tests/actionExtensions/serverm/ueamail-mark \
	sieve/tests/actionExtensions/serverm/ueamail-denotify2 \
	sieve/tests/actionExtensions/serverm/ueamail-flag2 \
	sieve/tests/actionExtensions/serverm/ueamail-unmark \
	sieve/tests/actionExtensions/serverm/ueamail-reject \
	sieve/tests/actionExtensions/serverm/ueamail-flag3 \
	sieve/tests/actionExtensions/serverm/ueamail-fileinto \
	sieve/tests/actionExtensions/serverm/ueamail-flag1 \
	sieve/tests/actionExtensions/serverm/ueamail-notify \
	sieve/tests/actionExtensions/serverm/ueamail-flag5 \
	sieve/tests/actionExtensions/serverm/ueamail-notify2 \
	sieve/tests/actionExtensions/serverm/ueamail-vacation \
	timsieved/TODO

TEXINFO_TEX = com_err/et/texinfo.tex
dist_noinst_SCRIPTS = \
	com_err/et/compile_et.sh \
	com_err/et/config_script \
	imap/promdatagen \
	lib/mkchartable.pl \
	lib/test/run \
	perl/sieve/scripts/installsieve.pl \
	perl/sieve/scripts/sieveshell.pl \
	tools/arbitronsort.pl \
	tools/compile_st.pl \
	tools/config2header \
	tools/config2rst \
	tools/config2sample \
	tools/fixsearchpath.pl \
	tools/git-version.sh \
	tools/jenkins-build.sh \
	tools/masssievec \
	tools/mkimap \
	tools/mknewsgroups \
	tools/perl2rst \
	tools/rehash \
	tools/translatesieve
noinst_MAN = \
	com_err/et/com_err.3 \
	com_err/et/compile_et.1
noinst_TEXINFOS = com_err/et/com_err.texinfo

pkgconfigdir = $(libdir)/pkgconfig
pkgconfig_DATA = libcyrus_min.pc libcyrus.pc libcyrus_sieve.pc libcyrus_imap.pc

com_err_et_libcyrus_com_err_la_SOURCES = \
	com_err/et/com_err.c \
	com_err/et/com_err.h \
	com_err/et/error_message.c \
	com_err/et/error_table.h \
	com_err/et/et_name.c \
	com_err/et/init_et.c \
	com_err/et/internal.h \
	com_err/et/mit-sipb-copyright.h
com_err_et_libcyrus_com_err_la_CFLAGS = $(AM_CFLAGS) $(CFLAG_VISIBILITY)

com_err/et/compile_et: com_err/et/compile_et.sh com_err/et/config_script \
	config.h
	@${top_srcdir}/com_err/et/config_script ${top_srcdir}/com_err/et/compile_et.sh ${AWK} ${SED} > $@
	@chmod 755 $@

# ---- Libraries ----

# SIEVE is the libraries that sieve-using components need to link with
#
# This is empty if sieve is not enabled, so it can be used unconditionally
# elsewhere.

if SIEVE
LD_SIEVE_ADD = sieve/libcyrus_sieve.la $(LD_BASIC_ADD)
else
LD_SIEVE_ADD =
endif

# BASIC is the libraries that every Cyrus program (except master) will
# need to link with.
#
# Note that several places in the code use -lcrypto, e.g. for SHA1 or
# MD5 algorithms, without needing SSL.  Currently we have no way of
# minimally linking such code.
LD_BASIC_ADD = lib/libcyrus.la lib/libcyrus_min.la ${LIBS} \
	${LIB_SASL} $(SSL_LIBS) $(GCOV_LIBS)

# UTILITY is the libraries that utility programs which use Cyrus'
# mailbox and message handling code need to link with.

LD_UTILITY_ADD = imap/libcyrus_imap.la $(LD_BASIC_ADD) $(LD_SIEVE_ADD) $(COM_ERR_LIBS)

# SERVER is the libraries that network-facing servers need to link with
#
# Note that the code is horribly intertwingled e.g. in imap/global.c
# so that even utilities which never open a socket need to link against
# the SASL library.
LD_SERVER_ADD = $(LD_UTILITY_ADD) $(LIB_WRAP)

# ----

if USE_LIBCHARDET
AM_LDFLAGS += $(LIBCHARDET_LIBS)
AM_CPPFLAGS += $(LIBCHARDET_CFLAGS)
LD_SERVER_ADD += $(LIBCHARDET_LIBS)
endif

if USE_JANSSON
AM_LDFLAGS += $(JANSSON_LIBS)
AM_CPPFLAGS += $(JANSSON_CFLAGS)
LD_SERVER_ADD += $(JANSSON_LIBS)
endif

if CUNIT

CUNIT_PROJECT = cunit/default.cunit
BUILT_SOURCES += cunit/registers.h $(CUNIT_PROJECT)
CLEANFILES += cunit/registers.h $(CUNIT_PROJECT)
check_PROGRAMS += cunit/unit

cunit_FRAMEWORK = \
	cunit/unit.c \
	cunit/cyrunit.h \
	cunit/syslog.c \
	cunit/cunit-syslog.h \
	cunit/timeout.c \
	cunit/timeout.h \
	cunit/timezones.c \
	cunit/timezones.h \
	cunit/timeofday.c \
	cunit/timeofday.h

cunit_TESTS = \
	cunit/aaa-db.testc \
	cunit/annotate.testc \
	cunit/backend.testc \
	cunit/binhex.testc \
	cunit/bitvector.testc \
	cunit/buf.testc \
	cunit/byteorder.testc \
	cunit/charset.testc \
	cunit/command.testc \
	cunit/conversations.testc \
	cunit/cyr_qsort_r.testc \
	cunit/crc32.testc \
	cunit/dlist.testc \
	cunit/duplicate.testc \
	cunit/getxstring.testc \
	cunit/glob.testc \
	cunit/guid.testc \
	cunit/hash.testc \
	cunit/hashset.testc \
	cunit/imapurl.testc \
	cunit/imparse.testc \
	cunit/libconfig.testc \
	cunit/mboxname.testc \
	cunit/md5.testc \
	cunit/message.testc \
	cunit/msgid.testc \
	cunit/parseaddr.testc \
	cunit/parse.testc \
	cunit/procinfo.testc \
	cunit/prot.testc \
	cunit/ptrarray.testc \
	cunit/quota.testc \
	cunit/rfc822tok.testc \
	cunit/search_expr.testc \
	cunit/seqset.testc

if SIEVE
cunit_TESTS += cunit/sieve.testc
endif

cunit_TESTS += \
	cunit/spool.testc \
	cunit/squat.testc \
	cunit/strarray.testc \
	cunit/strconcat.testc \
	cunit/times.testc \
	cunit/tok.testc \
	cunit/vparse.testc \
	cunit/dynarray.testc

cunit_unit_SOURCES = $(cunit_FRAMEWORK) $(cunit_TESTS) \
		imap/mutex_fake.c imap/spool.c
cunit_unit_LDADD = $(LD_SIEVE_ADD) $(LD_UTILITY_ADD) -lcunit

CUNIT_PL = $(top_srcdir)/cunit/cunit.pl --project $(CUNIT_PROJECT)



# don't discard the temporary source file if building with coverage
if HAVE_COVERAGE
    CUNIT_RM = true
else
    CUNIT_RM = $(RM)
endif

.testc.o:
	$(AM_V_at)$(CUNIT_PL) --generate-wrapper $<
	$(AM_V_CC)$(COMPILE) -c -o $@ $<-cunit.c
	$(AM_V_at)$(CUNIT_RM) $<-cunit.c

$(CUNIT_PROJECT):
	$(AM_V_at)$(RM) $@
	$(AM_V_GEN)$(CUNIT_PL) --add-sources $(addprefix $(top_srcdir)/,$(cunit_TESTS))

cunit/registers.h: $(CUNIT_PROJECT)
	$(AM_V_GEN)$(CUNIT_PL) --generate-register-function $@

# To run under Valgrind, do: make VG=1 check
VALGRIND = libtool --mode=execute valgrind --tool=memcheck --leak-check=full --suppressions=vg.supp

check-local:
	@echo "Running unit tests"
	@vg= ; \
		test -z "$$VG" || vg="$(VALGRIND)" ; \
		f="-v" ; \
		test "x$$CUFORMAT" = xjunit && f="-x" ; \
		cd cunit ; \
		$$vg ./unit $$f ; \
		retval=$$? ; \
		if [ "x$$CUFORMAT" = xjunit ] ; then \
			$(RM) -rf reports ; mkdir reports ; ./cunit-to-junit.pl ; \
		fi ; \
		exit $$retval

# Run every test individually, as if you had run them one at a time as
# `make check-suitename:testname` manually.  Mainly useful for detecting
# abstraction failures within our testing infrastructure -- if tests
# succeed with `make check` but fail with `make check-discrete`, or
# vice-versa, some state is leaking between tests!
#
# This assumes your sh supports arithmetic and process substitutions.
# Sorry <3
check-discrete: cunit/unit
	@echo "Running unit tests, one at a time"
	@vg= ; \
		test -z "$$VG" || vg="$(VALGRIND)" ; \
		cd cunit ; \
		fails=0 ; \
		tests=0 ; \
		while read t ; do \
			tests=$$(($$tests + 1)) ; \
			if $$vg ./unit -v $$t >/dev/null 2>/dev/null ; then \
				echo "[  OK  ] $$t" ; \
			else \
				fails=$$(($$fails + 1)) ; \
				echo "[FAILED] $$t" ; \
			fi ; \
		done < <( ./unit -l ) ; \
		echo "$$fails/$$tests tests failed" ; \
		exit $$fails

check-%: cunit/unit
	@echo "Running unit tests for $*"
	@vg= ; \
		test -z "$$VG" || vg="$(VALGRIND)" ; \
		cd cunit ; \
		$$vg ./unit -v $* ; \
		retval=$$? ; \
		exit $$retval

endif

includedir=@includedir@/cyrus

include_HEADERS = \
	lib/acl.h \
	lib/arrayu64.h \
	lib/assert.h \
	lib/auth.h \
	lib/auth_pts.h \
	lib/bitvector.h \
	lib/bloom.h \
	lib/bsearch.h \
	lib/bufarray.h \
	lib/charset.h \
	lib/chartable.h \
	lib/command.h \
	lib/crc32.h \
	lib/cyr_lock.h \
	lib/cyr_qsort_r.h \
	lib/cyrusdb.h \
	lib/dynarray.h \
	lib/glob.h \
	lib/gmtoff.h \
	lib/hash.h \
	lib/hashset.h \
	lib/hashu64.h \
	lib/imapurl.h \
	lib/imclient.h \
	lib/imparse.h \
	lib/iostat.h \
	lib/iptostring.h \
	lib/libcyr_cfg.h \
	lib/lsort.h \
	lib/map.h \
	lib/mappedfile.h \
	lib/mkgmtime.h \
	lib/mpool.h \
	lib/murmurhash2.h \
	lib/nonblock.h \
	lib/parseaddr.h \
	lib/procinfo.h \
	lib/retry.h \
	lib/rfc822tok.h \
	lib/signals.h \
	lib/sqldb.h \
	lib/strarray.h \
	lib/strhash.h \
	lib/stristr.h \
	lib/times.h \
	lib/tok.h \
	lib/vparse.h \
	lib/wildmat.h \
	lib/xmalloc.h

nodist_include_HEADERS = \
	lib/imapopts.h

nobase_include_HEADERS = sieve/sieve_interface.h
nobase_nodist_include_HEADERS = sieve/sieve_err.h

noinst_HEADERS += \
	lib/byteorder.h \
	lib/gai.h \
	lib/libconfig.h \
	lib/md5.h \
	lib/prot.h \
	lib/ptrarray.h \
	lib/util.h \
	lib/xsha1.h \
	lib/xstrlcat.h \
	lib/xstrlcpy.h \
	lib/xstrnchr.h

backup_libcyrus_backup_la_SOURCES = \
    lib/gzuncat.c \
    lib/gzuncat.h \
    backup/lcb.c \
    backup/lcb_append.c \
    backup/lcb_backupdb.c \
    backup/lcb_compact.c \
    backup/lcb_indexr.c \
    backup/lcb_indexw.c \
    backup/lcb_internal.c \
    backup/lcb_internal.h \
    backup/lcb_partlist.c \
    backup/lcb_read.c \
    backup/lcb_sqlconsts.c \
    backup/lcb_sqlconsts.h \
    backup/lcb_verify.c
backup_libcyrus_backup_la_LIBADD = $(LD_BASIC_ADD)

backup_backupd_SOURCES = \
    imap/mutex_fake.c \
    imap/sync_support.c \
    imap/sync_support.h \
    master/service.c \
    backup/backupd.c
backup_backupd_LDADD = backup/libcyrus_backup.la $(LD_SIEVE_ADD) $(LD_SERVER_ADD)

backup_ctl_backups_SOURCES = \
    imap/mutex_fake.c \
    imap/sync_support.c \
    imap/sync_support.h \
    backup/ctl_backups.c
backup_ctl_backups_LDADD = backup/libcyrus_backup.la $(LD_SIEVE_ADD) $(LD_UTILITY_ADD)

backup_cyr_backup_SOURCES = \
    imap/json_support.h \
    imap/mutex_fake.c \
    backup/cyr_backup.c
backup_cyr_backup_LDADD = backup/libcyrus_backup.la $(LD_UTILITY_ADD)

backup_restore_SOURCES = \
    imap/mutex_fake.c \
    imap/sync_support.c \
    imap/sync_support.h \
    backup/restore.c
backup_restore_LDADD = backup/libcyrus_backup.la $(LD_SIEVE_ADD) $(LD_UTILITY_ADD)

imap_arbitron_SOURCES = imap/arbitron.c imap/cli_fatal.c imap/mutex_fake.c
imap_arbitron_LDADD = $(LD_UTILITY_ADD)

imap_chk_cyrus_SOURCES = imap/chk_cyrus.c imap/cli_fatal.c imap/mutex_fake.c
imap_chk_cyrus_LDADD = $(LD_UTILITY_ADD)

imap_ctl_conversationsdb_SOURCES = imap/ctl_conversationsdb.c imap/mutex_fake.c
imap_ctl_conversationsdb_LDADD = $(LD_UTILITY_ADD)

imap_ctl_cyrusdb_SOURCES = imap/cli_fatal.c imap/ctl_cyrusdb.c imap/mutex_fake.c
imap_ctl_cyrusdb_LDADD = $(LD_UTILITY_ADD)

imap_ctl_deliver_SOURCES = imap/cli_fatal.c imap/ctl_deliver.c imap/mutex_fake.c
imap_ctl_deliver_LDADD = $(LD_UTILITY_ADD)

imap_ctl_mboxlist_SOURCES = imap/cli_fatal.c imap/ctl_mboxlist.c imap/mutex_fake.c
imap_ctl_mboxlist_LDADD = $(LD_UTILITY_ADD)

imap_ctl_zoneinfo_SOURCES = imap/cli_fatal.c imap/ctl_zoneinfo.c imap/mutex_fake.c imap/zoneinfo_db.c imap/xml_support.c
imap_ctl_zoneinfo_LDADD = $(LD_UTILITY_ADD)

imap_cvt_cyrusdb_SOURCES = imap/cli_fatal.c imap/cvt_cyrusdb.c imap/mutex_fake.c
imap_cvt_cyrusdb_LDADD = $(LD_UTILITY_ADD)

imap_cyrdump_SOURCES = imap/cli_fatal.c imap/cyrdump.c imap/mutex_fake.c
imap_cyrdump_LDADD = $(LD_UTILITY_ADD)

imap_cyr_dbtool_SOURCES = imap/cli_fatal.c imap/cyr_dbtool.c imap/mutex_fake.c
imap_cyr_dbtool_LDADD = $(LD_UTILITY_ADD)

imap_cyr_deny_SOURCES = imap/cli_fatal.c imap/cyr_deny.c imap/mutex_fake.c
imap_cyr_deny_LDADD = $(LD_UTILITY_ADD)

imap_cyr_df_SOURCES = imap/cli_fatal.c imap/cyr_df.c imap/mutex_fake.c
imap_cyr_df_LDADD = $(LD_UTILITY_ADD)

imap_cyr_expire_SOURCES = imap/cli_fatal.c imap/cyr_expire.c imap/mutex_fake.c
imap_cyr_expire_LDADD = $(LD_UTILITY_ADD)

imap_cyr_info_SOURCES = imap/cli_fatal.c imap/cyr_info.c imap/mutex_fake.c master/masterconf.c
imap_cyr_info_LDADD = $(LD_UTILITY_ADD)

imap_cyr_buildinfo_SOURCES = imap/cli_fatal.c imap/cyr_buildinfo.c imap/mutex_fake.c master/masterconf.c
imap_cyr_buildinfo_LDADD = $(LD_UTILITY_ADD)

imap_cyr_sequence_SOURCES = imap/cli_fatal.c imap/cyr_sequence.c imap/mutex_fake.c
imap_cyr_sequence_LDADD = $(LD_UTILITY_ADD)

imap_cyr_synclog_SOURCES = imap/cli_fatal.c imap/cyr_synclog.c imap/mutex_fake.c
imap_cyr_synclog_LDADD = $(LD_UTILITY_ADD)

imap_cyr_userseen_SOURCES = imap/cli_fatal.c imap/cyr_userseen.c imap/mutex_fake.c
imap_cyr_userseen_LDADD = $(LD_UTILITY_ADD)

imap_cyr_virusscan_SOURCES = imap/cli_fatal.c imap/cyr_virusscan.c imap/mutex_fake.c
imap_cyr_virusscan_CFLAGS = $(AM_CFLAGS) $(CLAMAV_CFLAGS) $(CFLAG_VISIBILITY)
imap_cyr_virusscan_LDADD = $(LD_UTILITY_ADD) $(CLAMAV_LIBS)

imap_deliver_SOURCES = \
	imap/deliver.c \
	imap/lmtpengine.c \
	imap/mutex_fake.c \
	imap/proxy.c \
	imap/spool.c

nodist_imap_deliver_SOURCES = imap/lmtp_err.c

imap_deliver_LDADD = $(LD_UTILITY_ADD)

imap_fetchnews_SOURCES = imap/cli_fatal.c imap/fetchnews.c imap/mutex_fake.c
imap_fetchnews_LDADD = $(LD_UTILITY_ADD)

imap_fud_SOURCES = imap/fud.c imap/mutex_fake.c master/service.c
imap_fud_LDADD = $(LD_SERVER_ADD)

imap_idled_SOURCES = imap/idled.c imap/mutex_fake.c
imap_idled_LDADD = $(LD_UTILITY_ADD)

imap_calalarmd_SOURCES = imap/calalarmd.c imap/mutex_fake.c
imap_calalarmd_LDADD = $(LD_SERVER_ADD)

imap_imapd_SOURCES = \
	imap/imap_proxy.c \
	imap/imap_proxy.h \
	imap/imapd.c \
	imap/imapd.h \
	imap/mutex_fake.c \
	imap/proxy.c \
	imap/proxy.h \
	imap/sync_support.c \
	imap/sync_support.h \
	master/service.c

if AUTOCREATE
imap_imapd_SOURCES += \
	imap/autocreate.h \
	imap/autocreate.c
endif

imap_imapd_LDADD = $(LD_SIEVE_ADD) $(LD_SERVER_ADD)

imap_ipurge_SOURCES = imap/cli_fatal.c imap/ipurge.c imap/mutex_fake.c
imap_ipurge_LDADD = $(LD_UTILITY_ADD)

nodist_imap_libcyrus_imap_la_SOURCES = \
	imap/http_err.c \
	imap/http_err.h \
	imap/imap_err.c \
	imap/imap_err.h \
	imap/mupdate_err.c \
	imap/mupdate_err.h \
	imap/promdata.c \
	imap/promdata.h

imap_libcyrus_imap_la_LIBADD = \
    $(COM_ERR_LIBS) \
    $(LIB_UUID) \
    $(GCOV_LIBS) \
    lib/libcyrus_min.la \
    lib/libcyrus.la

imap_libcyrus_imap_la_CFLAGS = $(AM_CFLAGS) $(CFLAG_VISIBILITY)
imap_libcyrus_imap_la_CXXFLAGS = $(AM_CXXFLAGS)

imap_libcyrus_imap_la_SOURCES = \
	imap/annotate.c \
	imap/annotate.h \
	imap/append.c \
	imap/append.h \
	imap/backend.c \
	imap/backend.h \
	imap/conversations.c \
	imap/conversations.h \
	imap/convert_code.c \
	imap/convert_code.h \
	imap/dlist.c \
	imap/dlist.h \
	imap/duplicate.c \
	imap/duplicate.h \
	imap/global.c \
	imap/global.h \
	imap/http_client.c \
	imap/http_client.h \
	imap/idle.c \
	imap/idle.h \
	imap/idlemsg.c \
	imap/idlemsg.h \
	imap/imapparse.c \
	imap/imapparse.h \
	imap/index.c \
	imap/index.h \
	imap/json_support.h \
	imap/mailbox.c \
	imap/mailbox.h \
	imap/mbdump.c \
	imap/mbdump.h \
	imap/mboxkey.c \
	imap/mboxkey.h \
	imap/mboxlist.c \
	imap/mboxlist.h \
	imap/mboxevent.c \
	imap/mboxevent.h \
	imap/mboxname.c \
	imap/mboxname.h \
	imap/message_guid.c \
	imap/message_guid.h \
	imap/message.c \
	imap/message.h \
	imap/message_priv.h \
	imap/msgrecord.c \
	imap/msgrecord.h \
	imap/mupdate-client.c \
	imap/mupdate-client.h \
	imap/mutex.h \
	imap/notify.c \
	imap/notify.h \
	imap/partlist.c \
	imap/partlist.h \
	imap/proc.c \
	imap/proc.h \
	imap/prometheus.c \
	imap/prometheus.h \
	imap/protocol.h \
	imap/quota_db.c \
	imap/rfc822_header.c \
	imap/rfc822_header.h \
	imap/mailbox_header_cache.h \
	imap/saslclient.c \
	imap/saslclient.h \
	imap/saslserver.c \
	imap/search_engines.c \
	imap/search_engines.h \
	imap/search_expr.c \
	imap/search_expr.h \
	imap/search_query.c \
	imap/search_query.h \
	imap/search_part.h \
	imap/search_sort.h \
	imap/seen.h \
	imap/seen_db.c \
	imap/sequence.c \
	imap/sequence.h \
	imap/setproctitle.c \
        imap/sievedir.c \
	imap/sievedir.h \
	imap/spool.c \
	imap/spool.h \
	imap/statuscache.h \
	imap/statuscache_db.c \
	imap/sync_log.c \
	imap/sync_log.h \
	imap/telemetry.c \
	imap/telemetry.h \
	imap/tls.c \
	imap/tls.h \
	imap/tls_th-lock.c \
	imap/tls_th-lock.h \
	imap/user.c \
	imap/user.h \
	imap/userdeny_db.c \
	imap/userdeny.h \
	imap/version.c \
	imap/version.h \
	imap/xstats.c \
	imap/xstats.h \
	imap/xstats_metrics.h

if OBJECTSTORE
imap_libcyrus_imap_la_SOURCES += \
    imap/objectstore_db.c \
    imap/objectstore_db.h \
    imap/objectstore.h
if WITH_OPENIO
imap_libcyrus_imap_la_SOURCES += imap/objectstore_openio.c
else
if WITH_CARINGO
imap_libcyrus_imap_la_SOURCES += imap/objectstore_caringo.c
else
if WITH_OBJSTR_DUMMY
imap_libcyrus_imap_la_SOURCES += imap/objectstore_dummy.c
endif
endif
endif
endif

if USE_SQUAT
imap_libcyrus_imap_la_SOURCES += \
	imap/search_squat.c \
	imap/squat.c \
	imap/squat.h \
	imap/squat_build.c \
	imap/squat_internal.c \
	imap/squat_internal.h
endif

if HTTPD
imap_libcyrus_imap_la_SOURCES += \
	imap/caldav_alarm.c \
	imap/caldav_alarm.h \
	imap/caldav_db.c \
	imap/caldav_db.h \
	imap/carddav_db.c \
	imap/carddav_db.h \
	imap/dav_db.c \
	imap/dav_db.h \
	imap/dav_util.c \
	imap/dav_util.h \
	imap/ical_support.c \
	imap/ical_support.h \
	imap/icu_wrap.h \
	imap/icu_wrap.cpp \
	imap/vcard_support.c \
	imap/vcard_support.h \
	imap/webdav_db.c \
	imap/webdav_db.h

endif # HTTPD

if JMAP
imap_libcyrus_imap_la_SOURCES += \
	imap/smtpclient.c \
	imap/smtpclient.h
endif

if USE_XAPIAN
imap_libcyrus_imap_la_SOURCES += \
	imap/search_xapian.c \
	imap/xapian_wrap.h \
	imap/xapian_wrap.cpp
imap_libcyrus_imap_la_LIBADD += $(XAPIAN_LIBS)
imap_libcyrus_imap_la_CXXFLAGS += $(XAPIAN_CXXFLAGS)

if HAVE_CLD2
imap_libcyrus_imap_la_LIBADD += $(CLD2_LIBS)
imap_libcyrus_imap_la_CXXFLAGS += $(CLD2_CFLAGS)
endif

endif

imap_lmtpd_SOURCES = \
	imap/lmtpd.c \
	imap/lmtpd.h \
	imap/lmtpengine.c \
	imap/lmtpengine.h \
	imap/mutex_fake.c \
	imap/proxy.c \
	imap/spool.c \
	imap/sync_support.c \
	imap/sync_support.h \
	master/service.c

nodist_imap_lmtpd_SOURCES = imap/lmtp_err.c

if AUTOCREATE
imap_lmtpd_SOURCES += \
	imap/autocreate.c \
	imap/autocreate.h
endif # AUTOCREATE

if SIEVE
imap_lmtpd_SOURCES += imap/lmtp_sieve.c imap/lmtp_sieve.h imap/smtpclient.c

if JMAP
imap_lmtpd_SOURCES += \
	imap/jmap_util.c imap/jmap_mail_query.c imap/jmap_mail_query_parse.c
endif # JMAP

endif # SIEVE

imap_lmtpd_LDADD = $(LD_SIEVE_ADD) $(LD_SERVER_ADD)

imap_mbexamine_SOURCES = imap/cli_fatal.c imap/mbexamine.c imap/mutex_fake.c
imap_mbexamine_LDADD = $(LD_UTILITY_ADD)

imap_mbpath_SOURCES = imap/cli_fatal.c imap/mbpath.c imap/mutex_fake.c
imap_mbpath_LDADD = $(LD_UTILITY_ADD)

imap_mbtool_SOURCES = imap/cli_fatal.c imap/mbtool.c imap/mutex_fake.c
imap_mbtool_LDADD = $(LD_UTILITY_ADD)

imap_message_test_SOURCES = imap/message_test.c imap/mutex_fake.c
imap_message_test_LDADD = $(LD_UTILITY_ADD)

imap_mupdate_SOURCES = \
	imap/mupdate.c \
	imap/mupdate.h \
	imap/mupdate-slave.c \
	imap/mutex_pthread.c \
	imap/tls_th-lock.c \
	master/service-thread.c
imap_mupdate_LDADD = $(LD_SERVER_ADD) -lpthread
imap_mupdate_CFLAGS =  $(AM_CFLAGS) -pthread

nodist_imap_nntpd_SOURCES = imap/nntp_err.c

imap_nntpd_SOURCES = \
	imap/mutex_fake.c \
	imap/nntpd.c \
	imap/proxy.c \
	imap/smtpclient.c \
	imap/smtpclient.h \
	imap/spool.c \
	imap/spool.h \
	imap/sync_support.c \
	imap/sync_support.h \
	master/service.c
imap_nntpd_LDADD = $(LD_SIEVE_ADD) $(LD_SERVER_ADD)

nodist_imap_httpd_SOURCES = \
	imap/http_caldav_js.h \
	imap/http_carddav_js.h \
	imap/tz_err.c \
	imap/tz_err.h

imap_httpd_SOURCES = \
	imap/css3_color.c \
	imap/css3_color.h \
	imap/http_admin.c \
	imap/http_applepush.c \
	imap/http_caldav.c \
	imap/http_caldav.h \
	imap/http_caldav_js.h \
	imap/http_caldav_sched.c \
	imap/http_caldav_sched.h \
	imap/http_carddav.c \
	imap/http_carddav.h \
	imap/http_carddav_js.h \
	imap/http_cgi.c \
	imap/http_dav.c \
	imap/http_dav.h \
	imap/http_dav_sharing.c \
	imap/http_dav_sharing.h \
	imap/http_dblookup.c \
	imap/http_h2.c \
	imap/http_h2.h \
	imap/http_ischedule.c \
	imap/http_prometheus.c \
	imap/http_proxy.c \
	imap/http_proxy.h \
	imap/http_rss.c \
	imap/http_tzdist.c \
	imap/http_webdav.c \
	imap/http_ws.c \
	imap/http_ws.h \
	imap/httpd.c \
	imap/httpd.h \
	imap/jcal.c \
	imap/jcal.h \
	imap/json_support.h \
	imap/mutex_fake.c \
	imap/proxy.c \
	imap/smtpclient.c \
	imap/spool.c \
	imap/sync_support.c \
        imap/sync_support.h \
	imap/xcal.c \
	imap/xcal.h \
	imap/xml_support.c \
	imap/xml_support.h \
	imap/zoneinfo_db.c \
	imap/zoneinfo_db.h \
	master/masterconf.c \
	master/service.c

imap_httpd_LDADD = $(LD_SIEVE_ADD) $(LD_SERVER_ADD)

if JMAP
BUILT_SOURCES += \
	imap/jmap_err.c \
	imap/jmap_err.h

imap_httpd_SOURCES += \
	imap/http_jmap.c \
	imap/http_jmap.h \
	imap/jmap_api.c \
	imap/jmap_api.h \
	imap/jmap_backup.c \
	imap/jmap_calendar.c \
	imap/jmap_contact.c \
	imap/jmap_core.c \
	imap/jmap_ical.c \
	imap/jmap_ical.h \
	imap/jmap_mail.c \
	imap/jmap_mail.h \
	imap/jmap_mail_query.c \
	imap/jmap_mail_query.h \
	imap/jmap_mail_query_parse.c \
	imap/jmap_mail_query_parse.h \
	imap/jmap_mail_submission.c \
	imap/jmap_mailbox.c \
	imap/jmap_mdn.c \
	imap/jmap_notes.c \
	imap/jmap_util.c \
	imap/jmap_util.h \
	imap/jmap_vacation.c

if SIEVE
imap_httpd_SOURCES += \
	imap/jmap_sieve.c
endif

nodist_imap_httpd_SOURCES += \
	imap/jmap_err.c \
	imap/jmap_err.h

imap_libcyrus_imap_la_SOURCES += \
	imap/jmap_util.c \
	imap/jmap_util.h \
	imap/json_support.c \
	imap/json_support.h

imap_httpd_LDADD += $(LD_SIEVE_ADD)

if CUNIT

cunit_TESTS += cunit/jmap_util.testc

endif # CUNIT

endif # JMAP

imap_pop3d_SOURCES = \
	imap/mutex_fake.c \
	imap/pop3d.c \
	imap/proxy.c \
	imap/sync_support.c \
	imap/sync_support.h \
	master/service.c

if AUTOCREATE
imap_pop3d_SOURCES += \
	imap/autocreate.c \
	imap/autocreate.h
endif # AUTOCREATE

imap_pop3d_LDADD = $(LD_SIEVE_ADD) $(LD_SERVER_ADD)

PROMDATAGEN = $(abs_top_srcdir)/imap/promdatagen

imap/promdata.c: imap/promdata.p $(PROMDATAGEN)
	$(AM_V_GEN)$(PROMDATAGEN) -c $@.NEW $< && mv $@.NEW $@

imap/promdata.h: imap/promdata.p $(PROMDATAGEN)
	$(AM_V_GEN)$(PROMDATAGEN) -h $@.NEW $< && mv $@.NEW $@

imap_promstatsd_SOURCES = imap/promstatsd.c imap/mutex_fake.c
imap_promstatsd_LDADD = $(LD_UTILITY_ADD)

imap_quota_SOURCES = imap/cli_fatal.c imap/mutex_fake.c imap/quota.c imap/quota.h
imap_quota_LDADD = $(LD_UTILITY_ADD)

imap_reconstruct_SOURCES = imap/cli_fatal.c imap/mutex_fake.c imap/reconstruct.c
imap_reconstruct_LDADD = $(LD_UTILITY_ADD)

imap_dav_reconstruct_SOURCES = imap/cli_fatal.c imap/mutex_fake.c imap/dav_reconstruct.c
imap_dav_reconstruct_LDADD = $(LD_UTILITY_ADD)

imap_ical_apply_patch_SOURCES = imap/cli_fatal.c imap/mutex_fake.c imap/ical_apply_patch.c
imap_ical_apply_patch_LDADD = $(LD_UTILITY_ADD)

imap_search_test_SOURCES = imap/search_test.c imap/mutex_fake.c
imap_search_test_LDADD = $(LD_UTILITY_ADD)

imap_smmapd_SOURCES = imap/mutex_fake.c imap/proxy.c imap/smmapd.c master/service.c
imap_smmapd_LDADD = $(LD_SERVER_ADD)

imap_squatter_SOURCES = imap/cli_fatal.c imap/mutex_fake.c imap/squatter.c
imap_squatter_LDADD = $(LD_UTILITY_ADD)

imap_squat_dump_SOURCES = imap/cli_fatal.c imap/mutex_fake.c imap/squat_dump.c
imap_squat_dump_LDADD = $(LD_UTILITY_ADD)

imap_sync_client_SOURCES = imap/mutex_fake.c imap/sync_client.c imap/sync_support.c imap/sync_support.h
imap_sync_client_LDADD = $(LD_SIEVE_ADD) $(LD_UTILITY_ADD)

imap_sync_reset_SOURCES = imap/mutex_fake.c imap/sync_reset.c imap/sync_support.c imap/sync_support.h
imap_sync_reset_LDADD = $(LD_SIEVE_ADD) $(LD_UTILITY_ADD)

imap_sync_server_SOURCES = imap/mutex_fake.c imap/sync_server.c imap/sync_support.c imap/sync_support.h master/service.c
imap_sync_server_LDADD = $(LD_SIEVE_ADD) $(LD_SERVER_ADD)

imap_tls_prune_SOURCES = imap/cli_fatal.c imap/mutex_fake.c imap/tls_prune.c
imap_tls_prune_LDADD = $(LD_UTILITY_ADD)

imap_unexpunge_SOURCES = imap/cli_fatal.c imap/mutex_fake.c imap/unexpunge.c
imap_unexpunge_LDADD = $(LD_UTILITY_ADD)

# $(COMPILE_ET) creates its output files in the directory it's run from,
# so do a tricky directory change
%_err.h %_err.c: %_err.et $(COMPILE_ET_DEP)
	$(AM_V_GEN)(cd $(@D) && $(COMPILE_ET) $(realpath $<))

# xxd cannot have path details in its input filename, otherwise it junks up
# the variable names in the output file.  so do a tricky directory change.
# the /dev/null redirection on cd is to prevent shell environments with
# CDPATH echoing the path change on stdout and consequently into the .h file
%_js.h: %.js
	$(AM_V_GEN)(cd $(<D) > /dev/null && xxd -i $(<F)) > $@.NEW && mv $@.NEW $@

if MAINTAINER_MODE
imap/rfc822_header.c: imap/rfc822_header.st
	$(AM_V_GEN)${top_srcdir}/tools/compile_st.pl -c $< > $@.NEW && mv $@.NEW $@

imap/rfc822_header.h: imap/rfc822_header.st
	$(AM_V_GEN)${top_srcdir}/tools/compile_st.pl -h $< > $@.NEW && mv $@.NEW $@

lib/htmlchar.c: lib/htmlchar.st
	$(AM_V_GEN)${top_srcdir}/tools/compile_st.pl -c $< > $@.NEW && mv $@.NEW $@

lib/htmlchar.h: lib/htmlchar.st
	$(AM_V_GEN)${top_srcdir}/tools/compile_st.pl -h $< > $@.NEW && mv $@.NEW $@

imap/mailbox_header_cache.h: imap/mailbox_header_cache.gperf
	$(AM_V_GEN)gperf --ignore-case --initializer-suffix=,0 -p -j1 -i 1 -g -o -t -H mailbox_header_cache_hash -N mailbox_header_cache_lookup -k1,3,$$ $< > $@.NEW && mv $@.NEW $@
endif

imtest_imtest_SOURCES = imtest/imtest.c
imtest_imtest_LDADD = $(LD_BASIC_ADD)
imtest_imtest_CFLAGS = $(AM_CFLAGS) $(CFLAG_VISIBILITY)

nodist_lib_libcyrus_la_SOURCES = lib/chartable.c
lib_libcyrus_la_SOURCES = \
	lib/acl.c \
	lib/acl_afs.c \
	lib/auth.c \
	lib/auth_krb.c \
	lib/auth_krb5.c \
	lib/auth_pts.c \
	lib/auth_unix.c \
	lib/bitvector.c \
	lib/bloom.c \
	lib/bsearch.c \
	lib/charset.c \
	lib/command.c \
	lib/cyr_qsort_r.c \
	lib/cyrusdb.c \
	lib/cyrusdb_flat.c \
	lib/cyrusdb_quotalegacy.c \
	lib/cyrusdb_skiplist.c \
	lib/cyrusdb_twoskip.c \
	lib/glob.c \
	lib/htmlchar.c \
	lib/htmlchar.h \
	lib/imapurl.c \
	lib/imclient.c \
	lib/imparse.c \
	lib/iostat.c \
	lib/iptostring.c \
	lib/libcyr_cfg.c \
	lib/lsort.c \
	lib/mappedfile.c \
	lib/murmurhash.c \
	lib/mkgmtime.c \
	lib/parseaddr.c \
	lib/procinfo.c \
	lib/prot.c \
	lib/ptrarray.c \
	lib/rfc822tok.c \
	lib/signals.c \
	lib/stristr.c \
	lib/times.c \
	lib/tok.c \
	lib/wildmat.c
if USE_CYRUSDB_SQL
lib_libcyrus_la_SOURCES += lib/cyrusdb_sql.c
endif
if USE_SQLITE
lib_libcyrus_la_SOURCES += lib/sqldb.c
endif
if GMTOFF_TM
lib_libcyrus_la_SOURCES += lib/gmtoff_tm.c
else
lib_libcyrus_la_SOURCES += lib/gmtoff_gmtime.c
endif
if NONBLOCK_FCNTL
lib_libcyrus_la_SOURCES += lib/nonblock_fcntl.c
else
lib_libcyrus_la_SOURCES += lib/nonblock_ioctl.c
endif
lib_libcyrus_la_LIBADD = libcrc32.la ${LIB_SASL} $(SSL_LIBS) $(GCOV_LIBS)
lib_libcyrus_la_CFLAGS = $(AM_CFLAGS) $(CFLAG_VISIBILITY)

if USE_ZEROSKIP
lib_libcyrus_la_SOURCES += lib/cyrusdb_zeroskip.c
lib_libcyrus_la_LIBADD += $(ZEROSKIP_LIBS)
lib_libcyrus_la_CFLAGS += $(ZEROSKIP_CFLAGS)
AM_CPPFLAGS += $(ZEROSKIP_CFLAGS)
endif

noinst_LTLIBRARIES += libcrc32.la
libcrc32_la_SOURCES = lib/crc32.c
libcrc32_la_CFLAGS = -O3 $(AM_CFLAGS) $(CFLAG_VISIBILITY)

nodist_lib_libcyrus_min_la_SOURCES = \
	lib/imapopts.c

lib_libcyrus_min_la_SOURCES = \
	lib/arrayu64.c \
	lib/assert.c \
	lib/bufarray.c \
	lib/byteorder.c \
	lib/dynarray.c \
	lib/hash.c \
	lib/hashset.c \
	lib/hashu64.c \
	lib/libconfig.c \
	lib/mpool.c \
	lib/retry.c \
	lib/strarray.c \
	lib/strhash.c \
	lib/util.c \
	lib/vparse.c \
	lib/xmalloc.c \
	lib/xstrlcat.c \
	lib/xstrlcpy.c \
	lib/xstrnchr.c
if !HAVE_SSL
lib_libcyrus_min_la_SOURCES += lib/xsha1.c
endif
if IPV6_noGETADDRINFO
lib_libcyrus_min_la_SOURCES += lib/getaddrinfo.c
endif
if IPV6_noGETNAMEINFO
lib_libcyrus_min_la_SOURCES += lib/getnameinfo.c
endif
if LOCK_FCNTL
lib_libcyrus_min_la_SOURCES += lib/lock_fcntl.c
else
lib_libcyrus_min_la_SOURCES += lib/lock_flock.c
endif
if MAP_SHARED
lib_libcyrus_min_la_SOURCES += lib/map_shared.c
else
if MAP_STUPIDSHARED
lib_libcyrus_min_la_SOURCES += lib/map_stupidshared.c
else
lib_libcyrus_min_la_SOURCES += lib/map_nommap.c
endif
endif
lib_libcyrus_min_la_LIBADD = $(LTLIBOBJS) $(LIB_UUID) $(GCOV_LIBS) $(LIBCAP_LIBS)
lib_libcyrus_min_la_CFLAGS = $(AM_CFLAGS) $(CFLAG_VISIBILITY)

# n.b. the order of the -m arguments to mkchartable.pl is important,
# in particular ellie believes unifix.txt must be before UnicodeData.txt
lib/chartable.c: lib/mkchartable.pl lib/charset/unifix.txt \
	$(top_srcdir)/lib/charset/*.t \
	lib/charset/UnicodeData.txt lib/charset/aliases.txt
	@echo "### Building chartables..."
	$(AM_V_GEN)perl $(top_srcdir)/lib/mkchartable.pl -m $(top_srcdir)/lib/charset/unifix.txt -m $(top_srcdir)/lib/charset/UnicodeData.txt -a $(top_srcdir)/lib/charset/aliases.txt -o $@ $(top_srcdir)/lib/charset/*.t || (rm -f $@ && exit 1)
	@echo "### Done building chartables."

lib/imapopts.h: lib/imapopts.c

lib/imapopts.c: lib/imapoptions tools/config2header
	$(AM_V_GEN)$(top_srcdir)/tools/config2header CC="$(CC)" $(top_builddir)/lib/imapopts.c $(top_builddir)/lib/imapopts.h < $(top_srcdir)/lib/imapoptions

imap_cvt_xlist_specialuse_SOURCES = imap/mutex_fake.c imap/cvt_xlist_specialuse.c
imap_cvt_xlist_specialuse_LDADD = $(LD_UTILITY_ADD)

@SET_MAKE@

dist_man1_MANS = \
	man/imtest.1 \
	man/installsieve.1 \
	man/httptest.1 \
	man/lmtptest.1 \
	man/mupdatetest.1 \
	man/nntptest.1 \
	man/pop3test.1 \
	man/sieveshell.1 \
	man/sivtest.1 \
	man/smtptest.1

dist_man3_MANS = \
	man/imclient.3

dist_man5_MANS = \
	man/cyrus.conf.5 \
	man/imapd.conf.5 \
	man/krb.equiv.5

dist_man8_MANS = \
	man/arbitron.8 \
	man/backupd.8 \
	man/chk_cyrus.8 \
	man/ctl_backups.8 \
	man/ctl_conversationsdb.8 \
	man/ctl_cyrusdb.8 \
	man/ctl_deliver.8 \
	man/ctl_mboxlist.8 \
	man/cvt_cyrusdb.8 \
	man/cyr_backup.8 \
	man/cyr_buildinfo.8 \
	man/cyr_dbtool.8 \
	man/cyr_deny.8 \
	man/cyr_df.8 \
	man/cyr_expire.8 \
	man/cyr_info.8 \
	man/cyr_synclog.8 \
	man/cyr_virusscan.8 \
	man/deliver.8 \
	man/fud.8 \
	man/idled.8 \
	man/imapd.8 \
	man/ipurge.8 \
	man/lmtpd.8 \
	man/master.8 \
	man/mbexamine.8 \
	man/mbpath.8 \
	man/mbtool.8 \
	man/notifyd.8 \
	man/pop3d.8 \
	man/quota.8 \
	man/reconstruct.8 \
	man/restore.8 \
	man/smmapd.8 \
	man/timsieved.8 \
	man/tls_prune.8 \
	man/unexpunge.8

if SQUATTER
dist_man8_MANS += \
	man/squatter.8
endif # SQUATTER

if NNTPD
dist_man8_MANS += \
	man/fetchnews.8 \
	man/nntpd.8
endif # NNTPD

if HTTPD
dist_man8_MANS += \
	man/ctl_zoneinfo.8 \
	man/httpd.8
endif # HTTPD

if BENCH
check_PROGRAMS += bench/cyrdbbench
bench_cyrdbbench_SOURCES = bench/cyrdbbench.c imap/mutex_fake.c
bench_cyrdbbench_LDADD = $(LD_BASIC_ADD)
endif # BENCH

if REPLICATION
dist_man8_MANS += \
	man/sync_client.8 \
	man/sync_reset.8 \
	man/sync_server.8
endif

master_master_SOURCES = \
	master/master.c \
	master/master.h \
	master/masterconf.c \
	master/masterconf.h \
	master/service.h
master_master_LDADD = lib/libcyrus_min.la $(LIBS) $(GCOV_LIBS) -lm


netnews_remotepurge_SOURCES = \
	netnews/macros.h \
	netnews/readconfig.c \
	netnews/readconfig.h \
	netnews/remotepurge.c
netnews_remotepurge_LDADD = $(LD_BASIC_ADD)

notifyd_notifyd_SOURCES = \
	imap/mutex_fake.c \
	master/service.c \
	notifyd/notify_external.c \
	notifyd/notify_external.h \
	notifyd/notify_log.c \
	notifyd/notify_log.h \
	notifyd/notify_mailto.c \
	notifyd/notify_mailto.h \
	notifyd/notify_null.c \
	notifyd/notify_null.h \
	notifyd/notifyd.c \
	notifyd/notifyd.h
if ZEPHYR
notifyd_notifyd_SOURCES += notifyd/notify_zephyr.c notifyd/notify_zephyr.h
endif
notifyd_notifyd_LDADD = $(LD_SERVER_ADD) $(ZEPHYR_LIBS)

notifyd_notifytest_SOURCES = notifyd/notifytest.c imap/mutex_fake.c
notifyd_notifytest_LDADD = $(LD_BASIC_ADD)

nodist_perl_libcyrus_la_SOURCES = $(nodist_lib_libcyrus_la_SOURCES)
perl_libcyrus_la_SOURCES = $(lib_libcyrus_la_SOURCES)
perl_libcyrus_la_LIBADD = $(lib_libcyrus_la_LIBADD)
nodist_perl_libcyrus_min_la_SOURCES = $(nodist_lib_libcyrus_min_la_SOURCES)
perl_libcyrus_min_la_SOURCES = $(lib_libcyrus_min_la_SOURCES)
perl_libcyrus_min_la_LIBADD = $(lib_libcyrus_min_la_LIBADD)

perl_sieve_lib_libisieve_la_SOURCES = \
	perl/sieve/lib/codes.h \
	perl/sieve/lib/isieve.c \
	perl/sieve/lib/isieve.h \
	perl/sieve/lib/lex.c \
	perl/sieve/lib/lex.h \
	perl/sieve/lib/request.c \
	perl/sieve/lib/request.h

ptclient_ptdump_SOURCES = imap/cli_fatal.c imap/mutex_fake.c ptclient/ptdump.c
ptclient_ptdump_LDADD = $(LD_UTILITY_ADD)
ptclient_ptexpire_SOURCES = imap/cli_fatal.c imap/mutex_fake.c ptclient/ptexpire.c
ptclient_ptexpire_LDADD = $(LD_UTILITY_ADD)

ptclient_ptloader_SOURCES = \
	imap/mutex_fake.c \
	ptclient/ptloader.c \
	ptclient/ptloader.h \
	master/service-thread.c
ptclient_ptloader_LDFLAGS =
ptclient_ptloader_LDADD = $(LD_SERVER_ADD)

if HAVE_LDAP
ptclient_ptloader_SOURCES += ptclient/ldap.c
ptclient_ptloader_LDADD += $(LDAP_LIBS)
ptclient_ptloader_LDFLAGS += $(LDAP_LDFLAGS)
endif

if USE_AFSKRB
ptclient_ptloader_SOURCES += ptclient/afskrb.c
ptclient_ptloader_LDADD += $(AFS_LIBS)
ptclient_ptloader_LDFLAGS += $(AFS_LDFLAGS)
endif

# Each new version of flex seems to generate new sign-comparison
# warnings, while they switch code around between int/yy_size_t.
#
# This is a pain because most of us Cyrus devs build with -Werror.
#
# Instead of continuing to maintain an ever-growing, increasingly
# precarious set of post-hoc fixes (see: the former lex-fix rule),
# let's just ignore sign-comparison warnings from flex-generated
# sources only.
sieve_libcyrus_sieve_lex_la_SOURCES = \
	sieve/addr-lex.l \
	sieve/sieve-lex.l
sieve_libcyrus_sieve_lex_la_LIBADD =
sieve_libcyrus_sieve_lex_la_CFLAGS = $(AM_CFLAGS) $(CFLAG_VISIBILITY) $(NOWARN_SIGN_COMPARE)

nodist_sieve_libcyrus_sieve_la_SOURCES = \
	sieve/sieve_err.c \
	sieve/sieve_err.h
sieve_libcyrus_sieve_la_SOURCES = \
	sieve/bytecode.h \
	sieve/addr.y \
	sieve/bc_emit.c \
	sieve/bc_eval.c \
	sieve/bc_generate.c \
	sieve/bc_parse.c \
	sieve/bc_parse.h \
	sieve/comparator.c \
	sieve/comparator.h \
	sieve/flags.c \
	sieve/flags.h \
	sieve/grammar.c \
	sieve/grammar.h \
	sieve/interp.c \
	sieve/interp.h \
	sieve/message.c \
	sieve/message.h \
	sieve/rebuild.c \
	sieve/script.c \
	sieve/script.h \
	sieve/sieve.y \
	sieve/tree.c \
	sieve/tree.h \
	sieve/variables.c \
	sieve/variables.h \
	sieve/varlist.c \
	sieve/varlist.h

if JMAP
sieve_libcyrus_sieve_la_SOURCES += \
	imap/jmap_mail_query_parse.c \
	imap/jmap_mail_query_parse.h \
	imap/json_support.c \
	imap/json_support.h
endif

sieve_libcyrus_sieve_la_LIBADD = \
    sieve/libcyrus_sieve_lex.la \
    $(COM_ERR_LIBS) \
    lib/libcyrus_min.la \
    lib/libcyrus.la
sieve_libcyrus_sieve_la_CFLAGS = $(AM_CFLAGS) $(CFLAG_VISIBILITY)

sieve_sievec_LDADD = $(LD_SIEVE_ADD)
sieve_sieved_LDADD = $(LD_SIEVE_ADD)

sieve_test_SOURCES = \
    sieve/test.c \
    imap/mutex_fake.c \
    sieve/sieve_interface.h
if JMAP
sieve_test_SOURCES += \
	imap/jmap_util.c imap/jmap_mail_query.c imap/jmap_mail_query_parse.c
endif
sieve_test_LDADD = $(LD_SIEVE_ADD) $(LD_UTILITY_ADD)

sieve_test_mailbox_SOURCES = \
    sieve/test_mailbox.c \
    imap/mutex_fake.c \
    sieve/sieve_interface.h
sieve_test_mailbox_LDADD = $(LD_SIEVE_ADD) $(LD_UTILITY_ADD)

timsieved_timsieved_SOURCES = \
	imap/mutex_fake.c \
	imap/proxy.c \
	master/service.c \
	timsieved/actions.c \
	timsieved/actions.h \
	timsieved/codes.h \
	timsieved/lex.c \
	timsieved/lex.h \
	timsieved/parser.c \
	timsieved/parser.h \
	timsieved/timsieved.c

timsieved_timsieved_LDADD = $(LD_SIEVE_ADD) $(LD_SERVER_ADD)

# The lex-fix rule is now obsolete, but let's leave a crumb here for a
# while so that custom build scripts that expect it to exist don't choke.
lex-fix:

snapshot::
	@echo "Creating snapshot $(PACKAGE_NAME)-$(PACKAGE_VERSION)"
	@$(MKDIR_P) snapshot
	@git archive --format=tar --prefix=$(PACKAGE_NAME)-$(PACKAGE_VERSION)/ HEAD | tar -C snapshot/ -x -f -
	@echo "creating tarfile"
	tar -C snapshot -c -f - $(PACKAGE_NAME)-$(PACKAGE_VERSION) | gzip -9 > $(PACKAGE_NAME)-$(PACKAGE_VERSION).tar.gz
	@rm -rf snapshot

docsrc/imap/reference/manpages/systemcommands/cyradm.rst: $(top_srcdir)/perl/imap/IMAP/Shell.pm
	@$(MKDIR_P) $(@D)
	$(AM_V_GEN)$(top_srcdir)/tools/perl2rst cyradm < $< > $@.NEW && mv $@.NEW $@

docsrc/imap/reference/manpages/configs/imapd.conf.rst: $(top_srcdir)/tools/config2rst $(top_srcdir)/lib/imapoptions
	@$(MKDIR_P) $(@D)
	$(AM_V_GEN)$(top_srcdir)/tools/config2rst $(top_srcdir)/lib/imapoptions > $@

doc/examples/imapd_conf/imapd.conf.sample: $(top_srcdir)/tools/config2sample $(top_srcdir)/lib/imapoptions
	@$(MKDIR_P) $(@D)
	$(AM_V_GEN)$(top_srcdir)/tools/config2sample $(top_srcdir)/lib/imapoptions > $@

docsrc/imap/reference/manpages/usercommands/sieveshell.rst: $(top_srcdir)/perl/sieve/scripts/sieveshell.pl
	@$(MKDIR_P) $(@D)
	$(AM_V_GEN)$(top_srcdir)/tools/perl2rst sieveshell < $< > $@.NEW && mv $@.NEW $@

%.1: man/.sphinx-build.stamp
	@$(MKDIR_P) $(@D)
	$(AM_V_GEN)touch $@

%.3: man/.sphinx-build.stamp
	@$(MKDIR_P) $(@D)
	$(AM_V_GEN)touch $@

%.5: man/.sphinx-build.stamp
	@$(MKDIR_P) $(@D)
	$(AM_V_GEN)touch $@

%.8: man/.sphinx-build.stamp
	@$(MKDIR_P) $(@D)
	$(AM_V_GEN)touch $@

## define this unconditionally because dist-hook references it
SPHINX_CACHE = docsrc/.doctrees

.PHONY: clean-sphinx-cache clean-docsrc
clean-sphinx-cache:
	@$(RM) -r $(SPHINX_CACHE)

if HAVE_SPHINX_BUILD

SPHINX_OPTS = -d $(SPHINX_CACHE) -n -q

## detect when source directory is not build directory (i.e. VPATH
## build), and clone the docsrc tree into the build directory, so
## that we have a single "source directory" for sphinx-build to use.
docsrc/.sphinx-build.stamp: docsrc/imap/reference/manpages/configs/imapd.conf.rst docsrc/imap/reference/manpages/systemcommands/cyradm.rst docsrc/imap/reference/manpages/usercommands/sieveshell.rst
	$(AM_V_GEN)test x"$(top_srcdir)" = x"$(top_builddir)" || \
        (cd $(top_srcdir) && tar cf - --mode=gu+w docsrc doc/examples) | tar xf -
	@touch $@

clean-docsrc:
	test x"$(top_srcdir)" = x"$(top_builddir)" || \
		$(RM) -r $(top_builddir)/docsrc $(top_builddir)/doc/examples

## XXX doesn't detect if other rst sources are updated...
man/.sphinx-build.stamp: docsrc/.sphinx-build.stamp
	$(AM_V_GEN)DOCSRC=$(top_builddir)/docsrc $(SPHINX_BUILD) $(SPHINX_OPTS) -b cyrman $(top_builddir)/docsrc $(top_builddir)/man
	@touch $@

clean-man:
	@$(RM) -r man

## XXX doesn't detect if other rst sources are updated...
doc/html/.sphinx-build.stamp: docsrc/.sphinx-build.stamp
	$(AM_V_GEN)DOCSRC=$(top_builddir)/docsrc $(SPHINX_BUILD) $(SPHINX_OPTS) -b html $(top_builddir)/docsrc $(top_builddir)/doc/html
	@touch $@

## XXX doesn't detect if other rst sources are updated...
doc/text/.sphinx-build.stamp: docsrc/.sphinx-build.stamp
	$(AM_V_GEN)DOCSRC=$(top_builddir)/docsrc $(SPHINX_BUILD) $(SPHINX_OPTS) -b text $(top_builddir)/docsrc $(top_builddir)/doc/text
	@touch $@
else
clean-docsrc:

man/.sphinx-build.stamp:
	@$(MKDIR_P) $(@D)
	$(AM_V_GEN)touch $@
	@echo "warning: missing documentation dependencies. man pages will be empty" 1>&2

clean-man:

doc/html/.sphinx-build.stamp:
	@echo "error: missing documentation dependencies. cannot build html documentation" 1>&2
	@false

doc/text/.sphinx-build.stamp:
	@echo "error: missing documentation dependencies. cannot build text documentation" 1>&2
	@false
endif

.PHONY: man man-force clean-man
man-force:
	## trash the timestamps, so we always re-run sphinx-build.
	## sphinx-build tracks source modifications itself, so forced
	## rebuilds will still be a lot quicker once it has run once.
	@$(RM) docsrc/.sphinx-build.stamp man/.sphinx-build.stamp

man: man-force $(dist_man1_MANS) $(dist_man3_MANS) $(dist_man5_MANS) $(dist_man8_MANS)

# clean-man is conditionally defined above. We do not want to remove
# man pages if the user is unable to rebuild them.

.PHONY: doc-html doc-html-force clean-doc-html
doc-html-force:
	@$(RM) docsrc/.sphinx-build.stamp doc/html/.sphinx-build.stamp

doc-html: doc-html-force doc/html/.sphinx-build.stamp

clean-doc-html:
	@$(RM) -r doc/html

.PHONY: doc-text doc-text-force clean-doc-text
doc-text-force:
	@$(RM) docsrc/.sphinx-build.stamp doc/text/.sphinx-build.stamp

doc-text: doc-text-force doc/text/.sphinx-build.stamp

clean-doc-text:
	@$(RM) -r doc/text

GENERATED_EXAMPLES = doc/examples/imapd_conf/imapd.conf.sample

.PHONY: doc-examples doc-examples-force clean-doc-examples
doc-examples-force:

doc-examples: doc-examples-force $(GENERATED_EXAMPLES)

clean-doc-examples:
	@$(RM) $(GENERATED_EXAMPLES)

.PHONY: doc clean-doc
doc: man doc-html doc-text doc-examples

clean-doc: clean-man clean-doc-html clean-doc-text clean-doc-examples

.PHONY: clean-local
clean-local: clean-doc clean-sphinx-cache clean-docsrc

distgit:
	$(MKDIR_P) dist
	@echo "checking out the distribution from tag $(PACKAGE_NAME)-$(PACKAGE_VERSION)"
	git archive --format=tar --prefix=$(PACKAGE_NAME)-$(PACKAGE_VERSION)/ $(PACKAGE_NAME)-$(PACKAGE_VERSION) | tar -C dist -x -f -
	touch distgit

dist-hook:
	find $(top_distdir) -type f -name .sphinx-build.stamp -delete
	find $(top_distdir) -type f -name .gitignore -delete
	rm -rf $(top_distdir)/$(SPHINX_CACHE)

VERSION: tools/git-version.sh
	$(AM_V_GEN)$< > $@.NEW && mv $@.NEW $@

install-data-hook:
if CMULOCAL
	$(INSTALL) -m 644 $(top_srcdir)/depot/depot.conf $(DESTDIR)/
endif

install-exec-hook:
if PERL
	for s in installsieve sieveshell; \
	do \
	  $(MKDIR_P) $(top_builddir)/perl/sieve/scripts ; \
	  $(PERL_PREINSTALL) < $(top_srcdir)/perl/sieve/scripts/$$s.pl > $(top_builddir)/perl/sieve/scripts/$$s ;\
	  $(INSTALL) -m 755 $(top_builddir)/perl/sieve/scripts/$$s $(DESTDIR)$(bindir)/$$s ; \
	done
endif

## The @$(MKDIR_P) line is added due to a bug in Automake 1.10 and can be removed if using Automake 1.12.
	@$(MKDIR_P) $(DESTDIR)$(libexecdir)
if SERVER
	cd $(DESTDIR)$(libexecdir) && \
	  $(LN_S) -f pop3d pop3proxyd && \
	  $(LN_S) -f imapd proxyd && \
	  $(LN_S) -f lmtpd lmtpproxyd
endif
## The @$(MKDIR_P) line is added due to a bug in Automake 1.10 and can be removed if using Automake 1.12.
	@$(MKDIR_P) $(DESTDIR)$(bindir)
	cd $(DESTDIR)$(bindir) && \
	  $(LN_S) -f imtest httptest && \
	  $(LN_S) -f imtest lmtptest && \
	  $(LN_S) -f imtest mupdatetest && \
	  $(LN_S) -f imtest nntptest && \
	  $(LN_S) -f imtest pop3test && \
	  $(LN_S) -f imtest sivtest && \
	  $(LN_S) -f imtest smtptest && \
	  $(LN_S) -f imtest synctest

uninstall-hook: cyrus-makemaker-uninstall-workaround
if PERL
	for s in installsieve sieveshell; do \
	    rm -f $(DESTDIR)$(bindir)/$$s; \
	done
endif

.PHONY: cyrus-makemaker-uninstall-workaround

# Workaround for deprecated no-op MakeMaker uninstall.
# Don't remove the packlists themselves, otherwise MakeMaker uninstall will
# crash.  Just remove the files MakeMaker uninstall won't remove itself.
#
# We have another layer of workaround in each module's Makefile that
# removes the packlist after MakeMaker uninstall has finished ignoring it.
cyrus-makemaker-uninstall-workaround:
if PERL
	( packlists=`find $(DESTDIR)$(libdir) -type f -name .packlist` && \
	  echo "uninstalling files from packlists: $$packlists" && \
	  rm -f `cat $$packlists` )
	( podfiles=`find $(DESTDIR)$(libdir) -type f -name perllocal.pod` && \
	  rm -f `echo $$podfiles` )
endif

install-binsymlinks:
## Let's symlink everything else
	for prog in $(sbin_PROGRAMS); do $(LN_S) -f $(sbindir)/`basename $$prog` $(DESTDIR)$(bindir)/; done
	for prog in $(libexec_PROGRAMS); do $(LN_S) -f $(libexecdir)/`basename $$prog` $(DESTDIR)$(bindir)/; done

SUFFIXES = .fig.png

.fig.png:
	mkdir -p $(@D)
	fig2dev -L png $< $@

valgrind:
	$(MAKE) VG=yes check

libtool: $(LIBTOOL_DEPS)
	$(SHELL) ./config.status libtool

# Install for Cassandane
cassandane:
	$(MAKE) DESTDIR=`cd ../inst ; /bin/pwd` install
