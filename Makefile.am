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
AM_CFLAGS = @PERL_CCCDLFLAGS@ $(COV_CFLAGS)

AM_CPPFLAGS = \
	$(COM_ERR_CPPFLAGS) \
	-I${top_builddir} \
	-I${top_builddir}/lib \
	-I${top_srcdir} \
	-I${top_srcdir}/lib \
	${DEFS} \
	${LOCALDEFS} \
	$(SASLFLAGS) \
	$(SSL_CPPFLAGS)

if HAVE_LDAP
AM_CPPFLAGS += $(LDAP_CPPFLAGS)
endif # HAVE_LDAP

AM_LDFLAGS = $(COV_LDFLAGS)
BUILT_SOURCES = \
	xversion.h \
	imap/imap_err.c \
	lib/imapopts.c \
	lib/imapopts.h

DISTCLEANFILES = \
	imap/imap_err.c \
	imap/imap_err.h \
	imap/mupdate_err.c \
	imap/mupdate_err.h \
	imap/nntp_err.c \
	imap/nntp_err.h \
	imap/http_err.c \
	imap/http_err.h \
	imap/tz_err.c \
	imap/tz_err.h \
	com_err/et/compile_et \
	perl/annotator/Makefile \
	perl/annotator/Makefile.PL \
	perl/imap/Makefile \
	perl/imap/Makefile.PL \
	perl/sieve/managesieve/Makefile \
	perl/sieve/managesieve/Makefile.PL \
	perl/sieve/scripts/installsieve \
	perl/sieve/scripts/sieveshell \
	sieve/sieve_err.c \
	sieve/sieve_err.h

MAINTAINERCLEANFILES = \
	doc/murder.png \
	doc/netnews.png \
	doc/man/cyradm.1.html \
	man/imapd.conf.5 \
	man/sieveshell.1 \
	doc/man/sieveshell.1.html \
	imap/lmtpstats.h \
	imap/pushstats.h \
	lib/chartable.c \
	lib/imapopts.h \
	sieve/addr.h \
	sieve/sieve.h

SUBDIRS = .
DIST_SUBDIRS = .
dist_sysconf_DATA =
lib_LTLIBRARIES = lib/libcyrus_min.la lib/libcyrus.la
EXTRA_PROGRAMS = tools/htmlstrip
check_PROGRAMS =
service_PROGRAMS =
user_PROGRAMS =
noinst_HEADERS =
noinst_LTLIBRARIES =
CLEANFILES =
EXTRA_DIST = \
	$(wildcard tools/vzic/*) \
	VERSION

if COM_ERR
COMPILE_ET_DEP = com_err/et/compile_et
BUILT_SOURCES += com_err/et/compile_et
lib_LTLIBRARIES += com_err/et/libcyrus_com_err.la
endif # COM_ERR

bin_PROGRAMS = imtest/imtest

if SERVER
BUILT_SOURCES += \
	imap/mupdate_err.c \
	imap/nntp_err.c \
	imap/lmtpstats.c \
	imap/pushstats.c \
	imap/rfc822_header.c \
	imap/rfc822_header.h

lib_LTLIBRARIES += imap/libcyrus_imap.la

service_PROGRAMS += \
	imap/imapd \
	imap/lmtpd \
	imap/pop3d \
	imap/smmapd

user_PROGRAMS += \
	imap/arbitron \
	imap/chk_cyrus \
	imap/ctl_cyrusdb \
	imap/ctl_deliver \
	imap/ctl_mboxlist \
	imap/cvt_cyrusdb \
	imap/cyr_buildinfo \
	imap/cyr_df \
	imap/cyrdump \
	imap/cyr_dbtool \
	imap/cyr_deny \
	imap/cyr_expire \
	imap/cyr_info \
	imap/cyr_sequence \
	imap/cyr_synclog \
	imap/cyr_userseen \
	imap/deliver \
	imap/ipurge \
	imap/mbexamine \
	imap/mbpath \
	imap/mbtool \
	imap/quota \
	imap/reconstruct \
	imap/squatter

if HAVE_CLAMAV
user_PROGRAMS += imap/cyr_virusscan
endif # HAVE_CLAMAV

if NNTPD
service_PROGRAMS += imap/nntpd
user_PROGRAMS += imap/fetchnews
endif # NNTPD

service_PROGRAMS += imap/fud

if IDLED
user_PROGRAMS += imap/idled
endif # IDLED

if MURDER
service_PROGRAMS += imap/mupdate
endif # MURDER

if HTTPD
AM_CPPFLAGS += $(HTTP_CPPFLAGS)
AM_LDFLAGS += $(HTTP_LIBS)

BUILT_SOURCES += \
	imap/http_err.c \
	imap/http_err.h \
	imap/tz_err.c \
	imap/tz_err.h

service_PROGRAMS += imap/httpd
user_PROGRAMS += \
	imap/ctl_zoneinfo \
	imap/dav_reconstruct

endif # HTTPD

if REPLICATION
user_PROGRAMS += imap/sync_client imap/sync_reset
service_PROGRAMS += imap/sync_server
endif # REPLICATION

if HAVE_SSL
user_PROGRAMS += imap/tls_prune
endif # HAVE_SSL

user_PROGRAMS += imap/unexpunge master/master

if SIEVE
check_PROGRAMS += notifyd/notifytest
service_PROGRAMS += notifyd/notifyd
endif # SIEVE

else # SERVER
EXTRA_DIST += \
    imap/mupdate_err.c \
    imap/nntp_err.c \
    imap/lmtpstats.c \
    imap/pushstats.c \
    imap/rfc822_header.c \
    imap/rfc822_header.h

if !HTTPD
EXTRA_DIST += \
	imap/http_err.c \
	imap/http_err.h \
	imap/tz_err.c \
	imap/tz_err.h
endif # HTTPD

endif # SERVER

if CMULOCAL
dist_sysconf_DATA += depot/rc.local.imap depot/rc.local.ptclient
user_PROGRAMS += netnews/remotepurge
endif # CMULOCAL

if PTCLIENT
user_PROGRAMS += ptclient/ptdump ptclient/ptexpire
service_PROGRAMS += \
	ptclient/ptloader
endif # PTCLIENT

if PERL
SUBDIRS += perl/annotator perl/imap
noinst_LTLIBRARIES += perl/libcyrus.la perl/libcyrus_min.la
endif # PERL

if SIEVE

if PERL
SUBDIRS += perl/sieve/managesieve
noinst_LIBRARIES = perl/sieve/lib/libisieve.a
endif # PERL

BUILT_SOURCES += sieve/addr.c sieve/sieve.c sieve/sieve_err.c
noinst_LTLIBRARIES += sieve/libcyrus_sieve_lex.la
lib_LTLIBRARIES += sieve/libcyrus_sieve.la
check_PROGRAMS += sieve/test
user_PROGRAMS += sieve/sievec sieve/sieved

if SERVER
service_PROGRAMS += timsieved/timsieved
endif # SERVER

endif # SIEVE

EXTRA_DIST += \
	COPYING \
	INSTALL \
	README.andrew \
	SMakefile \
	xversion.h \
	com_err/et/et_c.awk \
	com_err/et/et_h.awk \
	com_err/et/test1.et \
	com_err/et/test2.et \
	com_err/et/test_et.c \
	contrib/allow-broken-sslv23.patch \
	contrib/drac_auth.patch \
	contrib/sieve-spamasssassin \
	contrib/fud-client.c \
	contrib/deliver-notify-zephyr.patch \
	contrib/add-cyrus-user \
	contrib/README \
	contrib/cyrus-graphtools.1.0 \
	contrib/cyrus-graphtools.1.0/cgi-bin/cyrus_master.pl \
	contrib/cyrus-graphtools.1.0/cgi-bin/graph_cyrus_db.pl \
	contrib/cyrus-graphtools.1.0/cgi-bin/graph_cyrus_db-sum.pl \
	contrib/cyrus-graphtools.1.0/html \
	contrib/cyrus-graphtools.1.0/html/index.html \
	contrib/cyrus-graphtools.1.0/README \
	contrib/cyrus-graphtools.1.0/script \
	contrib/cyrus-graphtools.1.0/script/cyrus.pl \
	contrib/cyrus-graphtools.1.0/script/run \
	contrib/cyrus-graphtools.1.0/script/cyrusrc \
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
	doc/murder.png \
	doc/netnews.png \
	doc \
	imap/dav_util.h \
	imap/http_err.et \
	imap/imap_err.et \
	imap/mupdate_err.et \
	imap/nntp_err.et \
	imap/rfc822_header.st \
	imap/tz_err.et \
	lib/charset/aliases.txt \
	lib/charset/big5.t \
	lib/charset/gb2312.t \
	lib/charset/iso-2022-jp.t \
	lib/charset/iso-2022-kr.t \
	lib/charset/iso-8859-10.t \
	lib/charset/iso-8859-11.t \
	lib/charset/iso-8859-13.t \
	lib/charset/iso-8859-14.t \
	lib/charset/iso-8859-15.t \
	lib/charset/iso-8859-16.t \
	lib/charset/iso-8859-1.t \
	lib/charset/iso-8859-2.t \
	lib/charset/iso-8859-3.t \
	lib/charset/iso-8859-4.t \
	lib/charset/iso-8859-5.t \
	lib/charset/iso-8859-6.t \
	lib/charset/iso-8859-7.t \
	lib/charset/iso-8859-8.t \
	lib/charset/iso-8859-9.t \
	lib/charset/koi8-r.t \
	lib/charset/UnicodeData.txt \
	lib/charset/unifix.txt \
	lib/charset/us-ascii.t \
	lib/charset/windows-1250.t \
	lib/charset/windows-1251.t \
	lib/charset/windows-1252.t \
	lib/charset/windows-1254.t \
	lib/charset/windows-1255.t \
	lib/charset/windows-1256.t \
	lib/charset/windows-1258.t \
	lib/charset/windows-874.t \
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
	lib/test/testglob2.c \
	master/CYRUS-MASTER.mib \
	master/conf/cmu-backend.conf \
	master/conf/cmu-frontend.conf \
	master/conf/normal.conf \
	master/conf/prefork.conf \
	master/conf/small.conf \
	master/README \
	netnews/inn.diffs \
	perl/annotator/Daemon.pm \
	perl/annotator/Makefile.PL.in \
	perl/annotator/MANIFEST \
	perl/annotator/Message.pm \
	perl/annotator/README \
	perl/imap/Changes \
	perl/imap/cyradm.sh \
	perl/imap/cyrperl.h \
	perl/imap/Cyrus/Shell.pm \
	perl/imap/examples/auditmbox.pl \
	perl/imap/examples/imapcollate.pl \
	perl/imap/examples/imapdu.pl \
	perl/imap/examples/test-imsp.pl \
	perl/imap/IMAP/Admin.pm \
	perl/imap/IMAP/IMSP.pm \
	perl/imap/IMAP/Shell.pm \
	perl/imap/IMAP.pm \
	perl/imap/IMAP.xs \
	perl/imap/Makefile.PL.in \
	perl/imap/MANIFEST \
	perl/imap/README \
	perl/imap/t/01-imclient.t \
	perl/imap/t/02-admin.t \
	perl/imap/typemap \
	perl/imap/xsutil.c \
	perl/sieve/managesieve/Makefile.PL.in \
	perl/sieve/managesieve/managesieve.h \
	perl/sieve/managesieve/managesieve.pm \
	perl/sieve/managesieve/managesieve.xs \
	perl/sieve/managesieve/MANIFEST \
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
	imap/lmtpstats.snmp \
	imap/pushstats.snmp \
	lib/mkchartable.pl \
	lib/test/run \
	perl/sieve/scripts/installsieve.pl \
	perl/sieve/scripts/sieveshell.pl \
	tools/arbitronsort.pl \
	tools/compile_st.pl \
	tools/config2header \
	tools/config2man \
	tools/convert-sieve.pl \
	tools/dohash \
	tools/fixsearchpath.pl \
	tools/git-version.sh \
	tools/jenkins-build.sh \
	tools/masssievec \
	tools/migrate-metadata \
	tools/mkimap \
	tools/mknewsgroups \
	tools/mupdate-loadgen.pl \
	tools/rehash \
	tools/translatesieve \
	tools/undohash \
	tools/upgradesieve \
	snmp/snmpgen
noinst_MAN = \
	com_err/et/com_err.3 \
	com_err/et/compile_et.1
noinst_TEXINFOS = com_err/et/com_err.texinfo

pkgconfigdir = $(libdir)/pkgconfig
pkgconfig_DATA = libcyrus_min.pc libcyrus.pc libcyrus_sieve.pc

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

# BASIC is the libraries that every Cyrus program (except master) will
# need to link with.
#
# Note that several places in the code use -lcrypto, e.g. for SHA1 or
# MD5 algorithms, without needing SSL.  Currently we have no way of
# minimally linking such code.
LD_BASIC_ADD = lib/libcyrus.la lib/libcyrus_min.la ${LIBS} \
	${LIB_SASL} $(SSL_LIBS)

# UTILITY is the libraries that utility programs which use Cyrus'
# mailbox and message handling code need to link with.

LD_UTILITY_ADD = imap/libcyrus_imap.la $(LD_BASIC_ADD) $(COM_ERR_LIBS)

# SERVER is the libraries that network-facing servers need to link with
#
# Note that the code is horribly intertwingled e.g. in imap/global.c
# so that even utilities which never open a socket need to link against
# the SASL library.
LD_SERVER_ADD = $(LD_UTILITY_ADD) $(LIB_WRAP)

# ----

if CUNIT

CUNIT_PROJECT = cunit/default.cunit
BUILT_SOURCES += cunit/registers.h $(CUNIT_PROJECT)
CLEANFILES += cunit/registers.h $(CUNIT_PROJECT)
check_PROGRAMS += cunit/unit

cunit_FRAMEWORK = \
	cunit/unit.c \
	cunit/cunit.h \
	cunit/syslog.c \
	cunit/cunit-syslog.h \
	cunit/timeout.c \
	cunit/timeout.h

cunit_TESTS = \
	cunit/aaa-db.testc \
	cunit/annotate.testc \
	cunit/backend.testc \
	cunit/binhex.testc \
	cunit/bitvector.testc \
	cunit/buf.testc \
	cunit/byteorder64.testc \
	cunit/charset.testc \
	cunit/crc32.testc \
	cunit/dlist.testc \
	cunit/duplicate.testc \
	cunit/getxstring.testc \
	cunit/glob.testc \
	cunit/guid.testc \
	cunit/hash.testc \
	cunit/imapurl.testc \
	cunit/mboxname.testc \
	cunit/md5.testc \
	cunit/message.testc \
	cunit/msgid.testc \
	cunit/parseaddr.testc \
	cunit/parse.testc \
	cunit/prot.testc \
	cunit/ptrarray.testc \
	cunit/quota.testc \
	cunit/rfc822tok.testc

if SIEVE
cunit_TESTS += cunit/sieve.testc
endif

cunit_TESTS += \
	cunit/spool.testc \
	cunit/squat.testc \
	cunit/strarray.testc \
	cunit/strconcat.testc \
	cunit/strhash.testc \
	cunit/times.testc \
	cunit/tok.testc

cunit_unit_SOURCES = $(cunit_FRAMEWORK) $(cunit_TESTS) \
		imap/mutex_fake.c imap/spool.c
cunit_unit_LDADD =

if SIEVE
cunit_unit_LDADD += sieve/libcyrus_sieve.la
endif

cunit_unit_LDADD += $(LD_UTILITY_ADD) -lcunit

CUNIT_PL = cunit/cunit.pl --project $(CUNIT_PROJECT)

.testc.o:
	$(CUNIT_PL) --generate-wrapper $<
	$(COMPILE) -c -o $@ $<-cunit.c
	$(RM) $<-cunit.c

$(CUNIT_PROJECT):
	$(RM) $@
	$(CUNIT_PL) --add-sources $(cunit_TESTS)

cunit/registers.h: $(CUNIT_PROJECT)
	$(CUNIT_PL) --generate-register-function $@

# To run under Valgrind, do: make VG=1 check
VALGRIND = valgrind --tool=memcheck --leak-check=full --suppressions=vg.supp

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
endif

tools_htmlstrip_SOURCE = tools/htmlstrip.c

includedir=@includedir@/cyrus

include_HEADERS = \
	lib/acl.h \
	lib/arrayu64.h \
	lib/assert.h \
	lib/auth.h \
	lib/auth_pts.h \
	lib/bitvector.h \
	lib/bsearch.h \
	lib/charset.h \
	lib/chartable.h \
	lib/command.h \
	lib/crc32.h \
	lib/cyr_lock.h \
	lib/cyrusdb.h \
	lib/exitcodes.h \
	lib/glob.h \
	lib/gmtoff.h \
	lib/hash.h \
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
	lib/nonblock.h \
	lib/parseaddr.h \
	lib/retry.h \
	lib/rfc822tok.h \
	lib/signals.h \
	lib/strarray.h \
	lib/strhash.h \
	lib/stristr.h \
	lib/sysexits.h \
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
	lib/byteorder64.h \
	lib/gai.h \
	lib/libconfig.h \
	lib/md5.h \
	lib/prot.h \
	lib/ptrarray.h \
	lib/util.h \
	lib/xstrlcat.h \
	lib/xstrlcpy.h

imap_arbitron_SOURCES = imap/arbitron.c imap/cli_fatal.c imap/mutex_fake.c
imap_arbitron_LDADD = $(LD_UTILITY_ADD)

imap_chk_cyrus_SOURCES = imap/chk_cyrus.c imap/cli_fatal.c imap/mutex_fake.c
imap_chk_cyrus_LDADD = $(LD_UTILITY_ADD)

imap_ctl_cyrusdb_SOURCES = imap/cli_fatal.c imap/ctl_cyrusdb.c imap/mutex_fake.c
imap_ctl_cyrusdb_LDADD = $(LD_UTILITY_ADD)

imap_ctl_deliver_SOURCES = imap/cli_fatal.c imap/ctl_deliver.c imap/mutex_fake.c
imap_ctl_deliver_LDADD = $(LD_UTILITY_ADD)

imap_ctl_mboxlist_SOURCES = imap/cli_fatal.c imap/ctl_mboxlist.c imap/mutex_fake.c
imap_ctl_mboxlist_LDADD = $(LD_UTILITY_ADD)

imap_cvt_cyrusdb_SOURCES = imap/cli_fatal.c imap/cvt_cyrusdb.c imap/mutex_fake.c
imap_cvt_cyrusdb_LDADD = $(LD_UTILITY_ADD)

imap_cyrdump_SOURCES = imap/cli_fatal.c imap/cyrdump.c imap/mutex_fake.c
imap_cyrdump_LDADD = $(LD_UTILITY_ADD)

imap_cyr_buildinfo_SOURCES = imap/cli_fatal.c imap/cyr_buildinfo.c imap/mutex_fake.c
imap_cyr_buildinfo_LDADD = $(LD_UTILITY_ADD)

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

imap_cyr_sequence_SOURCES = imap/cli_fatal.c imap/cyr_sequence.c imap/mutex_fake.c
imap_cyr_sequence_LDADD = $(LD_UTILITY_ADD)

imap_cyr_synclog_SOURCES = imap/cli_fatal.c imap/cyr_synclog.c imap/mutex_fake.c
imap_cyr_synclog_LDADD = $(LD_UTILITY_ADD)

imap_cyr_userseen_SOURCES = imap/cli_fatal.c imap/cyr_userseen.c imap/mutex_fake.c
imap_cyr_userseen_LDADD = $(LD_UTILITY_ADD)

imap_cyr_virusscan_SOURCES = imap/cli_fatal.c imap/cyr_virusscan.c imap/mutex_fake.c
imap_cyr_virusscan_LDADD = $(LD_UTILITY_ADD) $(CLAMAV_LIBS)

if HTTPD
imap_ctl_zoneinfo_SOURCES = imap/cli_fatal.c imap/ctl_zoneinfo.c imap/mutex_fake.c
imap_ctl_zoneinfo_LDADD = $(LD_UTILITY_ADD)
else # HTTPD
EXTRA_DIST += \
	imap/ctl_zoneinfo.c

endif # HTTPD

imap_deliver_SOURCES = \
	imap/deliver.c \
	imap/lmtpengine.c \
	imap/lmtpstats.c \
	imap/mutex_fake.c \
	imap/proxy.c \
	imap/spool.c

imap_deliver_LDADD = $(LD_UTILITY_ADD)

imap_fetchnews_SOURCES = imap/cli_fatal.c imap/fetchnews.c imap/mutex_fake.c
imap_fetchnews_LDADD = $(LD_UTILITY_ADD)

imap_fud_SOURCES = imap/fud.c imap/mutex_fake.c master/service.c
imap_fud_LDADD = $(LD_SERVER_ADD)

imap_idled_SOURCES = imap/idled.c imap/mutex_fake.c
imap_idled_LDADD = $(LD_UTILITY_ADD)

imap_imapd_SOURCES = \
	imap/imap_proxy.c \
	imap/imap_proxy.h \
	imap/imapd.c \
	imap/imapd.h \
	imap/mutex_fake.c \
	imap/pushstats.c \
	imap/pushstats.h \
	imap/proxy.c \
	imap/proxy.h \
	master/service.c

if AUTOCREATE
imap_imapd_SOURCES += \
	imap/autocreate.h \
	imap/autocreate.c
endif

imap_imapd_LDADD =

if SIEVE
imap_imapd_LDADD += sieve/libcyrus_sieve.la
endif

imap_imapd_LDADD += $(LD_SERVER_ADD)

imap_ipurge_SOURCES = imap/cli_fatal.c imap/ipurge.c imap/mutex_fake.c
imap_ipurge_LDADD = $(LD_UTILITY_ADD)

nodist_imap_libcyrus_imap_la_SOURCES = \
	imap/imap_err.c \
	imap/mupdate_err.c \
	imap/mupdate_err.h

dist_imap_libcyrus_imap_la_SOURCES =

imap_libcyrus_imap_la_SOURCES = \
	imap/annotate.c \
	imap/annotate.h \
	imap/append.c \
	imap/append.h \
	imap/backend.c \
	imap/backend.h \
	imap/convert_code.c \
	imap/convert_code.h \
	imap/dlist.c \
	imap/dlist.h \
	imap/duplicate.c \
	imap/duplicate.h \
	imap/global.c \
	imap/global.h \
	imap/idle.c \
	imap/idle.h \
	imap/idlemsg.c \
	imap/idlemsg.h \
	imap/imapparse.c \
	imap/index.c \
	imap/index.h \
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
	imap/mupdate-client.c \
	imap/mupdate-client.h \
	imap/mutex.h \
	imap/notify.c \
	imap/notify.h \
	imap/partlist.c \
	imap/partlist.h \
	imap/proc.c \
	imap/proc.h \
	imap/protocol.h \
	imap/quota_db.c \
	imap/rfc822_header.c \
	imap/rfc822_header.h \
	imap/saslclient.c \
	imap/saslclient.h \
	imap/saslserver.c \
	imap/search_engines.c \
	imap/search_engines.h \
	imap/seen.h \
	imap/seen_db.c \
	imap/sequence.c \
	imap/sequence.h \
	imap/setproctitle.c \
	imap/squat.c \
	imap/squat.h \
	imap/squat_internal.c \
	imap/squat_internal.h \
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
	imap/version.h

imap_libcyrus_imap_la_LIBADD = $(COM_ERR_LIBS) $(LIB_UUID) lib/libcyrus_min.la lib/libcyrus.la
imap_libcyrus_imap_la_CFLAGS = $(AM_CFLAGS) $(CFLAG_VISIBILITY)

if JANSSON
imap_libcyrus_imap_la_LIBADD += $(JANSSON_LIBS)
imap_libcyrus_imap_la_CFLAGS += $(JANSSON_CFLAGS)
endif

if HTTPD
imap_libcyrus_imap_la_SOURCES += \
	imap/caldav_db.c \
	imap/caldav_db.h \
	imap/carddav_db.c \
	imap/carddav_db.h \
	imap/dav_db.c \
	imap/dav_db.h \
	imap/dav_util.c \
	imap/dav_util.h \
	imap/http_caldav.c \
	imap/http_caldav_sched.h \
	imap/http_carddav.c \
	imap/http_client.c \
	imap/http_client.h \
	imap/http_dav.c \
	imap/http_dav.h \
	imap/http_dblookup.c \
	imap/http_ischedule.c \
	imap/http_proxy.c \
	imap/http_proxy.h \
	imap/http_rss.c \
	imap/http_timezone.c \
	imap/httpd.c \
	imap/httpd.h \
	imap/jcal.c \
	imap/jcal.h \
	imap/json_support.h \
	imap/proxy.c \
	imap/proxy.h \
	imap/smtpclient.c \
	imap/smtpclient.h \
	imap/spool.c \
	imap/spool.h \
	imap/xcal.c \
	imap/xcal.h \
	imap/zoneinfo_db.c \
	imap/zoneinfo_db.h

nodist_imap_libcyrus_imap_la_SOURCES += \
	imap/http_err.c \
	imap/tz_err.c

endif # HTTPD

imap_lmtpd_SOURCES = \
	imap/lmtpd.c \
	imap/lmtpd.h \
	imap/lmtpengine.c \
	imap/lmtpengine.h \
	imap/lmtpstats.c \
	imap/lmtpstats.h \
	imap/mutex_fake.c \
	imap/proxy.c \
	imap/spool.c \
	master/service.c

if AUTOCREATE
imap_lmtpd_SOURCES += \
	imap/autocreate.c \
	imap/autocreate.h
endif # AUTOCREATE

imap_lmtpd_LDADD =

if SIEVE
imap_lmtpd_SOURCES += imap/lmtp_sieve.c imap/lmtp_sieve.h imap/smtpclient.c
imap_lmtpd_LDADD += sieve/libcyrus_sieve.la
endif # SIEVE

imap_lmtpd_LDADD += $(LD_SERVER_ADD)

imap/lmtpstats.c: imap/lmtpstats.snmp snmp/snmpgen
	cd imap && ../${top_srcdir}/snmp/snmpgen ../${top_srcdir}/imap/lmtpstats.snmp

imap/pushstats.c: imap/pushstats.snmp snmp/snmpgen
	cd imap && ../${top_srcdir}/snmp/snmpgen ../${top_srcdir}/imap/pushstats.snmp

imap_mbexamine_SOURCES = imap/cli_fatal.c imap/mbexamine.c imap/mutex_fake.c
imap_mbexamine_LDADD = $(LD_UTILITY_ADD)

imap_mbpath_SOURCES = imap/cli_fatal.c imap/mbpath.c imap/mutex_fake.c
imap_mbpath_LDADD = $(LD_UTILITY_ADD)

imap_mbtool_SOURCES = imap/cli_fatal.c imap/mbtool.c imap/mutex_fake.c
imap_mbtool_LDADD = $(LD_UTILITY_ADD)

imap_mupdate_SOURCES = \
	imap/mupdate.c \
	imap/mupdate.h \
	imap/mupdate-slave.c \
	imap/mutex_pthread.c \
	imap/tls_th-lock.c \
	master/service-thread.c
imap_mupdate_LDADD = $(LD_SERVER_ADD) -lpthread

nodist_imap_nntpd_SOURCES = \
	imap/nntp_err.c \
	imap/nntp_err.h
imap_nntpd_SOURCES = \
	imap/mutex_fake.c \
	imap/nntpd.c \
	imap/proxy.c \
	imap/smtpclient.c \
	imap/smtpclient.h \
	imap/spool.c \
	imap/spool.h \
	master/service.c
imap_nntpd_LDADD = $(LD_SERVER_ADD)

nodist_imap_httpd_SOURCES = \
	imap/http_err.c \
	imap/http_err.h \
	imap/tz_err.c \
	imap/tz_err.h

imap_httpd_SOURCES = \
	imap/caldav_db.c \
	imap/carddav_db.c \
	imap/carddav_db.h \
	imap/dav_db.c \
	imap/dav_util.c \
	imap/http_caldav.c \
	imap/http_carddav.c \
	imap/http_client.c \
	imap/http_dav.c \
	imap/http_dblookup.c \
	imap/http_ischedule.c \
	imap/http_proxy.c \
	imap/http_rss.c \
	imap/http_timezone.c \
	imap/httpd.c \
	imap/jcal.c \
	imap/json_support.h \
	imap/mutex_fake.c \
	imap/proxy.c \
	imap/smtpclient.c \
	imap/spool.c \
	imap/xcal.c \
	imap/zoneinfo_db.c \
	master/service.c

imap_httpd_LDADD = $(LD_SERVER_ADD)

imap_pop3d_SOURCES = \
	imap/mutex_fake.c \
	imap/pop3d.c \
	imap/proxy.c \
	master/service.c

if AUTOCREATE
imap_pop3d_SOURCES += \
	imap/autocreate.c \
	imap/autocreate.h
endif # AUTOCREATE

imap_pop3d_LDADD =

if SIEVE
imap_pop3d_LDADD += sieve/libcyrus_sieve.la
endif # SIEVE

imap_pop3d_LDADD += $(LD_SERVER_ADD)

imap_quota_SOURCES = imap/cli_fatal.c imap/mutex_fake.c imap/quota.c imap/quota.h
imap_quota_LDADD = $(LD_UTILITY_ADD)

imap_reconstruct_SOURCES = imap/cli_fatal.c imap/mutex_fake.c imap/reconstruct.c
imap_reconstruct_LDADD = $(LD_UTILITY_ADD)

imap_dav_reconstruct_SOURCES = imap/cli_fatal.c imap/mutex_fake.c imap/dav_reconstruct.c
imap_dav_reconstruct_LDADD = $(LD_UTILITY_ADD)

imap_smmapd_SOURCES = imap/mutex_fake.c imap/proxy.c imap/smmapd.c master/service.c
imap_smmapd_LDADD = $(LD_SERVER_ADD)

imap_squatter_SOURCES = imap/cli_fatal.c imap/mutex_fake.c imap/squatter.c imap/squat_build.c
imap_squatter_LDADD = $(LD_UTILITY_ADD)

imap_sync_client_SOURCES = imap/mutex_fake.c imap/sync_client.c \
	imap/sync_support.c imap/sync_support.h
imap_sync_client_LDADD = $(LD_UTILITY_ADD)

imap_sync_reset_SOURCES = imap/mutex_fake.c imap/sync_reset.c imap/sync_support.c
imap_sync_reset_LDADD = $(LD_UTILITY_ADD)

imap_sync_server_SOURCES = imap/mutex_fake.c imap/sync_server.c imap/sync_support.c master/service.c
imap_sync_server_LDADD = $(LD_SERVER_ADD)

imap_tls_prune_SOURCES = imap/cli_fatal.c imap/mutex_fake.c imap/tls_prune.c
imap_tls_prune_LDADD = $(LD_UTILITY_ADD)

imap_unexpunge_SOURCES = imap/cli_fatal.c imap/mutex_fake.c imap/unexpunge.c
imap_unexpunge_LDADD = $(LD_UTILITY_ADD)

imap/imap_err.h imap/imap_err.c: imap/imap_err.et $(COMPILE_ET_DEP)
	cd imap && $(COMPILE_ET) ../$(top_srcdir)/imap/imap_err.et

imap/mupdate_err.h imap/mupdate_err.c: imap/mupdate_err.et $(COMPILE_ET_DEP)
	cd imap && $(COMPILE_ET) ../$(top_srcdir)/imap/mupdate_err.et

imap/nntp_err.h imap/nntp_err.c: imap/nntp_err.et $(COMPILE_ET_DEP)
	cd imap && $(COMPILE_ET) ../$(top_srcdir)/imap/nntp_err.et

imap/http_err.h imap/http_err.c: imap/http_err.et $(COMPILE_ET_DEP)
	cd imap && $(COMPILE_ET) ../$(top_srcdir)/imap/http_err.et

imap/tz_err.h imap/tz_err.c: imap/tz_err.et $(COMPILE_ET_DEP)
	cd imap && $(COMPILE_ET) ../$(top_srcdir)/imap/tz_err.et

if MAINTAINER_MODE
imap/rfc822_header.c: imap/rfc822_header.st
	${top_srcdir}/tools/compile_st.pl -c $< > $@.NEW && mv $@.NEW $@

imap/rfc822_header.h: imap/rfc822_header.st
	${top_srcdir}/tools/compile_st.pl -h $< > $@.NEW && mv $@.NEW $@
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
	lib/bsearch.c \
	lib/byteorder64.c \
	lib/charset.c \
	lib/command.c \
	lib/crc32.c \
	lib/cyrusdb.c \
	lib/cyrusdb_flat.c \
	lib/cyrusdb_quotalegacy.c \
	lib/cyrusdb_skiplist.c \
	lib/cyrusdb_twoskip.c \
	lib/glob.c \
	lib/imapurl.c \
	lib/imclient.c \
	lib/imparse.c \
	lib/iostat.c \
	lib/iptostring.c \
	lib/libcyr_cfg.c \
	lib/lsort.c \
	lib/mappedfile.c \
	lib/mkgmtime.c \
	lib/parseaddr.c \
	lib/prot.c \
	lib/ptrarray.c \
	lib/rfc822tok.c \
	lib/signals.c \
	lib/stristr.c \
	lib/times.c \
	lib/tok.c \
	lib/wildmat.c
if USE_BERKELEY
lib_libcyrus_la_SOURCES += lib/cyrusdb_berkeley.c
endif
if USE_SQL
lib_libcyrus_la_SOURCES += lib/cyrusdb_sql.c
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
lib_libcyrus_la_LIBADD = ${LIB_SASL} $(SSL_LIBS)
lib_libcyrus_la_CFLAGS = $(AM_CFLAGS) $(CFLAG_VISIBILITY)

nodist_lib_libcyrus_min_la_SOURCES = \
	lib/imapopts.c

lib_libcyrus_min_la_SOURCES = \
	lib/arrayu64.c \
	lib/assert.c \
	lib/hash.c \
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
	lib/xstrlcpy.c
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
lib_libcyrus_min_la_LIBADD = $(LTLIBOBJS)
lib_libcyrus_min_la_CFLAGS = $(AM_CFLAGS) $(CFLAG_VISIBILITY)

lib/chartable.c: lib/mkchartable.pl lib/charset/unifix.txt \
	$(top_srcdir)/lib/charset/*.t lib/charset/UnicodeData.txt \
	lib/charset/aliases.txt
	@echo "### Building chartables..."
	perl $(top_srcdir)/lib/mkchartable.pl -m $(top_srcdir)/lib/charset/unifix.txt -m $(top_srcdir)/lib/charset/UnicodeData.txt -a $(top_srcdir)/lib/charset/aliases.txt -o $@ $(top_srcdir)/lib/charset/*.t || (rm -f $@ && exit 1)
	@echo "### Done building chartables."

lib/imapopts.h: lib/imapopts.c

lib/imapopts.c: lib/imapoptions tools/config2header
	$(top_srcdir)/tools/config2header CC="$(CC)" $(top_builddir)/lib/imapopts.c $(top_builddir)/lib/imapopts.h < $(top_srcdir)/lib/imapoptions

#this is from lib/test/Makefile.in, however testglob.c does not exist in
#/lib/test, instead testglob2.c is there.
#lib_test_testglob_LIRBARIES = lib/libcyrus.la lib/libcyrus_min.la -ldb-4.0


@SET_MAKE@

dist_man_MANS = \
	man/imtest.1 \
	man/installsieve.1 \
	man/lmtptest.1 \
	man/mupdatetest.1 \
	man/nntptest.1 \
	man/pop3test.1 \
	man/sieveshell.1 \
	man/sivtest.1 \
	man/smtptest.1 \
	man/imclient.3 \
	man/cyrus.conf.5 \
	man/imapd.conf.5 \
	man/krb.equiv.5 \
	man/arbitron.8 \
	man/chk_cyrus.8 \
	man/ctl_cyrusdb.8 \
	man/ctl_deliver.8 \
	man/ctl_mboxlist.8 \
	man/cyr_expire.8 \
	man/cvt_cyrusdb.8 \
	man/cyr_dbtool.8 \
	man/cyr_deny.8 \
	man/cyr_df.8 \
	man/cyr_info.8 \
	man/cyr_synclog.8 \
	man/deliver.8 \
	man/fud.8 \
	man/idled.8 \
	man/imapd.8 \
	man/ipurge.8 \
	man/lmtpd.8 \
	man/master.8 \
	man/mbexamine.8 \
	man/mbpath.8 \
	man/notifyd.8 \
	man/pop3d.8 \
	man/quota.8 \
	man/reconstruct.8 \
	man/rmnews.8 \
	man/smmapd.8 \
	man/squatter.8 \
	man/sync_client.8 \
	man/sync_reset.8 \
	man/sync_server.8 \
	man/timsieved.8 \
	man/tls_prune.8 \
	man/unexpunge.8

if NNTPD
dist_man_MANS += \
	man/fetchnews.8 \
	man/nntpd.8

else # NNTPD
EXTRA_DIST += \
	man/fetchnews.8 \
	man/nntpd.8

endif # NNTPD

if HTTPD
dist_man_MANS += \
	man/ctl_zoneinfo.8 \
	man/httpd.8

else # HTTPD
EXTRA_DIST += \
	man/ctl_zoneinfo.8 \
	man/httpd.8

endif # HTTPD

master_master_SOURCES = \
	master/cyrusMasterMIB.c \
	master/cyrusMasterMIB.h \
	master/master.c \
	master/master.h \
	master/masterconf.c \
	master/masterconf.h \
	master/service.h
master_master_LDADD = lib/libcyrus_min.la $(LIB_UCDSNMP) $(LIBS) -lm


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

perl_sieve_lib_libisieve_a_SOURCES = \
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
	sieve/bc_dump.c \
	sieve/bc_emit.c \
	sieve/bc_eval.c \
	sieve/bc_generate.c \
	sieve/comparator.c \
	sieve/comparator.h \
	sieve/flags.c \
	sieve/flags.h \
	sieve/interp.c \
	sieve/interp.h \
	sieve/message.c \
	sieve/message.h \
	sieve/script.c \
	sieve/script.h \
	sieve/sieve.y \
	sieve/tree.c \
	sieve/tree.h \
	sieve/varlist.c \
	sieve/varlist.h
sieve_libcyrus_sieve_la_LIBADD = \
    sieve/libcyrus_sieve_lex.la \
    $(COM_ERR_LIBS) \
    lib/libcyrus_min.la \
    lib/libcyrus.la
sieve_libcyrus_sieve_la_CFLAGS = $(AM_CFLAGS) $(CFLAG_VISIBILITY)

LD_SIEVE_ADD = sieve/libcyrus_sieve.la $(LD_BASIC_ADD)

sieve_sievec_LDADD = $(LD_SIEVE_ADD)
sieve_sieved_LDADD = $(LD_SIEVE_ADD)

sieve/sieve_err.h sieve/sieve_err.c: sieve/sieve_err.et $(COMPILE_ET_DEP)
	cd sieve && $(COMPILE_ET) ../$(top_srcdir)/sieve/sieve_err.et

sieve_test_SOURCES = sieve/test.c imap/mutex_fake.c
sieve_test_LDADD = sieve/libcyrus_sieve.la $(LD_UTILITY_ADD)

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
	timsieved/scripttest.c \
	timsieved/scripttest.h \
	timsieved/timsieved.c

timsieved_timsieved_LDADD = sieve/libcyrus_sieve.la $(LD_SERVER_ADD)

# The lex-fix rule is now obsolete, but let's leave a crumb here for a
# while so that custom build scripts that expect it to exist don't choke.
lex-fix:

snapshot::
	@echo "Creating snapshot $(PACKAGE_NAME)-$(PACKAGE_VERSION)"
	@$(MKDIR_P) snapshot
	@git archive --format=tar --prefix=$(PACKAGE_NAME)-$(PACKAGE_VERSION)/ HEAD | tar -C snapshot/ -x -f -
	@echo "/* $(PACKAGE_NAME) $(PACKAGE_VERSION) */" > snapshot/$(PACKAGE_NAME)-$(PACKAGE_VERSION)/xversion.h
	@echo "#define _CYRUS_VERSION \"$(PACKAGE_VERSION)\"" >> snapshot/$(PACKAGE_NAME)-$(PACKAGE_VERSION)/xversion.h
	@echo "#define CYRUS_GITVERSION \"`git log --abbrev=8 --pretty=\"format:%h %ci\" -1 | cut -d\" \" -f1,2`\"" >> snapshot/$(PACKAGE_NAME)-$(PACKAGE_VERSION)/xversion.h
	@touch snapshot/$(PACKAGE_NAME)-$(PACKAGE_VERSION)/xversion
	@echo "creating tarfile"
	tar -C snapshot -c -f - $(PACKAGE_NAME)-$(PACKAGE_VERSION) | gzip -9 > $(PACKAGE_NAME)-$(PACKAGE_VERSION).tar.gz
	@rm -rf snapshot

man/imapd.conf.5: $(top_srcdir)/tools/config2man $(top_srcdir)/lib/imapoptions
	@echo creating man/imapd.conf.5
	@$(MKDIR_P) man
	$(top_srcdir)/tools/config2man $(top_srcdir)/lib/imapoptions > $@

man/sieveshell.1: $(top_srcdir)/perl/sieve/scripts/sieveshell.pl
	@echo creating man/sieveshell.1
	@$(MKDIR_P) man
	pod2man $(top_srcdir)/perl/sieve/scripts/sieveshell.pl > $@

doc/man/cyradm.1.html: $(top_srcdir)/perl/imap/cyradm.sh
	@$(MKDIR_P) doc/man
	pod2html $(top_srcdir)/perl/imap/cyradm.sh > $@
	rm pod2htm*

doc/man/sieveshell.1.html: $(top_srcdir)/perl/sieve/scripts/sieveshell.pl
	@$(MKDIR_P) doc/man
	pod2html $(top_srcdir)/perl/sieve/scripts/sieveshell.pl > $@
	rm pod2htm*


dist-old:: distgit
	@echo "creating configure"
	@cd dist/cyrus-imapd-$(PACKAGE_VERSION) ; sh SMakefile
	@for d in $(DIST_SUBDIRS); \
	do \
	(cd dist/cyrus-imapd-$(PACKAGE_VERSION)/$$d; \
	if [ -f Makefile.dist ]; then \
	echo "### Making" dist "in" `pwd`; \
	$(MAKE) $(MFLAGS) YACC='$(YACC)' LEX='$(LEX)' \
	COMPILE_ET='$(COMPILE_ET)' -f Makefile.dist dist ; \
	fi) || exit 1; \
	done
	@echo "creating tarfile"
	@cd dist ; tar cf - cyrus-imapd-$(PACKAGE_VERSION) | \
	gzip -9 > ../cyrus-imapd-$(PACKAGE_VERSION).tar.gz
	rm -f distgit
	rm -rf dist

distgit:
	$(MKDIR_P) dist
	@echo "checking out the distribution from tag $(PACKAGE_NAME)-$(PACKAGE_VERSION)"
	git archive --format=tar --prefix=$(PACKAGE_NAME)-$(PACKAGE_VERSION)/ $(PACKAGE_NAME)-$(PACKAGE_VERSION) | tar -C dist -x -f -
	echo "/* Release $(PACKAGE_NAME)-$(PACKAGE_VERSION) */" > dist/$(PACKAGE_NAME)-$(PACKAGE_VERSION)/xversion.h
	echo "#define _CYRUS_VERSION \"v$(PACKAGE_VERSION)\"" >> dist/$(PACKAGE_NAME)-$(PACKAGE_VERSION)/xversion.h
	echo "#define CYRUS_GITVERSION \"`git log --abbrev=8 --pretty=\"format:%h %ci\" -1 | cut -d\" \" -f1,2`\"" >> dist/$(PACKAGE_NAME)-$(PACKAGE_VERSION)/xversion.h
	touch dist/$(PACKAGE_NAME)-$(PACKAGE_VERSION)/xversion
	touch distgit

xversion xversion.h:
	@echo "/* Development version */" > xversion.h.tmp
	@echo "#define _CYRUS_VERSION \"$(PACKAGE_VERSION)\"" >> xversion.h.tmp
	@echo "#define CYRUS_GITVERSION \"`git log --abbrev=8 --pretty=\"format:%h %ci\" -1 | cut -d\" \" -f1,2`\"" >> xversion.h.tmp
	@cmp -s xversion.h.tmp xversion.h || mv xversion.h.tmp xversion.h
	@rm -f xversion.h.tmp

.PHONY: doc

doc: tools/htmlstrip doc/man/cyradm.1.html doc/man/sieveshell.1.html
	@$(MKDIR_P) doc/text doc/man
	for man in $(top_builddir)/man/*.[1-9] $(top_srcdir)/man/*.[1-9]; \
	do \
		echo "=== $$man ==="; \
		groff -man -Thtml $$man > doc/man/`basename $$man`.html; \
	done
	rm -f doc/groff-html-*.png

	for file in $(top_srcdir)/doc/*.html; \
	do \
		echo "=== $$file ==="; \
		tools/htmlstrip $$file > doc/text/`basename $$file .html`; \
	done
	@echo "== done =="

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
	  $(PERL_PREINSTALL) < perl/sieve/scripts/$$s.pl > perl/sieve/scripts/$$s ;\
	  $(INSTALL) -m 755 perl/sieve/scripts/$$s $(DESTDIR)$(bindir)/$$s ; \
	done
endif

## The @$(MKDIR_P) line is added due to a bug in Automake 1.10 and can be removed if using Automake 1.12.
	@$(MKDIR_P) $(DESTDIR)$(userdir)
	@$(MKDIR_P) $(DESTDIR)$(servicedir)
if SERVER
	cd $(DESTDIR)$(servicedir) && \
	  $(LN_S) -f pop3d pop3proxyd && \
	  $(LN_S) -f imapd proxyd && \
	  $(LN_S) -f lmtpd lmtpproxyd
endif
## The @$(MKDIR_P) line is added due to a bug in Automake 1.10 and can be removed if using Automake 1.12.
	@$(MKDIR_P) $(DESTDIR)$(bindir)
	cd $(DESTDIR)$(bindir) && \
	  $(LN_S) -f imtest lmtptest && \
	  $(LN_S) -f imtest mupdatetest && \
	  $(LN_S) -f imtest nntptest && \
	  $(LN_S) -f imtest pop3test && \
	  $(LN_S) -f imtest sivtest && \
	  $(LN_S) -f imtest smtptest && \
	  $(LN_S) -f imtest synctest

SUFFIXES = .fig.png

.fig.png:
	fig2dev -L png $< $@

valgrind:
	$(MAKE) VG=yes check

libtool: $(LIBTOOL_DEPS)
	$(SHELL) ./config.status libtool
