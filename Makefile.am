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
AM_CFLAGS = @PERL_CCCDLFLAGS@ $(EXTRACFLAGS)
AM_CPPFLAGS = @COM_ERR_CPPFLAGS@ -I${top_srcdir} -I${top_srcdir}/lib -I${top_builddir} -I${top_builddir}/lib ${DEFS} ${LOCALDEFS} @SASLFLAGS@
AM_LDFLAGS = ${EXTRALDFLAGS}
BUILT_SOURCES = xversion.h lib/imapopts.c

SUBDIRS = . imtest
noinst_LIBRARIES =
lib_LIBRARIES = lib/libcyrus.a lib/libcyrus_min.a
check_PROGRAMS =
service_PROGRAMS =

if COM_ERR
BUILT_SOURCES += com_err/et/compile_et
noinst_LIBRARIES += com_err/et/libcom_err.a
COM_ERR_LIBS += com_err/et/libcom_err.a
endif

if SYSLOG
SUBDIRS += syslog
endif
if CMULOCAL
SUBDIRS += depot netnews
endif
if PTCLIENT
SUBDIRS += ptclient
endif
if PERL
SUBDIRS += perl
endif
if SIEVE
BUILT_SOURCES += sieve/addr.c sieve/sieve.c sieve/sieve_err.c
lib_LIBRARIES += sieve/libsieve.a
check_PROGRAMS += sieve/test
service_PROGRAMS += sieve/sievec sieve/sieved
endif
if SERVER
SUBDIRS += imap
service_PROGRAMS += master/master
endif

if SIEVE
if SERVER
SUBDIRS += notifyd timsieved
endif
if PERL
SUBDIRS += perl/sieve perl/sieve/lib
endif
endif

if CUNIT
SUBDIRS += cunit
endif

EXTRA_DIST = xversion.h com_err/et/com_err com_err/et/et_c.awk \
	com_err/et/et_h.awk com_err/et/test1.et com_err/et/test2.et \
	com_err/et/test_et.c lib/charset/aliases.txt lib/charset/big5.t \
	lib/charset/gb2312.t lib/charset/iso-2022-jp.t \
	lib/charset/iso-2022-kr.t lib/charset/iso-8859-10.t \
	lib/charset/iso-8859-11.t lib/charset/iso-8859-13.t \
	lib/charset/iso-8859-14.t lib/charset/iso-8859-15.t \
	lib/charset/iso-8859-16.t lib/charset/iso-8859-1.t \
	lib/charset/iso-8859-2.t lib/charset/iso-8859-3.t \
	lib/charset/iso-8859-4.t lib/charset/iso-8859-5.t \
	lib/charset/iso-8859-6.t lib/charset/iso-8859-7.t \
	lib/charset/iso-8859-8.t lib/charset/iso-8859-9.t \
	lib/charset/koi8-r.t lib/charset/UnicodeData.txt \
	lib/charset/unifix.txt lib/charset/us-ascii.t \
	lib/charset/windows-1250.t lib/charset/windows-1251.t \
	lib/charset/windows-1252.t lib/charset/windows-1255.t \
	lib/charset/windows-1256.t lib/test/cyrusdb.c lib/test/cyrusdb.INPUT \
	lib/test/cyrusdblong.INPUT lib/test/cyrusdblong.OUTPUT \
	lib/test/cyrusdb.OUTPUT lib/test/cyrusdbtxn.INPUT \
	lib/test/cyrusdbtxn.OUTPUT lib/test/pool.c lib/test/rnddb.c \
	lib/test/testglob2.c \
	master/CYRUS-MASTER.mib master/conf/cmu-backend.conf master/conf/cmu-frontend.conf master/conf/normal.conf master/conf/prefork.conf master/conf/small.conf master/README \
	sieve/test/testExtension sieve/test/testExtension/uberExtensionTestScript.key sieve/test/testExtension/testm sieve/test/testExtension/testm/uetest-envelope sieve/test/testExtension/testm/uetest-asub sieve/test/testExtension/testm/uetest-areg sieve/test/testExtension/testm/uetest-count sieve/test/testExtension/testm/uetest-value sieve/test/testExtension/testm/uetest-hreg sieve/test/testExtension/serverm sieve/test/testExtension/serverm/uetmail-hreg sieve/test/testExtension/serverm/uetmail-value sieve/test/testExtension/serverm/uetmail-count2 sieve/test/testExtension/serverm/uetmail-envelope sieve/test/testExtension/serverm/uetmail-asub sieve/test/testExtension/serverm/uetmail-value2 sieve/test/testExtension/serverm/uetmail-areg sieve/test/testExtension/serverm/uetmail-count sieve/test/testExtension/uberExtensionTestScript.s sieve/test/README sieve/test/action sieve/test/action/testm sieve/test/action/testm/uatest-keep sieve/test/action/testm/uatest-redirect sieve/test/action/testm/uatest-discard sieve/test/action/testm/uatest-stop2 sieve/test/action/testm/uatest-stop sieve/test/action/serverm sieve/test/action/serverm/uamail-stop2 sieve/test/action/serverm/uamail-redirect sieve/test/action/serverm/uamail-stop sieve/test/action/serverm/uamail-keep sieve/test/action/serverm/uamail-discard sieve/test/action/uberActionScript.key sieve/test/action/uberActionScript.s sieve/test/test sieve/test/test/uberTestScript.key sieve/test/test/testm sieve/test/test/testm/utest-header sieve/test/test/testm/utest-address sieve/test/test/serverm sieve/test/test/serverm/utmail-address sieve/test/test/serverm/utmail-header sieve/test/test/uberTestScript.s sieve/test/actionExtensions sieve/test/actionExtensions/uberExtensionActionScript.s sieve/test/actionExtensions/testm sieve/test/actionExtensions/testm/ueatest-flag4 sieve/test/actionExtensions/testm/ueatest-flag2 sieve/test/actionExtensions/testm/ueatest-fileinto sieve/test/actionExtensions/testm/ueatest-denotify sieve/test/actionExtensions/testm/ueatest-vacation sieve/test/actionExtensions/testm/ueatest-reject sieve/test/actionExtensions/testm/ueatest-mark sieve/test/actionExtensions/testm/ueatest-denotify2 sieve/test/actionExtensions/testm/ueatest-flag5 sieve/test/actionExtensions/testm/ueatest-notify2 sieve/test/actionExtensions/testm/ueatest-notify sieve/test/actionExtensions/testm/ueatest-flag1 sieve/test/actionExtensions/testm/ueatest-flag3 sieve/test/actionExtensions/testm/ueatest-unmark sieve/test/actionExtensions/uberExtensionActionScript.key sieve/test/actionExtensions/serverm sieve/test/actionExtensions/serverm/ueamail-flag4 sieve/test/actionExtensions/serverm/ueamail-denotify sieve/test/actionExtensions/serverm/ueamail-mark sieve/test/actionExtensions/serverm/ueamail-denotify2 sieve/test/actionExtensions/serverm/ueamail-flag2 sieve/test/actionExtensions/serverm/ueamail-unmark sieve/test/actionExtensions/serverm/ueamail-reject sieve/test/actionExtensions/serverm/ueamail-flag3 sieve/test/actionExtensions/serverm/ueamail-fileinto sieve/test/actionExtensions/serverm/ueamail-flag1 sieve/test/actionExtensions/serverm/ueamail-notify sieve/test/actionExtensions/serverm/ueamail-flag5 sieve/test/actionExtensions/serverm/ueamail-notify2 sieve/test/actionExtensions/serverm/ueamail-vacation

TEXINFO_TEX = com_err/et/texinfo.tex
EXTRA_SCRIPTS = com_err/et/compile_et.sh com_err/et/config_script \
	lib/imapoptions lib/mkchartable.pl lib/test/run
noinst_MAN = com_err/et/com_err.3 com_err/et/compile_et.1
noinst_TEXINFOS = com_err/et/com_err.texinfo

com_err_et_libcom_err_a_SOURCES = com_err/et/com_err.c com_err/et/com_err.h \
	com_err/et/error_message.c com_err/et/error_table.h \
	com_err/et/et_name.c com_err/et/init_et.c com_err/et/internal.h \
	com_err/et/mit-sipb-copyright.h

com_err/et/compile_et: com_err/et/compile_et.sh com_err/et/config_script \
	config.h
	@${top_srcdir}/com_err/et/config_script ${top_srcdir}/com_err/et/compile_et.sh ${AWK} ${SED} > $@
	@chmod 755 $@

includedir=@includedir@/cyrus
include_HEADERS = lib/acl.h lib/assert.h lib/auth.h lib/auth_pts.h \
	lib/bsearch.h lib/charset.h lib/chartable.h lib/crc32.h \
	lib/cyr_lock.h lib/cyrusdb.h lib/exitcodes.h lib/glob.h lib/gmtoff.h \
	lib/hash.h lib/imapopts.h lib/imapurl.h lib/imclient.h lib/imparse.h \
	lib/iostat.h lib/iptostring.h lib/libcyr_cfg.h lib/lsort.h \
	lib/map.h lib/mappedfile.h lib/mkgmtime.h lib/mpool.h lib/nonblock.h \
	lib/parseaddr.h lib/retry.h lib/rfc822date.h lib/signals.h \
	lib/strhash.h lib/stristr.h lib/sysexits.h lib/times.h lib/tok.h \
	lib/wildmat.h lib/xmalloc.h

noinst_HEADERS = lib/byteorder64.h lib/gai.h lib/libconfig.h lib/md5.h \
	lib/prot.h lib/ptrarray.h lib/strarray.h lib/util.h lib/xstrlcat.h \
	lib/xstrlcpy.h

lib_libcyrus_a_SOURCES = lib/acl.c lib/acl_afs.c lib/auth.c lib/auth_krb.c \
	lib/auth_krb5.c lib/auth_pts.c lib/auth_unix.c lib/bsearch.c \
	lib/byteorder64.c lib/charset.c lib/chartable.c lib/crc32.c \
	lib/cyrusdb.c 
if USE_BERKELEY
lib_libcyrus_a_SOURCES += lib/cyrusdb_berkeley.c
endif
lib_libcyrus_a_SOURCES += lib/cyrusdb_flat.c lib/cyrusdb_quotalegacy.c \
	lib/cyrusdb_skiplist.c
if USE_SQL
lib_libcyrus_a_SOURCES += lib/cyrusdb_sql.c
endif
lib_libcyrus_a_SOURCES += lib/cyrusdb_twoskip.c lib/glob.c
if GMTOFF_TM
lib_libcyrus_a_SOURCES += lib/gmtoff_tm.c
else
lib_libcyrus_a_SOURCES += lib/gmtoff_gmtime.c
endif
lib_libcyrus_a_SOURCES += lib/imapurl.c lib/imclient.c lib/imparse.c \
	lib/iostat.c lib/iptostring.c lib/libcyr_cfg.c lib/lsort.c \
	lib/mkgmtime.c
if NONBLOCK_FCNTL
lib_libcyrus_a_SOURCES += lib/nonblock_fcntl.c
else
lib_libcyrus_a_SOURCES += lib/nonblock_ioctl.c
endif
lib_libcyrus_a_SOURCES += lib/parseaddr.c lib/prot.c lib/ptrarray.c \
	lib/signals.c lib/stristr.c lib/times.c lib/tok.c lib/wildmat.c

lib_libcyrus_min_a_SOURCES = lib/assert.c
if IPV6_noGETADDRINFO
lib_libcyrus_min_a_SOURCES += lib/getaddrinfo.c
endif
if IPV6_noGETNAMEINFO
lib_libcyrus_min_a_SOURCES += lib/getnameinfo.c
endif
lib_libcyrus_min_a_SOURCES += lib/hash.c lib/imapopts.c lib/libconfig.c
if LOCK_FCNTL
lib_libcyrus_min_a_SOURCES += lib/lock_fcntl.c
else
lib_libcyrus_min_a_SOURCES += lib/lock_flock.c
endif
lib_libcyrus_min_a_SOURCES += lib/mappedfile.c
if MAP_SHARED
lib_libcyrus_min_a_SOURCES += lib/map_shared.c
else
if MAP_STUPIDSHARED
lib_libcyrus_min_a_SOURCES += lib/map_stupidshared.c
else
lib_libcyrus_min_a_SOURCES += lib/map_nommap.c
endif
endif
lib_libcyrus_min_a_SOURCES += lib/mpool.c lib/retry.c lib/strarray.c \
	lib/strhash.c lib/util.c lib/xmalloc.c lib/xstrlcat.c lib/xstrlcpy.c
lib_libcyrus_min_a_LIBADD = $(LIBOBJS)


lib/chartable.c: lib/mkchartable.pl lib/charset/unifix.txt \
	$(top_srcdir)/lib/charset/*.t lib/charset/UnicodeData.txt \
	lib/charset/aliases.txt
	@echo "### Building chartables..."
	perl $(top_srcdir)/lib/mkchartable.pl -m $(top_srcdir)/lib/charset/unifix.txt -m $(top_srcdir)/lib/charset/UnicodeData.txt -a $(top_srcdir)/lib/charset/aliases.txt -o $@ $(top_srcdir)/lib/charset/*.t
	@echo "### Done building chartables."

lib/imapopts.c: lib/imapoptions tools/config2header
	$(top_srcdir)/tools/config2header CC="$(CC)" $(top_builddir)/lib/imapopts.c $(top_builddir)/lib/imapopts.h < $(top_srcdir)/lib/imapoptions

#this is from lib/test/Makefile.in, however testglob.c does not exist in
#/lib/test, instead testglob2.c is there.
#lib_test_testglob_LIRBARIES = lib/libcyrus.a lib/libcyrus_min.a -ldb-4.0


DISTSUBDIRS = doc

SHELL = /bin/sh
@SET_MAKE@

dist_man_MANS = man/imtest.1 man/installsieve.1 man/lmtptest.1 \
	man/mupdatetest.1 man/nntptest.1 man/pop3test.1 man/sieveshell.1 \
	man/sivtest.1 man/smtptest.1 \
	man/imclient.3 \
	man/cyrus.conf.5 man/imapd.conf.5 man/krb.equiv.5 \
	man/arbitron.8 man/chk_cyrus.8 man/ctl_cyrusdb.8 man/ctl_deliver.8 \
	man/ctl_mboxlist.8 man/cyr_expire.8 man/cvt_cyrusdb.8 \
	man/cyr_dbtool.8 man/cyr_df.8 man/cyr_info.8 man/cyr_synclog.8 \
	man/deliver.8 man/fetchnews.8 man/fud.8 man/idled.8 man/imapd.8 \
	man/ipurge.8 man/lmtpd.8 man/master.8 man/mbexamine.8 man/mbpath.8 \
	man/nntpd.8 man/notifyd.8 man/pop3d.8 man/quota.8 man/reconstruct.8 \
	man/rmnews.8 man/smmapd.8 man/squatter.8 man/syncnews.8 \
	man/sync_client.8 man/sync_reset.8 man/sync_server.8 man/timsieved.8 \
	man/tls_prune.8 man/unexpunge.8

master_master_SOURCES = master/cyrusMasterMIB.c master/cyrusMasterMIB.h \
	master/master.c master/master.h master/masterconf.c \
	master/masterconf.h master/service.h
master_master_LDADD = lib/libcyrus_min.a @LIB_UCDSNMP@ @LIBS@ -lm $(DEPLIBS)

sieve_libsieve_a_SOURCES = sieve/bytecode.h sieve/addr.y sieve/addr-lex.l \
	sieve/bc_dump.c sieve/bc_emit.c sieve/bc_eval.c sieve/bc_generate.c \
	sieve/comparator.c sieve/comparator.h sieve/interp.c sieve/interp.h \
	sieve/message.c sieve/message.h sieve/script.c sieve/script.h \
	sieve/sieve-lex.l sieve/sieve.y sieve/sieve_err.c sieve/sieve_err.h \
	sieve/sieve_interface.h sieve/tree.c sieve/tree.h

sieve_sievec_LDADD = sieve/libsieve.a lib/libcyrus.a lib/libcyrus_min.a ${COM_ERR_LIBS} @DEPLIBS@ @LIB_RT@ ${LIB_SASL} @LIB_UUID@
sieve_sieved_LDADD = ${sieve_sievec_LDADD}

sieve/sieve_err.h sieve/sieve_err.c: sieve/sieve_err.et
	cd sieve && $(top_builddir)/../$(COMPILE_ET) ../$(top_srcdir)/sieve/sieve_err.et

sieve_test_SOURCES = sieve/test.c imap/mutex_fake.c
sieve_test_LDADD = imap/libimap.a ${sieve_sievec_LDADD}

GIT_VERSION = $(PACKAGE_VERSION).git$(shell date +'%Y%m%d%H%M')

snapshot::
	@echo "creating snapshot $(GIT_VERSION)"
	@$(MKDIR_P) snapshot
	@git archive --format=tar --prefix=$(PACKAGE_NAME)-$(GIT_VERSION)/ HEAD | tar -C snapshot/ -x -f -
	@echo "/* $(PACKAGE_NAME) $(GIT_VERSION) */" > snapshot/$(PACKAGE_NAME)-$(GIT_VERSION)/xversion.h
	@echo "#define _CYRUS_VERSION \"git$(PACKAGE_VERSION)+`git log --pretty=oneline $(PACKAGE_NAME)-$(PACKAGE_VERSION)..HEAD | wc -l`\"" >> snapshot/$(PACKAGE_NAME)-$(GIT_VERSION)/xversion.h
	@echo "#define CYRUS_GITVERSION \"`git log --abbrev=8 --pretty=\"format:%h %ci\" -1 | cut -d\" \" -f1,2`\"" >> snapshot/$(PACKAGE_NAME)-$(GIT_VERSION)/xversion.h
	@touch snapshot/$(PACKAGE_NAME)-$(GIT_VERSION)/xversion
	@cd snapshot/$(PACKAGE_NAME)-$(GIT_VERSION) ; sh SMakefile
	@for d in $(DIST_SUBDIRS) $(DISTSUBDIRS); \
	do \
	(cd snapshot/$(PACKAGE_NAME)-$(GIT_VERSION)/$$d; \
	if [ -f Makefile.dist ]; then \
	echo "### Making" snapshot "in" `pwd`; \
	$(MAKE) $(MFLAGS) YACC='$(YACC)' LEX='$(LEX)' \
	COMPILE_ET='$(COMPILE_ET)' -f Makefile.dist dist ; \
	fi) || exit 1; \
	done
	@echo "creating tarfile"
	tar -C snapshot -c -f - $(PACKAGE_NAME)-$(GIT_VERSION) | gzip -9 > $(PACKAGE_NAME)-$(GIT_VERSION).tar.gz
	@rm -rf snapshot

man/imapd.conf.5:
	@echo creating man/imapd.conf.5
	@$(MKDIR_P) man
	$(top_srcdir)/tools/config2man $(top_srcdir)/lib/imapoptions > man/imapd.conf.5

man/sieveshell.1: $(top_srcdir)/perl/sieve/scripts/sieveshell.pl
	@echo creating man/sieveshell.1
	@$(MKDIR_P) man
	pod2man $(top_srcdir)/perl/sieve/scripts/sieveshell.pl > man/sieveshell.1

dist-old:: distgit
	@echo "creating configure"
	@cd dist/cyrus-imapd-$(PACKAGE_VERSION) ; sh SMakefile
	@for d in $(DIST_SUBDIRS) $(DISTSUBDIRS); \
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
	@echo "#define _CYRUS_VERSION \"git$(PACKAGE_VERSION)+`git log --pretty=oneline $(PACKAGE_NAME)-$(PACKAGE_VERSION)..HEAD | wc -l`\"" >> xversion.h.tmp
	@echo "#define CYRUS_GITVERSION \"`git log --abbrev=8 --pretty=\"format:%h %ci\" -1 | cut -d\" \" -f1,2`\"" >> xversion.h.tmp
	@cmp -s xversion.h.tmp xversion.h || mv xversion.h.tmp xversion.h
	@rm -f xversion.h.tmp

valgrind:
	$(MAKE) VG=yes check

depend::
	@for d in  $(DIST_SUBDIRS); \
	do \
		(cd $$d; echo "### Making" depend "in" `pwd`;	\
			$(MAKE) $(MFLAGS) DESTDIR=$(DESTDIR) depend) || exit 1; \
	done

coverage_all:
	$(MAKE) COVERAGE="--coverage" EXTRACFLAGS="--coverage" EXTRALDFLAGS="--coverage" all

coverage_check:
	$(MAKE) COVERAGE="--coverage" EXTRACFLAGS="--coverage" EXTRALDFLAGS="--coverage" check

tags cscope:
	find $(DIST_SUBDIRS) -type f -name '*.[ch]' > cs.files
	cscope -b -k -i cs.files
	$(RM) cs.files

checkdepend::

depend::
	echo '/^# DO NOT DELETE THIS LINE/+2,$$d' >eddep
	echo 'w' >>eddep
	cp Makefile Makefile.bak
	ed -s Makefile < eddep
	rm eddep
	echo '' >> Makefile
	echo '# IF YOU PUT STUFF HERE IT WILL GO AWAY' >> Makefile
	echo '# see make depend above' >> Makefile

# DO NOT DELETE THIS LINE -- make depend uses it

# The following rule ensures that "make depend" gets run at least
# once before a "make all".  The "depend" rule above removes
# this rule from the Makefile the first time the "make depend"
# has been run after the Makefile is generated by Configure

checkdepend:: depend

# IF YOU PUT STUFF HERE IT WILL GO AWAY
# see make depend above
