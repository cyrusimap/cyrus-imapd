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
AM_CPPFLAGS = @COM_ERR_CPPFLAGS@ -I${top_builddir} -I${top_builddir}/lib -I${top_srcdir} -I${top_srcdir}/lib ${DEFS} ${LOCALDEFS} @SASLFLAGS@
AM_LDFLAGS = ${EXTRALDFLAGS}
BUILT_SOURCES = xversion.h lib/imapopts.c

SUBDIRS = .
dist_doc_DATA = README README.andrew
dist_sysconf_DATA =
check_LIBRARIES =
noinst_LIBRARIES =
lib_LIBRARIES = lib/libcyrus.a lib/libcyrus_min.a
noinst_PROGRAMS = doc/text/htmlstrip
check_PROGRAMS =
service_PROGRAMS =

if COM_ERR
BUILT_SOURCES += com_err/et/compile_et
noinst_LIBRARIES += com_err/et/libcom_err.a
COM_ERR_LIBS += com_err/et/libcom_err.a
endif

bin_PROGRAMS = imtest/imtest
if SYSLOG
noinst_LIBRARIES += syslog/libsyslog.a
noinst_PROGRAMS += syslog/syslogd
endif
if SERVER
BUILT_SOURCES += imap/imap_err.c imap/mupdate_err.c imap/nntp_err.c \
	imap/lmtpstats.c imap/pushstats.c imap/rfc822_header.c \
	imap/rfc822_header.h
noinst_LIBRARIES += imap/libimap.a
service_PROGRAMS += imap/arbitron imap/chk_cyrus imap/ctl_cyrusdb \
	imap/ctl_deliver imap/ctl_mboxlist imap/cvt_cyrusdb imap/cyr_df \
	imap/cyrdump imap/cyr_dbtool imap/cyr_expire imap/cyr_info \
	imap/cyr_sequence imap/cyr_synclog imap/cyr_userseen imap/deliver
if NNTPD
service_PROGRAMS += imap/fetchnews
endif
service_PROGRAMS += imap/fud
if IDLED
service_PROGRAMS += imap/idled
endif
service_PROGRAMS += imap/imapd imap/ipurge imap/lmtpd imap/mbexamine \
	imap/mbpath imap/mbtool
if MURDER
service_PROGRAMS += imap/mupdate
endif
if NNTPD
service_PROGRAMS += imap/nntpd
endif
service_PROGRAMS += imap/pop3d imap/quota imap/reconstruct imap/smmapd \
	imap/squatter
if REPLICATION
service_PROGRAMS += imap/sync_client imap/sync_reset imap/sync_server
endif
if WITH_OPENSSL
service_PROGRAMS += imap/tls_prune
endif
service_PROGRAMS += imap/unexpunge master/master
endif
if CMULOCAL
dist_sysconf_DATA += depot/rc.local.imap depot/rc.local.ptclient
service_PROGRAMS += netnews/remotepurge
endif
if SIEVE
if SERVER
check_PROGRAMS += notifyd/notifytest
service_PROGRAMS += notifyd/notifyd
endif
endif
if PTCLIENT
service_PROGRAMS += ptclient/ptdump ptclient/ptexpire ptclient/ptloader
# ptclient/ptextract
endif
if PERL
SUBDIRS += perl/annotator perl/imap
BUILT_SOURCES += perl/imap/Makefile perl/annotator/Makefile
endif
if SIEVE
if PERL
SUBDIRS += perl/sieve/managesieve
BUILT_SOURCES += perl/sieve/managesieve/Makefile
noinst_LIBRARIES += perl/sieve/lib/libisieve.a
endif
BUILT_SOURCES += sieve/addr.c sieve/sieve.c sieve/sieve_err.c
lib_LIBRARIES += sieve/libsieve.a
check_PROGRAMS += installsieve/installsieve
check_LIBRARIES += installsieve/libinstallsieve.a
check_PROGRAMS += sieve/test
service_PROGRAMS += sieve/sievec sieve/sieved
if SERVER
service_PROGRAMS += timsieved/timsieved
endif
endif

if CUNIT
SUBDIRS += cunit
endif

EXTRA_DIST = xversion.h SMakefile COPYRIGHT \
	com_err/et/com_err com_err/et/et_c.awk com_err/et/et_h.awk \
	com_err/et/test1.et com_err/et/test2.et com_err/et/test_et.c \
	contrib/drac_auth.patch contrib/sieve-spamasssassin contrib/fud-client.c contrib/deliver-notify-zephyr.patch contrib/add-cyrus-user contrib/README contrib/cyrus-graphtools.1.0 contrib/cyrus-graphtools.1.0/cgi-bin/cyrus_master.pl contrib/cyrus-graphtools.1.0/cgi-bin/graph_cyrus_db.pl contrib/cyrus-graphtools.1.0/cgi-bin/graph_cyrus_db-sum.pl contrib/cyrus-graphtools.1.0/html contrib/cyrus-graphtools.1.0/html/index.html contrib/cyrus-graphtools.1.0/README contrib/cyrus-graphtools.1.0/script contrib/cyrus-graphtools.1.0/script/cyrus.pl contrib/cyrus-graphtools.1.0/script/run contrib/cyrus-graphtools.1.0/script/cyrusrc contrib/notify_unix/notify contrib/notify_unix/net-server-prefork-0.01.tgz contrib/notify_unix/README contrib/notify_unix/sql_notify.pl contrib/notify_unix/simple_notify.pl contrib/squatrunner.pl contrib/mupdate-test.pl contrib/squatrunner.txt \
	lib/charset/aliases.txt lib/charset/big5.t \
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
	netnews/inn.diffs \
	perl/annotator/Daemon.pm perl/annotator/Makefile.PL perl/annotator/MANIEST perl/annotator/Message.pm perl/annotator/README \
	perl/imap/Changes perl/imap/cyradm.sh perl/imap/cyrperl.h perl/imap/Cyrus/Shell.pm perl/imap/examples/auditmbox.pl perl/imap/examples/imapcollate.pl perl/imap/examples/imapdu.pl perl/imap/example/test-imsp.pl perl/imap/IMAP/Admin.pm perl/imap/IMAP/IMSP.pm perl/imap/IMAP/Shell.pm perl/imap/IMAP.pm perl/imap/IMAP.xs perl/imap/Makefile.PL perl/imap/README perl/imap/t/01-imclient.t perl/imap/t/02-admin.t perl/imap/typemap perl/imap/xsutil.c \
	perl/sieve/managesieve/Makefile.PL perl/sieve/managesieve/managesieve.h perl/sieve/managesieve/managesieve.pm perl/sieve/managesieve/managesieve.xs perl/sieve/managesieve/MANIFEST perl/sieve/managesieve/typemap \
	ptclient/README ptclient/test.c ptclient/test2.c \
	sieve/tests/testExtension sieve/tests/testExtension/uberExtensionTestScript.key sieve/tests/testExtension/testm sieve/tests/testExtension/testm/uetest-envelope sieve/tests/testExtension/testm/uetest-asub sieve/tests/testExtension/testm/uetest-areg sieve/tests/testExtension/testm/uetest-count sieve/tests/testExtension/testm/uetest-value sieve/tests/testExtension/testm/uetest-hreg sieve/tests/testExtension/serverm sieve/tests/testExtension/serverm/uetmail-hreg sieve/tests/testExtension/serverm/uetmail-value sieve/tests/testExtension/serverm/uetmail-count2 sieve/tests/testExtension/serverm/uetmail-envelope sieve/tests/testExtension/serverm/uetmail-asub sieve/tests/testExtension/serverm/uetmail-value2 sieve/tests/testExtension/serverm/uetmail-areg sieve/tests/testExtension/serverm/uetmail-count sieve/tests/testExtension/uberExtensionTestScript.s sieve/tests/README sieve/tests/action sieve/tests/action/testm sieve/tests/action/testm/uatest-keep sieve/tests/action/testm/uatest-redirect sieve/tests/action/testm/uatest-discard sieve/tests/action/testm/uatest-stop2 sieve/tests/action/testm/uatest-stop sieve/tests/action/serverm sieve/tests/action/serverm/uamail-stop2 sieve/tests/action/serverm/uamail-redirect sieve/tests/action/serverm/uamail-stop sieve/tests/action/serverm/uamail-keep sieve/tests/action/serverm/uamail-discard sieve/tests/action/uberActionScript.key sieve/tests/action/uberActionScript.s sieve/tests/test sieve/tests/test/uberTestScript.key sieve/tests/test/testm sieve/tests/test/testm/utest-header sieve/tests/test/testm/utest-address sieve/tests/test/serverm sieve/tests/test/serverm/utmail-address sieve/tests/test/serverm/utmail-header sieve/tests/test/uberTestScript.s sieve/tests/actionExtensions sieve/tests/actionExtensions/uberExtensionActionScript.s sieve/tests/actionExtensions/testm sieve/tests/actionExtensions/testm/ueatest-flag4 sieve/tests/actionExtensions/testm/ueatest-flag2 sieve/tests/actionExtensions/testm/ueatest-fileinto sieve/tests/actionExtensions/testm/ueatest-denotify sieve/tests/actionExtensions/testm/ueatest-vacation sieve/tests/actionExtensions/testm/ueatest-reject sieve/tests/actionExtensions/testm/ueatest-mark sieve/tests/actionExtensions/testm/ueatest-denotify2 sieve/tests/actionExtensions/testm/ueatest-flag5 sieve/tests/actionExtensions/testm/ueatest-notify2 sieve/tests/actionExtensions/testm/ueatest-notify sieve/tests/actionExtensions/testm/ueatest-flag1 sieve/tests/actionExtensions/testm/ueatest-flag3 sieve/tests/actionExtensions/testm/ueatest-unmark sieve/tests/actionExtensions/uberExtensionActionScript.key sieve/tests/actionExtensions/serverm sieve/tests/actionExtensions/serverm/ueamail-flag4 sieve/tests/actionExtensions/serverm/ueamail-denotify sieve/tests/actionExtensions/serverm/ueamail-mark sieve/tests/actionExtensions/serverm/ueamail-denotify2 sieve/tests/actionExtensions/serverm/ueamail-flag2 sieve/tests/actionExtensions/serverm/ueamail-unmark sieve/tests/actionExtensions/serverm/ueamail-reject sieve/tests/actionExtensions/serverm/ueamail-flag3 sieve/tests/actionExtensions/serverm/ueamail-fileinto sieve/tests/actionExtensions/serverm/ueamail-flag1 sieve/tests/actionExtensions/serverm/ueamail-notify sieve/tests/actionExtensions/serverm/ueamail-flag5 sieve/tests/actionExtensions/serverm/ueamail-notify2 sieve/tests/actionExtensions/serverm/ueamail-vacation \
	syslog/syslog.conf syslog/README syslog/logger.c \
	timsieved/TODO

TEXINFO_TEX = com_err/et/texinfo.tex
EXTRA_SCRIPTS = com_err/et/compile_et.sh com_err/et/config_script \
	lib/imapoptions lib/mkchartable.pl lib/test/run \
	perl/sieve/scripts/installsieve.pl perl/sieve/scripts/sieveshell.pl \
	tools/arbitronsort.pl tools/compile_st.pl tools/config2header tools/config2man tools/convert-sieve.pl tools/dohash tools/masssievec tools/migrate-metadata tools/mkimap tools/mknewsgroups tools/mupdate-loadgen.pl tools/rehash tools/translatesieve tools/undohash tools/upgradesieve \
	snmp/snmpgen \
	autobuild.sh
noinst_MAN = com_err/et/com_err.3 com_err/et/compile_et.1 syslog/logger.1 \
	syslog/syslog.3 syslog/syslog.8
noinst_TEXINFOS = com_err/et/com_err.texinfo

com_err_et_libcom_err_a_SOURCES = com_err/et/com_err.c com_err/et/com_err.h \
	com_err/et/error_message.c com_err/et/error_table.h \
	com_err/et/et_name.c com_err/et/init_et.c com_err/et/internal.h \
	com_err/et/mit-sipb-copyright.h

com_err/et/compile_et: com_err/et/compile_et.sh com_err/et/config_script \
	config.h
	@${top_srcdir}/com_err/et/config_script ${top_srcdir}/com_err/et/compile_et.sh ${AWK} ${SED} > $@
	@chmod 755 $@

doc_text_htmlstrip_SOURCE = doc/text/htmlstrip.c

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

imap_arbitron_SOURCES = imap/arbitron.c imap/cli_fatal.c imap/mutex_fake.c
imap_arbitron_LDADD = $(ptclient_ptdump_LDADD)

imap_chk_cyrus_SOURCES = imap/chk_cyrus.c imap/cli_fatal.c imap/mutex_fake.c
imap_chk_cyrus_LDADD = $(ptclient_ptdump_LDADD)

imap_ctl_cyrusdb_SOURCES = imap/cli_fatal.c imap/ctl_cyrusdb.c imap/mutex_fake.c
imap_ctl_cyrusdb_LDADD = $(ptclient_ptdump_LDADD)

imap_ctl_deliver_SOURCES = imap/cli_fatal.c imap/ctl_deliver.c imap/mutex_fake.c
imap_ctl_deliver_LDADD = $(ptclient_ptdump_LDADD)

imap_ctl_mboxlist_SOURCES = imap/cli_fatal.c imap/ctl_mboxlist.c imap/mutex_fake.c
imap_ctl_mboxlist_LDADD = $(ptclient_ptdump_LDADD)

imap_cvt_cyrusdb_SOURCES = imap/cli_fatal.c imap/cvt_cyrusdb.c imap/mutex_fake.c
imap_cvt_cyrusdb_LDADD = $(ptclient_ptdump_LDADD)

imap_cyrdump_SOURCES = imap/cli_fatal.c imap/cyrdump.c imap/index.c imap/mutex_fake.c
imap_cyrdump_LDADD = $(ptclient_ptdump_LDADD)

imap_cyr_dbtool_SOURCES = imap/cli_fatal.c imap/cyr_dbtool.c imap/mutex_fake.c
imap_cyr_dbtool_LDADD = $(ptclient_ptdump_LDADD)

imap_cyr_df_SOURCES = imap/cli_fatal.c imap/cyr_df.c imap/mutex_fake.c
imap_cyr_df_LDADD = $(ptclient_ptdump_LDADD)

imap_cyr_expire_SOURCES = imap/cli_fatal.c imap/cyr_expire.c imap/mutex_fake.c
imap_cyr_expire_LDADD = $(ptclient_ptdump_LDADD)

imap_cyr_info_SOURCES = imap/cli_fatal.c imap/cyr_info.c imap/mutex_fake.c master/masterconf.c
imap_cyr_info_LDADD = $(ptclient_ptdump_LDADD)

imap_cyr_sequence_SOURCES = imap/cli_fatal.c imap/cyr_sequence.c imap/mutex_fake.c
imap_cyr_sequence_LDADD = $(ptclient_ptdump_LDADD)

imap_cyr_synclog_SOURCES = imap/cli_fatal.c imap/cyr_synclog.c imap/mutex_fake.c
imap_cyr_synclog_LDADD = $(ptclient_ptdump_LDADD)

imap_cyr_userseen_SOURCES = imap/cli_fatal.c imap/cyr_userseen.c imap/mutex_fake.c
imap_cyr_userseen_LDADD = $(ptclient_ptdump_LDADD)

#imap_cyr_virusscan_SOURCES = imap/cli_fatal.c imap/cyr_virusscan.c imap/index.c imap/mutex_fake.c
#imap_cyr_virusscan_LDADD = $(ptclient_ptdump_LDADD) -lclamav

imap_deliver_SOURCES = imap/deliver.c imap/lmtpengine.c imap/lmtpstats.c imap/mutex_fake.c imap/proxy.c imap/spool.c
imap_deliver_LDADD = $(ptclient_ptdump_LDADD)

imap_fetchnews_SOURCES = imap/cli_fatal.c imap/fetchnews.c imap/mutex_fake.c
imap_fetchnews_LDADD = $(ptclient_ptdump_LDADD)

imap_fud_SOURCES = imap/fud.c imap/mutex_fake.c master/service.c
imap_fud_LDADD = $(ptclient_ptdump_LDADD) @LIB_WRAP@

imap_idled_SOURCES = imap/idled.c imap/mutex_fake.c
imap_idled_LDADD = $(ptclient_ptdump_LDADD)

imap_imapd_SOURCES = imap/imap_proxy.c imap/imap_proxy.h imap/imapd.c imap/imapd.h imap/index.c imap/mutex_fake.c imap/pushstats.c imap/pushstats.h imap/proxy.c master/service.c
imap_imapd_LDADD = $(imap_fud_LDADD)

imap_ipurge_SOURCES = imap/cli_fatal.c imap/ipurge.c imap/mutex_fake.c
imap_ipurge_LDADD = $(ptclient_ptdump_LDADD)

imap_libimap_a_SOURCES = imap/annotate.c imap/annotate.h imap/append.c \
	imap/append.h imap/backend.c imap/backend.h imap/convert_code.c \
	imap/convert_code.h imap/dlist.c imap/dlist.h imap/duplicate.c \
	imap/duplicate.h imap/global.c imap/global.h imap/idle.c imap/idle.h \
	imap/idlemsg.c imap/idlemsg.h imap/imapparse.c imap/imap_err.c \
	imap/index.h imap/mailbox.c imap/mailbox.c imap/mbdump.c \
	imap/mbdump.h imap/mboxkey.c imap/mboxkey.h imap/mboxlist.c \
	imap/mboxlist.h imap/mboxname.c imap/mboxname.h imap/message_guid.c \
	imap/message_guid.h imap/message.c imap/message.h \
	imap/mupdate-client.c imap/mupdate-client.h imap/mupdate_err.c \
	imap/mupdate_err.h imap/mutex.h imap/notify.c imap/notify.h \
	imap/proc.c imap/proc.h imap/protocol.h imap/quota_db.c \
	imap/rfc822_header.c imap/rfc822_header.h imap/saslclient.c \
	imap/saslclient.h imap/saslserver.c imap/search_engines.c \
	imap/search_engines.h imap/seen.h imap/seen_db.c imap/sequence.c \
	imap/sequence.h imap/setproctitle.c imap/squat.c imap/squat.h \
	imap/squat_internal.c imap/squat_internal.h imap/statuscache.h \
	imap/statuscache_db.c imap/sync_log.c imap/sync_log.h \
	imap/telemetry.c imap/telemetry.h imap/tls.c imap/tls.h \
	imap/upgrade_index.c imap/upgrade_index.h imap/user.c imap/user.h \
	imap/userdeny_db.c imap/userdeny.h imap/version.c imap/version.h

imap_lmtpd_SOURCES = imap/lmtpd.c imap/lmtpd.h imap/lmtpengine.c \
	imap/lmtpengine.h imap/lmtpstats.c imap/lmtpstats.h \
	imap/mutex_fake.c imap/proxy.c imap/spool.c master/service.c
imap_lmtpd_LDADD =
# sieve/libsieve.a must be added to LDADD before lib/libcyrus.a (#3677)
if SIEVE
imap_lmtpd_SOURCES += imap/lmtp_sieve.c imap/smtpclient.c
imap_lmtpd_LDADD += sieve/libsieve.a
endif
imap_lmtpd_LDADD += $(imap_fud_LDADD)

imap/lmtpstats.c: imap/lmtpstats.snmp snmp/snmpgen
	cd imap && ../${top_srcdir}/snmp/snmpgen ../${top_srcdir}/imap/lmtpstats.snmp

imap/pushstats.c: imap/pushstats.snmp snmp/snmpgen
	cd imap && ../${top_srcdir}/snmp/snmpgen ../${top_srcdir}/imap/pushstats.snmp

imap_mbexamine_SOURCES = imap/cli_fatal.c imap/mbexamine.c imap/mutex_fake.c
imap_mbexamine_LDADD = $(ptclient_ptdump_LDADD)

imap_mbpath_SOURCES = imap/cli_fatal.c imap/mbpath.c imap/mutex_fake.c
imap_mbpath_LDADD = $(ptclient_ptdump_LDADD)

imap_mbtool_SOURCES = imap/cli_fatal.c imap/mbtool.c imap/mutex_fake.c
imap_mbtool_LDADD = $(ptclient_ptdump_LDADD)

imap_mupdate_SOURCES = imap/mupdate.c imap/mupdate-slave.c imap/mutex_pthread.c master/service-thread.c
imap_mupdate_LDADD = $(imap_fud_LDADD) -lpthread

imap_nntpd_SOURCES = imap/index.c imap/mutex_fake.c imap/nntpd.c \
	imap/nntp_err.c imap/nntp_err.h imap/proxy.c imap/smtpclient.c \
	imap/smtpclient.h imap/spool.c imap/spool.h master/service.c
imap_nntpd_LDADD = $(imap_fud_LDADD)

imap_pop3d_SOURCES = imap/mutex_fake.c imap/pop3d.c imap/proxy.c master/service.c
imap_pop3d_LDADD = $(imap_fud_LDADD)

imap_quota_SOURCES = imap/cli_fatal.c imap/mutex_fake.c imap/quota.c
imap_quota_LDADD = $(ptclient_ptdump_LDADD)

imap_reconstruct_SOURCES = imap/cli_fatal.c imap/mutex_fake.c imap/reconstruct.c
imap_reconstruct_LDADD = $(ptclient_ptdump_LDADD)

imap_smmapd_SOURCES = imap/mutex_fake.c imap/proxy.c imap/smmapd.c master/service.c
imap_smmapd_LDADD = $(imap_fud_LDADD)

imap_squatter_SOURCES = imap/cli_fatal.c imap/index.c imap/mutex_fake.c imap/squatter.c imap/squat_build.c
imap_squatter_LDADD = $(ptclient_ptdump_LDADD)

imap_sync_client_SOURCES = imap/mutex_fake.c imap/sync_client.c imap/sync_support.c
imap_sync_client_LDADD = $(ptclient_ptdump_LDADD)

imap_sync_reset_SOURCES = imap/mutex_fake.c imap/sync_reset.c imap/sync_support.c
imap_sync_reset_LDADD = $(ptclient_ptdump_LDADD)

imap_sync_server_SOURCES = imap/mutex_fake.c imap/sync_server.c imap/sync_support.c master/service.c
imap_sync_server_LDADD = $(imap_fud_LDADD)

imap_tls_prune_SOURCES = imap/cli_fatal.c imap/mutex_fake.c imap/tls_prune.c
imap_tls_prune_LDADD = $(ptclient_ptdump_LDADD)

imap_unexpunge_SOURCES = imap/cli_fatal.c imap/mutex_fake.c imap/unexpunge.c
imap_unexpunge_LDADD = $(ptclient_ptdump_LDADD)

imap/imap_err.h imap/imap_err.c: imap/imap_err.et
	cd imap && $(COMPILE_ET) ../$(top_srcdir)/imap/imap_err.et

imap/mupdate_err.h imap/mupdate_err.c: imap/mupdate_err.et
	cd imap && $(COMPILE_ET) ../$(top_srcdir)/imap/mupdate_err.et

imap/nntp_err.h imap/nntp_err.c: imap/nntp_err.et
	cd imap && $(COMPILE_ET) ../$(top_srcdir)/imap/nntp_err.et

imap/rfc822_header.c: imap/rfc822_header.st
	${top_srcdir}/tools/compile_st.pl -c $< > $@

imap/rfc822_header.h: imap/rfc822_header.st
	${top_srcdir}/tools/compile_st.pl -h $< > $@

imtest_imtest_SOURCES = imtest/imtest.c
imtest_imtest_LDADD = ${netnews_remotepurge_LDADD}

installsieve_libinstallsieve_a_SOURCES = installsieve/codes.h installsieve/exitcodes.h installsieve/isieve.c installsieve/isieve.h installsieve/lex.c installsieve/lex.h installsieve/mystring.c installsieve/mystring.h installsieve/request.c installsieve/request.h
installsieve_installsieve_SOURCES = installsieve/installscript.c
installsieve_installsieve_LDADD = installsieve/libinstallsieve.a lib/libcyrus.a @SYSLOG_LIBS@ $(LIB_SASL) ${LIBS}

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
	perl $(top_srcdir)/lib/mkchartable.pl -m $(top_srcdir)/lib/charset/unifix.txt -m $(top_srcdir)/lib/charset/UnicodeData.txt -a $(top_srcdir)/lib/charset/aliases.txt -o $@ $(top_srcdir)/lib/charset/*.t || (rm -f $@ && exit 1)
	@echo "### Done building chartables."

lib/imapopts.c: lib/imapoptions tools/config2header
	$(top_srcdir)/tools/config2header CC="$(CC)" $(top_builddir)/lib/imapopts.c $(top_builddir)/lib/imapopts.h < $(top_srcdir)/lib/imapoptions

#this is from lib/test/Makefile.in, however testglob.c does not exist in
#/lib/test, instead testglob2.c is there.
#lib_test_testglob_LIRBARIES = lib/libcyrus.a lib/libcyrus_min.a -ldb-4.0


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
master_master_LDADD = lib/libcyrus_min.a @LIB_UCDSNMP@ @LIBS@ -lm @SYSLOG_LIBS@

netnews_remotepurge_SOURCES = netnews/macros.h netnews/readconfig.c netnews/readconfig.h netnews/remotepurge.c
netnews_remotepurge_LDADD = lib/libcyrus.a lib/libcyrus_min.a @LIB_RT@ ${LIB_SASL} @LIB_UUID@ ${LIBS} @SYSLOG_LIBS@

notifyd_notifyd_SOURCES = imap/mutex_fake.c master/service.c \
	notifyd/exitcodes.h notifyd/notify_external.c \
	notifyd/notify_external.h notifyd/notify_log.c notifyd/notify_log.h \
	notifyd/notify_mailto.c notifyd/notify_mailto.h notifyd/notify_null.c \
	notifyd/notify_null.h notifyd/notify_zephyr.c notifyd/notify_zephyr.h \
	notifyd/notifyd.c notifyd/notifyd.h notifyd/version.h
notifyd_notifyd_LDADD = $(imap_fud_LDADD) @ZEPHYR_LIBS@

notifyd_notifytest_SOURCES = notifyd/notifytest.c imap/mutex_fake.c
notifyd_notifytest_LDADD = ${notifyd_notifyd_LDADD}

perl_sieve_lib_libisieve_a_SOURCES = perl/sieve/lib/isieve.c perl/sieve/lib/lex.c perl/sieve/lib/mystring.c perl/sieve/lib/request.c

perl/annotator/Makefile: perl/annotator/Makefile.PL
	@cd perl/annotator; \
	  $(PERL) ../../${top_srcdir}/perl/annotator/Makefile.PL PREFIX=$(prefix);

perl/imap/Makefile:  perl/imap/Makefile.PL
	@cd perl/imap; \
	  $(PERL) ../../${top_srcdir}/perl/imap/Makefile.PL PREFIX=$(prefix);

perl/sieve/managesieve/Makefile: perl/sieve/managesieve/Makefile.PL
	@cd perl/sieve/managesieve; \
	   $(PERL) ../../../${top_srcdir}/perl/sieve/managesieve/Makefile.PL PREFIX=$(prefix);

ptclient_ptdump_SOURCES = imap/cli_fatal.c imap/mutex_fake.c ptclient/ptdump.c
ptclient_ptdump_LDADD = imap/libimap.a @COM_ERR_LIBS@ $(netnews_remotepurge_LDADD)
ptclient_ptexpire_SOURCES = imap/cli_fatal.c imap/mutex_fake.c ptclient/ptexpire.c
ptclient_ptexpire_LDADD = $(ptclient_ptdump_LDADD)

#ptclient_ptextract_SOURCES = imap/cli_fatal.c imap/mutex_fake.c ptclient/ptextrac.c
#ptclient_ptextract_LDADD = $(ptclient_ptdump_LDADD)

ptclient_ptloader_SOURCES = ptclient/ptloader.c ptclient/ptloader.h imap/mutex_fake.c master/service-thread.c
ptclient_ptloader_LDADD = $(ptclient_ptdump_LDADD) @LIB_WRAP@
ptclient_ptloader_LDFLAGS = 

if USE_LDAP
ptclient_ptloader_SOURCES += ptclient/ldap.c
ptclient_ptloader_LDADD += @LDAP_LIBS@
ptclient_ptloader_LDFLAGS += @LDAP_LDFLAGS@
endif

if USE_AFSKRB
ptclient_ptloader_SOURCES += ptclient/afskrb.c
ptclient_ptloader_LDADD += @AFS_LIBS@
ptclient_ptloader_LDFLAGS += @AFS_LDFLAGS@
endif

sieve_libsieve_a_SOURCES = sieve/bytecode.h sieve/addr.y sieve/addr-lex.l \
	sieve/bc_dump.c sieve/bc_emit.c sieve/bc_eval.c sieve/bc_generate.c \
	sieve/comparator.c sieve/comparator.h sieve/interp.c sieve/interp.h \
	sieve/message.c sieve/message.h sieve/script.c sieve/script.h \
	sieve/sieve-lex.l sieve/sieve.y sieve/sieve_err.c sieve/sieve_err.h \
	sieve/sieve_interface.h sieve/tree.c sieve/tree.h

sieve_sievec_LDADD = sieve/libsieve.a lib/libcyrus.a lib/libcyrus_min.a ${COM_ERR_LIBS} @LIB_RT@ ${LIB_SASL} @LIB_UUID@ @SYSLOG_LIBS@
sieve_sieved_LDADD = ${sieve_sievec_LDADD}

sieve/sieve_err.h sieve/sieve_err.c: sieve/sieve_err.et
	cd sieve && $(COMPILE_ET) ../$(top_srcdir)/sieve/sieve_err.et

sieve_test_SOURCES = sieve/test.c imap/mutex_fake.c
sieve_test_LDADD = imap/libimap.a ${sieve_sievec_LDADD}

syslog_syslogd_SOURCES = syslog/syslogd.c syslog/syslogd.h
syslog_syslogd_LDADD = @LIBS@
syslog_libsyslog_a_SOURCES = syslog/syslog.c syslog/syslog.h

timsieved_timsieved_SOURCES = imap/mutex_fake.c imap/proxy.c master/service.c \
	timsieved/actions.c timsieved/actions.h timsieved/codes.h \
	timsieved/exitcodes.h timsieved/lex.c timsieved/lex.h \
	timsieved/mystring.c timsieved/mystring.h timsieved/parser.c \
	timsieved/parser.h timsieved/scripttest.c timsieved/scripttest.h \
	timsieved/timsieved.c
timsieved_timsieved_LDADD = sieve/libsieve.a imap/libimap.a @COM_ERR_LIBS@ @LIB_WRAP@ ${netnews_remotepurge_LDADD}

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
	@for d in $(DIST_SUBDIRS); \
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

man/imapd.conf.5: $(top_srcdir)/tools/config2man $(top_srcdir)/lib/imapoptions
	@echo creating man/imapd.conf.5
	@$(MKDIR_P) man
	$(top_srcdir)/tools/config2man $(top_srcdir)/lib/imapoptions > man/imapd.conf.5

man/sieveshell.1: $(top_srcdir)/perl/sieve/scripts/sieveshell.pl
	@echo creating man/sieveshell.1
	@$(MKDIR_P) man
	pod2man $(top_srcdir)/perl/sieve/scripts/sieveshell.pl > man/sieveshell.1
man/cyradm.1.html: $(top_srcdir)/perl/imap/cyradm.sh
	@$(MKDIR_P) man
	pod2html $(top_srcdir)/perl/imap/cyradm.sh > man/cyradm.1.html
	rm man/pod2htm*

man/sieveshell.1.html: $(top_srcdir)/perl/sieve/scripts/sieveshell.pl
	@$(MKDIR_P) man
	pod2html $(top_srcdir)/perl/sieve/scripts/sieveshell.pl > man/sieveshell.1.html
	rm man/pod2htm*


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
	@echo "#define _CYRUS_VERSION \"git$(PACKAGE_VERSION)+`git log --pretty=oneline $(PACKAGE_NAME)-$(PACKAGE_VERSION)..HEAD | wc -l`\"" >> xversion.h.tmp
	@echo "#define CYRUS_GITVERSION \"`git log --abbrev=8 --pretty=\"format:%h %ci\" -1 | cut -d\" \" -f1,2`\"" >> xversion.h.tmp
	@cmp -s xversion.h.tmp xversion.h || mv xversion.h.tmp xversion.h
	@rm -f xversion.h.tmp

dist-hook: doc/text/htmlstrip man/cyradm.1.html man/sieveshell.1.html
	@$(MKDIR_P) doc
	@$(MKDIR_P) doc/text
	for man in $(top_builddir)/man/*.[1-9] $(top_srcdir)/man/*.[1-9]; \
	do \
		echo "=== $$man ==="; \
		groff -man -Thtml $$man > man/`basename $$man`.html; \
	done
	rm -f doc/groff-html-*.png

	fig2dev -L png doc/murder.fig doc/murder.png
	fig2dev -L png doc/netnews.fig doc/netnews.png

	for file in $(top_srcdir)/doc/*.html; \
	do \
		echo "=== $$file ==="; \
		doc/text/htmlstrip $$file > doc/text/`basename $$file .html`; \
	done
	@echo "== done =="

install-data-hook:
if CMULOCAL
	$(INSTALL) -m 644 $(top_srcdir)/depot/depot.conf $(DESTDIR)/
endif

install-exec-hook:
	for s in installsieve sieveshell; \
	do \
	  $(PERL_PREINSTALL) < perl/sieve/scripts/$$s.pl > perl/sieve/scripts/$$s ;\
	  $(INSTALL) -m 755 perl/sieve/scripts/$$s $(DESTDIR)$(bindir)/$$s ; \
	done

	cd $(DESTDIR)$(servicedir) && \
	  $(LN_S) -f pop3d pop3proxyd && \
	  $(LN_S) -f imapd proxyd && \
	  $(LN_S) -f lmtpd lmtpproxyd
	cd $(DESTDIR)$(bindir) && \
	  $(LN_S) -f imtest lmtptest && \
	  $(LN_S) -f imtest mupatetest && \
	  $(LN_S) -f imtest nntptest && \
	  $(LN_S) -f imtest pop3test && \
	  $(LN_S) -f imtest sivtest && \
	  $(LN_S) -f imtest smpttest && \
	  $(LN_S) -f imtest synctest

valgrind:
	$(MAKE) VG=yes check

coverage_all:
	$(MAKE) COVERAGE="--coverage" EXTRACFLAGS="--coverage" EXTRALDFLAGS="--coverage" all

coverage_check:
	$(MAKE) COVERAGE="--coverage" EXTRACFLAGS="--coverage" EXTRALDFLAGS="--coverage" check

tags cscope:
	find $(DIST_SUBDIRS) -type f -name '*.[ch]' > cs.files
	cscope -b -k -i cs.files
	$(RM) cs.files
