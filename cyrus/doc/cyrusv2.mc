# divert(-1)
#
#	(C) Copyright 2000 by Carnegie Mellon University
#
#	This sample mc file is for a site that uses the Cyrus IMAP server
#	exclusively for local mail. This requires Sendmail 8.10 or later.
#
# $Id: cyrusv2.mc,v 1.3 2000/09/09 04:02:11 leg Exp $

divert(0)dnl
VERSIONID(`cyrus v2 sample configuartion')

OSTYPE(linux)
define(`confBIND_OPTS',`-DNSRCH -DEFNAMES')
define(`confTO_IDENT',`0')

dnl setting cyrus as the trusted user will make it easier to pass
dnl Sendmail's safefile checks.  however, it means that someone with the
dnl "cyrus" password could easily become root.
dnl define(`confTRUSTED_USER', `cyrus')

define(`confLOCAL_MAILER', `cyrus')

FEATURE(`nocanonify')
FEATURE(`always_add_domain')
MAILER(`local')
MAILER(`smtp')

MAILER_DEFINITIONS
Mcyrus,		P=[IPC], F=lsDFMnqA@/:|SmXz, E=\r\n,
		S=EnvFromL, R=EnvToL/HdrToL, T=DNS/RFC822/X-Unix, 
		A=FILE /var/imap/socket/lmtp

LOCAL_RULE_0
Rbb + $+ < @ $=w . >	$#cyrus $: + $1

