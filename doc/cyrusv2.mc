# divert(-1)
#
#	(C) Copyright 2000 by Carnegie Mellon University
#
#	This sample mc file is for a site that uses the Cyrus IMAP server
#	exclusively for local mail.
#

divert(0)dnl
VERSIONID(`cyrus v2 sample configuartion')

OSTYPE(linux)
define(`confBIND_OPTS',`-DNSRCH -DEFNAMES')
define(`confTO_IDENT',`0')

define(`confLOCAL_MAILER', `cyrus')

FEATURE(`nocanonify')
FEATURE(`always_add_domain')
MAILER(`local')
MAILER(`smtp')

MAILER_DEFINITIONS
Mcyrus,		P=[IPC], F=lsDFMnqA5@/:|SmXz, E=\r\n,
		S=EnvFromL, R=EnvToL/HdrToL, T=DNS/RFC822/X-Unix, 
		A=FILE /var/imap/socket/lmtp

LOCAL_RULE_0
Rbb + $+ < @ $=w . >	$#cyrus $: + $1

LOCAL_RULESETS
# if there's a plus part, we want to directly deliver it
SLocal_localaddr
R$+ + $*	$#cyrus $@ $: $1 + $2
