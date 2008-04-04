# divert(-1)
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
# $Id: cyrusv2.mc,v 1.5 2008/04/04 12:46:34 murch Exp $

#
#	This sample mc file is for a site that uses the Cyrus IMAP server
#	exclusively for local mail. This requires Sendmail 8.10 or later.
#

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

dnl if you aren't using Sendmail 8.12, you might need to remove
dnl the following feature.
FEATURE(`preserve_local_plus_detail')

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

