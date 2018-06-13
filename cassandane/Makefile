#
#  Copyright (c) 2011 Opera Software Australia Pty. Ltd.  All rights
#  reserved.
#
#  Redistribution and use in source and binary forms, with or without
#  modification, are permitted provided that the following conditions
#  are met:
#
#  1. Redistributions of source code must retain the above copyright
#     notice, this list of conditions and the following disclaimer.
#
#  2. Redistributions in binary form must reproduce the above copyright
#     notice, this list of conditions and the following disclaimer in
#     the documentation and/or other materials provided with the
#     distribution.
#
#  3. The name "Opera Software Australia" must not be used to
#     endorse or promote products derived from this software without
#     prior written permission. For permission or any legal
#     details, please contact
# 	Opera Software Australia Pty. Ltd.
# 	Level 50, 120 Collins St
# 	Melbourne 3000
# 	Victoria
# 	Australia
#
#  4. Redistributions of any form whatsoever must retain the following
#     acknowledgment:
#     "This product includes software developed by Opera Software
#     Australia Pty. Ltd."
#
#  OPERA SOFTWARE AUSTRALIA DISCLAIMS ALL WARRANTIES WITH REGARD TO
#  THIS SOFTWARE, INCLUDING ALL IMPLIED WARRANTIES OF MERCHANTABILITY
#  AND FITNESS, IN NO EVENT SHALL OPERA SOFTWARE AUSTRALIA BE LIABLE
#  FOR ANY SPECIAL, INDIRECT OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES
#  WHATSOEVER RESULTING FROM LOSS OF USE, DATA OR PROFITS, WHETHER IN
#  AN ACTION OF CONTRACT, NEGLIGENCE OR OTHER TORTIOUS ACTION, ARISING
#  OUT OF OR IN CONNECTION WITH THE USE OR PERFORMANCE OF THIS SOFTWARE.
#

SUBDIRS = utils

all clean install::
	@for dir in $(SUBDIRS) ; do cd $$dir ; $(MAKE) $@ || exit 1 ; done

PERL=	perl
all::
	@echo ./utils/annotator.pl syntax check SKIPPED
	@ e=0; \
	for script in ./utils/fakeldapd `find . -type f -name '*.pl' | grep -v 'utils\/annotator.pl' | sort` ;\
	do \
		$(PERL) -c $$script || e=1 ;\
	done ;\
	for module in `find . -type f -name '*.pm'| sort` ;\
	do \
	    $(PERL) -c $$module || e=1 ;\
	done ;\
	exit $$e;


# XXX utils/annotator.pl depends on modules installed with Cyrus, which it
#     will only be able to find when invoked by Cyrus::Instance (which sets
#     up $PERL5LIB appropriately) or when the system coincidentally also has
#     a real Cyrus installation on it.  So we can't rely on it to pass a
#     simple 'perl -c' check.
