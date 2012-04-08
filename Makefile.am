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
BUILT_SOURCES = xversion.h

SUBDIRS = . lib imtest man
if COM_ERR
SUBDIRS += com_err/et
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
SUBDIRS += sieve
endif
if SERVER
SUBDIRS += master imap
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

EXTRA_DIST = xversion.h
DISTSUBDIRS = doc

SHELL = /bin/sh
@SET_MAKE@

GIT_VERSION = $(PACKAGE_VERSION).git$(shell date +'%Y%m%d%H%M')

snapshot::
	@echo "creating snapshot $(GIT_VERSION)"
	@if [ \! -d snapshot ]; then mkdir snapshot ; fi
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
	if [ \! -d dist ]; then mkdir dist ; fi
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
