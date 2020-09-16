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

SUBDIRS := utils
PERL := perl

all clean install::
	@for dir in $(SUBDIRS) ; do cd $$dir ; $(MAKE) $@ || exit 1 ; done

all:: syntax

SCRIPTS := $(shell find . -type f -name '*.pl' | sort)

MODULES := $(shell find . -type f -name '*.pm' | sort)

CYRUS_PERL_PATHS := $(shell $(PERL) utils/cyrus-perl-paths.pl)

SYNTAX_rules =

define SYNTAX_template
 $(1)_syntax: $(1)
	@$(PERL) $(CYRUS_PERL_PATHS) -c $(1)
 SYNTAX_rules += $(1)_syntax
endef

$(foreach s,$(SCRIPTS),$(eval $(call SYNTAX_template,$(s))))

$(foreach m,$(MODULES),$(eval $(call SYNTAX_template,$(m))))

syntax: $(SYNTAX_rules)

.PHONY: all syntax $(SYNTAX_rules)
