# Cassandane modules whose Pod is published to the doc site, as stems: paths
# under cassandane/, without the .pm extension (e.g. "Cassandane/TestUser").
#
# The list is discovered at make time -- every module with an "=head" line --
# so it can't drift out of sync with the source and nobody has to remember to
# maintain it.  cassandane_srcdir comes from outside, and it differs between
# the autoconf build and docsrc/Makefile!
CASSANDANE_POD := $(shell cd $(cassandane_srcdir) && \
    grep -rl '^=head' Cassandane --include='*.pm' | sed 's|\.pm$$||' | sort)
