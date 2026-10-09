# C headers whose Doxygen docs are published to the doc site, as stems: paths
# under the source root, without the .h extension (e.g. "imap/auditlog").
#
# The list is discovered at make time -- every header under the Doxyfile's
# INPUT directories with an @file block -- so documenting a header is all it
# takes to publish it.  Vendored headers that happen to carry Doxygen markup
# are filtered out, and the Doxyfile excludes them too.  c_api_srcdir comes
# from outside, and it differs between the autoconf build and docsrc/Makefile!
C_API_VENDORED = lib/xxhash

C_API_STEMS := $(filter-out $(C_API_VENDORED),$(shell cd $(c_api_srcdir) && \
    grep -rlE '^[[:space:]/*]*[@\\]file\b' imap lib sieve --include='*.h' | \
    sed 's|\.h$$||' | sort))
