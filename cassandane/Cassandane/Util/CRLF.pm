# SPDX-License-Identifier: BSD-3-Clause-CMU
# See COPYING file at the root of the distribution for more details.

package Cassandane::Util::CRLF;
use v5.28.0; # strict, indented here-docs
use warnings;
use experimental 'signatures';
use base qw(Exporter);

our @EXPORT = qw(&to_crlf);

# Return $str with every line ending normalized to CRLF.  Tests build message,
# iCalendar and vCard payloads as LF-terminated here-docs, but IMAP, JMAP and
# sieve all want them in wire format, so nearly every such here-doc needs this
# on the way out.
#
# The \r? makes this idempotent: text that is already CRLF, or that mixes the
# two, comes back correct rather than growing a second CR.  A lone CR with no
# LF is not a line ending here, and is left alone.
sub to_crlf ($str)
{
    return $str unless defined $str;

    $str =~ s/\r?\n/\r\n/g;
    return $str;
}

1;
