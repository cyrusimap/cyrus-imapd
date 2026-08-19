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
sub to_crlf ($str)
{
    return $str unless defined $str;

    # \r? for idempotency
    $str =~ s/\r?\n/\r\n/g;
    return $str;
}

1;
