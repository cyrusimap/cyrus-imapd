# SPDX-License-Identifier: BSD-3-Clause-CMU
# See COPYING file at the root of the distribution for more details.

package Cassandane::Util::CRLF;
use strict;
use warnings;
use experimental 'signatures';
use base qw(Exporter);

our @EXPORT = qw(&to_crlf);

# Convert a string's newlines to CRLF, for use where the wire format demands
# them -- appending a message over IMAP, say.
#
# Lines that already end in CRLF are left alone, so this is safe to apply to
# a string that's already part-converted.
sub to_crlf ($string)
{
    return undef if !defined $string;
    return $string =~ s/\r?\n/\r\n/gr;
}

1;
