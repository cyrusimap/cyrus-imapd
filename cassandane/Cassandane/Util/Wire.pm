# SPDX-License-Identifier: BSD-3-Clause-CMU
# See COPYING file at the root of the distribution for more details.

package Cassandane::Util::Wire;
use v5.36.0;
use base qw(Exporter);

our @EXPORT = qw(wire_sent wire_recv);

=head1 NAME

Cassandane::Util::Wire - record protocol traffic in the test log

=head1 OVERVIEW

For tests that use raw sockets, not instrumented clients,
Cassandane::Util::Wire provides a simple way to log telemetry as we go.

Bytes that aren't printable ASCII are escaped, so a binary body or a stray
control character can't mangle the log.

=head1 FUNCTIONS

=head2 wire_sent

    wire_sent($peer, $text);

Log C<$text> as traffic Cassandane sent to C<$peer>, a string naming the far
end of the connection -- by convention C<host:port>.

=cut

sub wire_sent ($peer, $text)
{
    _wire_log("<<<<<<<< to $peer", $text);
    return;
}

=head2 wire_recv

    wire_recv($peer, $text);

Log C<$text> as traffic Cassandane received from C<$peer>.

=cut

sub wire_recv ($peer, $text)
{
    _wire_log(">>>>>>>> from $peer", $text);
    return;
}

sub _wire_log ($banner, $text)
{
    $text //= '';
    $text =~ s/\r\n/\n/g;
    $text =~ s/([^\n\t\x20-\x7e])/sprintf('\\x%02x', ord $1)/ge;
    $text =~ s/\n\z//;

    print STDERR "$banner\n$text\n========\n\n";
    return;
}

1;
