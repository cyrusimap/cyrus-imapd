# SPDX-License-Identifier: BSD-3-Clause-CMU
# See COPYING file at the root of the distribution for more details.

package Cassandane::JMAPAbort;
use strict;
use warnings;
use experimental 'signatures';

use parent qw(Test::Unit::Failure);

use Error ();

=head1 NAME

Cassandane::JMAPAbort - a JMAP::Tester abort that Test::Unit calls a failure

=head1 DESCRIPTION

When JMAP::Tester gives up, it throws a L<JMAP::Tester::Abort>, which is a
Throwable::Error.  Test::Unit only understands Error.pm exceptions, and of
those only a Test::Unit::Failure is reported as a failing test; anything else
is an error, meaning the test suite itself is broken.  An abort is a I<failing>
test, so it should look like one.

This stupid class saves us from multiple inheritance, and
L<Cassandane::Role::JMAPTester> makes our JMAP::Tester classes use it.

=cut

# The packages between the abort and the test that provoked it.  We don't want
# to report any of their frames as the location of the failure.
my $PLUMBING = qr{
    \A (?: JMAP::Tester
         | Cassandane::JMAPAbort
         | Cassandane::Role::JMAPTester )
    \b
}x;

=head1 METHODS

=head2 new

    Cassandane::JMAPAbort->new($message);
    Cassandane::JMAPAbort->new({ message => $message, diagnostics => \@diags });

Those are the two ways JMAP::Tester builds an abort.  The diagnostics have
already been formatted by the tester's diagnostic dumper, and get folded into
the message, because the message is all that Test::Unit will ever show.

Called any other way, we assume we've been given the usual Error.pm arguments.
That happens when Test::Unit::Assert rethrows an exception to blame the caller
of an assertion, which it does by passing our own guts back to C<new>.

=cut

sub new ($class, @args) {
    unless (@args == 1) {
        local $Error::Depth = $Error::Depth + 1;
        return $class->SUPER::new(@args);
    }

    my $arg = ref $args[0] ? $args[0] : { message => $args[0] };

    my $text = $arg->{message};
    for my $diagnostic (@{ $arg->{diagnostics} // [] }) {
        $text .= "\n" unless $text =~ /\n\z/;
        $text .= $diagnostic;
    }
    $text =~ s/\n\z//;

    # Error->new blames the caller $Error::Depth frames up and prunes the stack
    # trace it captures to match.  Everything between us and the test is
    # plumbing, so skip it.
    my $depth = 0;
    while (my $package = (caller $depth)[0]) {
        last unless $package =~ $PLUMBING;
        $depth++;
    }

    local $Error::Depth = $depth + 1;
    return $class->SUPER::new(-text => $text);
}

1;
