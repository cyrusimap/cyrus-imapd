# SPDX-License-Identifier: BSD-3-Clause-CMU
# See COPYING file at the root of the distribution for more details.

package Cassandane::Error;
use strict;
use warnings;
use experimental 'signatures';

use parent qw(Cassandane::Exception);

=head1 NAME

Cassandane::Error - the exception meaning "this test broke"

=head1 DESCRIPTION

This class exists as a generic thing into which to reconstitute any exception
thrown by a test that wasn't a L<Cassandane::Failure>.  You won't throw one
yourself.

=head2 from_thrown

    Cassandane::Error->from_thrown($@);

Make one out of whatever was thrown.  An Error.pm exception keeps its text,
file, line and stack trace; anything else -- a string, an object with opinions
of its own -- gets stringified into a new one.

=cut

sub from_thrown ($class, $thrown)
{
    if (ref $thrown && eval { $thrown->isa('Error') }) {
        my $error = $class->new(%$thrown);

        # Error::new takes a fresh stack trace, which describes this wrapping
        # rather than whatever we are wrapping
        $error->{'-stacktrace'} = $thrown->{'-stacktrace'}
            if defined $thrown->{'-stacktrace'};

        return $error;
    }

    return $class->new(-text => "exception while testing: $thrown");
}

1;
