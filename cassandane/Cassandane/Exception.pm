# SPDX-License-Identifier: BSD-3-Clause-CMU
# See COPYING file at the root of the distribution for more details.

package Cassandane::Exception;
use strict;
use warnings;
use experimental 'signatures';

use parent qw(Error);

# What a report says about this exception: the stack trace when Error was
# asked to take one, and otherwise just the message.  Below the test method
# it's all framework, and nobody reading a failure wants to see it.
sub stringify ($self, @)
{
    my $trace = $self->{'-stacktrace'} // $self->text // 'Died';
    $trace =~ s/[\w:]+::run_test\(.*/[...framework calls elided...]/s;

    return $trace;
}

sub to_string ($self)
{
    return $self->stringify;
}

sub get_message ($self)
{
    return $self->text;
}

1;
