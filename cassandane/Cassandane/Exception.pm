# SPDX-License-Identifier: BSD-3-Clause-CMU
# See COPYING file at the root of the distribution for more details.

package Cassandane::Exception;
use strict;
use warnings;
use experimental 'signatures';

use parent qw(Error);

sub stringify ($self, @)
{
    my $test = $self->object;

    my $named = $test && $test->can('to_string') ? $test->to_string() . "\n "
                                                 : q{};

    my $trace = $self->{'-stacktrace'} // $self->text // 'Died';
    $trace =~ s/[\w:]+::run_test\(.*/[...framework calls elided...]/s;

    return $named . $trace;
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
