# SPDX-License-Identifier: BSD-3-Clause-CMU
# See COPYING file at the root of the distribution for more details.

package Cassandane::Unit::TestPlanItem;
use strict;
use warnings;
use experimental 'signatures';

use Cassandane::Unit::TestCase;

sub new
{
    my ($class, $suite) = @_;
    my $self = {
        suite => $suite,
        loaded_suite => undef,
        denied => {},
        allowed => {},
    };
    return bless $self, $class;
}

sub _get_loaded_suite
{
    my ($self) = @_;
    return $self->{loaded_suite} ||= Test::Unit::Loader::load($self->{suite});
}

sub _is_allowed
{
    my ($self, $name) = @_;

    # Rules are:
    # deny if method has been explicitly denied
    return 0 if $self->{denied}->{$name};

    # deny if test name matches any denied pattern
    $name =~ $_ && return 0 for @{ $self->{denied_patterns} // [] };

    # allow if method has been explicitly allowed
    return 1 if $self->{allowed}->{$name};

    # allow if test name matches any allowed patterns
    my @allow_patterns = @{ $self->{allowed_patterns} // []};
    $name =~ $_ && return 1 for @allow_patterns;

    # deny if anything is explicitly allowed
    return 0 if %{$self->{allowed}} || @allow_patterns;

    # finally, allow
    return 1;
}

sub _deny
{
    my ($self, $test) = @_;
    if (ref $test) {
        push @{ $self->{denied_patterns} }, $test;
    } else {
        $self->{denied}->{$test} = 1;
    }
    return;
}

sub _allow
{
    my ($self, $test, $spec) = @_;

    # $spec is the specification this came from, kept only so that
    # _get_candidates can complain about it by the name the user typed
    push $self->{allowed_specs}->@*, { spec => $spec, test => $test };

    if (ref $test) {
        push @{ $self->{allowed_patterns} }, $test;
    } else {
        $self->{allowed}->{$test} = 1;
    }
    return;
}

# Returns, for each specification that selected individual tests from this
# suite, a hash of the specification and the test names it actually matched.
# Loading the suite is the only way to know those names, so this can't be
# answered until scheduling is finished.
sub _get_candidates ($self)
{
    return if not $self->{allowed_specs};

    my @names = map {; s/^test_//r } $self->_get_loaded_suite()->names()->@*;

    my @matches;
    foreach my $allowed ($self->{allowed_specs}->@*)
    {
        my $test = $allowed->{test};
        my @matched = ref $test ? grep {; $_ =~ $test } @names
                                : grep {; $_ eq $test } @names;

        push @matches, { spec => $allowed->{spec}, tests => \@matched };
    }

    return @matches;
}

1;
