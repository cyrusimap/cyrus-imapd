# SPDX-License-Identifier: BSD-3-Clause-CMU
# See COPYING file at the root of the distribution for more details.

package Cassandane::Test::Clone;
use strict;
use warnings;
use Clone qw(clone);

use base qw(Cassandane::Unit::TestCase);

sub new
{
    my $class = shift;
    my $self = $class->SUPER::new(@_);
    return $self;
}

sub test_undef
{
    my ($self) = @_;
    my $a = undef;
    my $b = clone($a);
    $self->assert_null($a);
    $self->assert_null($b);
}

sub test_string
{
    my ($self) = @_;
    my $a = "Hello World";
    my $b = clone($a);
    $self->assert_str_equals("Hello World", $a);
    $self->assert_str_equals("Hello World", $b);
    $b = "Jeepers";
    $self->assert_str_equals("Hello World", $a);
    $self->assert_str_equals("Jeepers", $b);
}

sub test_hash
{
    my ($self) = @_;
    my $a = { foo => 42 };
    my $b = clone($a);
    $self->assert_deep_equals({ foo => 42 }, $a);
    $self->assert_deep_equals({ foo => 42 }, $b);
    $b->{bar} = 123;
    $self->assert_deep_equals({ foo => 42 }, $a);
    $self->assert_deep_equals({ foo => 42, bar => 123 }, $b);
    delete $b->{foo};
    $self->assert_deep_equals({ foo => 42 }, $a);
    $self->assert_deep_equals({ bar => 123 }, $b);
}

sub test_array
{
    my ($self) = @_;
    my $a = [ 42 ];
    my $b = clone($a);
    $self->assert_deep_equals([ 42 ], $a);
    $self->assert_deep_equals([ 42 ], $b);
    push(@$b, 123);
    $self->assert_deep_equals([ 42 ], $a);
    $self->assert_deep_equals([ 42, 123 ], $b);
    shift @$b;
    $self->assert_deep_equals([ 42 ], $a);
    $self->assert_deep_equals([ 123 ], $b);
}

sub test_complex
{
    my ($self) = @_;
    my $a = { foo => [ { x => 42, y => 123 } ],
              bar => { quux => 37, foonly => 475 } };
    my $b = clone($a);
    $self->assert_deep_equals($a, $b);
}

1;
