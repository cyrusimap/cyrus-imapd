# SPDX-License-Identifier: BSD-3-Clause-CMU
# See COPYING file at the root of the distribution for more details.

package Cassandane::Test::Sample;
use strict;
use warnings;

use base qw(Cassandane::Unit::TestCase);
use Cassandane::Util::Sample;
use Cassandane::Util::Log;

sub new
{
    my $class = shift;
    return $class->SUPER::new(@_);
}

sub check_expected
{
    my ($self, $ss, $ecount, $eavg, $emin, $emax, $estd) = @_;

    my $epsilon = 0.01;

    $self->assert_equals($ss->nsamples(), $ecount);

    my $avg = $ss->average();
    $self->assert(abs($eavg - $avg) < $epsilon,
                  "Average: expecting $eavg got $avg");

    my $min = $ss->minimum();
    $self->assert(abs($emin - $min) < $epsilon,
                  "Minimum: expecting $emin got $min");

    my $max = $ss->maximum();
    $self->assert(abs($emax - $max) < $epsilon,
                  "Maximum: expecting $emax got $max");

    my $std = $ss->sample_deviation();
    $self->assert(abs($estd - $std) < $epsilon,
                  "Sample Deviation: expecting $estd got $std");
}

sub test_uniform
{
    my ($self) = @_;

    xlog "Sample with 4 x 10.0";
    my $ss = new Cassandane::Util::Sample;
    $ss->add(10.0);
    $ss->add(10.0);
    $ss->add(10.0);
    $ss->add(10.0);
    xlog "Sample: $ss";
    $self->check_expected($ss, 4, 10.0, 10.0, 10.0, 0.0);
}

sub test_ramp
{
    my ($self) = @_;

    xlog "Sample with ramp from 1 to 5";
    my $ss = new Cassandane::Util::Sample;
    $ss->add(1.0);
    $ss->add(2.0);
    $ss->add(3.0);
    $ss->add(4.0);
    $ss->add(5.0);
    xlog "Sample: $ss";
    $self->check_expected($ss, 5, 3.0, 1.0, 5.0, 1.5811);
}

1;
