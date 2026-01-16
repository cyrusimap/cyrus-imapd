# SPDX-License-Identifier: BSD-3-Clause-CMU
# See COPYING file at the root of the distribution for more details.

package Cassandane::Test::Metronome;
use strict;
use warnings;

use base qw(Cassandane::Unit::TestCase);
use Cassandane::Util::Metronome;
use Cassandane::Util::Sample;
use Cassandane::Util::Log;

sub new
{
    my $class = shift;
    my $self = $class->SUPER::new(@_);
    return $self;
}

sub test_basic
{
    my ($self) = @_;

    return unless $ENV{METRONOME_ENABLED};

    my $rate = 100.0;
    my $epsilon = 0.05;
    my $m = Cassandane::Util::Metronome->new(rate => $rate);

    my $ss = new Cassandane::Util::Sample;

    for (1..$rate)
    {
        $m->tick();
        my $r = $m->actual_rate();
        xlog "Actual rate $r";
        # Be forgiving of early samples to let the
        # metronome stabilise.
        $ss->add($r) if ($_ >= 20)
    }

    xlog "Rates: $ss";
    my $avg = $ss->average();
    my $std = $ss->sample_deviation();
    $self->assert($avg >= (1.0-$epsilon)*$rate && $avg <= (1.0+$epsilon)*$rate,
                  "Average $avg is outside expected range");
    $self->assert($std/$rate < $epsilon,
                  "Standard deviation $std is too high");
}

1;
