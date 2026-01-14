# SPDX-License-Identifier: BSD-3-Clause-CMU
# See COPYING file at the root of the distribution for more details.

package Cassandane::Cyrus::Flags;
use strict;
use warnings;
use DateTime;
use Data::Dumper;

use base qw(Cassandane::Cyrus::TestCase);
use Cassandane::Util::Log;
use Cassandane::Util::Words;
use JSON;

sub new
{
    my $class = shift;
    return $class->SUPER::new({adminstore => 1}, @_);
}

sub set_up
{
    my ($self) = @_;
    $self->SUPER::set_up();
}

sub tear_down
{
    my ($self) = @_;
    $self->SUPER::tear_down();
}

#
# Test that
#  - 100 separate user flags can be used
#  - no more can be used
#  - (we lock out at 100 except for replication to avoid
#  -  one-extra problems)
#
use constant MAX_USER_FLAGS => 100;

# Get the modseq of a given returned message
sub get_modseq
{
    my ($actual, $which) = @_;

    my $msl = $actual->{'Message ' . $which}->get_attribute('modseq');
    return undef unless defined $msl;
    return undef unless ref $msl eq 'ARRAY';
    return undef unless scalar @$msl == 1;
    return 0 + $msl->[0];
}

# Get the modseq from a FETCH response
sub get_modseq_from_fetch
{
    my ($fetched, $i) = @_;

    my $msl = $fetched->{$i}->{modseq};
    return undef unless defined $msl;
    return undef unless ref $msl eq 'ARRAY';
    return undef unless scalar @$msl == 1;
    return 0 + $msl->[0];
}

# Get the highestmodseq of the folder
sub get_highestmodseq
{
    my ($self) = @_;

    my $store = $self->{store};
    my $talk = $store->get_client();
    my $stat = $talk->status($store->{folder}, '(highestmodseq)');
    return undef unless defined $stat;
    return undef unless ref $stat eq 'HASH';
    return undef unless defined $stat->{highestmodseq};
    return 0 + $stat->{highestmodseq};
}

use Cassandane::Tiny::Loader;

1;
