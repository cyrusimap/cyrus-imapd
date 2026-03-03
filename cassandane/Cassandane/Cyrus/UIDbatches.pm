# SPDX-License-Identifier: BSD-3-Clause-CMU
# See COPYING file at the root of the distribution for more details.

package Cassandane::Cyrus::UIDbatches;
use strict;
use warnings;
use Cwd qw(abs_path);
use DateTime;
use Data::Dumper;

use base qw(Cassandane::Cyrus::TestCase);
use Cassandane::Util::Log;

sub new
{
    my $class = shift;
    my $config = Cassandane::Config->default()->clone();
    $config->set(conversations => 'on');
    $config->set(uidbatches_min_batch => '10');
    return $class->SUPER::new({adminstore => 1, config => $config}, @_);
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

use Cassandane::Tiny::Loader;

1;
