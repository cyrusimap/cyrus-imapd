# SPDX-License-Identifier: BSD-3-Clause-CMU
# See COPYING file at the root of the distribution for more details.

package Cassandane::Cyrus::Create;
use strict;
use warnings;
use Data::Dumper;

use base qw(Cassandane::Cyrus::TestCase);
use Cassandane::Util::Log;
use Cassandane::Util::Slurp;
use Cassandane::Instance;
use Cyrus::IndexFile;

$Data::Dumper::Sortkeys = 1;

sub new
{
    my $class = shift;
    return $class->SUPER::new({ adminstore => 1 }, @_);
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
