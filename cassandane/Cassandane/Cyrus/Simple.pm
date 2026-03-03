# SPDX-License-Identifier: BSD-3-Clause-CMU
# See COPYING file at the root of the distribution for more details.

package Cassandane::Cyrus::Simple;
use strict;
use warnings;
use Cwd qw(getcwd realpath);
use Data::Dumper;
use DateTime;

use base qw(Cassandane::Cyrus::TestCase);
use Cassandane::Util::Log;
use Cassandane::Util::Slurp;

$Data::Dumper::Sortkeys = 1;

sub new
{
    my $class = shift;
    return $class->SUPER::new({}, @_);
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
