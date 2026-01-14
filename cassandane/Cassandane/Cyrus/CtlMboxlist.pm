# SPDX-License-Identifier: BSD-3-Clause-CMU
# See COPYING file at the root of the distribution for more details.

package Cassandane::Cyrus::CtlMboxlist;
use strict;
use warnings;

use Data::Dumper;

use base qw(Cassandane::Cyrus::TestCase);
use Cassandane::Util::Log;
use Cassandane::Util::Slurp;
use Cassandane::Instance;

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

sub fudge_mtimes
{
    my ($hash) = @_;

    foreach my $v (values %{$hash}) {
        if (exists $v->{mtime}) {
            $v->{mtime} = 1;
        }
    }
}

use Cassandane::Tiny::Loader;

1;
