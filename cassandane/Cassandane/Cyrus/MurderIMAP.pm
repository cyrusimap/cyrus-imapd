# SPDX-License-Identifier: BSD-3-Clause-CMU
# See COPYING file at the root of the distribution for more details.

package Cassandane::Cyrus::MurderIMAP;
use strict;
use warnings;
use Data::Dumper;

use base qw(Cassandane::Cyrus::TestCase);
use Cassandane::Util::Log;
use Cassandane::Util::Words;
use Cassandane::Instance;

$Data::Dumper::Sortkeys = 1;

sub new
{
    my $class = shift;

    my $config = Cassandane::Config->default()->clone();

    $config->set(conversations => 'yes');

    my $self = $class->SUPER::new({
        imapmurder => 1, adminstore => 1, deliver => 1,
    }, @_);

    $self->needs('component', 'murder');
    return $self;
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

# XXX test_xfer_partition
# XXX test_xfer_mboxpattern
# XXX shared mailboxes!

use Cassandane::Tiny::Loader;

1;
