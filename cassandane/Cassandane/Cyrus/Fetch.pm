# SPDX-License-Identifier: BSD-3-Clause-CMU
# See COPYING file at the root of the distribution for more details.

package Cassandane::Cyrus::Fetch;
use strict;
use warnings;
use Data::Dumper;
use DateTime;
use IO::Scalar;

use base qw(Cassandane::Cyrus::TestCase);
use Cassandane::Address;
use Cassandane::Util::DateTime qw(to_rfc822);
use Cassandane::Util::Log;

$Data::Dumper::Sortkeys = 1;

sub new
{
    my $class = shift;

    my $config = Cassandane::Config->default()->clone();
    $config->set(
        jmap_preview_annot => '/shared/vendor/messagingengine.com/preview',
    );

    return $class->SUPER::new({ config => $config, adminstore => 1 }, @_);
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
