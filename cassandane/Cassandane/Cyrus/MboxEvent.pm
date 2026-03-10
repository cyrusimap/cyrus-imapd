# SPDX-License-Identifier: BSD-3-Clause-CMU
# See COPYING file at the root of the distribution for more details.

package Cassandane::Cyrus::MboxEvent;
use strict;
use warnings;
use Data::Dumper;
use JSON;

use base qw(Cassandane::Cyrus::TestCase);
use Cassandane::Util::Log;
use Cassandane::Generator;
use Cassandane::MessageStoreFactory;
use Cassandane::Instance;

sub new
{
    my ($class, @args) = @_;

    # all of them!
    my @event_groups = qw(
        message
        quota
        flags
        access
        mailbox
        subscription
        calendar
        applepushservice
    );

    my $config = Cassandane::Config->default()->clone();
    $config->set(event_groups => join(' ', @event_groups));

    return $class->SUPER::new({
        config => $config,
    }, @args);
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
