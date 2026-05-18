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

    # The default value of event_extra_params is just 'timestamp'; opt in
    # to the parameters individual tests want to inspect.
    $config->set(event_extra_params => 'timestamp vnd.fastmail.traceId');

    # Enable enough HTTP to drive CalDAV requests from tests that want to
    # exercise the http engine's contribution to events (e.g. X-Trace-Id).
    $config->set(httpmodules => 'caldav');
    $config->set(caldav_realm => 'Cassandane');

    return $class->SUPER::new({
        config => $config,
        deliver => 1,
        services => ['imap', 'http'],
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
