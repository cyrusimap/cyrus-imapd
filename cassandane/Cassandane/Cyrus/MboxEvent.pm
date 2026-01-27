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

sub test_tls_login_event
    :TLS :min_version_3_0
{
    my ($self) = @_;

    my $instance = $self->{instance};

    my $svc = $instance->get_service('imaps');
    $self->assert_not_null($svc);

    my $store = $svc->create_store();
    $self->assert_not_null($store);

    # discard unwanted events from setup_mailbox
    $self->{instance}->getnotify();

    # we're just gonna log in, but not do anything else
    my $client = $store->get_client();

    my $events = $self->{instance}->getnotify();
    my %event_counts;

    foreach my $e (@{$events}) {
        my $message = decode_json($e->{MESSAGE});
        $event_counts{$message->{event}}++;
    }

    # client should still be connected
    # XXX on an ssl socket (which must be blocking), is_open blocks!
    # XXX prefer to do this:
    #    my $still_connected = $client->is_open();
    #    $self->assert_not_null($still_connected, "connection dropped");
    # XXX but instead, check if a select succeeds
    $client->select('INBOX');
    $self->assert_str_equals('ok', $client->get_last_completion_response());

    # we should have gotten one Login event and no others
    $self->assert_equals(1, $event_counts{'Login'});

    # XXX more correct, but may race against setup_mailbox finishing up
    #$self->assert_deep_equals({ Login => 1 }, \%event_counts);

    # XXX explicitly log out to work around Mail::IMAPTalk destructor
    # XXX calling is_open()
    $client->logout();
}

1;
