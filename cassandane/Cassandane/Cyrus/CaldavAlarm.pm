# SPDX-License-Identifier: BSD-3-Clause-CMU
# See COPYING file at the root of the distribution for more details.

package Cassandane::Cyrus::CaldavAlarm;
use strict;
use warnings;
use DateTime;
use DateTime::Format::ISO8601;
use JSON::XS;
use Net::CalDAVTalk 0.05;
use Data::Dumper;
use POSIX;
use Carp;

use base qw(Cassandane::Cyrus::TestCase);
use Cassandane::Util::Log;

sub new
{
    my $class = shift;

    my $config = Cassandane::Config->default()->clone();
    $config->set(caldav_realm => 'Cassandane');
    $config->set(conversations => 'yes');
    $config->set(httpmodules => 'caldav jmap tzdist');
    $config->set(httpallowcompress => 'no');
    $config->set(caldav_historical_age => -1);
    $config->set(calendar_minimum_alarm_interval => '61s');
    $config->set(jmap_nonstandard_extensions => 'yes');

    my $self = $class->SUPER::new({
        config => $config,
        jmap => 1,
        adminstore => 1,
        services => ['imap', 'http'],
    }, @_);

    $self->needs('component', 'calalarmd');
    return $self;
}

sub set_up
{
    my ($self) = @_;
    $self->SUPER::set_up();
    my $service = $self->{instance}->get_service("http");
    $ENV{DEBUGDAV} = 1;
    $self->{caldav} = Net::CalDAVTalk->new(
        user => 'cassandane',
        password => 'pass',
        host => $service->host(),
        port => $service->port(),
        scheme => 'http',
        url => '/',
        expandurl => 1,
    );
    $self->{jmap}->DefaultUsing([
        'urn:ietf:params:jmap:core',
        'urn:ietf:params:jmap:calendars',
        'urn:ietf:params:jmap:principals',
        'urn:ietf:params:jmap:calendars:preferences',
        'https://cyrusimap.org/ns/jmap/calendars',
        'https://cyrusimap.org/ns/jmap/debug',
    ]);
}

sub _can_match {
    my $event = shift;
    my $want = shift;

    # I wrote a really good one of these for Caldav, but this will do for now
    foreach my $key (keys %$want) {
        return 0 if not exists $event->{$key};
        return 0 if $event->{$key} ne $want->{$key};
    }

    return 1;
}

sub assert_alarms {
    my $self = shift;
    my @want = @_;
    # pick first calendar alarm from notifications
    my $data = $self->{instance}->getnotify();
    if ($self->{replica}) {
        my $more = $self->{replica}->getnotify();
        push @$data, @$more;
    }
    my @events;
    foreach (@$data) {
        if ($_->{CLASS} eq 'EVENT') {
            my $e = decode_json($_->{MESSAGE});
            if ($e->{event} eq "CalendarAlarm") {
                push @events, $e;
            }
        }
    }

    my @left;
    while (my $event = shift @events) {
        my $found = 0;
        my @newwant;
        foreach my $data (@want) {
            if (not $found and _can_match($event, $data)) {
                $found = 1;
            }
            else {
                push @newwant, $data;
            }
        }
        if (not $found) {
            push @left, $event;
        }
        @want = @newwant;
    }

    if (@want or @left) {
        my $dump = Data::Dumper->Dump([\@want, \@left], [qw(want left)]);
        $self->assert_equals(0, scalar @want,
                             "expected events were not received:\n$dump");
        $self->assert_equals(0, scalar @left,
                             "unexpected extra events were received:\n$dump");
    }
}

sub tear_down
{
    my ($self) = @_;

    $self->SUPER::tear_down();
}

use Cassandane::Tiny::Loader 'tiny-tests/CaldavAlarm';

1;
