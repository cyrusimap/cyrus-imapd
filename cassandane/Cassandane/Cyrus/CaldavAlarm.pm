#!/usr/bin/perl
#
#  Copyright (c) 2011-2017 FastMail Pty Ltd. All rights reserved.
#
#  Redistribution and use in source and binary forms, with or without
#  modification, are permitted provided that the following conditions
#  are met:
#
#  1. Redistributions of source code must retain the above copyright
#     notice, this list of conditions and the following disclaimer.
#
#  2. Redistributions in binary form must reproduce the above copyright
#     notice, this list of conditions and the following disclaimer in
#     the documentation and/or other materials provided with the
#     distribution.
#
#  3. The name "Fastmail Pty Ltd" must not be used to
#     endorse or promote products derived from this software without
#     prior written permission. For permission or any legal
#     details, please contact
#      FastMail Pty Ltd
#      PO Box 234
#      Collins St West 8007
#      Victoria
#      Australia
#
#  4. Redistributions of any form whatsoever must retain the following
#     acknowledgment:
#     "This product includes software developed by Fastmail Pty. Ltd."
#
#  FASTMAIL PTY LTD DISCLAIMS ALL WARRANTIES WITH REGARD TO THIS SOFTWARE,
#  INCLUDING ALL IMPLIED WARRANTIES OF MERCHANTABILITY  AND FITNESS, IN NO
#  EVENT SHALL OPERA SOFTWARE AUSTRALIA BE LIABLE FOR ANY SPECIAL, INDIRECT
#  OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES WHATSOEVER RESULTING FROM LOSS OF
#  USE, DATA OR PROFITS, WHETHER IN AN ACTION OF CONTRACT, NEGLIGENCE OR OTHER
#  TORTIOUS ACTION, ARISING OUT OF OR IN CONNECTION WITH THE USE OR PERFORMANCE
#  OF THIS SOFTWARE.
#

package Cassandane::Cyrus::CaldavAlarm;
use strict;
use warnings;
use DateTime;
use DateTime::Format::ISO8601;
use JSON::XS;
use Net::CalDAVTalk 0.05;
use Mail::JMAPTalk 0.13;
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
