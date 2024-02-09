#!/usr/bin/perl
#
#  Copyright (c) 2011-2024 FastMail Pty Ltd. All rights reserved.
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

package Cassandane::Cyrus::MaxMessages;
use strict;
use warnings;
use v5.10;
use Data::Dumper;
use Net::DAVTalk 0.14;
use Net::CardDAVTalk 0.05;
use Net::CardDAVTalk::VCard;

use lib '.';
use base qw(Cassandane::Cyrus::TestCase);
use Cassandane::Generator;
use Cassandane::Util::Log;

sub new
{
    my $class = shift;

    my $config = Cassandane::Config->default()->clone();
    $config->set(caldav_realm => 'Cassandane');
    $config->set(calendar_user_address_set => 'example.com');
    $config->set(caldav_historical_age => -1);
    $config->set(httpmodules => 'carddav caldav');
    $config->set(httpallowcompress => 'no');
    $config->set(icalendar_max_size => 100000);
    $config->set(vcard_max_size => 100000);

    return $class->SUPER::new({
        config => $config,
        services => ['imap', 'http'],
    }, @_);
}

sub set_up
{
    my ($self) = @_;
    $self->SUPER::set_up();
    $ENV{DEBUGDAV} = 1;
    $ENV{JMAP_ALWAYS_FULL} = 1;
}

sub tear_down
{
    my ($self) = @_;
    $self->SUPER::tear_down();
}

sub _random_vevent
{
    my ($self) = @_;
    state $counter = 1;

    my $uuid = $self->{caldav}->genuuid();

    my $ics = <<"EOF";
BEGIN:VCALENDAR
VERSION:2.0
PRODID:-//Apple Inc.//Mac OS X 10.10.4//EN
CALSCALE:GREGORIAN
BEGIN:VEVENT
CREATED:20150701T234327Z
UID:$uuid
DTEND;TZID=Australia/Melbourne:20160601T183000
TRANSP:OPAQUE
DTSTART;TZID=Australia/Melbourne:20160601T153000
DTSTAMP:20150806T234327Z
DESCRIPTION:event $counter
END:VEVENT
END:VCALENDAR
EOF

    $counter ++;

    return $ics, $uuid;
}

sub _random_vcard
{
    my $fn = Cassandane::Generator::make_random_address()->name();
    my ($first, $middle, $last) = split /[\s\.]+/, $fn;
    my $n = "$last;$first;$middle;;";
    my $str = <<"EOF";
BEGIN:VCARD
VERSION:3.0
N:$n
FN:$fn
REV:2008-04-24T19:52:43Z
END:VCARD
EOF
    return $str;
}

sub test_maxmsg_addressbook_limited
    :needs_component_httpd :NoStartInstances
{
    my ($self) = @_;

    my $mailbox_maxmessages_addressbook = 5;
    $self->{instance}->{config}->set(
        mailbox_maxmessages_addressbook => $mailbox_maxmessages_addressbook,
    );
    $self->_start_instances();
    $self->_setup_http_service_objects();

    my $carddav = $self->{carddav};
    my $id = $carddav->NewAddressBook('foo');
    $self->assert_not_null($id);
    $self->assert_str_equals($id, 'foo');

    # should be able to upload 5
    foreach my $i (1..$mailbox_maxmessages_addressbook) {
        my $vcard = Net::CardDAVTalk::VCard->new_fromstring(_random_vcard());

        $carddav->NewContact($id, $vcard);
    }

    # but any more should be rejected
    eval {
        my $vcard = Net::CardDAVTalk::VCard->new_fromstring(_random_vcard());

        $carddav->NewContact($id, $vcard);
    };
    my $e = $@;
    $self->assert_not_null($e);
    $self->assert_matches(qr{quota-not-exceeded}, $e);

    # should have syslogged about it too
    $self->assert_syslog_matches($self->{instance},
                                 qr{client hit per-addressbook exists limit});
}

sub test_maxmsg_addressbook_unlimited
    :needs_component_httpd
{
    my ($self) = @_;

    my $carddav = $self->{carddav};
    my $id = $carddav->NewAddressBook('foo');
    $self->assert_not_null($id);
    $self->assert_str_equals($id, 'foo');

    # no limit, should be able to upload a bunch
    foreach my $i (1..100) {
        my $vcard = Net::CardDAVTalk::VCard->new_fromstring(_random_vcard());

        $carddav->NewContact($id, $vcard);
    }
}

sub test_maxmsg_calendar_limited
    :needs_component_httpd :NoStartInstances
{
    my ($self) = @_;

    my $mailbox_maxmessages_calendar = 5;
    $self->{instance}->{config}->set(
        mailbox_maxmessages_calendar => $mailbox_maxmessages_calendar,
    );
    $self->_start_instances();
    $self->_setup_http_service_objects();

    my $caldav = $self->{caldav};
    my $calendarid = $caldav->NewCalendar({name => 'mycalendar'});
    $self->assert_not_null($calendarid);

    # should be able to upload 5
    foreach my $i (1..$mailbox_maxmessages_calendar) {
        my ($ics, $uuid) = $self->_random_vevent();
        my $href = "$calendarid/$uuid.ics";

        $self->{caldav}->Request('PUT', $href, $ics,
                                 'Content-Type' => 'text/calendar');
    }

    # but any more should be rejected
    eval {
        my ($ics, $uuid) = $self->_random_vevent();
        my $href = "$calendarid/$uuid.ics";

        $self->{caldav}->Request('PUT', $href, $ics,
                                 'Content-Type' => 'text/calendar');
    };
    my $e = $@;
    $self->assert_not_null($e);
    $self->assert_matches(qr{quota-not-exceeded}, $e);

    # should have syslogged about it too
    $self->assert_syslog_matches($self->{instance},
                                 qr{client hit per-calendar exists limit});
}

sub test_maxmsg_calendar_unlimited
    :needs_component_httpd
{
    my ($self) = @_;

    my $caldav = $self->{caldav};

    my $calendarid = $caldav->NewCalendar({name => 'mycalendar'});
    $self->assert_not_null($calendarid);

    # no limit, should be able to upload a bunch
    foreach my $i (1..100) {
        my ($ics, $uuid) = $self->_random_vevent();
        my $href = "$calendarid/$uuid.ics";

        $self->{caldav}->Request('PUT', $href, $ics,
                                 'Content-Type' => 'text/calendar');
    }
}

1;
