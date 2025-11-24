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
use v5.28.0;
use warnings;
use Data::Dumper;
use Net::DAVTalk 0.14;
use Net::CardDAVTalk 0.05;
use Net::CardDAVTalk::VCard;

use base qw(Cassandane::Cyrus::TestCase);
use Cassandane::Generator;
use Cassandane::Util::Log;

my $LOTS = 20;
my $LIMITED = 5;

sub new
{
    my $class = shift;

    my $config = Cassandane::Config->default()->clone();
    $config->set(
        caldav_realm => 'Cassandane',
        calendar_user_address_set => 'example.com',
        caldav_historical_age => -1,
        conversations => 1,
        httpmodules => 'caldav carddav jmap',
        httpallowcompress => 'no',
        icalendar_max_size => 100000,
        jmap_nonstandard_extensions => 'yes',
        sieve_maxscripts => $LOTS,
        vcard_max_size => 100000,
    );

    my $self = $class->SUPER::new({
        config => $config,
        jmap => 1,
        services => ['imap', 'http', 'sieve'],
        smtpdaemon => 1,
    }, @_);

    $self->needs('component', 'jmap');
    $self->needs('component', 'sieve');
    return $self;
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

sub put_vevent
{
    my ($self, $calendarid) = @_;

    my ($ics, $uuid) = $self->_random_vevent();
    my $href = "$calendarid/$uuid.ics";

    $self->{caldav}->Request('PUT', $href, $ics,
                             'Content-Type' => 'text/calendar');
}

sub put_vcard
{
    my ($self, $addrbookid) = @_;

    my $vcard = Net::CardDAVTalk::VCard->new_fromstring(_random_vcard());

    $self->{carddav}->NewContact($addrbookid, $vcard);
}

sub put_script
{
    my ($self) = @_;
    state $counter = 1;

    my $name = "script $counter";
    my $script = "# $name\r\nkeep;\r\n";
    $counter ++;

    $self->{jmap}->DefaultUsing([
        'urn:ietf:params:jmap:core',
        'urn:ietf:params:jmap:mail',
        'https://cyrusimap.org/ns/jmap/sieve',
        'https://cyrusimap.org/ns/jmap/blob',
    ]);

    my $res = $self->{jmap}->CallMethods([
        ['Blob/upload', {
            create => {
               "A" => { data => [{'data:asText' => $script}] }
            }
         }, "R0"],
        ['SieveScript/set', {
            create => {
                "1" => {
                    name => $name,
                    blobId => "#A"
                },
            },
         }, "R1"],
    ]);

    $self->assert_not_null($res);
    $self->assert_not_null($res->[1][1]{created}{"1"}{id});
}

# XXX lots of copies of getinbox -- dedup them!
sub getinbox
{
    my ($self, $args) = @_;

    $args = {} unless $args;

    my $jmap = $self->{jmap};

    xlog $self, "get existing mailboxes";
    my $res = $jmap->CallMethods([['Mailbox/get', $args, "R1"]]);
    $self->assert_not_null($res);

    my %m = map { $_->{name} => $_ } @{$res->[0][1]{list}};
    return $m{"Inbox"};
}

sub _submissions_mailbox
{
    my ($self, $counter) = @_;

    my $jmap = $self->{jmap};
    my $folder = "submission $counter";

    my $inboxId = $self->getinbox()->{id};
    $self->assert_not_null($inboxId);

    my $res = $jmap->CallMethods([['Mailbox/set', {
        create => {
            "m$counter" => {
                parentId => $inboxId,
                name => $folder,
            },
        },
    }, "R1"]]);

    $self->assert_not_null($res);
    $self->assert_not_null($res->[0][1]{created}{"m$counter"}{id});

    return $res->[0][1]{created}{"m$counter"}{id};
}

sub put_submission
{
    my ($self) = @_;
    state $counter = 0;

    $counter ++;

    my $jmap = $self->{jmap};
    $jmap->DefaultUsing([
        'urn:ietf:params:jmap:core',
        'urn:ietf:params:jmap:mail',
        'urn:ietf:params:jmap:submission',
    ]);

    my $res = $jmap->CallMethods( [ [ 'Identity/get', {}, "R1" ] ] );
    my $identityId = $res->[0][1]->{list}[0]->{id};
    $self->assert_not_null($identityId);

    # upload each draft to its own mailbox so that we don't accidentally
    # exceed mailbox_maxmessages_email
    my $mailboxId = $self->_submissions_mailbox($counter);
    $self->assert_not_null($mailboxId);

    my $rcpt = Cassandane::Generator::make_random_address();

    $res = $jmap->CallMethods([
        ['Email/set', {
            create => {
                "m$counter" => {
                    mailboxIds => {
                        $mailboxId => JSON::true,
                    },
                    from => [{
                        name => 'cassandane',
                        email => 'cassandane@local',
                    }],
                    to => [{
                        name => $rcpt->name(),
                        email => $rcpt->address(),
                    }],
                    subject => "message $counter",
                    bodyStructure => {
                        type => 'text/plain',
                        partId => 'part1',
                    },
                    bodyValues => {
                        part1 => {
                            value => 'hello world',
                        }
                    },
                },
            },
        }, 'R1'],
        [ 'EmailSubmission/set', {
            create => {
                "s$counter" => {
                    identityId => $identityId,
                    emailId  => "#m$counter",
                    envelope => {
                        mailFrom => {
                            email => 'cassandane@localhost',
                            parameters => {
                                "holdfor" => "30",
                            }
                        },
                        rcptTo => [{
                            email => $rcpt->address(),
                        }],
                    },
                }
           },
        }, 'R2' ],
    ]);

    $self->assert_not_null($res);
    $self->assert_num_equals(1, scalar keys %{$res->[0][1]{created}});
    $self->assert_num_equals(0, scalar keys %{$res->[0][1]{notCreated}});
    $self->assert_num_equals(1, scalar keys %{$res->[1][1]{created}});
    $self->assert_num_equals(0, scalar keys %{$res->[1][1]{notCreated}});
}

sub put_email
{
    my ($self) = @_;
    state $counter = 0;

    $counter ++;

    $self->make_message("message $counter");
}

sub test_maxmsg_addressbook_limited
    :JMAPExtensions :NoStartInstances
{
    my ($self) = @_;

    my $mailbox_maxmessages_addressbook = $LIMITED;
    $self->{instance}->{config}->set(
        mailbox_maxmessages_addressbook => $mailbox_maxmessages_addressbook,
    );
    $self->_start_instances();
    $self->_setup_http_service_objects();

    my $carddav = $self->{carddav};
    my $addrbookid = $carddav->NewAddressBook('foo');
    $self->assert_not_null($addrbookid);

    # should be able to upload 5
    foreach my $i (1..$mailbox_maxmessages_addressbook) {
        $self->put_vcard($addrbookid);
    }

    # but any more should be rejected
    eval {
        $self->put_vcard($addrbookid);
    };
    my $e = $@;
    $self->assert_not_null($e);
    $self->assert_matches(qr{quota-not-exceeded}, $e);

    # should have syslogged about it too
    $self->assert_syslog_matches($self->{instance},
                                 qr{client hit per-addressbook exists limit});

    # should be able to upload lots of calendar events
    my $caldav = $self->{caldav};
    my $calendarid = $caldav->NewCalendar({name => 'mycalendar'});
    $self->assert_not_null($calendarid);
    foreach my $i (1..$LOTS) {
        $self->put_vevent($calendarid);
    }

    # should be able to upload lots of sieve scripts
    foreach my $i (1..$LOTS) {
        $self->put_script();
    }

    # should be able to upload lots of jmap submissions
    foreach my $i (1..$LOTS) {
        $self->put_submission();
    }

    # should be able to upload lots of regular emails
    foreach my $i (1..$LOTS) {
        $self->put_email();
    }
}

sub test_maxmsg_calendar_limited
    :JMAPExtensions :NoStartInstances
{
    my ($self) = @_;

    my $mailbox_maxmessages_calendar = $LIMITED;
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
        $self->put_vevent($calendarid);
    }

    # but any more should be rejected
    eval {
        $self->put_vevent($calendarid);
    };
    my $e = $@;
    $self->assert_not_null($e);
    $self->assert_matches(qr{quota-not-exceeded}, $e);

    # should have syslogged about it too
    $self->assert_syslog_matches($self->{instance},
                                 qr{client hit per-calendar exists limit});

    # should be able to upload lots of contacts
    my $carddav = $self->{carddav};
    my $addrbookid = $carddav->NewAddressBook('foo');
    $self->assert_not_null($addrbookid);
    foreach my $i (1..$LOTS) {
        $self->put_vcard($addrbookid);
    }

    # should be able to upload lots of sieve scripts
    foreach my $i (1..$LOTS) {
        $self->put_script();
    }

    # should be able to upload lots of jmap submissions
    foreach my $i (1..$LOTS) {
        $self->put_submission();
    }

    # should be able to upload lots of regular emails
    foreach my $i (1..$LOTS) {
        $self->put_email();
    }
}

sub test_maxmsg_email_limited
    :JMAPExtensions :NoStartInstances
{
    my ($self) = @_;

    my $mailbox_maxmessages_email = $LIMITED;
    $self->{instance}->{config}->set(
        mailbox_maxmessages_email => $mailbox_maxmessages_email,
    );
    $self->_start_instances();
    $self->_setup_http_service_objects();

    # should be able to upload 5
    foreach my $i (1..$mailbox_maxmessages_email) {
        $self->put_email();
    }

    # but any more should be rejected
    eval {
        $self->put_email();
    };
    my $e = $@;
    $self->assert_not_null($e);
    $self->assert_matches(qr{Over quota}, $e);

    # should have syslogged about it too
    $self->assert_syslog_matches($self->{instance},
                                 qr{client hit per-mailbox exists limit});

    # should be able to upload lots of contacts
    my $carddav = $self->{carddav};
    my $addrbookid = $carddav->NewAddressBook('foo');
    $self->assert_not_null($addrbookid);
    foreach my $i (1..$LOTS) {
        $self->put_vcard($addrbookid);
    }

    # should be able to upload lots of calendar events
    my $caldav = $self->{caldav};
    my $calendarid = $caldav->NewCalendar({name => 'mycalendar'});
    $self->assert_not_null($calendarid);
    foreach my $i (1..$LOTS) {
        $self->put_vevent($calendarid);
    }

    # should be able to upload lots of sieve scripts
    foreach my $i (1..$LOTS) {
        $self->put_script();
    }

    # should be able to upload lots of jmap submissions
    foreach my $i (1..$LOTS) {
        $self->put_submission();
    }
}

sub test_maxmsg_unlimited
    :JMAPExtensions
{
    my ($self) = @_;

    # should be able to upload lots of contacts
    my $carddav = $self->{carddav};
    my $addrbookid = $carddav->NewAddressBook('foo');
    $self->assert_not_null($addrbookid);
    foreach my $i (1..$LOTS) {
        $self->put_vcard($addrbookid);
    }

    # should be able to upload lots of calendar events
    my $caldav = $self->{caldav};
    my $calendarid = $caldav->NewCalendar({name => 'mycalendar'});
    $self->assert_not_null($calendarid);
    foreach my $i (1..$LOTS) {
        $self->put_vevent($calendarid);
    }

    # should be able to upload lots of sieve scripts
    foreach my $i (1..$LOTS) {
        $self->put_script();
    }

    # should be able to upload lots of jmap submissions
    foreach my $i (1..$LOTS) {
        $self->put_submission();
    }

    # should be able to upload lots of regular emails
    foreach my $i (1..$LOTS) {
        $self->put_email();
    }
}

1;
