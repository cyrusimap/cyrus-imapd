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

package Cassandane::Cyrus::JMAPCalendars;
use strict;
use warnings;
use DateTime;
use JSON::XS;
use Net::CalDAVTalk 0.09;
use Net::CardDAVTalk 0.03;
use Mail::JMAPTalk 0.13;
use Data::ICal;
use Data::Dumper;
use Data::GUID qw(guid_string);
use Storable 'dclone';
use Cwd qw(abs_path);
use File::Basename;
use XML::Spice;
use MIME::Base64 qw(encode_base64url decode_base64url);

use lib '.';
use base qw(Cassandane::Cyrus::TestCase);
use Cassandane::Util::Log;

use charnames ':full';

sub new
{
    my ($class, @args) = @_;
    my $config = Cassandane::Config->default()->clone();

    $config->set(caldav_realm => 'Cassandane',
                 caldav_historical_age => -1,
                 conversations => 'yes',
                 httpmodules => 'carddav caldav jmap',
                 httpallowcompress => 'no',
                 sync_log => 'yes',
                 jmap_nonstandard_extensions => 'yes',
                 defaultdomain => 'example.com');

    # Configure Sieve iMIP delivery
    my ($maj, $min) = Cassandane::Instance->get_version();
    if ($maj == 3 && $min == 0) {
        # need to explicitly add 'body' to sieve_extensions for 3.0
        $config->set(sieve_extensions =>
            "fileinto reject vacation vacation-seconds imap4flags notify " .
            "envelope relational regex subaddress copy date index " .
            "imap4flags mailbox mboxmetadata servermetadata variables " .
            "body");
    }
    elsif ($maj < 3) {
        # also for 2.5 (the earliest Cyrus that Cassandane can test)
        $config->set(sieve_extensions =>
            "fileinto reject vacation vacation-seconds imap4flags notify " .
            "envelope relational regex subaddress copy date index " .
            "imap4flags body");
    }
    $config->set(sievenotifier => 'mailto');
    $config->set(calendar_user_address_set => 'example.com');
    $config->set(caldav_historical_age => -1);
    $config->set(virtdomains => 'no');

    return $class->SUPER::new({
        config => $config,
        jmap => 1,
        adminstore => 1,
        deliver => 1,
        services => [ 'imap', 'sieve', 'http' ],
    }, @args);
}

sub set_up
{
    my ($self) = @_;
    $self->SUPER::set_up();
    $self->{jmap}->DefaultUsing([
        'urn:ietf:params:jmap:core',
        'urn:ietf:params:jmap:calendars',
        'urn:ietf:params:jmap:principals',
        'urn:ietf:params:jmap:calendars:preferences',
        'https://cyrusimap.org/ns/jmap/calendars',
        'https://cyrusimap.org/ns/jmap/debug',
    ]);
}

sub encode_eventid
{
    # This function hard-codes the event id format.
    # It might break if we change the id scheme.
    my ($uid, $recurid) = @_;
    my $eid = 'E';
    if ($recurid) {
        $eid .= 'R'
    }
    if ($uid =~ /[^0-9A-Za-z\-_]/) {
        $eid .= 'B';
    }
    $eid .= '-';
    if ($recurid) {
        $eid .= $recurid . '-';
    }
    if ($uid =~ /[^0-9A-Za-z\-_]/) {
        $eid .= encode_base64url($uid);
    }
    else {
        $eid .= $uid;
    }
    return $eid;
}

sub normalize_event
{
    my ($event) = @_;

    if (not exists $event->{q{@type}}) {
        $event->{q{@type}} = 'Event';
    }
    if (not exists $event->{freeBusyStatus}) {
        $event->{freeBusyStatus} = 'busy';
    }
    if (not exists $event->{priority}) {
        $event->{priority} = 0;
    }
    if (not exists $event->{title}) {
        $event->{title} = '';
    }
    if (not exists $event->{description}) {
        $event->{description} = '';
    }
    if (not exists $event->{descriptionContentType}) {
        $event->{descriptionContentType} = 'text/plain';
    }
    if (not exists $event->{showWithoutTime}) {
        $event->{showWithoutTime} = JSON::false;
    }
    if (not exists $event->{locations}) {
        $event->{locations} = undef;
    } elsif (defined $event->{locations}) {
        foreach my $loc (values %{$event->{locations}}) {
            if (not exists $loc->{name}) {
                $loc->{name} = '';
            }
            if (not exists $loc->{q{@type}}) {
                $loc->{q{@type}} = 'Location';
            }
            foreach my $link (values %{$loc->{links}}) {
                if (not exists $link->{q{@type}}) {
                    $link->{q{@type}} = 'Link';
                }
            }
        }
    }
    if (not exists $event->{virtualLocations}) {
        $event->{virtualLocations} = undef;
    } elsif (defined $event->{virtualLocations}) {
        foreach my $loc (values %{$event->{virtualLocations}}) {
            if (not exists $loc->{name}) {
                $loc->{name} = ''
            }
            if (not exists $loc->{description}) {
                $loc->{description} = undef;
            }
            if (not exists $loc->{uri}) {
                $loc->{uri} = undef;
            }
            if (not exists $loc->{q{@type}}) {
                $loc->{q{@type}} = 'VirtualLocation';
            }
        }
    }
    if (not exists $event->{keywords}) {
        $event->{keywords} = undef;
    }
    if (not exists $event->{locale}) {
        $event->{locale} = undef;
    }
    if (not exists $event->{links}) {
        $event->{links} = undef;
    } elsif (defined $event->{links}) {
        foreach my $link (values %{$event->{links}}) {
            if (not exists $link->{q{@type}}) {
                $link->{q{@type}} = 'Link';
            }
        }
    }
    if (not exists $event->{relatedTo}) {
        $event->{relatedTo} = undef;
    } elsif (defined $event->{relatedTo}) {
        foreach my $rel (values %{$event->{relatedTo}}) {
            if (not exists $rel->{q{@type}}) {
                $rel->{q{@type}} = 'Relation';
            }
        }
    }
    if (not exists $event->{participants}) {
        $event->{participants} = undef;
    } elsif (defined $event->{participants}) {
        foreach my $p (values %{$event->{participants}}) {
            if (not exists $p->{linkIds}) {
                $p->{linkIds} = undef;
            }
            if (not exists $p->{participationStatus}) {
                $p->{participationStatus} = 'needs-action';
            }
            if (not exists $p->{expectReply}) {
                $p->{expectReply} = JSON::false;
            }
            if (not exists $p->{scheduleSequence}) {
                $p->{scheduleSequence} = 0;
            }
            if (not exists $p->{q{@type}}) {
                $p->{q{@type}} = 'Participant';
            }
            foreach my $link (values %{$p->{links}}) {
                if (not exists $link->{q{@type}}) {
                    $link->{q{@type}} = 'Link';
                }
            }
        }
    }
    if (not exists $event->{replyTo}) {
        $event->{replyTo} = undef;
    }
    if (not exists $event->{recurrenceRules}) {
        $event->{recurrenceRules} = undef;
    } elsif (defined $event->{recurrenceRules}) {
        foreach my $rrule (@{$event->{recurrenceRules}}) {
            if (not exists $rrule->{interval}) {
                $rrule->{interval} = 1;
            }
            if (not exists $rrule->{firstDayOfWeek}) {
                $rrule->{firstDayOfWeek} = 'mo';
            }
            if (not exists $rrule->{rscale}) {
                $rrule->{rscale} = 'gregorian';
            }
            if (not exists $rrule->{skip}) {
                $rrule->{skip} = 'omit';
            }
            if (not exists $rrule->{byDay}) {
                $rrule->{byDay} = undef;
            } elsif (defined $rrule->{byDay}) {
                foreach my $nday (@{$rrule->{byDay}}) {
                    if (not exists $nday->{q{@type}}) {
                        $nday->{q{@type}} = 'NDay';
                    }
                }
            }
            if (not exists $rrule->{q{@type}}) {
                $rrule->{q{@type}} = 'RecurrenceRule';
            }
        }
    }
    if (not exists $event->{excludedRecurrenceRules}) {
        $event->{excludedRecurrenceRules} = undef;
    } elsif (defined $event->{excludedRecurrenceRules}) {
        foreach my $exrule (@{$event->{excludedRecurrenceRules}}) {
            if (not exists $exrule->{interval}) {
                $exrule->{interval} = 1;
            }
            if (not exists $exrule->{firstDayOfWeek}) {
                $exrule->{firstDayOfWeek} = 'mo';
            }
            if (not exists $exrule->{rscale}) {
                $exrule->{rscale} = 'gregorian';
            }
            if (not exists $exrule->{skip}) {
                $exrule->{skip} = 'omit';
            }
            if (not exists $exrule->{byDay}) {
                $exrule->{byDay} = undef;
            } elsif (defined $exrule->{byDay}) {
                foreach my $nday (@{$exrule->{byDay}}) {
                    if (not exists $nday->{q{@type}}) {
                        $nday->{q{@type}} = 'NDay';
                    }
                }
            }
            if (not exists $exrule->{q{@type}}) {
                $exrule->{q{@type}} = 'RecurrenceRule';
            }
        }
    }
    if (not exists $event->{recurrenceOverrides}) {
        $event->{recurrenceOverrides} = undef;
    }
    if (not exists $event->{alerts}) {
        $event->{alerts} = undef;
    }
    elsif (defined $event->{alerts}) {
        foreach my $alert (values %{$event->{alerts}}) {
            if (not exists $alert->{action}) {
                $alert->{action} = 'display';
            }
            if (not exists $alert->{q{@type}}) {
                $alert->{q{@type}} = 'Alert';
            }
            if (not exists $alert->{relatedTo}) {
                $alert->{relatedTo} = undef;
            } elsif (defined $alert->{relatedTo}) {
                foreach my $rel (values %{$alert->{relatedTo}}) {
                    if (not exists $rel->{q{@type}}) {
                        $rel->{q{@type}} = 'Relation';
                    }
                }
            }
            if ($alert->{trigger} and $alert->{trigger}{q{@type}} eq 'OffsetTrigger') {
                if (not exists $alert->{trigger}{relativeTo}) {
                    $alert->{trigger}{relativeTo} = 'start';
                }
            }
        }
    }
    if (not exists $event->{useDefaultAlerts}) {
        $event->{useDefaultAlerts} = JSON::false;
    }
    if (not exists $event->{prodId}) {
        $event->{prodId} = undef;
    }
    if (not exists $event->{links}) {
        $event->{links} = undef;
    } elsif (defined $event->{links}) {
        foreach my $link (values %{$event->{links}}) {
            if (not exists $link->{cid}) {
                $link->{cid} = undef;
            }
            if (not exists $link->{contentType}) {
                $link->{contentType} = undef;
            }
            if (not exists $link->{size}) {
                $link->{size} = undef;
            }
            if (not exists $link->{title}) {
                $link->{title} = undef;
            }
            if (not exists $link->{q{@type}}) {
                $link->{q{@type}} = 'Link';
            }
        }
    }
    if (not exists $event->{status}) {
        $event->{status} = "confirmed";
    }
    if (not exists $event->{privacy}) {
        $event->{privacy} = "public";
    }
    if (not exists $event->{isDraft}) {
        $event->{isDraft} = JSON::false;
    }
    if (not exists $event->{excluded}) {
        $event->{excluded} = JSON::false,
    }

    if (not exists $event->{calendarIds}) {
        $event->{calendarIds} = undef;
    }
    if (not exists $event->{timeZone}) {
        $event->{timeZone} = undef;
    }

    if (not exists $event->{mayInviteSelf}) {
        $event->{mayInviteSelf} = JSON::false,
    }

    # undefine dynamically generated values
    $event->{created} = undef;
    $event->{updated} = undef;
    $event->{uid} = undef;
    $event->{id} = undef;
    $event->{"x-href"} = undef;
    $event->{sequence} = 0;
    $event->{prodId} = undef;
    $event->{isOrigin} = undef;
    delete($event->{blobId});
    delete($event->{debugBlobId});
}

sub assert_normalized_event_equals
{
    my ($self, $a, $b) = @_;
    my $copyA = dclone($a);
    my $copyB = dclone($b);
    normalize_event($copyA);
    normalize_event($copyB);
    return $self->assert_deep_equals($copyA, $copyB);
}

sub putandget_vevent
{
    my ($self, $id, $ical, $props) = @_;

    my $jmap = $self->{jmap};
    my $caldav = $self->{caldav};

    xlog $self, "get default calendar id";
    my $res = $jmap->CallMethods([['Calendar/get', {ids => ["Default"]}, "R1"]]);
    $self->assert_str_equals("Default", $res->[0][1]{list}[0]{id});
    my $calid = $res->[0][1]{list}[0]{id};
    my $xhref = $res->[0][1]{list}[0]{"x-href"};

    # Create event via CalDAV to test CalDAV/JMAP interop.
    xlog $self, "create event (via CalDAV)";
    my $href = "$xhref/$id.ics";

    $caldav->Request('PUT', $href, $ical, 'Content-Type' => 'text/calendar');

    xlog $self, "get event $id";
    $res = $jmap->CallMethods([['CalendarEvent/get', {ids => [$id], properties => $props}, "R1"]]);

    my $event = $res->[0][1]{list}[0];
    $self->assert_not_null($event);
    return $event;
}

sub icalfile
{
    my ($self, $name) = @_;

    my $path = abs_path("data/icalendar/$name.ics");
    $self->assert(-f $path);
    open(FH, "<$path");
    local $/ = undef;
    my $data = <FH>;
    close(FH);
    my ($id) = ($data =~ m/^UID:(\S+)\r?$/m);
    $self->assert($id);
    return ($id, $data);
}

sub createandget_event
{
    my ($self, $event, %params) = @_;

    my $jmap = $self->{jmap};
    my $accountId = $params{accountId} || 'cassandane';

    xlog $self, "create event";
    my $res = $jmap->CallMethods([['CalendarEvent/set', {
                    accountId => $accountId,
                    create => {"1" => $event}},
    "R1"]]);
    $self->assert_not_null($res->[0][1]{created});
    my $id = $res->[0][1]{created}{"1"}{id};

    xlog $self, "get calendar event $id";
    $res = $jmap->CallMethods([['CalendarEvent/get', {ids => [$id]}, "R1"]]);
    my $ret = $res->[0][1]{list}[0];
    return $ret;
}

sub updateandget_event
{
    my ($self, $event) = @_;

    my $jmap = $self->{jmap};
    my $id = $event->{id};

    xlog $self, "update event $id";
    my $res = $jmap->CallMethods([['CalendarEvent/set', {update => {$id => $event}}, "R1"]]);
    $self->assert_not_null($res->[0][1]{updated});

    xlog $self, "get calendar event $id";
    $res = $jmap->CallMethods([['CalendarEvent/get', {ids => [$id]}, "R1"]]);
    my $ret = $res->[0][1]{list}[0];
    return $ret;
}

sub createcalendar
{
    my ($self) = @_;

    my $jmap = $self->{jmap};

    xlog $self, "create calendar";
    my $res = $jmap->CallMethods([
            ['Calendar/set', { create => { "1" => {
                            name => "foo", color => "coral", sortOrder => 1, isVisible => \1
             }}}, "R1"]
    ]);
    $self->assert_not_null($res->[0][1]{created});
    return $res->[0][1]{created}{"1"}{id};
}

sub assert_rewrite_webdav_attachment_url_itip
    :min_version_3_5 :needs_component_jmap
{
    my ($self, $eventHref) = @_;
    my $jmap = $self->{jmap};
    my $caldav = $self->{caldav};

    xlog "Assert ATTACH in iTIP message is a BINARY value";
    my $data = $self->{instance}->getnotify();
    my ($imip) = grep { $_->{METHOD} eq 'imip' } @$data;
    $self->assert_not_null($imip);
    my $payload = decode_json($imip->{MESSAGE});

    my $ical = Data::ICal->new(data => $payload->{ical});
    my %entries = map { $_->ical_entry_type() => $_ } @{$ical->entries()};
    my $event = $entries{'VEVENT'};
    $self->assert_not_null($event);

    my $attach = $event->property('ATTACH');
    $self->assert_num_equals(1, scalar @{$attach});
    $self->assert_null($attach->[0]->parameters()->{'MANAGED-ID'});
    $self->assert_str_equals('BINARY', $attach->[0]->parameters()->{VALUE});
    $self->assert_str_equals('c29tZWJsb2I=', $attach->[0]->value()); # 'someblob' in base64

    xlog "Assert ATTACH on server is a WebDAV attachment URI";
    my $caldavResponse = $caldav->Request('GET', $eventHref);
    $ical = Data::ICal->new(data => $caldavResponse->{content});
    %entries = map { $_->ical_entry_type() => $_ } @{$ical->entries()};
    $event = $entries{'VEVENT'};
    $self->assert_not_null($event);

    $attach = $event->property('ATTACH');
    $self->assert_num_equals(1, scalar @{$attach});
    $self->assert_not_null($attach->[0]->parameters()->{'MANAGED-ID'});
    $self->assert_null($attach->[0]->parameters()->{VALUE});
    my $webdavAttachURI =
       $self->{instance}->{config}->get('webdav_attachments_baseurl') .
       '/dav/calendars/user/cassandane/Attachments/';
    $self->assert($attach->[0]->value() =~ /^$webdavAttachURI.+/);
}

sub create_user
{
    my ($self, $username) = @_;

    xlog $self, "create user $username";
    my $admin = $self->{adminstore}->get_client();
    $admin->create("user.$username");
    $admin->setacl("user.$username", admin => 'lrswipkxtecdan') or die;
    $admin->setacl("user.$username", $username => 'lrswipkxtecdn') or die;

    my $http = $self->{instance}->get_service("http");
    my $userJmap = Mail::JMAPTalk->new(
        user => $username,
        password => 'pass',
        host => $http->host(),
        port => $http->port(),
        scheme => 'http',
        url => '/jmap/',
    );
    $userJmap->DefaultUsing([
        'urn:ietf:params:jmap:core',
        'urn:ietf:params:jmap:calendars',
        'https://cyrusimap.org/ns/jmap/calendars',
    ]);

    my $userCalDAV = Net::CalDAVTalk->new(
        user => $username,
        password => 'pass',
        host => $http->host(),
        port => $http->port(),
        scheme => 'http',
        url => '/',
        expandurl => 1,
    );

    return ($userJmap, $userCalDAV);
}

sub deliver_imip {
    my ($self) = @_;

    my $uuid = guid_string();
    my $imip = <<"EOF";
Date: Thu, 23 Sep 2021 09:06:18 -0400
From: Sally Sender <sender\@example.net>
To: Cassandane <cassandane\@example.com>
Message-ID: <$uuid\@example.net>
Content-Type: text/calendar; method=REQUEST; component=VEVENT
X-Cassandane-Unique: $uuid

BEGIN:VCALENDAR
VERSION:2.0
PRODID:-//Apple Inc.//Mac OS X 10.10.4//EN
METHOD:REQUEST
BEGIN:VEVENT
CREATED:20210923T034327Z
UID:$uuid
DTEND;TZID=America/New_York:20210923T183000
TRANSP:OPAQUE
SUMMARY:An Event
DTSTART;TZID=American/New_York:20210923T153000
DTSTAMP:20210923T034327Z
SEQUENCE:0
ORGANIZER;CN=Test User:MAILTO:foo\@example.net
ATTENDEE;PARTSTAT=NEEDS-ACTION;RSVP=TRUE:MAILTO:cassandane\@example.com
END:VEVENT
END:VCALENDAR
EOF

    xlog $self, "Deliver iMIP invite";
    $self->{instance}->deliver(Cassandane::Message->new(raw => $imip));
};

use Cassandane::Tiny::Loader 'tiny-tests/JMAPCalendars';

1;
