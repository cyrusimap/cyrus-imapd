# SPDX-License-Identifier: BSD-3-Clause-CMU
# See COPYING file at the root of the distribution for more details.

package Cassandane::Cyrus::JMAPCalendars;
use strict;
use warnings;
use DateTime;
use JSON::XS;
use Net::CalDAVTalk 0.14;
use Net::CardDAVTalk 0.11;
use Data::ICal;
use Data::Dumper;
use Data::GUID qw(guid_string);
use Storable 'dclone';
use Cwd qw(abs_path);
use File::Basename;
use XML::Spice;
use MIME::Base64 qw(encode_base64url decode_base64url encode_base64 decode_base64);

use base qw(Cassandane::Cyrus::TestCase);
use Cassandane::Util::Log;
use Cassandane::Util::Slurp;

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
                 imipnotifier => 'imip',
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

    my $self = $class->SUPER::new({
        config => $config,
        jmap => 1,
        adminstore => 1,
        deliver => 1,
        services => [ 'imap', 'sieve', 'http' ],
    }, @args);

    $self->needs('component', 'jmap');
    return $self;
}

sub jmap_default_using
{
    return [
        'urn:ietf:params:jmap:core',
        'urn:ietf:params:jmap:calendars',
        'urn:ietf:params:jmap:principals',
        'urn:ietf:params:jmap:calendars:preferences',
        'https://cyrusimap.org/ns/jmap/calendars',
        'https://cyrusimap.org/ns/jmap/debug',
        'https://cyrusimap.org/ns/jmap/jscalendarbis',
    ];
}

sub encode_eventid
{
    # This function hard-codes the event id format.
    # It might break if we change the id scheme.
    my ($id, $recurid) = @_;
    my $eid = '';
    if ($recurid) {
        $eid .= 'ER' . $recurid . '-';
    }
    $eid .= $id;
    return $eid;
}

sub normalize_event
{
    my ($event) = @_;

    # @type
    $event->{q{@type}} //= 'Event';
    # calendarIds
    if (not defined $event->{calendarIds}) {
        delete($event->{calendarIds});
    }
    # alerts
    if (not defined $event->{alerts}) {
        delete($event->{alerts});
    }
    else {
        foreach my $alert (values %{$event->{alerts}}) {
            $alert->{action} //= 'display';
            $alert->{q{@type}} //= 'Alert';
            if (not defined $alert->{relatedTo}) {
                delete($alert->{relatedTo});
            } else {
                foreach my $rel (values %{$alert->{relatedTo}}) {
                    $rel->{q{@type}} //= 'Relation';
                    $rel->{relation} //= {};
                }
            }
            if (defined $alert->{trigger}) {
                $alert->{trigger}{q{@type}} //= 'OffsetTrigger';
                if ((not defined $alert->{trigger}{relativeTo}) &&
                    $alert->{trigger}{q{@type}} eq 'OffsetTrigger') {
                    $alert->{trigger}{relativeTo} = 'start';
                }
            }
        }
    }
    # categories
    if (not defined $event->{categories}) {
        delete($event->{categories});
    }
    # color
    if (not defined $event->{color}) {
        delete($event->{color});
    }
    # description
    $event->{description} //= '';
    # descriptionContentType
    $event->{descriptionContentType} //= 'text/plain';
    # duration
    $event->{duration} //= 'PT0S';
    # endTimeZone
    if (not defined $event->{endTimeZone}) {
        delete($event->{endTimeZone});
    }
    # freeBusyStatus
    $event->{freeBusyStatus} //= 'busy';
    # keywords
    if (not defined $event->{keywords}) {
        delete($event->{keywords});
    }
    # isDraft
    $event->{isDraft} //= JSON::false;
    # links
    if (not defined $event->{links}) {
        delete($event->{links});
    } else {
        foreach my $link (values %{$event->{links}}) {
            if (not defined $link->{cid}) {
                delete($link->{cid});
            }
            if (not defined $link->{contentType}) {
                delete($link->{contentType});
            }
            if (not defined $link->{size}) {
                delete($link->{size});
            }
            if (not defined $link->{title}) {
                delete($link->{title});
            }
            $link->{q{@type}} //= 'Link';
        }
    }
    # locale
    if (not defined $event->{locale}) {
        delete($event->{locale});
    }
    # locations
    if (not defined $event->{locations}) {
        delete($event->{locations});
    } else {
        foreach my $loc (values %{$event->{locations}}) {
            $loc->{q{@type}} //= 'Location';
            foreach my $link (values %{$loc->{links}}) {
                $link->{q{@type}} //= 'Link';
            }
        }
    }
    # mainLocationId
    if (not defined $event->{mainLocationId}) {
        delete($event->{mainLocationId});
    }
    # method
    if (not defined $event->{method}) {
        delete($event->{method});
    }
    # organizerCalendarAddress
    if (not defined $event->{organizerCalendarAddress}) {
        delete($event->{organizerCalendarAddress});
    }
    # participants
    if (not defined $event->{participants}) {
        delete($event->{participants});
    } else {
        foreach my $p (values %{$event->{participants}}) {
            if (not defined $p->{linkIds}) {
                delete($p->{linkIds});
            }
            $p->{participationStatus} //= 'needs-action';
            $p->{expectReply} //= JSON::false;
            $p->{scheduleSequence} //= 0;
            $p->{q{@type}} //= 'Participant';
            foreach my $link (values %{$p->{links}}) {
                $link->{q{@type}} //= 'Link';
            }
        }
    }
    # priority
    $event->{priority} //= 0;
    # privacy
    $event->{privacy} //= "public";
    # recurrenceId
    if (not defined $event->{recurrenceId}) {
        delete($event->{recurrenceId});
    }
    # recurrenceIdTimeZone
    if (not defined $event->{recurrenceIdTimeZone}) {
        delete($event->{recurrenceIdTimeZone});
    }
    # recurrenceRule
    if (not defined $event->{recurrenceRule}) {
        delete($event->{recurrenceRule});
    } else {
        my $rrule = $event->{recurrenceRule};
        $rrule->{interval} //= 1;
        $rrule->{firstDayOfWeek} //= 'mo';
        $rrule->{rscale} //= 'gregorian';
        $rrule->{skip} //= 'omit';
        if (not defined $rrule->{byDay}) {
            delete($rrule->{byDay});
        } else {
            foreach my $nday (@{$rrule->{byDay}}) {
                $nday->{q{@type}} //= 'NDay';
            }
        }
        $rrule->{q{@type}} //= 'RecurrenceRule';
    }
    # recurrenceOverrides
    if (not defined $event->{recurrenceOverrides}) {
        delete($event->{recurrenceOverrides});
    }
    # relatedTo
    if (not defined $event->{relatedTo}) {
        delete($event->{relatedTo});
    } else {
        foreach my $rel (values %{$event->{relatedTo}}) {
            $rel->{q{@type}} //= 'Relation';
        }
    }
    # sentBy
    if (not defined $event->{sentBy}) {
        delete($event->{sentBy});
    }
    # showWithoutTime
    $event->{showWithoutTime} //= JSON::false;
    # status
    $event->{status} //= "confirmed";
    # title
    $event->{title} //= '';
    # timeZone
    if (not defined $event->{timeZone}) {
        delete($event->{timeZone});
    }
    # useDefaultAlerts
    $event->{useDefaultAlerts} //= JSON::false;
    # virtualLocations
    if (not defined $event->{virtualLocations}) {
        delete($event->{virtualLocations});
    } else {
        foreach my $loc (values %{$event->{virtualLocations}}) {
            $loc->{name} //= '';
            if (not defined $loc->{description}) {
                delete($loc->{description});
            }
            if (not defined $loc->{uri}) {
                delete($loc->{uri});
            }
            $loc->{q{@type}} //= 'VirtualLocation';
        }
    }

    # delete dynamically generated values
    delete($event->{created});
    delete($event->{updated});
    delete($event->{uid});
    delete($event->{id});
    delete($event->{"x-href"});
    delete($event->{prodId});
    delete($event->{isOrigin});
    delete($event->{blobId});
    delete($event->{debugBlobId});
    $event->{sequence} = 0;
}

sub assert_normalized_event_equals
{
    my ($self, $a, $b) = @_;
    my $copyA = dclone($a);
    my $copyB = dclone($b);

    # Only compare property names and values,
    # regardless of version.
    delete($copyA->{version});
    delete($copyB->{version});

    normalize_event($copyA);
    normalize_event($copyB);
    return $self->assert_cmp_deeply($copyA, $copyB);
}

sub putandget_vevent
{
    my ($self, $id, $ical, $props) = @_;

    my $jmap = $self->{jmap};
    my $caldav = $self->{caldav};

    xlog $self, "get default calendar id and href";
    my $default_calendar = $self->default_user->calendars->default;
    my $calid = $default_calendar->id;
    my $xhref = $default_calendar->properties->{'x-href'};

    # Create event via CalDAV to test CalDAV/JMAP interop.
    xlog $self, "create event (via CalDAV)";
    my $href = "$xhref/$id.ics";

    $caldav->Request('PUT', $href, $ical, 'Content-Type' => 'text/calendar');

    xlog $self, "get event $id";
    my $res = $jmap->CallMethods([['CalendarEvent/get', {ids => [$id], properties => $props}, "R1"]]);

    my $event = $res->[0][1]{list}[0];
    $self->assert_not_null($event);
    return $event;
}

sub icalfile
{
    my ($self, $name) = @_;

    my $path = abs_path("data/icalendar/$name.ics");
    $self->assert_file_test($path, '-f');
    my $data = slurp_file($path);

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

    my $user_obj = Cassandane::TestUser->new({
        username => $username,
        password => 'pass',
        instance => $self->{instance},
    });

    my $jmap = $user_obj->new_jmaptester;

    my $caldav = $user_obj->caldav;

    return ($jmap, $caldav);
}

sub create_user_and_allocate_calendar
{
    my ($self, $username, %params) = @_;

    my $user = $self->{instance}->create_user($username, %params);

    # Connecting over CalDAV provisions the user's calendar home, e.g.
    # user.$username.#calendars.Default.  Some tests need that mailbox to
    # exist before the new user has issued any calendar request of their own
    # -- for example, to set an ACL on the default calendar.
    #
    # Hopefully this whole method can go, later.
    $user->caldav;

    return $user;
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

use Cassandane::Tiny::Loader;

1;
