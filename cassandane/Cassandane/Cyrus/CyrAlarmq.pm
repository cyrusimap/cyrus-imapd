#!/usr/bin/perl
#
#  Copyright (c) 2022 Fastmail Pty Ltd  All rights reserved.
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
#      Fastmail Pty Ltd
#      PO Box 234
#      Collins St West 8007
#      Victoria
#      Australia
#
#  4. Redistributions of any form whatsoever must retain the following
#     acknowledgment:
#     "This product includes software developed by Fastmail Pty. Ltd."
#
#  FASTMAIL PTY LTD DISCLAIMS ALL WARRANTIES WITH REGARD TO
#  THIS SOFTWARE, INCLUDING ALL IMPLIED WARRANTIES OF MERCHANTABILITY
#  AND FITNESS, IN NO EVENT SHALL OPERA SOFTWARE AUSTRALIA BE LIABLE
#  FOR ANY SPECIAL, INDIRECT OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES
#  WHATSOEVER RESULTING FROM LOSS OF USE, DATA OR PROFITS, WHETHER IN
#  AN ACTION OF CONTRACT, NEGLIGENCE OR OTHER TORTIOUS ACTION, ARISING
#  OUT OF OR IN CONNECTION WITH THE USE OR PERFORMANCE OF THIS SOFTWARE.
#

package Cassandane::Cyrus::CyrAlarmq;
use strict;
use warnings;
use Data::Dumper;

use lib '.';
use base qw(Cassandane::Cyrus::TestCase);
use Cassandane::Util::Log;

use charnames ':full';

sub new
{
    my ($class, @args) = @_;

    my $config = Cassandane::Config->default()->clone();
    $config->set(caldav_realm => 'Cassandane',
                 conversations => 'yes',
                 conversations_counted_flags => "\\Draft \\Flagged \$IsMailingList \$IsNotification \$HasAttachment",
                 event_groups => 'mailbox message flags calendar applepushservice jmap',
                 jmap_nonstandard_extensions => 'yes',
                 jmapsubmission_deleteonsend => 'no',
                 httpmodules => 'carddav caldav jmap',
                 httpallowcompress => 'no');

    return $class->SUPER::new({
        config => $config,
        jmap => 1,
        adminstore => 1,
        services => [ 'imap', 'http' ]
    }, @args);
}

sub set_up
{
    my ($self) = @_;
    $self->SUPER::set_up();
    $self->{jmap}->DefaultUsing([
        'urn:ietf:params:jmap:core',
        'urn:ietf:params:jmap:mail',
        'urn:ietf:params:jmap:submission',
    ]);
}

sub test_cyr_alarmq_json
    :min_version_3_9 :needs_component_jmap :needs_component_calalarmd
{
    my ($self) = @_;
    my $jmap = $self->{jmap};

    # we need 'https://cyrusimap.org/ns/jmap/mail' extension capability for
    # snoozed property
    my @using = @{ $jmap->DefaultUsing() };
    push @using, 'https://cyrusimap.org/ns/jmap/mail';
    $jmap->DefaultUsing(\@using);

    my $res = $jmap->CallMethods( [ [ 'Identity/get', {}, "R1" ] ] );
    my $identityid = $res->[0][1]->{list}[0]->{id};
    $self->assert_not_null($identityid);

    $res = $jmap->CallMethods([['Mailbox/query',
                                   {filter => {role => 'inbox'}}, "R1"]]);
    my $inbox = $res->[0][1]->{ids}[0];

    xlog $self, "create snooze mailbox";
    $res = $jmap->CallMethods([
        ['Mailbox/set', { create => { "1" => {
            name => "snoozed",
            parentId => undef,
            role => "snoozed"
        }}}, "R1"]
    ]);
    $self->assert_str_equals('Mailbox/set', $res->[0][0]);
    $self->assert_str_equals('R1', $res->[0][2]);
    $self->assert_not_null($res->[0][1]{created});
    my $snoozedmbox = $res->[0][1]{created}{"1"}{id};

    my %snooze_drafts;
    foreach my $i (1..20) {
        my $until = DateTime->now();
        $until->add(DateTime::Duration->new(seconds => 10 * $i));

        $snooze_drafts{$i} = {
            mailboxIds => { $snoozedmbox => JSON::true },
            from => [ { name => "Yosemite Sam", email => "sam\@acme.local" } ] ,
            to => [ { name => "Bugs Bunny", email => "bugs\@acme.local" }, ],
            subject => "Memo1",
            snoozed => { "until" => $until->strftime('%Y-%m-%dT%TZ') },
        };
    }

    $res = $jmap->CallMethods([['Email/set',
                              { create => \%snooze_drafts },
                              "R1"]]);
    $self->assert_num_equals(20, scalar keys %{$res->[0][1]->{created}});

    # XXX can we arrange for some of these snoozes to fail?

    ####
    xlog $self, "Generate a email via IMAP";
    $self->make_message("foo", body => "a email\r\nwithCRLF\r\n") or die;

    xlog $self, "get email id";
    $res = $jmap->CallMethods( [ [ 'Email/query', {}, "R1" ] ] );
    my $emailid = $res->[0][1]->{ids}[0];

    xlog $self, "create email submissions";
    my %create;
    foreach my $i (1..20) {
        $create{$i} = {
            identityId => $identityid,
            emailId => $emailid,
            envelope => {
                mailFrom => {
                    email => "from${i}\@localhost",
                    parameters => {
                        holdfor => "" . (10 * $i),
                    },
                },
                rcptTo => [
                    { email => "rcpt${i}a\@localhost" },
                    { email => "rcpt${i}b\@localhost" },
                ],
            },
        };
    }

    $res = $jmap->CallMethods( [ [ 'EmailSubmission/set', {
        create => \%create,
    }, "R1" ] ] );
    my $msgsubid1 = $res->[0][1]->{created}{1}{id};
    my $msgsubid2 = $res->[0][1]->{created}{2}{id};
    $self->assert_not_null($msgsubid1);
    $self->assert_not_null($msgsubid2);

    xlog $self, "event were added to the alarmdb";
    my $alarmdata = $self->{instance}->getalarmdb();
    $self->assert_num_equals(40, scalar @$alarmdata);

    xlog $self, "set up a send block";
    $self->{instance}->set_smtpd({ begin_data => ["451", "4.3.0 [jmapError:forbiddenToSend] try later"] });

    xlog $self, "attempt delivery of some of the messages";
    my $now = DateTime->now();
    $self->{instance}->run_command({ cyrus => 1 }, 'calalarmd', '-t' => $now->epoch() + 30 );

#   XXX xlog $self, "all events should still be in the alarmdb";
    $alarmdata = $self->{instance}->getalarmdb();
    $self->assert_num_equals(37, scalar @$alarmdata);

    xlog $self, "clear the send block";
    $self->{instance}->set_smtpd();

    xlog $self, "XXX running cyr_alarmq...";
    $self->{instance}->run_command({ cyrus => 1 }, 'cyr_alarmq',
        '--json',
    );
}

1;
