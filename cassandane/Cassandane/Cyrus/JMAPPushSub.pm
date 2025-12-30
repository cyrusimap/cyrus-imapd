#!/usr/bin/perl
#
#  Copyright (c) 2011-2019 FastMail Pty Ltd. All rights reserved.
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

package Cassandane::Cyrus::JMAPPushSub;
use strict;
use warnings;
use DateTime;
use JSON;
use JSON::XS;
use Mail::JMAPTalk 0.13;
use Data::Dumper;
use Storable 'dclone';
use File::Basename;
use IO::File;

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
                 httpmodules => 'jmap',
                 httpallowcompress => 'no',
                 event_groups => 'mailbox message flags calendar applepushservice jmap',
                 jmap_nonstandard_extensions => 'yes');

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
    ]);
}

sub tear_down
{
    my ($self) = @_;
    $self->SUPER::tear_down();
}

sub test_pushsub_set
    :min_version_3_7 :needs_component_jmap
{
    my ($self) = @_;

    my $jmap = $self->{jmap};

    xlog "create subscription";
    my $res = $jmap->CallMethods([
        ['PushSubscription/get', {
         }, "R0"],
        ['PushSubscription/set', {
            create => {
                "1" => {
                    deviceClientId => "a889-ffea-910",
                    url => "https://example.com/push/?device=X8980fc&client=12c6d086",
                    types => [ "Mailbox", "Email" ]
                },
            },
         }, "R1"],
        ['PushSubscription/get', {
            'ids' => [ '#1' ]
         }, "R2"]
    ]);
    $self->assert_not_null($res);
    $self->assert_num_equals(0, scalar @{$res->[0][1]{list}});

    $self->assert_not_null($res->[1][1]{created}{"1"}{id});
    $self->assert_not_null($res->[1][1]{created}{"1"}{expires});
    my $id = $res->[1][1]{created}{"1"}{id};

    $self->assert_num_equals(1, scalar @{$res->[2][1]{list}});
    $self->assert_str_equals($id, $res->[2][1]{list}[0]{id});
    $self->assert_null($res->[2][1]{list}[0]{url});
    $self->assert_null($res->[2][1]{list}[0]{keys});
    $self->assert_null($res->[2][1]{list}[0]{verificationCode});

    my $data = $self->{instance}->getnotify();
    my $code;
    foreach (@$data) {
        if ($_->{CLASS} eq 'EVENT') {
            my $e = decode_json($_->{MESSAGE});
            if ($e->{event} eq "PushSubscriptionCreated") {
                $code = $e->{content}->{verificationCode};
            }
        }
    }

    xlog "update subscription";
    $res = $jmap->CallMethods([
        ['PushSubscription/set', {
            update => {
                $id => {
                    verificationCode => $code,
                    expires => "2038-01-19T03:14:07Z",
                    types => [ "Email", "EmailSubmission" ]
                },
            },
         }, "R1"],
        ['PushSubscription/get', { }, "R2"]
    ]);
    $self->assert_not_null($res);
    $self->assert_not_null($res->[0][1]{updated}{$id}{expires});
    $self->assert_num_equals(1, scalar @{$res->[1][1]{list}});

    xlog "destroy subscription";
    $res = $jmap->CallMethods([
        ['PushSubscription/set', {
            destroy => [ $id ]
         }, "R1"],
        ['PushSubscription/get', { }, "R2"]
    ]);
    $self->assert_not_null($res);
    $self->assert_str_equals($id, $res->[0][1]{destroyed}[0]);
    $self->assert_num_equals(0, scalar @{$res->[1][1]{list}});
}

1;
