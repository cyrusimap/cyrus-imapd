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

package Cassandane::Cyrus::JMAPBackup;
use strict;
use warnings;
use DateTime;
use JSON::XS;
use Net::CalDAVTalk 0.09;
use Net::CardDAVTalk 0.03;
use Mail::JMAPTalk 0.13;
use Data::Dumper;
use Storable 'dclone';
use File::Basename;
use Test::Deep;

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
        'https://cyrusimap.org/ns/jmap/backup',
        'https://cyrusimap.org/ns/jmap/contacts',
    ]);
}

sub test_backup_restore_contacts
    :min_version_3_1 :needs_component_jmap
{
    my ($self) = @_;

    my $jmap = $self->{jmap};

    xlog "create contacts";
    my $res = $jmap->CallMethods([['Contact/set', {create => {
                        "a" => {firstName => "a", lastName => "a"},
                        "b" => {firstName => "b", lastName => "b"},
                        "c" => {firstName => "c", lastName => "c"},
                        "d" => {firstName => "d", lastName => "d"}
                    }}, "R1"]]);
    $self->assert_not_null($res);
    $self->assert_str_equals('Contact/set', $res->[0][0]);
    $self->assert_str_equals('R1', $res->[0][2]);
    my $contactA = $res->[0][1]{created}{"a"}{id};
    my $contactB = $res->[0][1]{created}{"b"}{id};
    my $contactC = $res->[0][1]{created}{"c"}{id};
    my $contactD = $res->[0][1]{created}{"d"}{id};

    xlog "destroy contact A, update contact B";
    $res = $jmap->CallMethods([['Contact/set', {
                    destroy => [$contactA],
                    update => {$contactB => {firstName => "B"}}
                }, "R2"]]);
    $self->assert_not_null($res);
    $self->assert_str_equals('Contact/set', $res->[0][0]);
    $self->assert_str_equals('R2', $res->[0][2]);

    xlog "get contacts";
    $res = $jmap->CallMethods([
        ['Contact/get', {
            properties => ['firstName', 'lastName'],
         }, "R3"]]);
    $self->assert_not_null($res);
    $self->assert_str_equals('Contact/get', $res->[0][0]);
    $self->assert_str_equals('R3', $res->[0][2]);

    my @expect = sort { $a->{firstName} cmp $b->{firstName} } @{$res->[0][1]{list}};

    sleep 1;
    xlog "destroy contact C, update contacts B and D, create contact E";
    $res = $jmap->CallMethods([['Contact/set', {
                    destroy => [$contactC],
                    update => {
                        $contactB => {lastName => "B"},
                        $contactD => {lastName => "D"},
                    },
                    create => {
                        "e" => {firstName => "e", lastName => "e"}
                    }
                }, "R4"]]);
    $self->assert_not_null($res);
    $self->assert_str_equals('Contact/set', $res->[0][0]);
    $self->assert_str_equals('R4', $res->[0][2]);

    xlog "restore contacts prior to most recent changes";
    $res = $jmap->CallMethods([['Backup/restoreContacts', {
                    undoPeriod => "PT1S",
                    undoCreate => JSON::true,
                    undoUpdate => JSON::true,
                    undoDestroy => JSON::true
                }, "R5"]]);
    $self->assert_not_null($res);
    $self->assert_str_equals('Backup/restoreContacts', $res->[0][0]);
    $self->assert_str_equals('R5', $res->[0][2]);
    $self->assert_num_equals(1, $res->[0][1]{numCreatesUndone});
    $self->assert_num_equals(2, $res->[0][1]{numUpdatesUndone});
    $self->assert_num_equals(1, $res->[0][1]{numDestroysUndone});

    xlog "get restored contacts";
    $res = $jmap->CallMethods([
        ['Contact/get', {
            properties => ['firstName', 'lastName'],
         }, "R6"]]);
    $self->assert_not_null($res);
    $self->assert_str_equals('Contact/get', $res->[0][0]);
    $self->assert_str_equals('R6', $res->[0][2]);

    my @got = sort { $a->{firstName} cmp $b->{firstName} } @{$res->[0][1]{list}};
    $self->assert_num_equals(scalar @expect, scalar @got);
    $self->assert_deep_equals(\@expect, \@got);

    xlog "restore contacts to before initial creation";
    $res = $jmap->CallMethods([['Backup/restoreContacts', {
                    undoPeriod => "P1D",
                    undoCreate => JSON::true,
                    undoUpdate => JSON::true,
                    undoDestroy => JSON::true
                }, "R7"]]);
    $self->assert_not_null($res);
    $self->assert_str_equals('Backup/restoreContacts', $res->[0][0]);
    $self->assert_str_equals('R7', $res->[0][2]);
    $self->assert_num_equals(3, $res->[0][1]{numCreatesUndone});
    $self->assert_num_equals(0, $res->[0][1]{numUpdatesUndone});
    $self->assert_num_equals(0, $res->[0][1]{numDestroysUndone});

    xlog "get restored contacts";
    $res = $jmap->CallMethods([
        ['Contact/get', {
            properties => ['firstName', 'lastName'],
         }, "R8"]]);
    $self->assert_not_null($res);
    $self->assert_str_equals('Contact/get', $res->[0][0]);
    $self->assert_str_equals('R8', $res->[0][2]);
    $self->assert_deep_equals([], $res->[0][1]{list});
}

1;
