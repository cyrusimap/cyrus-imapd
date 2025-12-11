#!/usr/bin/perl
#
#  Copyright (c) 2011-2023 FastMail Pty Ltd. All rights reserved.
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

package Cassandane::Cyrus::JMAPVacationResponse;
use strict;
use warnings;
use DateTime;
use JSON;
use JSON::XS;
use Data::Dumper;
use Storable 'dclone';
use File::Basename;
use IO::File;

use base qw(Cassandane::Cyrus::TestCase);
use Cassandane::Util::Log;

use charnames ':full';

sub new
{
    my ($class, @args) = @_;

    my $config = Cassandane::Config->default()->clone();

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

    $config->set(caldav_realm => 'Cassandane',
                 conversations => 'yes',
                 httpmodules => 'jmap',
                 httpallowcompress => 'no');

    my $self = $class->SUPER::new({
        config => $config,
        jmap => 1,
        deliver => 1,
        adminstore => 1,
        services => [ 'imap', 'sieve', 'http' ]
    }, @args);

    $self->needs('component', 'jmap');
    return $self;
}

sub set_up
{
    my ($self) = @_;
    $self->SUPER::set_up();
    $self->{jmap}->DefaultUsing([
        'urn:ietf:params:jmap:core',
        'urn:ietf:params:jmap:vacationresponse'
    ]);
}

sub tear_down
{
    my ($self) = @_;
    $self->SUPER::tear_down();
}

sub test_vacation_get_none
    :min_version_3_9
{
    my ($self) = @_;

    my $jmap = $self->{jmap};

    xlog "get vacation";
    my $res = $jmap->CallMethods([
        ['VacationResponse/get', {
            properties => ['isEnabled']
    }, "R1"]]);
    $self->assert_not_null($res);
    $self->assert_str_equals('VacationResponse/get', $res->[0][0]);
    $self->assert_str_equals('R1', $res->[0][2]);
    $self->assert_num_equals(1, scalar @{$res->[0][1]{list}});
    $self->assert_str_equals('singleton', $res->[0][1]{list}[0]{id});
    $self->assert_equals(JSON::false, $res->[0][1]{list}[0]{isEnabled});
    $self->assert(not exists $res->[0][1]{list}[0]{subject});
}

sub test_vacation_set
    :min_version_3_9
{
    my ($self) = @_;

    my $jmap = $self->{jmap};

    xlog "attempt to create a new vacation response";
    my $res = $jmap->CallMethods([
        ['VacationResponse/set', {
            create => {
                "1" => {
                    textBody => "Gone fishing"
                }
            }
    }, "R1"]]);
    $self->assert_not_null($res);
    $self->assert_str_equals('VacationResponse/set', $res->[0][0]);
    $self->assert_str_equals('R1', $res->[0][2]);
    $self->assert_str_equals('singleton', $res->[0][1]{notCreated}{1}{type});

    xlog "enable the vacation response";
    $res = $jmap->CallMethods([
        ['VacationResponse/set', {
            update => {
                "singleton" => {
                    isEnabled=> JSON::true,
                    textBody => "Gone fishing"
                }
            }
         }, "R1"],
        ['VacationResponse/get', {
    }, "R2"]
    ]);
    $self->assert_not_null($res);
    $self->assert_str_equals('VacationResponse/set', $res->[0][0]);
    $self->assert_str_equals('R1', $res->[0][2]);
    $self->assert(exists $res->[0][1]{updated}{singleton});
    $self->assert_str_equals('VacationResponse/get', $res->[1][0]);
    $self->assert_str_equals('R2', $res->[1][2]);
    $self->assert_num_equals(1, scalar @{$res->[1][1]{list}});
    $self->assert_str_equals('singleton', $res->[1][1]{list}[0]{id});
    $self->assert_equals(JSON::true, $res->[1][1]{list}[0]{isEnabled});
    $self->assert_str_equals('Gone fishing', $res->[1][1]{list}[0]{textBody});

    xlog "disable the vacation response";
    $res = $jmap->CallMethods([
        ['VacationResponse/set', {
            update => {
                "singleton" => {
                    isEnabled=> JSON::false
                }
            }
         }, "R1"],
        ['VacationResponse/get', {
    }, "R2"]
    ]);
    $self->assert_not_null($res);
    $self->assert_str_equals('VacationResponse/set', $res->[0][0]);
    $self->assert_str_equals('R1', $res->[0][2]);
    $self->assert(exists $res->[0][1]{updated}{singleton});
    $self->assert_str_equals('VacationResponse/get', $res->[1][0]);
    $self->assert_str_equals('R2', $res->[1][2]);
    $self->assert_num_equals(1, scalar @{$res->[1][1]{list}});
    $self->assert_str_equals('singleton', $res->[1][1]{list}[0]{id});
    $self->assert_equals(JSON::false, $res->[1][1]{list}[0]{isEnabled});
    $self->assert_str_equals('Gone fishing', $res->[1][1]{list}[0]{textBody});

    xlog "attempt to destroy the vacation response";
    $res = $jmap->CallMethods([
        ['VacationResponse/set', {
            destroy => ["singleton"]
         }, "R1"]]);
    $self->assert_not_null($res);
    $self->assert_str_equals('VacationResponse/set', $res->[0][0]);
    $self->assert_str_equals('R1', $res->[0][2]);
    $self->assert_str_equals('singleton',
                             $res->[0][1]{notDestroyed}{singleton}{type});
}

1;
