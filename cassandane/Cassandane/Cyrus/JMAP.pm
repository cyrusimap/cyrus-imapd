#!/usr/bin/perl
#
#  Copyright (c) 2011 Opera Software Australia Pty. Ltd.  All rights
#  reserved.
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
#  3. The name "Opera Software Australia" must not be used to
#     endorse or promote products derived from this software without
#     prior written permission. For permission or any legal
#     details, please contact
# 	Opera Software Australia Pty. Ltd.
# 	Level 50, 120 Collins St
# 	Melbourne 3000
# 	Victoria
# 	Australia
#
#  4. Redistributions of any form whatsoever must retain the following
#     acknowledgment:
#     "This product includes software developed by Opera Software
#     Australia Pty. Ltd."
#
#  OPERA SOFTWARE AUSTRALIA DISCLAIMS ALL WARRANTIES WITH REGARD TO
#  THIS SOFTWARE, INCLUDING ALL IMPLIED WARRANTIES OF MERCHANTABILITY
#  AND FITNESS, IN NO EVENT SHALL OPERA SOFTWARE AUSTRALIA BE LIABLE
#  FOR ANY SPECIAL, INDIRECT OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES
#  WHATSOEVER RESULTING FROM LOSS OF USE, DATA OR PROFITS, WHETHER IN
#  AN ACTION OF CONTRACT, NEGLIGENCE OR OTHER TORTIOUS ACTION, ARISING
#  OUT OF OR IN CONNECTION WITH THE USE OR PERFORMANCE OF THIS SOFTWARE.
#

use strict;
use warnings;

package Cassandane::Cyrus::JMAP;
use base qw(Cassandane::Cyrus::TestCase);
use DateTime;
use Cassandane::Util::Log;
use JSON::XS;
use Net::CardDAVTalk;
use Mail::JMAPTalk;
use Data::Dumper;

sub new
{
    my $class = shift;

    my $config = Cassandane::Config->default()->clone();
    $config->set(caldav_realm => 'Cassandane');
    $config->set(conversations => 'yes');
    $config->set(httpmodules => 'carddav jmap');
    $config->set(httpallowcompress => 'no');
    $config->set(sasl_mech_list => 'PLAIN LOGIN');
    return $class->SUPER::new({
	config => $config,
	services => ['imap', 'http'],
    }, @_);
}

sub set_up
{
    my ($self) = @_;
    $self->SUPER::set_up();
    my $service = $self->{instance}->get_service("http");
    $self->{carddav} = Net::CardDAVTalk->new(
	user => 'cassandane',
	password => 'pass',
	host => $service->host(),
	port => $service->port(),
	scheme => 'http',
	url => '/',
	expandurl => 1,
    );
    $self->{jmap} = Mail::JMAPTalk->new(
	user => 'cassandane',
	password => 'pass',
	host => $service->host(),
	port => $service->port(),
	scheme => 'http',
	url => '/jmap',
    );
}

sub tear_down
{
    my ($self) = @_;
    $self->SUPER::tear_down();
}


sub test_jmap_create
{
    my ($self) = @_;

    my $jmap = $self->{jmap};

    my $res = $jmap->Request([['setContacts', {create => {"#1" => {firstName => "first", lastName => "last"}}}, "R1"]]);
    $self->assert_not_null($res);
    $self->assert_str_equals($res->[0][0], 'contactsSet');
    $self->assert_str_equals($res->[0][2], 'R1');
    my $id = $res->[0][1]{created}{"#1"}{id};

    my $fetch = $jmap->Request([['getContacts', {}, "R2"]]);
    $self->assert_not_null($fetch);
    $self->assert_str_equals($fetch->[0][0], 'contacts');
    $self->assert_str_equals($fetch->[0][2], 'R2');
    $self->assert_str_equals($fetch->[0][1]{list}[0]{firstName}, 'first');
}

sub test_importance_later
{
    my ($self) = @_;

    my $jmap = $self->{jmap};

    xlog "create with no importance";
    my $res = $jmap->Request([['setContacts', {create => {"#1" => {firstName => "first", lastName => "last"}}}, "R1"]]);
    $self->assert_not_null($res);
    $self->assert_str_equals($res->[0][0], 'contactsSet');
    $self->assert_str_equals($res->[0][2], 'R1');
    my $id = $res->[0][1]{created}{"#1"}{id};

    my $fetch = $jmap->Request([['getContacts', {ids => [$id]}, "R2"]]);
    $self->assert_not_null($fetch);
    $self->assert_str_equals($fetch->[0][0], 'contacts');
    $self->assert_str_equals($fetch->[0][2], 'R2');
    $self->assert_str_equals($fetch->[0][1]{list}[0]{firstName}, 'first');
    $self->assert_num_equals($fetch->[0][1]{list}[0]{"x-importance"}, 0.0);

    $res = $jmap->Request([['setContacts', {update => {$id => {"x-importance" => -0.1}}}, "R3"]]);
    $self->assert_not_null($res);
    $self->assert_str_equals($res->[0][0], 'contactsSet');
    $self->assert_str_equals($res->[0][2], 'R3');
    $self->assert_str_equals($res->[0][1]{updated}[0], $id);

    $fetch = $jmap->Request([['getContacts', {ids => [$id]}, "R4"]]);
    $self->assert_not_null($fetch);
    $self->assert_str_equals($fetch->[0][0], 'contacts');
    $self->assert_str_equals($fetch->[0][2], 'R4');
    $self->assert_str_equals($fetch->[0][1]{list}[0]{firstName}, 'first');
    $self->assert_num_equals($fetch->[0][1]{list}[0]{"x-importance"}, -0.1);
}

sub test_importance_upfront
{
    my ($self) = @_;

    my $jmap = $self->{jmap};

    xlog "create with importance in initial create";
    my $res = $jmap->Request([['setContacts', {create => {"#1" => {firstName => "first", lastName => "last", "x-importance" => -5.2}}}, "R1"]]);
    $self->assert_not_null($res);
    $self->assert_str_equals($res->[0][0], 'contactsSet');
    $self->assert_str_equals($res->[0][2], 'R1');
    my $id = $res->[0][1]{created}{"#1"}{id};

    my $fetch = $jmap->Request([['getContacts', {ids => [$id]}, "R2"]]);
    $self->assert_not_null($fetch);
    $self->assert_str_equals($fetch->[0][0], 'contacts');
    $self->assert_str_equals($fetch->[0][2], 'R2');
    $self->assert_str_equals($fetch->[0][1]{list}[0]{firstName}, 'first');
    $self->assert_num_equals($fetch->[0][1]{list}[0]{"x-importance"}, -5.2);

    $res = $jmap->Request([['setContacts', {update => {$id => {"firstName" => "second"}}}, "R3"]]);
    $self->assert_not_null($res);
    $self->assert_str_equals($res->[0][0], 'contactsSet');
    $self->assert_str_equals($res->[0][2], 'R3');
    $self->assert_str_equals($res->[0][1]{updated}[0], $id);

    $fetch = $jmap->Request([['getContacts', {ids => [$id]}, "R4"]]);
    $self->assert_not_null($fetch);
    $self->assert_str_equals($fetch->[0][0], 'contacts');
    $self->assert_str_equals($fetch->[0][2], 'R4');
    $self->assert_str_equals($fetch->[0][1]{list}[0]{firstName}, 'second');
    $self->assert_num_equals($fetch->[0][1]{list}[0]{"x-importance"}, -5.2);
}

sub test_importance_multiedit
{
    my ($self) = @_;

    my $jmap = $self->{jmap};

    xlog "create with no importance";
    my $res = $jmap->Request([['setContacts', {create => {"#1" => {firstName => "first", lastName => "last", "x-importance" => -5.2}}}, "R1"]]);
    $self->assert_not_null($res);
    $self->assert_str_equals($res->[0][0], 'contactsSet');
    $self->assert_str_equals($res->[0][2], 'R1');
    my $id = $res->[0][1]{created}{"#1"}{id};

    my $fetch = $jmap->Request([['getContacts', {ids => [$id]}, "R2"]]);
    $self->assert_not_null($fetch);
    $self->assert_str_equals($fetch->[0][0], 'contacts');
    $self->assert_str_equals($fetch->[0][2], 'R2');
    $self->assert_str_equals($fetch->[0][1]{list}[0]{firstName}, 'first');
    $self->assert_num_equals($fetch->[0][1]{list}[0]{"x-importance"}, -5.2);

    $res = $jmap->Request([['setContacts', {update => {$id => {"firstName" => "second", "x-importance" => -0.2}}}, "R3"]]);
    $self->assert_not_null($res);
    $self->assert_str_equals($res->[0][0], 'contactsSet');
    $self->assert_str_equals($res->[0][2], 'R3');
    $self->assert_str_equals($res->[0][1]{updated}[0], $id);

    $fetch = $jmap->Request([['getContacts', {ids => [$id]}, "R4"]]);
    $self->assert_not_null($fetch);
    $self->assert_str_equals($fetch->[0][0], 'contacts');
    $self->assert_str_equals($fetch->[0][2], 'R4');
    $self->assert_str_equals($fetch->[0][1]{list}[0]{firstName}, 'second');
    $self->assert_num_equals($fetch->[0][1]{list}[0]{"x-importance"}, -0.2);
}

sub test_importance_zero_multi
{
    my ($self) = @_;

    my $jmap = $self->{jmap};

    xlog "create with no importance";
    my $res = $jmap->Request([['setContacts', {create => {"#1" => {firstName => "first", lastName => "last", "x-importance" => -5.2}}}, "R1"]]);
    $self->assert_not_null($res);
    $self->assert_str_equals($res->[0][0], 'contactsSet');
    $self->assert_str_equals($res->[0][2], 'R1');
    my $id = $res->[0][1]{created}{"#1"}{id};

    my $fetch = $jmap->Request([['getContacts', {ids => [$id]}, "R2"]]);
    $self->assert_not_null($fetch);
    $self->assert_str_equals($fetch->[0][0], 'contacts');
    $self->assert_str_equals($fetch->[0][2], 'R2');
    $self->assert_str_equals($fetch->[0][1]{list}[0]{firstName}, 'first');
    $self->assert_num_equals($fetch->[0][1]{list}[0]{"x-importance"}, -5.2);

    $res = $jmap->Request([['setContacts', {update => {$id => {"firstName" => "second", "x-importance" => 0}}}, "R3"]]);
    $self->assert_not_null($res);
    $self->assert_str_equals($res->[0][0], 'contactsSet');
    $self->assert_str_equals($res->[0][2], 'R3');
    $self->assert_str_equals($res->[0][1]{updated}[0], $id);

    $fetch = $jmap->Request([['getContacts', {ids => [$id]}, "R4"]]);
    $self->assert_not_null($fetch);
    $self->assert_str_equals($fetch->[0][0], 'contacts');
    $self->assert_str_equals($fetch->[0][2], 'R4');
    $self->assert_str_equals($fetch->[0][1]{list}[0]{firstName}, 'second');
    $self->assert_num_equals($fetch->[0][1]{list}[0]{"x-importance"}, 0);
}

sub test_importance_zero_byself
{
    my ($self) = @_;

    my $jmap = $self->{jmap};

    xlog "create with no importance";
    my $res = $jmap->Request([['setContacts', {create => {"#1" => {firstName => "first", lastName => "last", "x-importance" => -5.2}}}, "R1"]]);
    $self->assert_not_null($res);
    $self->assert_str_equals($res->[0][0], 'contactsSet');
    $self->assert_str_equals($res->[0][2], 'R1');
    my $id = $res->[0][1]{created}{"#1"}{id};

    my $fetch = $jmap->Request([['getContacts', {ids => [$id]}, "R2"]]);
    $self->assert_not_null($fetch);
    $self->assert_str_equals($fetch->[0][0], 'contacts');
    $self->assert_str_equals($fetch->[0][2], 'R2');
    $self->assert_str_equals($fetch->[0][1]{list}[0]{firstName}, 'first');
    $self->assert_num_equals($fetch->[0][1]{list}[0]{"x-importance"}, -5.2);

    $res = $jmap->Request([['setContacts', {update => {$id => {"x-importance" => 0}}}, "R3"]]);
    $self->assert_not_null($res);
    $self->assert_str_equals($res->[0][0], 'contactsSet');
    $self->assert_str_equals($res->[0][2], 'R3');
    $self->assert_str_equals($res->[0][1]{updated}[0], $id);

    $fetch = $jmap->Request([['getContacts', {ids => [$id]}, "R4"]]);
    $self->assert_not_null($fetch);
    $self->assert_str_equals($fetch->[0][0], 'contacts');
    $self->assert_str_equals($fetch->[0][2], 'R4');
    $self->assert_str_equals($fetch->[0][1]{list}[0]{firstName}, 'first');
    $self->assert_num_equals($fetch->[0][1]{list}[0]{"x-importance"}, 0);
}

1;

