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

package Cassandane::Cyrus::Carddav;
use base qw(Cassandane::Cyrus::TestCase);
use DateTime;
use Cassandane::Util::Log;
use JSON::XS;
use Net::CardDAVTalk;
use Data::Dumper;
use XML::Spice;

sub new
{
    my $class = shift;

    my $config = Cassandane::Config->default()->clone();
    $config->set(caldav_realm => 'Cassandane');
    $config->set(httpmodules => 'carddav');
    $config->set(httpallowcompress => 'no');
    $config->set(sasl_mech_list => 'PLAIN LOGIN');
    return $class->SUPER::new({
	adminstore => 1,
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
}

sub tear_down
{
    my ($self) = @_;
    $self->SUPER::tear_down();
}


sub test_carddavcreate
{
    my ($self) = @_;

    my $CardDAV = $self->{carddav};

    my $Id = $CardDAV->NewAddressBook('foo');
    $self->assert_not_null($Id);
}

sub test_ordering
{
    my ($self) = @_;

    my $CardDAV = $self->{carddav};
    my $Id = $CardDAV->NewAddressBook('foo', name => 'FIRSTNAME');
    $self->assert_not_null($Id);
    $self->assert_str_equals($Id, 'foo');

    my $admintalk = $self->{adminstore}->get_client();
    $admintalk->create("user.aafirst");

    system('mkdir', "$self->{instance}->{basedir}/conf/log/aafirst");
    system('chown', 'cyrus:mail', "$self->{instance}->{basedir}/conf/log/aafirst");

    my $service = $self->{instance}->get_service("http");
    my $FirstDAV = Net::CardDAVTalk->new(
	user => 'aafirst',
	password => 'pass',
	host => $service->host(),
	port => $service->port(),
	scheme => 'http',
	url => '/',
	expandurl => 1,
    );

    my $FirstId = $FirstDAV->NewAddressBook('aahello', name => 'SECONDNAME');
    $self->assert_not_null($FirstId);
    $self->assert_str_equals($FirstId, 'aahello');

    my $ABook = $FirstDAV->GetAddressBook($FirstId);
    $self->assert_not_null($ABook);

    $FirstDAV->UpdateShareACL($FirstId, { shareWith => [{ email => 'cassandane', mayRead => 1, mayWrite => 1 }] }, $ABook);

    my $Calendars = $CardDAV->GetAddressBooks();
    my $names = join(',', grep { m/NAME/ } map { $_->{name} } @$Calendars);

    $self->assert_str_equals("FIRSTNAME,SECONDNAME", $names);
}

1;
