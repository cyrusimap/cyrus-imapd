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

package Cassandane::Cyrus::JMAP;
use strict;
use warnings;
use DateTime;
use JSON::XS;
use Net::CalDAVTalk 0.09;
use Net::CardDAVTalk 0.03;
use Mail::JMAPTalk;
use Data::Dumper;
use Storable 'dclone';

use lib '.';
use base qw(Cassandane::Cyrus::TestCase);
use Cassandane::Util::Log;

use charnames ':full';

sub new
{
    my $class = shift;

    my $config = Cassandane::Config->default()->clone();
    $config->set(caldav_realm => 'Cassandane');
    $config->set(conversations => 'yes');
    $config->set(httpmodules => 'carddav caldav jmap');
    $config->set(httpallowcompress => 'no');
    return $class->SUPER::new(
        {
            config   => $config,
            services => [ 'imap', 'http' ],
            adminstore => 1,
        },
        @_
    );
}

sub set_up
{
    my ($self) = @_;
    $self->SUPER::set_up();
    my $service = $self->{instance}->get_service("http");
    $ENV{DEBUGJMAP} = 1;
    eval {
	$self->{carddav} = Net::CardDAVTalk->new(
	    user => 'cassandane',
	    password => 'pass',
	    host => $service->host(),
	    port => $service->port(),
	    scheme => 'http',
	    url => '/',
	    expandurl => 1,
	);
	$self->{caldav} = Net::CalDAVTalk->new(
	    user => 'cassandane',
	    password => 'pass',
	    host => $service->host(),
	    port => $service->port(),
	    scheme => 'http',
	    url => '/',
	    expandurl => 1,
	);
        $self->{caldav}->UpdateAddressSet("Test User", "cassandane\@example.com");
	$self->{jmap} = Mail::JMAPTalk->new(
	    user => 'cassandane',
	    password => 'pass',
	    host => $service->host(),
	    port => $service->port(),
	    scheme => 'http',
	    url => '/jmap',
	);
    };
    if ($@) {
	my $e = $@;
	$self->tear_down();
	die $e;
    }
}

sub tear_down
{
    my ($self) = @_;
    $self->SUPER::tear_down();
}

# XXX Can't have a test suite without any tests in it!
# (n.b. Cassandane::Cyrus::TestCase gets away with not having any tests,
# because Cassandane::Unit::TestPlan::_schedule() explicitly excludes it
# from scheduling.)
sub test_placeholder
{
    my ($self) = @_;
    $self->assert(1);
}

1;
