#!/usr/bin/perl
#
#  Copyright (c) 2012 Opera Software Australia Pty. Ltd.  All rights
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
package Cassandane::Cyrus::Deny;
use base qw(Cassandane::Cyrus::TestCase);
use Cassandane::Util::Log;

sub new
{
    my $class = shift;
    return $class->SUPER::new({}, @_);
}

sub set_up
{
    my ($self) = @_;
    $self->SUPER::set_up();
}

sub tear_down
{
    my ($self) = @_;
    $self->SUPER::tear_down();
}

sub test_basic
{
    my ($self) = @_;

    xlog "Test the cyr_deny utility with the imap service";

    # Data thanks to hipsteripsum.me
    my @cases = ({
	    # test default options
	    user => 'helvetica',
	    opts => [ ],
	    can_login => 0,
	},{
	    # test the -s option with our service
	    user => 'portland',
	    opts => [ '-s', 'imap' ],
	    can_login => 0,
	},{
	    # test the -s option with another service
	    user => 'stumptown',
	    opts => [ '-s', 'godard' ],
	    can_login => 1,
	},{
	    # test the -m option
	    user => 'mustache',
	    opts => [ '-m', 'Bugger off, you' ],
	    can_login => 0,
	},{
	    # control case - no cyr_deny command run
	    user => 'vegan',
	    can_login => 1,
	});


    xlog "Create all users";
    foreach my $case (@cases)
    {
	$self->{instance}->create_user($case->{user});
    }

    xlog "Running cyr_deny for some users";
    foreach my $case (@cases)
    {
	next unless defined $case->{opts};
	$self->{instance}->run_command({ cyrus => 1 },
		'cyr_deny', @{$case->{opts}}, $case->{user});
    }

    my $svc = $self->{instance}->get_service('imap');
    foreach my $case (@cases)
    {
	xlog "Trying to log in as user $case->{user}";
	my $store = $svc->create_store(username => $case->{user});
	if ($case->{can_login})
	{
	    xlog "Expecting this to succeeed";
	    my $talk = $store->get_client();
	    my $r = $talk->status('inbox', [ 'messages' ]);
	    $self->assert_deep_equals({ messages => 0 }, $r);
	    $talk = undef;
	}
	else
	{
	    xlog "Expecting this to fail";
	    eval { $store->get_client(); };
	    my $exception = $@;
	    $self->assert_matches(qr/no - login failed: authorization failure/i, $exception);
	}
    }
}

1;
