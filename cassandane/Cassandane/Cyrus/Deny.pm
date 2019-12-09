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

package Cassandane::Cyrus::Deny;
use strict;
use warnings;

use lib '.';
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

    xlog $self, "Test the cyr_deny utility with the imap service";

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


    xlog $self, "Create all users";
    foreach my $case (@cases)
    {
        $self->{instance}->create_user($case->{user});
    }

    xlog $self, "Running cyr_deny for some users";
    foreach my $case (@cases)
    {
        next unless defined $case->{opts};
        $self->{instance}->run_command({ cyrus => 1 },
                'cyr_deny', @{$case->{opts}}, $case->{user});
    }

    my $svc = $self->{instance}->get_service('imap');
    foreach my $case (@cases)
    {
        xlog $self, "Trying to log in as user $case->{user}";
        my $store = $svc->create_store(username => $case->{user});
        if ($case->{can_login})
        {
            xlog $self, "Expecting this to succeeed";
            my $talk = $store->get_client();
            my $r = $talk->status('inbox', [ 'messages' ]);
            $self->assert_deep_equals({ messages => 0 }, $r);
            $talk = undef;
        }
        else
        {
            xlog $self, "Expecting this to fail";
            eval { $store->get_client(); };
            my $exception = $@;
            $self->assert_matches(qr/no - login failed: authorization failure/i, $exception);
        }
    }
}

sub test_connected
{
    my ($self) = @_;

    xlog $self, "Test that cyr_deny shuts down any connected sessions";

    xlog $self, "Create a user";
    my $user = 'gastropub';
    $self->{instance}->create_user($user);

    xlog $self, "Set up a logged-in client for each of two users";
    my $cass_talk = $self->{store}->get_client();

    my $svc = $self->{instance}->get_service('imap');
    my $user_store = $svc->create_store(username => $user);
    my $user_talk = $user_store->get_client();

    xlog $self, "Check that we can run a command in each of the two clients";
    my $res;
    $res = $cass_talk->status('inbox', [ 'messages' ]);
    $self->assert_deep_equals({ messages => 0 }, $res);
    $res = $user_talk->status('inbox', [ 'messages' ]);
    $self->assert_deep_equals({ messages => 0 }, $res);

    $user_talk->clear_response_code('alert');

    xlog $self, "Deny the user";
    $self->{instance}->run_command({ cyrus => 1 }, 'cyr_deny', $user);

    xlog $self, "Check that we can run a command in the unaffected user";
    $res = $cass_talk->status('inbox', [ 'messages' ]);
    $self->assert_deep_equals({ messages => 0 }, $res);

    xlog $self, "Check that the affected user is disconnected";
    $res = undef;
    # Either is_open will return undef, or die; both of these
    # are good.  If it returned 1 we should worry.
    eval { $res = $user_talk->is_open(); };
    $self->assert_null($res);

    # Could do this, but Mail::IMAPTalk drops ALERTs in a BYE response
#     $self->assert_matches(qr/Access to this service has been blocked/i,
#                         $user_talk->get_response_code('alert'));
}

1;
