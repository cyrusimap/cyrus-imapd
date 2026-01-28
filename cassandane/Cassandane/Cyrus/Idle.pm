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

package Cassandane::Cyrus::Idle;
use strict;
use warnings;
use DateTime;

use base qw(Cassandane::Cyrus::TestCase);
use Cassandane::Util::Log;

sub new
{
    my $class = shift;
    my $config = Cassandane::Config->default()->clone();
    $config->set(imapidlepoll => 2);
    return $class->SUPER::new({
        config => $config,
        deliver => 1,
        start_instances => 0,
    }, @_);
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

sub start_and_abort_idled
{
    my ($self) = @_;

    # We don't start idled via the START section in cyrus.conf,
    # because master would restart it when we kill it, and we
    # want to test that the fallback to polling mode works even
    # when it's not restarted.
    #
    # Also note, one of the effects of the -d option is to prevent
    # idled forking, which lets us predict which pid to kill.

    my $pid = $self->{instance}->run_command({
        cyrus => 1,
        background => 1
    }, 'idled', '-d');
    xlog $self, "pid of idled should be $pid";

    xlog $self, "giving idled some time to start up";
    my $tries = 60;
    my $idle_sock = $self->{instance}->{basedir} . "/conf/socket/idle";
    while ($tries--) {
        last if -S $idle_sock;
        sleep 1;
    }
    $self->assert($tries > 0, "idled started successfully");

    xlog $self, "bring idled's reign to an abrupt and brutal end";
    kill('KILL', $pid)
        or die "Failed to kill idled $pid: $!";

    # reap_command will 'die' because the process terminated
    # on SIGKILL.  We need to avoid that stopping the test.
    # But we still need to waitpid() to avoid zombies.
    xlog $self, "reaping pid $pid";
    eval { $self->{instance}->reap_command($pid); };

    # Now, no idled is running, but any state created by idled in the
    # filesystem is still present.  In particular, the idle socket.
    # Let's check that our assumption is correct.
    xlog $self, "check that idle left a socket lying around";
    $self->assert( -S $idle_sock, "$idle_sock exists and is a socket");
}

sub common_basic
{
    my ($self) = @_;

    my $svc = $self->{instance}->get_service('imap');

    my $store = $svc->create_store(folder => 'INBOX');
    my $talk = $store->get_client();
    $store->_select();

    xlog $self, "The server should report the IDLE capability";
    $self->assert($talk->capability()->{idle});

    xlog $self, "Sending the IDLE command";
    $store->idle_begin()
        or die "IDLE failed: $@";

    xlog $self, "Poll for any unsolicited response - should be none";
    my $r = $store->idle_response({}, 0);
    $self->assert(!$r, "No unsolicted response");

    xlog $self, "Sending DONE continuation";
    $store->idle_end({});
    $self->assert_str_equals('ok', $talk->get_last_completion_response());

    xlog $self, "Testing that normal IMAP commands still work";
    my $res = $talk->status('INBOX', '(messages unseen)');
    $self->assert_deep_equals({ messages => 0, unseen => 0 }, $res);
}

sub common_delivery
{
    my ($self) = @_;

    xlog $self, "Starting up the instance";
    my $svc = $self->{instance}->get_service('imap');

    my $store = $svc->create_store(folder => 'INBOX');
    my $talk = $store->get_client();
    $store->_select();

    xlog $self, "Sending the IDLE command";
    $store->idle_begin()
        or die "IDLE failed: $@";

    xlog $self, "Poll for any unsolicited response - should be none";
    my $r = $store->idle_response({}, 0);
    $self->assert(!$r, "No unsolicted response");

    xlog $self, "sleeping for 3 seconds";
    sleep(3);

    xlog $self, "Poll for any unsolicited response - should be none";
    $r = $store->idle_response({}, 0);
    $self->assert(!$r, "No unsolicted response");

    xlog $self, "Deliver a message";
    my $msg = $self->{gen}->generate(subject => "Message 1");
    $self->{instance}->deliver($msg);

    $r = $store->idle_response({}, 5);
    $self->assert($r, "received an unsolicited response");
    $r = $store->idle_response({}, 5);
    $self->assert($r, "received an unsolicited response");
    $r = $store->idle_response({}, 1);
    $self->assert(!$r, "no more unsolicited responses");
    $self->assert_num_equals(1, $talk->get_response_code('exists'));
    $self->assert_num_equals(1, $talk->get_response_code('recent'));

    xlog $self, "Sending DONE continuation";
    $store->idle_end({});
    $self->assert_str_equals('ok', $talk->get_last_completion_response());
}

sub common_shutdownfile
{
    my ($self) = @_;

    xlog $self, "Starting up the instance";
    my $svc = $self->{instance}->get_service('imap');

    my $store = $svc->create_store(folder => 'INBOX');
    my $talk = $store->get_client();
    $store->_select();

    xlog $self, "Sending the IDLE command";
    $store->idle_begin()
        or die "IDLE failed: $@";

    xlog $self, "Poll for any unsolicited response - should be none";
    my $r = $store->idle_response({}, 0);
    $self->assert(!$r, "No unsolicted response");

    xlog $self, "sleeping for 3 seconds";
    sleep(3);

    xlog $self, "Poll for any unsolicited response - should be none";
    $r = $store->idle_response({}, 0);
    $self->assert(!$r, "No unsolicted response");

    $self->assert_null($talk->get_response_code('alert'));

    xlog $self, "Write some text to the shutdown file";
    my $admin_store = $svc->create_store(folder => 'user.cassandane',
                                         username => 'admin');
    my $shut_message = "The Mayans were right";
    $admin_store->get_client()->setmetadata("",
                     "/shared/vendor/cmu/cyrus-imapd/shutdown", $shut_message);
    $admin_store->disconnect();
    $admin_store = undef;

    # We want to override Mail::IMAPTalk's builtin handling of the BYE
    # untagged response, as it will 'die' immediately without parsing
    # the remainder of the line and especially without picking out the
    # [ALERT] message that we want to see.
    my $got_bye_alert;
    my $handlers =
    {
        bye => sub
        {
            my ($response, $rr) = @_;
            if (lc($rr->[0]) eq '[alert]')
            {
                # Arguments to [ALERT] is the rest of the line
                # Sadly we've already split on whitespace but lets
                # hope the original message only had single spaces
                $got_bye_alert = join(' ', splice(@$rr, 1));
            }
        }
    };

    xlog $self, "Check that we got a BYE [ALERT] response with the message";
    $r = $store->idle_response($handlers, 5);
    $self->assert($r, "Got an unsolicited response");
    $self->assert_not_null($got_bye_alert);
    $self->assert_str_equals($shut_message, $got_bye_alert);

    xlog $self, "Check that the server disconnected";
    eval
    {
        # We use _send_cmd() and _next_atom() rather the normal path
        # through _imap_cmd() because the latter will warn() to stderr
        # about the exception we're about to generate, which is
        # downright untidy.
        $talk->_send_cmd('status', 'INBOX', '(messages unseen)');
        $talk->_parse_response({});
    };
    my $mm = $@;    # this doesn't survive unless we save it
    $self->assert_matches(qr/IMAP Connection closed by other end/, $mm);
}

use Cassandane::Tiny::Loader 'tiny-tests/Idle';

1;
