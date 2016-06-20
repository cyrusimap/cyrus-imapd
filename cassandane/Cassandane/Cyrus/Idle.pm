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
package Cassandane::Cyrus::Idle;
use base qw(Cassandane::Cyrus::TestCase);
use DateTime;
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
    xlog "pid of idled should be $pid";

    xlog "giving idled some time to start up";
    sleep(1);

    xlog "bring idled's reign to an abrupt and brutal end";
    kill('KILL', $pid)
	or die "Failed to kill idled $pid: $!";

    # reap_command will 'die' because the process terminated
    # on SIGKILL.  We need to avoid that stopping the test.
    # But we still need to waitpid() to avoid zombies.
    xlog "reaping pid $pid";
    eval { $self->{instance}->reap_command($pid); };

    # Now, no idled is running, but any state created by idled in the
    # filesystem is still present.  In particular, the idle socket.
    # Let's check that our assumption is correct.
    xlog "check that idle left a socket lying around";
    my $idle_sock = $self->{instance}->{basedir} . "/conf/socket/idle";
    $self->assert( -S $idle_sock, "$idle_sock exists and is a socket");
}

sub test_disabled
{
    my ($self) = @_;

    xlog "Test that the IDLE command can be disabled in";
    xlog "imapd.conf by setting imapidlepoll = 0";

    xlog "Starting up the instance";
    $self->{instance}->{config}->set(imapidlepoll => '0');
    $self->{instance}->start();
    my $svc = $self->{instance}->get_service('imap');

    my $store = $svc->create_store(folder => 'INBOX');
    my $talk = $store->get_client();

    xlog "The server should not report the IDLE capability";
    $self->assert(!$talk->capability()->{idle});

    xlog "The IDLE command should not be recognised";
    # Note that we don't use idle_begin() because that will get
    # upset if we get "tag BAD ..." back instead of "+ something".
    my $r = $talk->_imap_cmd('idle', 0, '');
    $self->assert_null($r);
    $self->assert_str_equals('bad', $talk->get_last_completion_response());
    $self->assert_matches(qr/Unrecognized command/, $talk->get_last_error());
}

sub common_basic
{
    my ($self) = @_;

    my $svc = $self->{instance}->get_service('imap');

    my $store = $svc->create_store(folder => 'INBOX');
    my $talk = $store->get_client();
    $store->_select();

    xlog "The server should report the IDLE capability";
    $self->assert($talk->capability()->{idle});

    xlog "Sending the IDLE command";
    $store->idle_begin()
	or die "IDLE failed: $@";

    xlog "Poll for any unsolicited response - should be none";
    my $r = $store->idle_response({}, 0);
    $self->assert(!$r, "No unsolicted response");

    xlog "Sending DONE continuation";
    $store->idle_end({});
    $self->assert_str_equals('ok', $talk->get_last_completion_response());

    xlog "Testing that normal IMAP commands still work";
    my $res = $talk->status('INBOX', '(messages unseen)');
    $self->assert_deep_equals({ messages => 0, unseen => 0 }, $res);
}

sub test_basic_idled
{
    my ($self) = @_;

    xlog "Basic test of the IDLE command, idled started";

    $self->{instance}->{config}->set(imapidlepoll => '2');
    $self->{instance}->add_start(name => 'idled',
				 argv => [ 'idled' ]);
    $self->{instance}->start();
    $self->common_basic();
}

sub test_basic_noidled
{
    my ($self) = @_;

    xlog "Basic test of the IDLE command, no idled started";

    $self->{instance}->{config}->set(imapidlepoll => '2');
    $self->{instance}->start();
    $self->common_basic();
}

sub test_basic_abortedidled
{
    my ($self) = @_;

    xlog "Basic test of the IDLE command, idled started but aborted";

    $self->{instance}->{config}->set(imapidlepoll => '2');
    $self->{instance}->start();
    $self->start_and_abort_idled();

    $self->common_basic();
}

sub common_delivery
{
    my ($self) = @_;

    xlog "Starting up the instance";
    my $svc = $self->{instance}->get_service('imap');

    my $store = $svc->create_store(folder => 'INBOX');
    my $talk = $store->get_client();
    $store->_select();

    xlog "Sending the IDLE command";
    $store->idle_begin()
	or die "IDLE failed: $@";

    xlog "Poll for any unsolicited response - should be none";
    my $r = $store->idle_response({}, 0);
    $self->assert(!$r, "No unsolicted response");

    xlog "sleeping for 3 seconds";
    sleep(3);

    xlog "Poll for any unsolicited response - should be none";
    $r = $store->idle_response({}, 0);
    $self->assert(!$r, "No unsolicted response");

    xlog "Deliver a message";
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

    xlog "Sending DONE continuation";
    $store->idle_end({});
    $self->assert_str_equals('ok', $talk->get_last_completion_response());
}

sub test_delivery_idled
{
    my ($self) = @_;

    xlog "Test the IDLE command vs local delivery, idled started";

    $self->{instance}->{config}->set(imapidlepoll => '2');
    $self->{instance}->add_start(name => 'idled',
				 argv => [ 'idled' ]);
    $self->{instance}->start();
    $self->common_delivery();
}

sub test_delivery_noidled
{
    my ($self) = @_;

    xlog "Test the IDLE command vs local delivery, no idled started";

    $self->{instance}->{config}->set(imapidlepoll => '2');
    $self->{instance}->start();
    $self->common_delivery();
}

sub test_delivery_abortedidled
{
    my ($self) = @_;

    xlog "Test the IDLE command vs local delivery, idled started but aborted";

    $self->{instance}->{config}->set(imapidlepoll => '2');
    $self->{instance}->start();
    $self->start_and_abort_idled();

    $self->common_delivery();
}

sub common_shutdownfile
{
    my ($self) = @_;

    xlog "Starting up the instance";
    my $svc = $self->{instance}->get_service('imap');

    my $store = $svc->create_store(folder => 'INBOX');
    my $talk = $store->get_client();
    $store->_select();

    xlog "Sending the IDLE command";
    $store->idle_begin()
	or die "IDLE failed: $@";

    xlog "Poll for any unsolicited response - should be none";
    my $r = $store->idle_response({}, 0);
    $self->assert(!$r, "No unsolicted response");

    xlog "sleeping for 3 seconds";
    sleep(3);

    xlog "Poll for any unsolicited response - should be none";
    $r = $store->idle_response({}, 0);
    $self->assert(!$r, "No unsolicted response");

    $self->assert_null($talk->get_response_code('alert'));

    xlog "Write some text to the shutdown file";
    my $admin_store = $svc->create_store(folder => 'user.casssandane',
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

    xlog "Check that we got a BYE [ALERT] response with the message";
    $r = $store->idle_response($handlers, 5);
    $self->assert($r, "Got an unsolicited response");
    $self->assert_not_null($got_bye_alert);
    $self->assert_str_equals($shut_message, $got_bye_alert);

    xlog "Check that the server disconnected";
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

sub test_shutdownfile_idled
{
    my ($self) = @_;

    xlog "Test the IDLE command vs the shutdownfile, idled started";

    $self->{instance}->{config}->set(imapidlepoll => '2');
    $self->{instance}->add_start(name => 'idled',
				 argv => [ 'idled' ]);
    $self->{instance}->start();
    $self->common_shutdownfile();
}

sub test_shutdownfile_noidled
{
    my ($self) = @_;

    xlog "Test the IDLE command vs the shutdownfile";

    $self->{instance}->{config}->set(imapidlepoll => '2');
    $self->{instance}->start();
    $self->common_shutdownfile();
}

sub test_shutdownfile_abortedidled
{
    my ($self) = @_;

    xlog "Test the IDLE command vs the shutdownfile, idled started but aborted";

    $self->{instance}->{config}->set(imapidlepoll => '2');
    $self->{instance}->start();
    $self->start_and_abort_idled();

    $self->common_shutdownfile();
}

sub test_sigterm
{
    my ($self) = @_;

    xlog "Test that an imapd can be killed with SIGTERM";
    xlog "while executing an IDLE command";

    $self->{instance}->{config}->set(imapidlepoll => '2');
    $self->{instance}->add_start(name => 'idled',
				 argv => [ 'idled' ]);
    xlog "Starting up the instance";
    $self->{instance}->start();

    my $svc = $self->{instance}->get_service('imap');

    my $store = $svc->create_store(folder => 'INBOX');
    my $talk = $store->get_client();

    # User logged in SESSIONID=<0604061-29539-1337148251-1>
    my $rem = $talk->get_response_code('remainder');
    my ($name, $imapd_pid, $start, $n) =
	($rem =~ m/SESSIONID=<([^-]+)-(\d+)-(\d+)-(\d+)/);
    $self->assert_not_null($imapd_pid);
    $imapd_pid = 0 + $imapd_pid;
    $self->assert($imapd_pid > 1);
    xlog "PID of imapd process is $imapd_pid";

    $store->_select();

    xlog "Sending the IDLE command";
    $store->idle_begin()
	or die "IDLE failed: $@";

    xlog "Poll for any unsolicited response - should be none";
    my $r = $store->idle_response({}, 0);
    $self->assert(!$r, "No unsolicted response");

    xlog "sleeping for 3 seconds";
    sleep(3);

    xlog "Poll for any unsolicited response - should be none";
    $r = $store->idle_response({}, 0);
    $self->assert(!$r, "No unsolicted response");

    $self->assert_null($talk->get_response_code('alert'));

    xlog "Send SIGQUIT (or worse) to the imapd";
    $r = Cassandane::Instance::_stop_pid($imapd_pid);
    $self->assert($r == 1, "shutdown required brute force");

    xlog "Check that the server disconnected";
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

sub test_sigterm_many
{
    my ($self) = @_;

    xlog "Test that the Cyrus instance can be cleanly shut";
    xlog "down with SIGTERM while many imapds execute an";
    xlog "IDLE command";

    $self->{instance}->{config}->set(imapidlepoll => '2');
    $self->{instance}->add_start(name => 'idled',
				 argv => [ 'idled' ]);
    xlog "Starting up the instance";
    $self->{instance}->start();

    my $svc = $self->{instance}->get_service('imap');

    my $N = 16;
    my @stores;
    my $r;

    for (my $i = 0 ; $i < $N ; $i++)
    {
	my $store = $svc->create_store(folder => 'INBOX');
	push(@stores, $store);
	my $talk = $store->get_client();

	$store->_select();

	xlog "Sending the IDLE command";
	$store->idle_begin()
	    or die "IDLE failed: $@";

	xlog "Poll for any unsolicited response - should be none";
	$r = $store->idle_response({}, 0);
	$self->assert(!$r, "No unsolicted response");
    }

    xlog "sleeping for 3 seconds";
    sleep(3);

    foreach my $store (@stores)
    {
	xlog "Poll for any unsolicited response - should be none";
	$r = $store->idle_response({}, 0);
	$self->assert(!$r, "No unsolicted response");

	$self->assert_null($store->get_client()->get_response_code('alert'));
    }

    xlog "Shut down the instance";
    $self->{instance}->stop();
#     $self->assert($r == 1, "shutdown required brute force");

    xlog "Check that the server disconnected";

    foreach my $store (@stores)
    {
	eval
	{
	    # We use _send_cmd() and _next_atom() rather the normal path
	    # through _imap_cmd() because the latter will warn() to stderr
	    # about the exception we're about to generate, which is
	    # downright untidy.
	    my $talk = $store->get_client();
	    $talk->_send_cmd('status', 'INBOX', '(messages unseen)');
	    $talk->_parse_response({});
	};
	my $mm = $@;    # this doesn't survive unless we save it
	$self->assert_matches(qr/IMAP Connection closed by other end/, $mm);
    }
}



1;
