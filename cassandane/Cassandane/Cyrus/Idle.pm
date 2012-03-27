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
    }, @_);
}

sub set_up
{
    my ($self) = @_;
    $self->SUPER::set_up();
    $self->{instance}->add_start(name => 'idled',
				 argv => [ 'idled' ]);
}

sub tear_down
{
    my ($self) = @_;
    $self->SUPER::tear_down();
}

sub config_disabled
{
    my ($self, $conf) = @_;
    xlog "Setting imapidlepoll = 0";
    $conf->set(imapidlepoll => '0');
}

sub test_disabled
{
    my ($self) = @_;

    xlog "Test that the IDLE command can be disabled in";
    xlog "imapd.conf by settung imapidlepoll = 0";

    my $store = $self->{store};
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

sub test_basic
{
    my ($self) = @_;

    xlog "Basic test of the IDLE command";

    my $svc = $self->{instance}->get_service('imap');

    my $idle_store = $svc->create_store(folder => 'INBOX');
    my $idle_talk = $idle_store->get_client();
    $idle_store->_select();

    xlog "The server should report the IDLE capability";
    $self->assert($idle_talk->capability()->{idle});

    xlog "Sending the IDLE command";
    $idle_store->idle_begin()
	or die "IDLE failed: $@";

    xlog "Poll for any unsolicited response - should be none";
    my $r = $idle_store->idle_response({}, 0);
    $self->assert(!$r, "No unsolicted response");

    xlog "Sending DONE continuation";
    $idle_store->idle_end({});
    $self->assert_str_equals('ok', $idle_talk->get_last_completion_response());

    xlog "Testing that normal IMAP commands still work";
    my $res = $idle_talk->status('INBOX', '(messages unseen)');
    $self->assert_deep_equals({ messages => 0, unseen => 0 }, $res);
}


sub test_delivery
{
    my ($self) = @_;

    xlog "Test the IDLE command vs local delivery";

    my $svc = $self->{instance}->get_service('imap');

    my $idle_store = $svc->create_store(folder => 'INBOX');
    my $idle_talk = $idle_store->get_client();
    $idle_store->_select();

    xlog "Sending the IDLE command";
    $idle_store->idle_begin()
	or die "IDLE failed: $@";

    xlog "Poll for any unsolicited response - should be none";
    my $r = $idle_store->idle_response({}, 0);
    $self->assert(!$r, "No unsolicted response");

    xlog "sleeping for 3 seconds";
    sleep(3);

    xlog "Poll for any unsolicited response - should be none";
    $r = $idle_store->idle_response({}, 0);
    $self->assert(!$r, "No unsolicted response");

    xlog "Deliver a message";
    my $msg = $self->{gen}->generate(subject => "Message 1");
    $self->{instance}->deliver($msg);

    $r = $idle_store->idle_response({}, 5);
    $self->assert($r, "received an unsolicited response");
    $r = $idle_store->idle_response({}, 5);
    $self->assert($r, "received an unsolicited response");
    $r = $idle_store->idle_response({}, 1);
    $self->assert(!$r, "no more unsolicited responses");
    $self->assert_num_equals(1, $idle_talk->get_response_code('exists'));
    $self->assert_num_equals(1, $idle_talk->get_response_code('recent'));

    xlog "Sending DONE continuation";
    $idle_store->idle_end({});
    $self->assert_str_equals('ok', $idle_talk->get_last_completion_response());
}

sub test_shutdownfile
{
    my ($self) = @_;

    xlog "Test the IDLE command vs the shutdownfile";

    my $svc = $self->{instance}->get_service('imap');

    my $idle_store = $svc->create_store(folder => 'INBOX');
    my $idle_talk = $idle_store->get_client();
    $idle_store->_select();

    xlog "Sending the IDLE command";
    $idle_store->idle_begin()
	or die "IDLE failed: $@";

    xlog "Poll for any unsolicited response - should be none";
    my $r = $idle_store->idle_response({}, 0);
    $self->assert(!$r, "No unsolicted response");

    xlog "sleeping for 3 seconds";
    sleep(3);

    xlog "Poll for any unsolicited response - should be none";
    $r = $idle_store->idle_response({}, 0);
    $self->assert(!$r, "No unsolicted response");

    $self->assert_null($idle_talk->get_response_code('alert'));

    xlog "Write some text to the shutdown file";
    my $admin_store = $svc->create_store(folder => 'user.casssandane',
					 username => 'admin');
    my $shut_message = "The Mayans were right";
    $admin_store->get_client()->setmetadata("",
		"/shared/vendor/cmu/cyrus-imapd/shutdown", $shut_message);
    $admin_store->disconnect();
    $admin_store = undef;

    $self->{store}->disconnect();
    $self->{store} = undef;

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
    $r = $idle_store->idle_response($handlers, 5);
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
	$idle_talk->_send_cmd('status', 'INBOX', '(messages unseen)');
	$idle_talk->_parse_response({});
    };
    my $mm = $@;    # this doesn't survive unless we save it
    $self->assert_matches(qr/IMAP Connection closed by other end/, $mm);
}

1;
