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

package Cassandane::Cyrus::Simple;
use strict;
use warnings;
use Data::Dumper;
use DateTime;

use lib '.';
use base qw(Cassandane::Cyrus::TestCase);
use Cassandane::Util::Log;
use Cassandane::Util::Slurp;

$Data::Dumper::Sortkeys = 1;

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

#
# Test APPEND of messages to IMAP
#
sub test_append
{
    my ($self) = @_;

    my %exp;

    xlog $self, "generating message A";
    $exp{A} = $self->make_message("Message A");
    $self->check_messages(\%exp);

    xlog $self, "generating message B";
    $exp{B} = $self->make_message("Message B");
    $self->check_messages(\%exp);

    xlog $self, "generating message C";
    $exp{C} = $self->make_message("Message C");
    $self->check_messages(\%exp);

    xlog $self, "generating message D";
    $exp{D} = $self->make_message("Message D");
    $self->check_messages(\%exp);
}

sub test_appendlimit_default
    :min_version_3_6
{
    my ($self) = @_;

    my $imaptalk = $self->{store}->get_client();

    my $capa = $imaptalk->capability();
    my @appendlimits = grep { m/^appendlimit/ } keys %{$capa};

    # should be only one appendlimit
    $self->assert_num_equals(1, scalar @appendlimits);

    # we do not support per-mailbox limits, so it must have a value too
    $self->assert_matches(qr{^appendlimit=\d+$}, $appendlimits[0]);

    # and since we haven't configured it, it ought to be the default
    # value, which is BYTESIZE_UNLIMITED (2147483647).
    $self->assert_str_equals("appendlimit=2147483647", $appendlimits[0]);
}

sub test_appendlimit_configured
    :min_version_3_6 :NoStartInstances
{
    my ($self) = @_;

    my $desired_limit = "52428800"; # based on known failure

    $self->{instance}->{config}->set('maxmessagesize' => $desired_limit);
    $self->_start_instances();

    my $imaptalk = $self->{store}->get_client();

    my $capa = $imaptalk->capability();
    my @appendlimits = grep { m/^appendlimit/ } keys %{$capa};

    # should be only one appendlimit
    $self->assert_num_equals(1, scalar @appendlimits);

    # we do not support per-mailbox limits, so it must have a value too
    $self->assert_matches(qr{^appendlimit=\d+$}, $appendlimits[0]);

    # and since we've configured it, it'd better be what we asked for!
    $self->assert_str_equals("appendlimit=$desired_limit", $appendlimits[0]);
}

sub test_select
{
    my ($self) = @_;

    my $imaptalk = $self->{store}->get_client();

    xlog $self, "SELECTing INBOX";
    $imaptalk->select("INBOX");
    $self->assert(!$imaptalk->get_last_error());

    xlog $self, "SELECTing inbox";
    $imaptalk->select("inbox");
    $self->assert(!$imaptalk->get_last_error());

    xlog $self, "CREATEing sub folders";
    $imaptalk->create("INBOX.sub");
    $self->assert(!$imaptalk->get_last_error());
    $imaptalk->create("inbox.blub");
    $self->assert(!$imaptalk->get_last_error());

    xlog $self, "SELECTing subfolders";
    $imaptalk->select("inbox.sub");
    $self->assert(!$imaptalk->get_last_error());
    $imaptalk->select("INbOX.blub");
    $self->assert(!$imaptalk->get_last_error());
}

sub test_cmdtimer_sessionid
    :min_version_3_5 :NoStartInstances
{
    my ($self) = @_;

    # log the timing for anything that takes longer than zero seconds
    $self->{instance}->{config}->set('commandmintimer', '0');
    $self->_start_instances();

    my $imaptalk = $self->{store}->get_client();

    # put a bunch of messages in inbox to make sure fetch isn't instantaneous
    my %msgs;
    foreach my $n (1..5) {
        $msgs{$n} = $self->make_message("message $n");
    }

    $imaptalk->select("INBOX");
    $self->assert_str_equals("ok", $imaptalk->get_last_completion_response());

    # discard buffered syslog output from setup
    $self->{instance}->getsyslog();

    # fetch some things that will take a little while
    $imaptalk->fetch('1:*', '(uid flags body[])');
    $self->assert_str_equals("ok", $imaptalk->get_last_completion_response());

    # should have logged some timer output, which should include the sess id
    if ($self->{instance}->{have_syslog_replacement}) {
        # make sure that the connection is ended so that imapd reset happens
        $imaptalk->logout();
        undef $imaptalk;

        my @lines = $self->{instance}->getsyslog();

        my @timer_lines = grep { m/\bcmdtimer:/ } @lines;
        $self->assert_num_gte(1, scalar @timer_lines);
        foreach my $line (@timer_lines) {
            $self->assert_matches(qr/sessionid=<[^ >]+>/, $line);
        }

        my (@behavior_lines) = grep { /session ended/ } @lines;

        $self->assert_num_gte(1, scalar @behavior_lines);
    }
}

sub test_append_binary
{
    my ($self) = @_;
    my $imap = $self->{store}->get_client();

    my $mime = <<'EOF' =~ s/\n/\r\n/gr;
To: to@local
From: from@local
Subject: test
Content-Transfer-Encoding:binary

test
EOF

    $imap->append("INBOX", { Binary => $mime });
    $self->assert_str_equals('ok', $imap->get_last_completion_response());

    $imap->select('INBOX');
    my $res = $imap->fetch('1', '(BINARY[1])');
    $self->assert_str_equals("test\r\n", $res->{1}{binary});
}

sub test_sasl_ir
{
    my ($self) = @_;

    my $svc = $self->{instance}->get_service('imap');
    my $host = $svc->host();
    my $port = $svc->port();

    my $imtest = $self->{instance}->_find_binary('imtest');
    my $out = $self->{instance}->get_basedir() . "/imtest.$$.out";

    $self->{instance}->run_command(
        { redirects => { stdin => \". logout\r\n", stdout => $out } },
        $imtest, '-a', 'cassandane', '-w', 'password', '-m', 'plain',
                 '-p', $port, $host
    );

    my $exchange = slurp_file($out);

    # expect to have passed the hashed password in the authenticate line
    my $re = qr{^C: A01 AUTHENTICATE PLAIN AGNhc3NhbmRhbmUAcGFzc3dvcmQ=\r$}m;
    $self->assert_matches($re, $exchange);
}

1;
