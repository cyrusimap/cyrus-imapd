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
use Cwd qw(getcwd realpath);
use Data::Dumper;
use DateTime;

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

sub test_toggleable_debug_logging
    :min_version_3_9
{
    my ($self) = @_;

    my $config_debug = $self->{instance}->{config}->get_bool('debug', 'no');
    my $imaptalk = $self->{store}->get_client();

    # can't do anything without captured syslog
    if (!$self->{instance}->{have_syslog_replacement}) {
        xlog $self, "can't examine syslog, test is useless";
        return;
    }

    # find our imapd pid from syslog
    my $loginpat = qr{
        \bimap\[(\d+)\]:\sevent=login\.good
        .+
        u\.username=cassandane
    }x;
    my @logins = $self->{instance}->getsyslog($loginpat);
    $self->assert_num_equals(1, scalar @logins);
    $logins[0] =~ m/$loginpat/;
    my $imapd_pid = $1;

    for (1..5) {
        $imaptalk->unselect();
        my $res = $imaptalk->select('INBOX');
        $self->assert_str_equals('ok',
                                 $imaptalk->get_last_completion_response());

        # this is really looking at cassandane's own injected syslog
        # output, so it depends on the injected syslog doing the right
        # thing with masking
        my $selectpat = qr/open: user cassandane opened INBOX/;
        my @lines = $self->{instance}->getsyslog($selectpat);
        if ($config_debug) {
            $self->assert_num_equals(1, scalar @lines);
            $self->assert_matches(qr/imap\[$imapd_pid\]:/, $lines[0]);
        }
        else {
            $self->assert_num_equals(0, scalar @lines);
        }

        $config_debug = !$config_debug;

        # toggle debug logging by sending SIGUSR1
        my $count = kill 'SIGUSR1', $imapd_pid;
        $self->assert_num_equals(1, $count);

        # we can also look for the message logged by cyrus at the
        # time it toggles the value
        my $statuspat = qr/debug logging turned (on|off)/;
        @lines = $self->{instance}->getsyslog($statuspat);
        $self->assert_num_equals(1, scalar @lines);
        $self->assert_matches(qr/imap\[$imapd_pid\]:/, $lines[0]);
        $lines[0] =~ $statuspat;
        my $status = $1;
        if ($config_debug) {
            $self->assert_str_equals('on', $status);
        }
        else {
            $self->assert_str_equals('off', $status);
        }
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

sub test_fatals_abort_enabled
    :NoStartInstances
{
    my ($self) = @_;

    $self->{instance}->{config}->set(
        'fatals_abort' => 'yes',
        'prometheus_enabled' => 'no',
    );
    $self->_start_instances();

    my $basedir = $self->{instance}->get_basedir();

    # run `promstatsd -1` without having set up for prometheus, which should
    # produce a "Prometheus metrics are not being tracked..." fatal error
    eval {
        $self->{instance}->run_command({ cyrus => 1 }, 'promstatsd', '-1');
    };
    my $e = $@;
    $self->assert_not_null($e);
    $self->assert_matches(qr{promstatsd pid \d+\) terminated by signal 6},
                          $e->{'-text'});

    my @cores = $self->{instance}->find_cores();
    if (@cores) {
        # if we dumped core, there'd better only be one core file
        $self->assert_num_equals(1, scalar @cores);

        # don't barf on it existing during shutdown
        unlink $cores[0];
    }
}

sub test_fatals_abort_disabled
    :NoStartInstances
{
    my ($self) = @_;

    $self->{instance}->{config}->set(
        'fatals_abort' => 'no',
        'prometheus_enabled' => 'no',
    );
    $self->_start_instances();

    my $basedir = $self->{instance}->get_basedir();

    # run `promstatsd -1` without having set up for prometheus, which should
    # produce a "Prometheus metrics are not being tracked..." fatal error
    eval {
        $self->{instance}->run_command({ cyrus => 1 }, 'promstatsd', '-1');
    };
    my $e = $@;
    $self->assert_not_null($e);
    $self->assert_matches(qr{promstatsd pid \d+\) exited with code 78},
                          $e->{'-text'});

    # post-test sanity checks will complain for us if a core was left behind
}

sub test_fork_noexec
{
    my ($self) = @_;

    # need some not-executable file to test with, crash.c will do
    my $noexec_file = realpath('utils/crash.c');
    # it had better exist, and not be executable
    $self->assert_file_test($noexec_file, '-e');
    $self->assert_not_file_test($noexec_file, '-x');

    my $expect_pid = $$;
    my $expect_cwd = getcwd();

    # try to run it... the exec in the forked child process will fail
    eval {
        $self->{instance}->run_command({ cyrus => 0, }, $noexec_file);
    };
    my $e = $@;
    $self->assert_not_null($e);
    # the child process had better exit!
    $self->assert_matches(qr{exited with code 71}, $e->get_message());

    # this test had better still be running in the same process!
    $self->assert_num_equals($expect_pid, $$);

    # cwd better not have changed!
    $self->assert_str_equals($expect_cwd, getcwd());
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
