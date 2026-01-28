#!/usr/bin/perl
#
#  Copyright (c) 2017 FastMail Pty. Ltd.  All rights reserved.
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
#  3. The name "FastMail" must not be used to
#     endorse or promote products derived from this software without
#     prior written permission. For permission or any legal
#     details, please contact
#         FastMail Pty. Ltd.
#         Level 1, 91 William St
#         Melbourne 3000
#         Victoria
#         Australia
#
#  4. Redistributions of any form whatsoever must retain the following
#     acknowledgment:
#     "This product includes software developed by FastMail Pty. Ltd."
#
#  FASTMAIL PTY LTD DISCLAIMS ALL WARRANTIES WITH REGARD TO
#  THIS SOFTWARE, INCLUDING ALL IMPLIED WARRANTIES OF MERCHANTABILITY
#  AND FITNESS, IN NO EVENT SHALL OPERA SOFTWARE AUSTRALIA BE LIABLE
#  FOR ANY SPECIAL, INDIRECT OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES
#  WHATSOEVER RESULTING FROM LOSS OF USE, DATA OR PROFITS, WHETHER IN
#  AN ACTION OF CONTRACT, NEGLIGENCE OR OTHER TORTIOUS ACTION, ARISING
#  OUT OF OR IN CONNECTION WITH THE USE OR PERFORMANCE OF THIS SOFTWARE.
#

package Cassandane::Cyrus::Prometheus;
use strict;
use warnings;
use Data::Dumper;
use File::Slurp;
use HTTP::Tiny;

use base qw(Cassandane::Cyrus::TestCase);
use Cassandane::Util::Log;
use Cassandane::Instance;

$Data::Dumper::Sortkeys = 1;

sub new
{
    my $class = shift;

    my $config = Cassandane::Config->default()->clone();
    $config->set(prometheus_enabled => "yes");
    $config->set(httpmodules => "prometheus");
    $config->set(prometheus_need_auth => "none");
    $config->set(prometheus_service_update_freq => 2);
    $config->set(prometheus_master_update_freq => 2);
    $config->set(prometheus_usage_update_freq => 2);

    my $self = $class->SUPER::new(
        { adminstore => 1,
          config => $config,
          services => ['imap', 'http'] },
        @_);

    $self->needs('component', 'httpd');
    return $self;
}

sub set_up
{
    my ($self) = @_;
    $self->SUPER::set_up();
}

sub _create_instances
{
    my ($self) = @_;

    $self->SUPER::_create_instances();
    # XXX This should really run from the DAEMON section,
    # XXX but Cassandane doesn't know about that.
    $self->{instance}->add_start(name => 'promstatsd',
                                 argv => [ 'promstatsd' ]);
}

sub tear_down
{
    my ($self) = @_;
    $self->SUPER::tear_down();
}

sub http_report
{
    my ($self) = @_;

    my $service = $self->{instance}->get_service("http");
    my $url = join(q{},
                   q{http://}, $service->host(),
                   q{:}, $service->port(),
                   q{/metrics});

    return HTTP::Tiny->new()->get($url);
}

sub parse_report
{
    my ($content) = @_;

    my $report = {};

    foreach my $line (split /\n/, $content) {
        next if $line =~ /^\#/;
        my ($key, $val, $ts) = split /\s+/, $line;
        if ($key =~ m/^([^\{]+)\{([^\}]+)}$/) {
            $report->{$1}->{$2} = { value => $val, timestamp => $ts };
        }
        else {
            $report->{$key} = { value => $val, timestamp => $ts };
        }
    }

    return $report;
}

sub slowtest_50000_users
    :min_version_3_1
{
    my ($self) = @_;

    my $nusers = 50000;
    my @subfolders = qw(Drafts Sent Spam Trash);
    my $storage = 8000;

    my $admintalk = $self->{adminstore}->get_client();

    foreach my $n (1..$nusers) {
        # reconnect every so often so stuff can flush
        if ($n % 5000 == 0) {
            $admintalk->logout();
            $self->{adminstore}->disconnect();
            $admintalk = $self->{adminstore}->get_client();
        }

        my $folder = sprintf("user.a%08d", $n);
        $admintalk->create($folder);
        $self->assert_str_equals('ok',
            $admintalk->get_last_completion_response());

        $admintalk->setquota($folder, "(STORAGE $storage)");
        $self->assert_str_equals('ok',
            $admintalk->get_last_completion_response());

        foreach my $subfolder (@subfolders) {
            $admintalk->create("$folder.$subfolder");
            $self->assert_str_equals('ok',
                $admintalk->get_last_completion_response());
        }
    }

    # XXX may not be long enough!
    sleep 3;

    my $response = $self->http_report();
    $self->assert($response->{success});

    my $report = parse_report($response->{content});
    $self->assert(scalar keys %{$report});

    # n.b. user/mailbox counts are +1 cause of user.cassandane!
    $self->assert_num_equals(1 + $nusers,
        $report->{'cyrus_usage_users'}->{'partition="default"'}->{value});
    $self->assert_num_equals(1 + $nusers + ($nusers * scalar @subfolders),
        $report->{'cyrus_usage_mailboxes'}->{'partition="default"'}->{value});
    $self->assert_num_equals($nusers * $storage,
        $report->{'cyrus_usage_quota_commitment'}->{'partition="default",resource="STORAGE"'}->{value});
}

use Cassandane::Tiny::Loader 'tiny-tests/Prometheus';

1;
