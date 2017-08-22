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

use lib '.';
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
    $config->set(prometheus_update_freq => 2);

    return $class->SUPER::new(
        { config => $config, services => ['imap', 'http'] },
        @_);
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
        if ($key =~ m/^([^{]+){([^}]+)}$/) {
            $report->{$1}->{$2} = { value => $val, timestamp => $ts };
        }
        else {
            $report->{$key} = { value => $val, timestamp => $ts };
        }
    }

    return $report;
}

sub test_aaasetup
    :min_version_3_1
{
    my ($self) = @_;

    # does everything set up and tear down cleanly?
    $self->assert(1);
}

sub test_reportfile_exists
    :min_version_3_1
{
    my ($self) = @_;

    # do something that'll get counted
    my $imaptalk = $self->{store}->get_client();
    $imaptalk->select("INBOX");
    # and wait for a fresh report
    sleep 3;

    my $reportfile_name = "$self->{instance}->{basedir}/conf/stats/report.txt";

    $self->assert(-f $reportfile_name);

    my $report = parse_report(scalar read_file $reportfile_name);

    $self->assert(scalar keys %{$report});
    $self->assert(exists $report->{cyrus_imap_connections_total});
}

sub test_httpreport
    :min_version_3_1
{
    my ($self) = @_;

    # do something that'll get counted
    my $imaptalk = $self->{store}->get_client();
    $imaptalk->select("INBOX");
    # and wait for a fresh report
    sleep 3;

    my $response = $self->http_report();

    $self->assert($response->{success});
    $self->assert(length $response->{content});

    my $report = parse_report($response->{content});

    $self->assert(scalar keys %{$report});
    $self->assert(exists $report->{cyrus_imap_connections_total});
}

sub test_disabled
    :min_version_3_1 :NoStartInstances
{
    my ($self) = @_;

    my $instance = $self->{instance};
    $instance->{starts} = [ grep { $_->{name} ne 'promstatsd' } @{$instance->{starts}} ];
    $instance->{config}->set(prometheus_enabled => 'no');

    $self->_start_instances();

    # no stats directory
    my $stats_dir = "$self->{instance}->{basedir}/conf/stats";
    $self->assert(! -d $stats_dir);

    # no http report
    my $response = $self->http_report();
    $self->assert_equals(404, $response->{status});
}

1;
