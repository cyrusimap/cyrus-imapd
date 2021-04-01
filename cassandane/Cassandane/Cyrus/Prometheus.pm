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
        { adminstore => 1,
          config => $config,
          services => ['imap', 'http'] },
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
        if ($key =~ m/^([^\{]+)\{([^\}]+)}$/) {
            $report->{$1}->{$2} = { value => $val, timestamp => $ts };
        }
        else {
            $report->{$key} = { value => $val, timestamp => $ts };
        }
    }

    return $report;
}

sub test_aaasetup
    :min_version_3_1 :needs_component_httpd
{
    my ($self) = @_;

    # does everything set up and tear down cleanly?
    $self->assert(1);
}

sub test_reportfile_exists
    :min_version_3_1 :needs_component_httpd
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
    :min_version_3_1 :needs_component_httpd
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
    :min_version_3_1 :needs_component_httpd :NoStartInstances
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

# tests for pathological quotaroot/partition subdivisions
sub test_quota_commitments
    :min_version_3_1 :needs_component_httpd :Partition2
{
    my ($self) = @_;

    my $admintalk = $self->{adminstore}->get_client();

    my $inbox = 'user.cassandane';  # allocate top level quota here
    my $child = "$inbox.child";
    my $gchild1 = "$child.cat"; # we'll stick this one on a sep part
    my $gchild2 = "$child.dog"; # give this one its own quota
    my $gchild3 = "$child.sheep"; # normal, but sorts after weird ones
    my $ggchild1 = "$gchild1.manx"; # and give this one its own quota
    my $ggchild2 = "$gchild1.siamese"; # and this one back on def part
    my $interm = "$inbox.foo.bar.baz"; # contains intermediate folders
    my $inbox2 = 'user.cassandane-child'; # hyphen! own quota

    # make some folders
    foreach my $f ($child, $gchild1, $gchild2, $gchild3, $ggchild1,
                   $ggchild2, $interm, $inbox2) {
        $admintalk->create($f);
        $self->assert_str_equals('ok',
                                 $admintalk->get_last_completion_response());
    }

    # stick one of them on a different partition
    $admintalk->rename($gchild1, $gchild1, 'p2');
    $self->assert_str_equals('ok', $admintalk->get_last_completion_response());

    # but not one of its children
    $admintalk->rename($ggchild2, $ggchild2, 'default');
    $self->assert_str_equals('ok', $admintalk->get_last_completion_response());

    # create a mess of quotas
    $admintalk->setquota($inbox, '(STORAGE 8000)');
    $self->assert_str_equals('ok', $admintalk->get_last_completion_response());
    $admintalk->setquota($gchild2, '(STORAGE 4000)');
    $self->assert_str_equals('ok', $admintalk->get_last_completion_response());
    $admintalk->setquota($ggchild1, '(STORAGE 2000)');
    $self->assert_str_equals('ok', $admintalk->get_last_completion_response());
    $admintalk->setquota($inbox2, '(STORAGE 1000)');
    $self->assert_str_equals('ok', $admintalk->get_last_completion_response());

    $admintalk->logout();

    sleep 3;

    my $response = $self->http_report();
    $self->assert($response->{success});

    my $report = parse_report($response->{content});
    $self->assert(scalar keys %{$report});

    # now we expect default partition to have 8000 + 4000 + 1000 committed
    $self->assert_equals(13000, $report->{'cyrus_usage_quota_commitment'}->{'partition="default",resource="STORAGE"'}->{value});

    # and p2 partition to have 8000 + 2000 committed
    $self->assert_equals(10000, $report->{'cyrus_usage_quota_commitment'}->{'partition="p2",resource="STORAGE"'}->{value});
}

# tests for pathological quotaroot/partition subdivisions
sub test_quota_commitments_no_improved_mboxlist_sort
    :min_version_3_1 :needs_component_httpd :Partition2 :NoStartInstances
{
    my ($self) = @_;

    $self->{instance}->{config}->set('improved_mboxlist_sort', 'no');
    $self->_start_instances();

    my $admintalk = $self->{adminstore}->get_client();

    my $inbox = 'user.cassandane';  # allocate top level quota here
    my $child = "$inbox.child";
    my $gchild1 = "$child.cat"; # we'll stick this one on a sep part
    my $gchild2 = "$child.dog"; # give this one its own quota
    my $gchild3 = "$child.sheep"; # normal, but sorts after weird ones
    my $ggchild1 = "$gchild1.manx"; # and give this one its own quota
    my $ggchild2 = "$gchild1.siamese"; # and this one back on def part
    my $interm = "$inbox.foo.bar.baz"; # contains intermediate folders
    my $inbox2 = 'user.cassandane-child'; # hyphen! own quota

    # make some folders
    foreach my $f ($child, $gchild1, $gchild2, $gchild3, $ggchild1,
                   $ggchild2, $interm, $inbox2) {
        $admintalk->create($f);
        $self->assert_str_equals('ok',
                                 $admintalk->get_last_completion_response());
    }

    # stick one of them on a different partition
    $admintalk->rename($gchild1, $gchild1, 'p2');
    $self->assert_str_equals('ok', $admintalk->get_last_completion_response());

    # but not one of its children
    $admintalk->rename($ggchild2, $ggchild2, 'default');
    $self->assert_str_equals('ok', $admintalk->get_last_completion_response());

    # create a mess of quotas
    $admintalk->setquota($inbox, '(STORAGE 8000)');
    $self->assert_str_equals('ok', $admintalk->get_last_completion_response());
    $admintalk->setquota($gchild2, '(STORAGE 4000)');
    $self->assert_str_equals('ok', $admintalk->get_last_completion_response());
    $admintalk->setquota($ggchild1, '(STORAGE 2000)');
    $self->assert_str_equals('ok', $admintalk->get_last_completion_response());
    $admintalk->setquota($inbox2, '(STORAGE 1000)');
    $self->assert_str_equals('ok', $admintalk->get_last_completion_response());

    $admintalk->logout();

    sleep 3;

    my $response = $self->http_report();
    $self->assert($response->{success});

    my $report = parse_report($response->{content});
    $self->assert(scalar keys %{$report});

    # now we expect default partition to have 8000 + 4000 +1000 committed
    $self->assert_equals(13000, $report->{'cyrus_usage_quota_commitment'}->{'partition="default",resource="STORAGE"'}->{value});

    # and p2 partition to have 8000 + 2000 committed
    $self->assert_equals(10000, $report->{'cyrus_usage_quota_commitment'}->{'partition="p2",resource="STORAGE"'}->{value});
}

sub test_shared_mailbox_namespaces
    :min_version_3_1 :needs_component_httpd
{
    my ($self) = @_;

    my $admintalk = $self->{adminstore}->get_client();

    my $ns1 = 'foo';
    my $ns2 = 'bar';
    my @folders = map { ("$ns1.$_", "$ns2.$_" ) }
                      qw(cat sheep dog interm.interm.rabbit);

    foreach my $f (@folders) {
        $admintalk->create($f);
        $self->assert_str_equals('ok', $admintalk->get_last_completion_response());
    }

    sleep 3;

    my $response = $self->http_report();
    $self->assert($response->{success});

    my $report = parse_report($response->{content});
    $self->assert(scalar keys %{$report});

    my $num_folders = 4;
    my ($maj, $min) = Cassandane::Instance->get_version();
    if ($maj > 3 || ($maj == 3 && $min > 4)) {
        $num_folders = 7;
    }

    # expect to find $num_folders folders on each of 'foo' and 'bar' namespaces
    $self->assert_equals($num_folders, $report->{'cyrus_usage_shared_mailboxes'}->{'partition="default",namespace="bar"'}->{value});

    $self->assert_equals($num_folders, $report->{'cyrus_usage_shared_mailboxes'}->{'partition="default",namespace="foo"'}->{value});
}

sub slowtest_50000_users
    :min_version_3_1 :needs_component_httpd
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

sub test_connection_setup_failure_imapd
    :min_version_3_2 :needs_component_httpd :TLS
{
    my ($self) = @_;

    my $instance = $self->{instance};

    my $svc = $instance->get_service('imaps');
    $self->assert_not_null($svc);

    # we're gonna try to connect to it unencrypted, so it fails
    my $store = $svc->create_store('type' => 'imap');
    $self->assert_not_null($store);

    my $badconns = 2 + int(rand(4)); # between 2-5 tries
    for (1 .. $badconns) {
        # try to connect to it using a plain text client
        # and expect the server to drop the connection
        eval {
            $store->get_client();
        };
        my $error = $@;
        $self->assert_matches(qr{Connection closed by other end}, $error);
    }

    # wait a bit for the prometheus report to refresh
    sleep 3;

    # check the prom report
    my $response = $self->http_report();
    $self->assert($response->{success});

    my $report = parse_report($response->{content});
    $self->assert(scalar keys %{$report});

    my $active = $report->{'cyrus_imap_active_connections'};
    $self->assert_not_null($active);
    my $ready = $report->{'cyrus_imap_ready_listeners'};
    $self->assert_not_null($ready);
    my $total = $report->{'cyrus_imap_connections_total'};
    $self->assert_not_null($total);
    my $shutdown = $report->{'cyrus_imap_shutdown_total'};
    $self->assert_not_null($shutdown);

    my $service_label = 'service="imaps"';

    # number of active connections should definitely not be negative
    $self->assert_num_gte(0, $active->{$service_label}->{value});

    # number of active connections should in fact be zero
    $self->assert_num_equals(0, $active->{$service_label}->{value});

    # number of ready listeners should be zero or one, depending on
    # whether it felt like preforking
    $self->assert_num_gte(0, $ready->{$service_label}->{value});
    $self->assert_num_lte(1, $ready->{$service_label}->{value});

    # should not have had any successful connections to imaps
    $self->assert(not exists $total->{$service_label});

    # should be $badconn shutdowns counted (imapd treats this condition
    # as an ok shutdown, not an error)
    $self->assert_num_equals(
        $badconns,
        $shutdown->{"$service_label,status=\"ok\""}->{value}
    );

    # XXX someday: expect to find $badconns setup failures counted
}

1;
