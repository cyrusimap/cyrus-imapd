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

package Cassandane::Cyrus::Info;
use strict;
use warnings;
use Cwd qw(realpath);
use Data::Dumper;
use Date::Format qw(time2str);
use Time::HiRes qw(usleep);

use lib '.';
use base qw(Cassandane::Cyrus::TestCase);
use Cassandane::Util::Log;
use Cassandane::Instance;

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

sub test_conf
{
    my ($self) = @_;

    my %imapd_conf;
    my $filename = $self->{instance}->_imapd_conf();
    open my $fh, '<', $filename
        or die "Cannot open $filename for reading: $!";
    while (my $line = <$fh>) {
        chomp $line;
        my ($name, $value) = split /\s*:\s*/, $line, 2;
        if (Cassandane::Config::is_bitfield($name)) {
            my @values = split /\s+/, $value;
            $imapd_conf{$name} = join q{ }, sort @values;
        }
        else {
            $imapd_conf{$name} = $value;
        }
    }
    close $fh;

    my %cyr_info_conf;
    foreach my $line ($self->{instance}->run_cyr_info('conf')) {
        chomp $line;
        my ($name, $value) = split /\s*:\s*/, $line, 2;
        if (Cassandane::Config::is_bitfield($name)) {
            my @values = split /\s+/, $value;
            $cyr_info_conf{$name} = join q{ }, sort @values;
        }
        else {
            $cyr_info_conf{$name} = $value;
        }
    }

    # remove _db: values which are same as default, but coded in
    # so that we'll have them in the config
    delete $imapd_conf{$_} for grep { not $cyr_info_conf{$_} } grep { m/_db$/ } keys %imapd_conf;

    $self->assert_deep_equals(\%imapd_conf, \%cyr_info_conf);
}

sub test_conf_all
{
    my ($self) = @_;

    my %imapd_conf;
    my $filename = $self->{instance}->_imapd_conf();
    open my $fh, '<', $filename
        or die "Cannot open $filename for reading: $!";
    while (my $line = <$fh>) {
        chomp $line;
        my ($name, $value) = split /\s*:\s*/, $line, 2;
        if (Cassandane::Config::is_bitfield($name)) {
            my @values = split /\s+/, $value;
            $imapd_conf{$name} = join q{ }, sort @values;
        }
        else {
            $imapd_conf{$name} = $value;
        }
    }
    close $fh;

    my %cyr_info_conf;
    foreach my $line ($self->{instance}->run_cyr_info('conf-all')) {
        chomp $line;
        my ($name, $value) = split /\s*:\s*/, $line, 2;

        # conf-all outputs ALL configured values (including defaults)
        # but we can only really test for the ones we know we put there
        next if not exists $imapd_conf{$name};

        if (Cassandane::Config::is_bitfield($name)) {
            my @values = split /\s+/, $value;
            $cyr_info_conf{$name} = join q{ }, sort @values;
        }
        else {
            $cyr_info_conf{$name} = $value;
        }
    }

    $self->assert_deep_equals(\%imapd_conf, \%cyr_info_conf);
}

sub test_conf_default
{
    my ($self) = @_;

    # conf-default spits out all the defaults.  can't do much to
    # check the actual contents, short of duplicating lib/imapoptions
    # in here, but we can at least make sure it runs without crashing
    # and its output looks reasonably sane

    foreach my $line ($self->{instance}->run_cyr_info('conf-default')) {
        chomp $line;
        my ($name, $value) = split /\s*:\s*/, $line, 2;

        $self->assert_not_null($name);
        $self->assert_not_null($value);

        if (Cassandane::Config::is_bitfield($name)) {
            foreach my $v (split /\s+/, $value) {
                $self->assert_not_null(Cassandane::Config::is_bitfield_bit($name, $v));
            }
        }
    }
}

sub test_lint
{
    my ($self) = @_;

    xlog $self, "test 'cyr_info conf-lint' in the simplest case";

    my @output = $self->{instance}->run_cyr_info('conf-lint');
    @output = grep { !m/_db: / } @output;  # skip database types
    $self->assert_deep_equals([], \@output);
}

Cassandane::Cyrus::TestCase::magic(ConfigJunk => sub {
    shift->config_set(trust_fund => 'street art');
});

sub test_lint_junk
    :ConfigJunk
{
    my ($self) = @_;

    xlog $self, "test 'cyr_info conf-lint' with junk in the config";

    my @output = $self->{instance}->run_cyr_info('conf-lint');
    @output = grep { !m/_db: / } @output;  # skip database types
    $self->assert_deep_equals(["trust_fund: street art\n"], \@output);
}

sub test_lint_channels
    :min_version_3_2 :NoStartInstances
{
    my ($self) = @_;

    $self->config_set(
        'sync_log_channels' => 'banana',
        'banana_sync_host' => 'banana.internal',
        'banana_sync_trust_fund' => 'street art',
        'banana_tcp_keepalive' => 'yes',
        'banana_sasl_mech_list' => 'PLAIN',
    );

    $self->_start_instances();

    xlog $self, "test 'cyr_info conf-lint' with channel-specific sync config";

    my @output = $self->{instance}->run_cyr_info('conf-lint');
    @output = grep { !m/_db: / } @output;  # skip database types

    $self->assert_deep_equals(
        [ sort(
            "banana_sync_trust_fund: street art\n",
            "banana_tcp_keepalive: yes\n",
            "banana_sasl_mech_list: PLAIN\n",
        ) ],
        [ sort @output ]
    );
}

sub test_lint_partitions
    :min_version_3_0 :NoStartInstances
{
    my ($self) = @_;

    $self->config_set(
        # metapartition-, archivepartition- and searchpartition- must
        # correspond with an extant partition-
        'partition-good' => '/tmp/pgood',
        'metapartition-good' => '/tmp/mgood',
        'archivepartition-good' => '/tmp/agood',
        'foosearchpartition-good' => '/tmp/sgood',

        'metapartition-bad' => '/tmp/mbad',
        'archivepartition-bad' => '/tmp/abad',
        'foosearchpartition-bad' => '/tmp/sbad',

        # backuppartition- was deprecated
        'backuppartition-bad' => '/tmp/bbad',
    );

    $self->_start_instances();

    xlog $self, "test 'cyr_info conf-lint' with partitions configured";

    my @output = $self->{instance}->run_cyr_info('conf-lint');
    @output = grep { !m/_db: / } @output;  # skip database types

    $self->assert_deep_equals(
        [ sort(
            "archivepartition-bad: /tmp/abad\n",
            "backuppartition-bad: /tmp/bbad\n",
            "foosearchpartition-bad: /tmp/sbad\n",
            "metapartition-bad: /tmp/mbad\n",
        ) ],
        [ sort @output ]
    );
}

sub test_lint_services
    :want_service_http :needs_component_httpd :NoStartInstances
{
    my ($self) = @_;

    $self->config_set(
        'http_sasl_mech_list' => 'PLAIN',
        'http_sasl_trust_fund' => 'street art',
        'http_tcp_keepalive' => 'yes',
        'http_trust_fund' => 'street art',
    );

    $self->_start_instances();

    xlog $self, "test 'cyr_info conf-lint' with service-specific config";

    my @output = $self->{instance}->run_cyr_info('conf-lint');
    @output = grep { !m/_db: / } @output;  # skip database types

    $self->assert_deep_equals(
        [ sort(
            "http_trust_fund: street art\n",
            # XXX we don't verify sasl keys, so this isn't reported
            #"http_sasl_trust_fund: street art\n",
        ) ],
        [ sort @output ]
    );
}

sub test_proc_services
{
    my ($self) = @_;

    # no clients => no service daemons => no processes
    my @output = $self->{instance}->run_cyr_info('proc');
    $self->assert_num_equals(0, scalar @output);

    # master spawns service processes when clients connect to them
    my $imap_svc = $self->{instance}->get_service('imap');
    my @clients;
    foreach (1..5) {
        # five concurrent connections for a single user is normal,
        # e.g. thunderbird does this
        my $store = $imap_svc->create_store(username => 'cassandane');
        my $imaptalk = $store->get_client();
        push @clients, $imaptalk if $imaptalk;
    }

    # better have got some clients from that!
    $self->assert_num_gte(1, scalar @clients);

    # five clients => five service daemons => five processes
    @output = $self->{instance}->run_cyr_info('proc');
    $self->assert_num_equals(scalar @clients, scalar @output);

    # log clients out one at a time, expect proc count to decrease
    while (scalar @clients) {
        my $old = shift @clients;
        $old->logout();

        @output = $self->{instance}->run_cyr_info('proc');
        $self->assert_num_equals(scalar @clients, scalar @output);
    }
}

sub test_proc_crashed_services
{
    my ($self) = @_;

    # no clients => no service daemons => no processes
    my @output = $self->{instance}->run_cyr_info('proc');
    $self->assert_num_equals(0, scalar @output);

    # master spawns service processes when clients connect to them
    my $imap_svc = $self->{instance}->get_service('imap');
    my @clients;
    foreach (1..5) {
        # five concurrent connections for a single user is normal,
        # e.g. thunderbird does this
        my $store = $imap_svc->create_store(username => 'cassandane');
        my $imaptalk = $store->get_client();
        push @clients, $imaptalk if $imaptalk;
    }

    # better have got some clients from that!
    $self->assert_num_gte(1, scalar @clients);

    # five clients => five service daemons => five processes
    @output = $self->{instance}->run_cyr_info('proc');
    $self->assert_num_equals(scalar @clients, scalar @output);

    my @pids = sort map { (split /\s+/, $_, 2)[0] } @output;
    $self->assert_num_equals(scalar @clients, scalar @pids);

    # crash service processes one at a time, expect proc count to decrease
    while (scalar @pids) {
        my $pid = shift @pids;
        kill 'SEGV', $pid;
        usleep 250_000;

        my @cores = $self->{instance}->find_cores();
        if (@cores) {
            # if we dumped core, there'd better only be one core file
            $self->assert_num_equals(1, scalar @cores);

            # don't barf on it existing during shutdown
            unlink $cores[0];
        }

        # sanitizers might complain about the SEGV
        my $ubsan_logdir = $self->{instance}->_sanitizer_log_dir("ubsan");
        unlink("$ubsan_logdir/ubsan.$pid");
        my $asan_logdir = $self->{instance}->_sanitizer_log_dir("asan");
        unlink("$asan_logdir/asan.$pid");

        @output = $self->{instance}->run_cyr_info('proc');
        $self->assert_num_equals(scalar @pids, scalar @output);
    }

    # prevent a lot of "Connection closed by other end" noise by claiming
    # and discarding the client's socket before its DESTROY is called
    while (scalar @clients) {
        my $old = shift @clients;

        $old->release_socket(1);
    }
}

sub test_proc_starts
    :NoStartInstances :needs_component_idled
{
    my ($self) = @_;

    # we used to recommend starting idled from START, and it will
    # still work like that, so using it here saves me mocking something
    $self->{instance}->add_start(name => 'idled',
                                 argv => [ 'idled' ]);
    $self->{instance}->start();

    # entries listed in START run to completion before master fully
    # starts up.  if they fork themselves and hang around (like idled
    # does) then that's their business, but master can't and doesn't
    # track them
    my @output = $self->{instance}->run_cyr_info('proc');

    $self->assert_num_equals(0, scalar @output);
}

sub test_proc_periodic_events_slow
    :NoStartInstances
{
    my ($self) = @_;

    my $sleeper_time = 10; # seconds

    # periodic events first fire immediately at startup, and then every
    # 'period' minutes thereafter. the fastest we can schedule them is
    # every 1 minute, so this test must run for at least several real
    # minutes
    $self->{instance}->add_event(
        name => 'sleeper',
        argv => [ realpath('utils/sleeper'), $sleeper_time ],
        period => 1,
    );
    $self->{instance}->start();

    sleep 2; # offset our checks a little to avoid races

    # observe for three cycles
    my $observations = 3;
    while ($observations > 0) {
        # event should have fired and be running
        my @output = $self->{instance}->run_cyr_info('proc');
        $self->assert_num_equals(1, scalar @output);

        # wait for it to finish and check again
        sleep $sleeper_time;
        @output = $self->{instance}->run_cyr_info('proc');
        $self->assert_num_equals(0, scalar @output);

        # skip final wait if we're done
        $observations--;
        last if $observations == 0;

        # wait until next period
        sleep 60 - $sleeper_time;
    }
}

sub test_proc_scheduled_events
    :NoStartInstances
{
    my ($self) = @_;

    my $sleeper_time = 10;

    # schedule an event to fire at the next minute boundary that is at
    # least ten seconds away
    my $at = time + 70;
    $at -= ($at % 60);
    my $at_hm = time2str('%H%M', $at);
    xlog $self, "scheduling event to run at $at_hm ($at)";
    $self->{instance}->add_event(
        name => 'sleeper',
        argv => [ realpath('utils/sleeper'), $sleeper_time ],
        at => $at_hm,
    );
    $self->{instance}->start();

    # event process should not be running at startup
    my @output = $self->{instance}->run_cyr_info('proc');
    $self->assert_num_equals(0, scalar @output);

    # should be running at the scheduled time (with a little slop)
    sleep 2 + $at - time;
    @output = $self->{instance}->run_cyr_info('proc');
    $self->assert_num_equals(1, scalar @output);

    # should not be running after we expect it to have finished
    sleep $sleeper_time;
    @output = $self->{instance}->run_cyr_info('proc');
    $self->assert_num_equals(0, scalar @output);
}

sub test_proc_daemons
    :NoStartInstances
{
    my ($self) = @_;

    my $sleeper_time = 10; # seconds
    my $daemons = 3;

    for my $i (1 .. $daemons) {
        # you wouldn't usually run a daemon that exits and needs to be
        # restarted every ten seconds, but it's useful for testing
        # that cyr_info proc notices the pid changing
        $self->{instance}->add_daemon(
            name => "sleeper$i",
            argv => [ realpath('utils/sleeper'), $sleeper_time ],
        );
    }
    $self->{instance}->start();

    sleep 2; # offset our checks a little to avoid races

    my $observations = 3;
    my %lastpid = map {; "sleeper$_" => 0 } (1 .. $daemons);
    while ($observations > 0) {
        my @output = $self->{instance}->run_cyr_info('proc');

        # always exactly one process per daemon
        $self->assert_num_equals($daemons, scalar @output);

        # expect a new pid for each daemon each time
        foreach my $line (@output) {
            my ($pid, $servicename, $host, $user, $mailbox, $cmd)
                = split /\s/, $line, 6;
            $self->assert_num_not_equals($lastpid{$servicename}, $pid);
            $lastpid{$servicename} = $pid;
        }

        # skip final wait if we're done
        $observations--;
        last if $observations == 0;

        # wait for next restart
        sleep $sleeper_time;
    }
}

sub _set_and_get_fields {
    my ($self, $set_fields, $get_fields, $cmd) = @_;

    $self->config_set(%$set_fields);

    $self->_start_instances();

    $cmd //= 'conf';

    my %cyr_info_conf;
    foreach my $line ($self->{instance}->run_cyr_info($cmd)) {
        chomp $line;
        my ($name, $value) = split /\s*:\s*/, $line, 2;
        if (Cassandane::Config::is_bitfield($name)) {
            my @values = split /\s+/, $value;
            $cyr_info_conf{$name} = join q{ }, sort @values;
        }
        else {
            $cyr_info_conf{$name} = $value;
        }
    }

    for my $field (keys %$get_fields) {
        my $expect = join q{ }, sort split /\s+/, $get_fields->{$field};
        $self->assert_str_equals($expect, $cyr_info_conf{$field});
    }
}

sub test_bitfield_size_conf
    :min_version_3_2 :NoStartInstances
{
    my ($self) = @_;

    # The original code used 1<<j where j could be >= 31, which was undefined
    # behaviour and also overflowed, meaning fileinto would also list
    # vnd.cyrus.jmapquery!
    $self->_set_and_get_fields(
        { sieve_extensions => 'fileinto' },
        { sieve_extensions => 'fileinto' },
    );
}

sub test_bitfield_after_multiple_names
    :min_version_3_2 :NoStartInstances
{
    my ($self) = @_;

    # fields like vnd.cyrus.jmapquery=x-cyrus-jmapquery pushed the offset
    # for any fields after that to be off by one (for each field with
    # multiple names)
    $self->_set_and_get_fields(
        { sieve_extensions => 'snooze' },
        { sieve_extensions => 'snooze' },
    );
}

sub test_bitfield_with_multiple_names_new
    :min_version_3_2 :NoStartInstances
{
    my ($self) = @_;

    $self->_set_and_get_fields(
        { sieve_extensions => 'vnd.cyrus.jmapquery' },
        { sieve_extensions => 'vnd.cyrus.jmapquery' },
    );
}

sub test_bitfield_with_multiple_names_legacy
    :min_version_3_2 :NoStartInstances
{
    my ($self) = @_;

    # legacy names always come back in cyr_info as their current name
    $self->_set_and_get_fields(
        { sieve_extensions => 'x-cyrus-jmapquery' },
        { sieve_extensions => 'vnd.cyrus.jmapquery' },
    );
}

sub test_bitfield_defaults
    :min_version_3_2 :NoStartInstances
{
    my ($self) = @_;

    my $defaults = "fileinto reject vacation vacation-seconds notify include envelope environment body relational regex subaddress copy date index imap4flags mailbox mboxmetadata servermetadata variables editheader extlists duplicate ihave fcc special-use redirect-dsn redirect-deliverby mailboxid vnd.cyrus.log vnd.cyrus.jmapquery processcalendar snooze vnd.cyrus.implicit_keep_target";

    $self->_set_and_get_fields(
        { sieve_extensions => $defaults },
        { sieve_extensions => $defaults },
        'conf-default',
    );
}

1;
