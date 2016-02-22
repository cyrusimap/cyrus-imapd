#!/usr/bin/perl
#
#  Copyright (c) 2011 Opera Software Australia Pty. Ltd.  All rights
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
package Cassandane::Cyrus::Master;
use base qw(Cassandane::Cyrus::TestCase);
use POSIX qw(getcwd);
use DateTime;
use Cassandane::Util::Log;
use Cassandane::Util::Wait;
use Cassandane::Util::Socket;
use Cassandane::Util::Sample;
use Cassandane::Util::Metronome;
use Cassandane::Instance;
use Cassandane::Service;
use Cassandane::Config;

my $lemming_bin = getcwd() . '/utils/lemming';

sub new
{
    my $class = shift;
    my $self = $class->SUPER::new({ instance => 0 }, @_);

    return $self;
}

sub set_up
{
    my ($self) = @_;
    die "No lemming binary $lemming_bin.  Did you run \"make\" in the Cassandane directory?"
	unless (-f $lemming_bin);
    $self->SUPER::set_up();
    $self->{instance} = Cassandane::Instance->new(setup_mailbox => 0);
}

sub tear_down
{
    my ($self) = @_;
    $self->lemming_cull();
    $self->SUPER::tear_down();
}

sub lemming_connect
{
    my ($srv, $address_family) = @_;

    my $sock = create_client_socket(
		    defined($address_family) ? $address_family : $srv->address_family(),
		    $srv->host(), $srv->port())
	or die "Cannot connect to lemming " . $srv->address() . ": $@";

    # The lemming sends us his PID so we can later wait for him to die
    # properly.  It's easiest for synchronisation purposes to encode
    # this as a fixed sized field.
    my $pid;
    $sock->sysread($pid, 4)
	or die "Cannot read from lemming: $!";
    $pid = unpack("L", $pid);
    die "Cannot read from lemming: $!"
	unless defined $pid;

    return { sock => $sock, pid => $pid };
}

sub lemming_push
{
    my ($lemming, $mode) = @_;

#     xlog "Pushing mode=$mode to pid=$lemming->{pid}";

    # Push the lemming over the metaphorical cliff.
    $lemming->{sock}->syswrite($mode . "\r\n");
    $lemming->{sock}->close();

    # Wait for the master process to wake up and reap the lemming.
    return timed_wait(sub { kill(0, $lemming->{pid}) == 0 },
	       description => "master to reap lemming $lemming->{pid}");
}

sub lemming_census
{
    my ($self) = @_;
    my $coresdir = $self->{instance}->{basedir} . '/conf/cores';

    my %pids;
    opendir LEMM,$coresdir
	or die "cannot open $coresdir for reading: $!";
    while ($_ = readdir LEMM)
    {
	my ($tag, $pid) = m/^lemming\.(\w+).(\d+)$/;
	next
	    unless defined $pid;
	xlog "found lemming tag=$tag pid=$pid";
	$pids{$tag} = []
	    unless defined $pids{$tag};
	push (@{$pids{$tag}}, $pid);
    }
    closedir LEMM;

    my %actual;
    foreach my $tag (keys %pids)
    {
	my $ntotal = scalar @{$pids{$tag}};
	my $nlive = kill(0, @{$pids{$tag}});
	$actual{$tag} = {
	    live => $nlive,
	    dead => $ntotal - $nlive,
	};
    }
    return \%actual;
}

sub lemming_cull
{
    my ($self) = @_;
    return unless defined $self->{instance};
    my $coresdir = $self->{instance}->{basedir} . '/conf/cores';

    return unless -d $coresdir;
    opendir LEMM,$coresdir
	or die "cannot open $coresdir for reading: $!";
    while ($_ = readdir LEMM)
    {
	my ($tag, $pid) = m/^lemming\.(\w+).(\d+)$/;
	next
	    unless defined $pid;
	xlog "culled lemming tag=$tag pid=$pid"
	    if kill(9, $pid);
    }
    closedir LEMM;
}

sub _lemming_args
{
    my (%params) = @_;

    my $tag = delete $params{tag} || 'A';
    my $mode = delete $params{mode} || 'serve';
    my $delay = delete $params{delay};

    my @argv = ( $lemming_bin, '-t', $tag, '-m', $mode );
    push(@argv, '-d', $delay) if defined $delay;

    return (name => $tag, argv => \@argv, %params);
}

sub lemming_service
{
    my ($self, %params) = @_;
    return $self->{instance}->add_service(_lemming_args(%params));
}

sub lemming_start
{
    my ($self, %params) = @_;
    return $self->{instance}->add_start(_lemming_args(%params));
}

sub lemming_event
{
    my ($self, %params) = @_;
    return $self->{instance}->add_event(_lemming_args(%params));
}

sub lemming_wait
{
    my ($self, %expected_census) = @_;

    timed_wait(
	sub
	{
	    my $census = $self->lemming_census();
	    map {
		my $service_name = $_;
		return 0 if !defined $census->{$service_name};
		my $expected = $expected_census{$service_name};
		map {
		    return 0 if $census->{$service_name}->{$_} != $expected->{$_};
		} keys %$expected;
	    } keys %expected_census;
	    return 1;
	},
	description => "lemmings to reach the expected census");
}

sub start
{
    my ($self) = @_;
    $self->{instance}->start();
}

#
# Test a single running programs in SERVICES
#
sub test_service
{
    my ($self) = @_;

    xlog "single successful service";
    my $srv = $self->lemming_service();
    $self->start();

    xlog "not preforked, so no lemmings running yet";
    $self->assert_deep_equals({},
			      $self->lemming_census());

    my $lemm = lemming_connect($srv);

    xlog "connected so one lemming forked";
    $self->assert_deep_equals({ A => { live => 1, dead => 0 } },
			      $self->lemming_census());

    lemming_push($lemm, 'success');

    xlog "no more live lemmings";
    $self->assert_deep_equals({ A => { live => 0, dead => 1 } },
			      $self->lemming_census());
}

#
# Test multiple connections to a single running program in SERVICES
#
sub test_multi_connections
{
    my ($self) = @_;

    xlog "multiple connections to a single successful service";
    my $srv = $self->lemming_service();
    $self->start();

    xlog "not preforked, so no lemmings running yet";
    $self->assert_deep_equals({},
			      $self->lemming_census());

    my $lemm1 = lemming_connect($srv);

    xlog "connected so one lemming forked";
    $self->assert_deep_equals({ A => { live => 1, dead => 0 } },
			      $self->lemming_census());

    my $lemm2 = lemming_connect($srv);

    xlog "two connected so two lemmings forked";
    $self->assert_deep_equals({ A => { live => 2, dead => 0 } },
			      $self->lemming_census());

    my $lemm3 = lemming_connect($srv);

    xlog "three connected so three lemmings forked";
    $self->assert_deep_equals({ A => { live => 3, dead => 0 } },
			      $self->lemming_census());

    lemming_push($lemm1, 'success');
    lemming_push($lemm2, 'success');
    lemming_push($lemm3, 'success');

    xlog "no more live lemmings";
    $self->assert_deep_equals({ A => { live => 0, dead => 3 } },
			      $self->lemming_census());
}

#
# Test multiple running programs in SERVICES
#
sub test_multi_services
{
    my ($self) = @_;

    xlog "multiple successful services";
    my $srvA = $self->lemming_service(tag => 'A');
    my $srvB = $self->lemming_service(tag => 'B');
    my $srvC = $self->lemming_service(tag => 'C');
    $self->start();

    xlog "not preforked, so no lemmings running yet";
    $self->assert_deep_equals({},
			      $self->lemming_census());

    my $lemmA = lemming_connect($srvA);

    xlog "connected so one lemming forked";
    $self->assert_deep_equals({ A =>  { live => 1, dead => 0 } },
			      $self->lemming_census());

    my $lemmB = lemming_connect($srvB);

    xlog "two connected so two lemmings forked";
    $self->assert_deep_equals({
				A => { live => 1, dead => 0 },
				B => { live => 1, dead => 0 },
			      }, $self->lemming_census());

    my $lemmC = lemming_connect($srvC);

    xlog "three connected so three lemmings forked";
    $self->assert_deep_equals({
				A => { live => 1, dead => 0 },
				B => { live => 1, dead => 0 },
				C => { live => 1, dead => 0 },
			      }, $self->lemming_census());

    lemming_push($lemmA, 'success');
    lemming_push($lemmB, 'success');
    lemming_push($lemmC, 'success');

    xlog "no more live lemmings";
    $self->assert_deep_equals({
				A => { live => 0, dead => 1 },
				B => { live => 0, dead => 1 },
				C => { live => 0, dead => 1 },
			      }, $self->lemming_census());
}

#
# Test a preforked single running program in SERVICES
#
sub test_prefork
{
    my ($self) = @_;

    xlog "single successful service";
    my $srv = $self->lemming_service(prefork => 1);
    $self->start();
    $self->lemming_wait(A => { live => 1 });

    xlog "preforked, so one lemming running already";
    $self->assert_deep_equals({ A => { live => 1, dead => 0 } },
			      $self->lemming_census());

    my $lemm1 = lemming_connect($srv);
    $self->lemming_wait(A => { live => 2 });

    xlog "connected so one lemming forked";
    $self->assert_deep_equals({ A => { live => 2, dead => 0 } },
			      $self->lemming_census());

    my $lemm2 = lemming_connect($srv);
    $self->lemming_wait(A => { live => 3 });

    xlog "connected again so two additional lemmings forked";
    $self->assert_deep_equals({ A => { live => 3, dead => 0 } },
			      $self->lemming_census());

    lemming_push($lemm1, 'success');
    lemming_push($lemm2, 'success');

    xlog "always at least one live lemming";
    $self->assert_deep_equals({ A => { live => 1, dead => 2 } },
			      $self->lemming_census());
}

#
# Test multiple running programs in SERVICES, some preforked.
#
sub test_multi_prefork
{
    my ($self) = @_;

    xlog "multiple successful service some preforked";
    my $srvA = $self->lemming_service(tag => 'A', prefork => 2);
    my $srvB = $self->lemming_service(tag => 'B'); # no preforking
    my $srvC = $self->lemming_service(tag => 'C', prefork => 3);
    $self->start();

    # wait for lemmings to be preforked
    $self->lemming_wait(A => { live => 2 }, C => { live => 3 });

    my @lemmings;
    my $lemm;

    xlog "connect to A once";
    $lemm = lemming_connect($srvA);
    $self->lemming_wait(A => { live => 3 });
    push(@lemmings, $lemm);
    $self->assert_deep_equals({
				A => { live => 3, dead => 0 },
				C => { live => 3, dead => 0 },
			      }, $self->lemming_census());

    xlog "connect to A again";
    $lemm = lemming_connect($srvA);
    $self->lemming_wait(A => { live => 4 });
    push(@lemmings, $lemm);
    $self->assert_deep_equals({
				A => { live => 4, dead => 0 },
				C => { live => 3, dead => 0 },
			      }, $self->lemming_census());

    xlog "connect to A a third time";
    $lemm = lemming_connect($srvA);
    $self->lemming_wait(A => { live => 5 });
    push(@lemmings, $lemm);
    $self->assert_deep_equals({
				A => { live => 5, dead => 0 },
				C => { live => 3, dead => 0 },
			      }, $self->lemming_census());

    xlog "connect to B";
    $lemm = lemming_connect($srvB);
    push(@lemmings, $lemm);
    $self->assert_deep_equals({
				A => { live => 5, dead => 0 },
				B => { live => 1, dead => 0 },
				C => { live => 3, dead => 0 },
			      }, $self->lemming_census());

    foreach $lemm (@lemmings)
    {
	lemming_push($lemm, 'success');
    }

    xlog "our lemmings are gone, others have replaced them";
    $self->assert_deep_equals({
				A => { live => 2, dead => 3 },
				B => { live => 0, dead => 1 },
				C => { live => 3, dead => 0 },
			      }, $self->lemming_census());
}

#
# Test a single program in SERVICES which fails after connect
#
sub test_exit_after_connect
{
    my ($self) = @_;

    xlog "single service will exit after connect";
    my $srv = $self->lemming_service();
    $self->start();

    xlog "not preforked, so no lemmings running yet";
    $self->assert_deep_equals({},
			      $self->lemming_census());

    my $lemm = lemming_connect($srv);

    xlog "connected so one lemming forked";
    $self->assert_deep_equals({ A => { live => 1, dead => 0 } },
			      $self->lemming_census());

    xlog "push the lemming off the cliff";
    lemming_push($lemm, 'exit');
    $self->assert_deep_equals({ A => { live => 0, dead => 1 } },
			      $self->lemming_census());

    xlog "can connect again";
    $lemm = lemming_connect($srv);
    $self->assert_deep_equals({ A => { live => 1, dead => 1 } },
			      $self->lemming_census());

    xlog "push the lemming off the cliff";
    lemming_push($lemm, 'exit');
    $self->assert_deep_equals({ A => { live => 0, dead => 2 } },
			      $self->lemming_census());
}

#
# Test a single program in SERVICES which fails during startup
#
sub test_service_exit_during_start
{
    my ($self) = @_;
    my $lemm;

    xlog "single service will exit during startup";
    my $srv = $self->lemming_service(mode => 'exit', delay => 100);
    $self->start();

    xlog "not preforked, so no lemmings running yet";
    $self->assert_deep_equals({},
			      $self->lemming_census());

    xlog "connection fails due to dead lemming";
    eval
    {
	$lemm = lemming_connect($srv);
    };
    $self->assert_null($lemm);

    xlog "expect 5 dead lemmings";
    $self->assert_deep_equals({ A => { live => 0, dead => 5 } },
			      $self->lemming_census());

    xlog "connections should fail because service disabled";
    eval
    {
	$lemm = lemming_connect($srv);
    };
    $self->assert_null($lemm);
    $self->assert_deep_equals({ A => { live => 0, dead => 5 } },
			      $self->lemming_census());
}

sub test_startup
{
    my ($self) = @_;

    xlog "Test a program in the START section";
    $self->lemming_start(tag => 'A', delay => 100, mode => 'success');
    $self->lemming_start(tag => 'B', delay => 200, mode => 'success');
    # This service won't be used
    my $srv = $self->lemming_service(tag => 'C');
    $self->start();

    xlog "expect 2 dead lemmings";
    $self->assert_deep_equals({
				A => { live => 0, dead => 1 },
				B => { live => 0, dead => 1 },
			      }, $self->lemming_census());
}

sub test_startup_exits
{
    my ($self) = @_;

    xlog "Test a program in the START section which fails";
    $self->lemming_start(tag => 'A', delay => 100, mode => 'exit');
    $self->lemming_start(tag => 'B', delay => 200, mode => 'exit');
    # This service won't be used
    my $srv = $self->lemming_service(tag => 'C');
    eval
    {
	$self->start();
    };
    xlog "start failed (as expected): $@" if $@;

    xlog "master should have exited when first startup failed";
    $self->assert(!$self->{instance}->is_running());

    xlog "expect 1 dead lemming";
    $self->assert_deep_equals({
				A => { live => 0, dead => 1 },
			      }, $self->lemming_census());
}

# TODO: test exit during startup with prefork=

sub test_service_ipv6
{
    my ($self) = @_;

    xlog "single successful service on IPv6";
    my $srv = $self->lemming_service(host => '::1');
    $self->start();

    xlog "not preforked, so no lemmings running yet";
    $self->assert_deep_equals({},
			      $self->lemming_census());

    my $lemm = lemming_connect($srv);

    xlog "connected so one lemming forked";
    $self->assert_deep_equals({ A => { live => 1, dead => 0 } },
			      $self->lemming_census());

    lemming_push($lemm, 'success');

    xlog "no more live lemmings";
    $self->assert_deep_equals({ A => { live => 0, dead => 1 } },
			      $self->lemming_census());
}

sub test_service_unix
{
    my ($self) = @_;

    xlog "single successful service on UNIX domain socket";
    my $srv = $self->lemming_service(
			host => undef,
			port => '@basedir@/conf/socket/lemming.sock');
    $self->start();

    xlog "not preforked, so no lemmings running yet";
    $self->assert_deep_equals({},
			      $self->lemming_census());

    my $lemm = lemming_connect($srv);

    xlog "connected so one lemming forked";
    $self->assert_deep_equals({ A => { live => 1, dead => 0 } },
			      $self->lemming_census());

    lemming_push($lemm, 'success');

    xlog "no more live lemmings";
    $self->assert_deep_equals({ A => { live => 0, dead => 1 } },
			      $self->lemming_census());
}

sub test_service_nohost
{
    my ($self) = @_;

    xlog "single successful service with a port-only listen=";
    my $srv = $self->lemming_service(host => undef);
    $self->start();

    xlog "not preforked, so no lemmings running yet";
    $self->assert_deep_equals({},
			      $self->lemming_census());

    my $lemm = lemming_connect($srv);

    xlog "connected so one lemming forked";
    $self->assert_deep_equals({ A => { live => 1, dead => 0 } },
			      $self->lemming_census());

    lemming_push($lemm, 'success');

    xlog "no more live lemmings";
    $self->assert_deep_equals({ A => { live => 0, dead => 1 } },
			      $self->lemming_census());
}

sub test_service_dup_port
{
    my ($self) = @_;

    xlog "successful two services with listen= ";
    xlog "parameters which reference the same IPv4 port";
    my $srvA = $self->lemming_service(tag => 'A');
    my $srvB = $self->lemming_service(tag => 'B',
				      port => $srvA->port());

    # master should emit a syslog message like this
    #
    # Dec 31 14:40:57 enki 0340541/master[26085]: unable to create B
    # listener socket: Address already in use
    #
    # and struggle on.
    # TODO: need a way to check syslog
    $self->start();

    xlog "not preforked, so no lemmings running yet";
    $self->assert_deep_equals({},
			      $self->lemming_census());

    my $lemmA = lemming_connect($srvA);

    my $census = $self->lemming_census();
    my ($winner) = keys %$census;  # either could be the one that runs
    xlog "connected so one lemming forked";
    $self->assert_deep_equals({ $winner => { live => 1, dead => 0 } },
			      $self->lemming_census());

    my $lemmB = lemming_connect($srvB);

    xlog "the port is owned by service A";
    $self->assert_deep_equals({ $winner => { live => 2, dead => 0 } },
			      $self->lemming_census());

    lemming_push($lemmA, 'success');
    lemming_push($lemmB, 'success');

    xlog "no more live lemmings";
    $self->assert_deep_equals({ $winner => { live => 0, dead => 2 } },
			      $self->lemming_census());
}

sub test_service_noexe
{
    my ($self) = @_;

    xlog "single service with a non-existant executable";
    my $srvA = $self->lemming_service(tag => 'A');
    my $srvB = $self->{instance}->add_service(
		    name => 'B',
		    argv => ['/usr/bin/no-such-exe','--foo','--bar']);

    # master should exit while adding services, with a message
    # to syslog like this
    #
    # Dec 31 15:03:26 enki 0403231/master[26825]: cannot find executable
    # for service 'B'
    eval
    {
	$self->start();
    };
    xlog "start failed (as expected): $@" if $@;

    xlog "master should have exited when service verification failed";
    $self->assert(!$self->{instance}->is_running());
}

sub test_reap_rate
{
    my ($self) = @_;

    xlog "Testing latency after which cyrus reaps dead children";

    my $max_latency = 1.0;  # seconds

    my $srv = $self->lemming_service(tag => 'A');
    $self->start();

    xlog "not preforked, so no lemmings running yet";
    $self->assert_deep_equals({},
			      $self->lemming_census());

    xlog "Build a vast flock of lemmings";
    my @lemmings;
    for (1..100)
    {
	push(@lemmings, lemming_connect($srv));
    }
    $self->assert_deep_equals({
				A => { live => 100, dead => 0 },
			      }, $self->lemming_census());

    # This technique avoids having new connections at the
    # same time as we're trying to measure reaping latency,
    # which can hide racy bugs in the main select() loop.
    xlog "Killing all the lemmings one by one";
    my $ss = new Cassandane::Util::Sample;
    while (my $lemm = shift @lemmings)
    {
	my $t = lemming_push($lemm, 'success');
	$self->assert($t < $max_latency,
		      "Child reap latency is >= $max_latency sec");
	$ss->add($t);
    }
    xlog "Reap times: $ss";

    xlog "no more live lemmings";
    $self->assert_deep_equals({
				A => { live => 0, dead => 100 },
			      }, $self->lemming_census());
}

sub measure_fork_rate
{
    my ($self, $srv, $rate) = @_;

    my $metronome = Cassandane::Util::Metronome->new(rate => $rate);
    my @lemmings;
    for (1..100)
    {
	my $lemm = lemming_connect($srv);
	push(@lemmings, $lemm);
	$metronome->tick();
    }

    foreach my $lemm (@lemmings)
    {
	lemming_push($lemm, 'success');
    }

    return $metronome->actual_rate();
}

sub test_maxforkrate
{
    my ($self) = @_;

    xlog "Testing enforcement of the maxforkrate= parameter";

    # A very loose error factor.  We don't care too much if the
    # enforcement is slightly off, it's a rough resource limit and
    # fairness measure not a precise QoS issue.  Also, even modest fork
    # rates may be difficult to achieve when running under Valgrind, and
    # we don't want that to cause the test to fail spuriously.
    my $epsilon = 0.2;
    my $fast = 10.0;	    # forks/sec
    my $slow = 5.0;	    # forks/sec

    my $srvA = $self->lemming_service(tag => 'A');
    my $srvB = $self->lemming_service(tag => 'B', maxforkrate => int($slow));
    $self->start();

    xlog "not preforked, so no lemmings running yet";
    $self->assert_deep_equals({},
			      $self->lemming_census());

    xlog "Test that we can achieve the fast forks rate on the unlimited service";
    my $r = $self->measure_fork_rate($srvA, $fast);
    xlog "Actual rate: $r";
    $self->assert($r >= (1.0-$epsilon)*$fast,
		  "Fork rate too slow, for $r wanted $fast");
    $self->assert($r <= (1.0+$epsilon)*$fast,
		  "Fork rate too fast, for $r wanted $fast");

    xlog "Test that the fork rate is limited on the limited service";
    $r = $self->measure_fork_rate($srvB, $fast);
    xlog "Actual rate: $r";
    $self->assert($r >= (1.0-$epsilon)*$slow,
		  "Fork rate too slow, got $r wanted $slow");
    $self->assert($r <= (1.0+$epsilon)*$slow,
		  "Fork rate too fast, got $r wanted $slow");

    xlog "no more live lemmings";
    $self->assert_deep_equals({
				A => { live => 0, dead => 100 },
				B => { live => 0, dead => 100 },
			      }, $self->lemming_census());
}

sub XXXtest_periodic_event
{
    my ($self) = @_;

    xlog "Testing regular events";

    my $srv = $self->lemming_service(tag => 'A');
    # This is the fastest we can schedule events - every 1 minute
    # so in the absence of a per-process time machine our test will
    # need to run for several real minutes.
    $self->lemming_event(tag => 'B', mode => 'success', period => 1);
    $self->start();

    xlog "periodic events run immediately";

    xlog "waiting 5 mins for events to fire";
    sleep(5*60);

    $self->assert_deep_equals({
				B => { live => 0, dead => 6 },
			      }, $self->lemming_census());
}

sub test_service_bad_name
{
    my ($self) = @_;

    xlog "services with bad names (Bug 3654)";
    $self->lemming_service(tag => 'foo');
    $self->lemming_service(tag => 'foo_bar');
    $self->lemming_service(tag => 'foo-baz');
    $self->lemming_service(tag => 'foo&baz');

    # master should exit while adding services, with a message
    # to syslog like this
    #
    # Mar 21 19:53:21 gnb-desktop 0853201/master[8789]: configuration
    # file /var/tmp/cass/0853201/conf/cyrus.conf: bad character '-' in
    # name on line 2
    #
    eval
    {
	$self->start();
    };
    xlog "start failed (as expected): $@" if $@;

    xlog "master should have exited when service verification failed";
    $self->assert(!$self->{instance}->is_running());
}

sub test_service_associate
{
    my ($self) = @_;

    xlog "sending a SIGHUP to a master process with services";
    xlog "whose listen= parameters give more than one result in";
    xlog "getaddrinfo(), such as an IPv4 and IPv6 (Bug 3771)";

    my $host = 'localhost';

    $self->lemming_service(tag => 'foo', host => undef);

    $self->{instance}->start();
    $self->{instance}->send_sighup();
    $self->{instance}->stop();
}

sub XXX_test_service_primary_fail
{
    my ($self) = @_;

    my $host = 'localhost';

    my $srv = $self->lemming_service(tag => 'foo', host => undef, mode => 'exit-ipv4/serve');

    $self->start();

    xlog "connection fails due to dead IPv4 lemming";
    my $lemm;
    eval
    {
	$lemm = lemming_connect($srv, 'inet');
    };
    $self->assert_null($lemm);

    xlog "expect 5 dead lemmings";
    $self->assert_deep_equals({ foo => { live => 0, dead => 5 } },
	$self->lemming_census());

    xlog "check the IPv4 service is really dead";
    eval
    {
	$lemm = lemming_connect($srv, 'inet');
    };
    $self->assert_null($lemm);
    $self->assert_deep_equals({ foo => { live => 0, dead => 5 } },
	$self->lemming_census());

    xlog "breed one IPv6 lemming";
    $lemm = lemming_connect($srv, 'inet6');
    $self->assert_deep_equals({ foo => { live => 1, dead => 5 } },
	$self->lemming_census());

    lemming_push($lemm, 'success');

    xlog "no more live lemmings";
    $self->assert_deep_equals({ foo => { live => 0, dead => 6 } },
	$self->lemming_census());

    xlog "revive the dead IPv4 service";
    $self->{instance}->send_sighup();

    xlog "connection fails again due to dead IPv4 lemming";
    $lemm = undef;
    eval
    {
	$lemm = lemming_connect($srv, 'inet');
    };
    $self->assert_null($lemm);

    xlog "expect 5 more dead lemmings";
    $self->assert_deep_equals({ foo => { live => 0, dead => 11 } },
	$self->lemming_census());
}

sub XXX_test_service_associate_fail
{
    my ($self) = @_;

    my $host = 'localhost';

    my $srv = $self->lemming_service(tag => 'foo', host => undef, mode => 'exit-ipv6/serve');

    $self->start();

    xlog "connection fails due to dead IPv6 lemming";
    my $lemm;
    eval
    {
	$lemm = lemming_connect($srv, 'inet6');
    };
    $self->assert_null($lemm);

    xlog "expect 5 dead lemmings";
    $self->assert_deep_equals({ foo => { live => 0, dead => 5 } },
	$self->lemming_census());

    xlog "check the IPv6 service is really dead";
    eval
    {
	$lemm = lemming_connect($srv, 'inet6');
    };
    $self->assert_null($lemm);
    $self->assert_deep_equals({ foo => { live => 0, dead => 5 } },
	$self->lemming_census());

    xlog "breed one IPv4 lemming";
    $lemm = lemming_connect($srv, 'inet');
    $self->assert_deep_equals({ foo => { live => 1, dead => 5 } },
	$self->lemming_census());

    lemming_push($lemm, 'success');

    xlog "no more live lemmings";
    $self->assert_deep_equals({ foo => { live => 0, dead => 6 } },
	$self->lemming_census());

    xlog "revive the dead IPv6 service";
    $self->{instance}->send_sighup();

    xlog "connection fails again due to dead IPv6 lemming";
    $lemm = undef;
    eval
    {
	$lemm = lemming_connect($srv, 'inet6');
    };
    $self->assert_null($lemm);

    xlog "expect 5 dead lemmings";
    $self->assert_deep_equals({ foo => { live => 0, dead => 11 } },
	$self->lemming_census());
}

sub test_sighup_recycling
{
    my ($self) = @_;

    my $host = 'localhost';

    my $srv = $self->lemming_service(tag => 'foo', prefork => 1);
    $self->start();
    $self->lemming_wait(foo => { live => 1 });

    xlog "preforked, so one lemming running already";
    $self->assert_deep_equals({ foo => { live => 1, dead => 0 } },
	$self->lemming_census());

    my $lemm = lemming_connect($srv);
    $self->lemming_wait(foo => { live => 2 });

    xlog "connected so one lemming forked";
    $self->assert_deep_equals({ foo => { live => 2, dead => 0 } },
	$self->lemming_census());

    $self->{instance}->send_sighup();
    $self->lemming_wait(foo => { live => 2, dead => 1 });

    xlog "recycled, so expect one dead lemming";
    $self->assert_deep_equals({ foo => { live => 2, dead => 1 } },
	$self->lemming_census());

    $self->{instance}->send_sighup();
    $self->lemming_wait(foo => { live => 2, dead => 2 });

    xlog "recycled, again so expect one more dead lemming";
    $self->assert_deep_equals({ foo => { live => 2, dead => 2 } },
	$self->lemming_census());

    lemming_push($lemm, 'success');

    xlog "always at least one live lemming";
    $self->assert_deep_equals({ foo => { live => 1, dead => 3 } },
	$self->lemming_census());
}

sub test_sighup_reloading
{
    my ($self) = @_;

    my $host = 'localhost';

    my $srvA = $self->lemming_service(tag => 'A');
    $self->start();
    my $srvB = $self->lemming_service(tag => 'B');


    my $lemmA = lemming_connect($srvA);

    xlog "connected so one lemming forked";
    $self->assert_deep_equals({ A => { live => 1, dead => 0 } },
	$self->lemming_census());

    lemming_push($lemmA, 'success');

    xlog "no more live lemmings";
    $self->assert_deep_equals({ A => { live => 0, dead => 1 } },
	$self->lemming_census());

    xlog "connection fails due to unexisting lemming";
    my $lemmB;
    eval
    {
	$lemmB = lemming_connect($srvB);
    };
    $self->assert_null($lemmB);

    $self->assert_deep_equals({ A => { live => 0, dead => 1 } },
	$self->lemming_census());


    xlog "add service in cyrus.conf and reload";
    $self->{instance}->_generate_master_conf();
    $self->{instance}->send_sighup();

    $lemmA = lemming_connect($srvA);

    xlog "connected so one lemming forked";
    $self->assert_deep_equals({ A => { live => 1, dead => 1 } },
	$self->lemming_census());

    lemming_push($lemmA, 'success');

    xlog "no more live lemmings";
    $self->assert_deep_equals({ A => { live => 0, dead => 2 } },
	$self->lemming_census());

    $lemmB = lemming_connect($srvB);

    xlog "connected so one lemming forked";
    $self->assert_deep_equals({ A => { live => 0, dead => 2 },
				B => { live => 1, dead => 0 } },
	$self->lemming_census());

    lemming_push($lemmB, 'success');

    xlog "no more live lemmings";
    $self->assert_deep_equals({ A => { live => 0, dead => 2 },
				B => { live => 0, dead => 1 } },
	$self->lemming_census());


    xlog "remove service in cyrus.conf and reload";
    $self->{instance}->remove_service('A');
    $self->{instance}->_generate_master_conf();
    $self->{instance}->send_sighup();

    # wait a moment for the sighup to be processed
    # XXX next test does something tricky with prefork/wait,
    # XXX but i'm not sure if that can be used here.
    sleep 1;

    xlog "connection fails due to unexisting lemming";
    $lemmA = undef;
    eval
    {
	$lemmA = lemming_connect($srvA);
    };
    $self->assert_null($lemmA);

    $self->assert_deep_equals({ A => { live => 0, dead => 2 },
				B => { live => 0, dead => 1 } },
	$self->lemming_census());

    $lemmB = lemming_connect($srvB);

    xlog "connected so one lemming forked";
    $self->assert_deep_equals({ A => { live => 0, dead => 2 },
				B => { live => 1, dead => 1 } },
	$self->lemming_census());

    lemming_push($lemmB, 'success');

    xlog "no more live lemmings";
    $self->assert_deep_equals({ A => { live => 0, dead => 2 },
				B => { live => 0, dead => 2 } },
	$self->lemming_census());
}

sub test_sighup_reloading_listen
{
    my ($self) = @_;

    my $host = 'localhost';

    # Note: we need to wait for SIGHUP to be processed; prefork can do the trick
    # to help us check that
    my $srv = $self->lemming_service(tag => 'A', prefork => 1);
    $self->start();
    $self->lemming_wait(A => { live => 1 });

    xlog "preforked, so one lemming running already";
    $self->assert_deep_equals({ A => { live => 1, dead => 0 } },
	$self->lemming_census());

    my $lemm = lemming_connect($srv);
    $self->lemming_wait(A => { live => 2 });

    xlog "connected so one lemming forked";
    $self->assert_deep_equals({ A => { live => 2, dead => 0 } },
	$self->lemming_census());

    lemming_push($lemm, 'success');

    xlog "always at least one live lemming";
    $self->assert_deep_equals({ A => { live => 1, dead => 1 } },
	$self->lemming_census());


    xlog "change service listen port in cyrus.conf and reload";
    my $port1 = $srv->port();
    $srv->set_port();
    my $port2 = $srv->port();
    $self->assert_not_equals($port1, $port2);
    $self->{instance}->_generate_master_conf();
    $self->{instance}->send_sighup();
    # Here is the trick with prefork: wait for the previously forked A instance
    # to die and be replaced by a new one
    $self->lemming_wait(A => { live => 1, dead => 2 });

    $self->assert_deep_equals({ A => { live => 1, dead => 2 } },
	$self->lemming_census());

    $lemm = lemming_connect($srv);
    $self->lemming_wait(A => { live => 2 });

    xlog "connected so one lemming forked";
    $self->assert_deep_equals({ A => { live => 2, dead => 2 } },
	$self->lemming_census());

    lemming_push($lemm, 'success');

    xlog "always at least one live lemming";
    $self->assert_deep_equals({ A => { live => 1, dead => 3 } },
	$self->lemming_census());
}

sub test_sighup_reloading_proto
{
    my ($self) = @_;

    my $host = 'localhost';

    # Note: we need to wait for SIGHUP to be processed; prefork can do the trick
    # to help us check that
    # Note: since we are listening on IPv4 *and* IPv6, there will be 2 preforked
    # instances
    my $srv = $self->lemming_service(tag => 'A', host => undef, prefork => 1);
    $self->start();
    $self->lemming_wait(A => { live => 2 });

    xlog "preforked, so two lemmings running already";
    $self->assert_deep_equals({ A => { live => 2, dead => 0 } },
	$self->lemming_census());

    # check IPv4
    my $lemm = lemming_connect($srv, 'inet');
    $self->lemming_wait(A => { live => 3 });

    xlog "connected so one lemming forked";
    $self->assert_deep_equals({ A => { live => 3, dead => 0 } },
	$self->lemming_census());

    lemming_push($lemm, 'success');

    xlog "always at least two live lemmings";
    $self->assert_deep_equals({ A => { live => 2, dead => 1 } },
	$self->lemming_census());

    # check IPv6
    $lemm = lemming_connect($srv, 'inet6');
    $self->lemming_wait(A => { live => 3 });

    xlog "connected so one lemming forked";
    $self->assert_deep_equals({ A => { live => 3, dead => 1 } },
	$self->lemming_census());

    lemming_push($lemm, 'success');

    xlog "always at least two live lemmings";
    $self->assert_deep_equals({ A => { live => 2, dead => 2 } },
	$self->lemming_census());


    xlog "change service listen proto in cyrus.conf and reload";
    $srv->set_master_param('proto', 'tcp4');
    $self->{instance}->_generate_master_conf();
    $self->{instance}->send_sighup();
    # Here is the trick with prefork: wait for the previously forked A instances
    # to die and be replaced by a new one
    $self->lemming_wait(A => { live => 1, dead => 4 });

    $self->assert_deep_equals({ A => { live => 1, dead => 4 } },
	$self->lemming_census());

    # check IPv4
    $lemm = lemming_connect($srv, 'inet');
    $self->lemming_wait(A => { live => 2 });

    xlog "connected so one lemming forked";
    $self->assert_deep_equals({ A => { live => 2, dead => 4 } },
	$self->lemming_census());

    lemming_push($lemm, 'success');

    xlog "always at least one live lemming";
    $self->assert_deep_equals({ A => { live => 1, dead => 5 } },
	$self->lemming_census());

    # check IPv6
    xlog "connection fails due to unexisting IPv6 lemming";
    $lemm = undef;
    eval
    {
	$lemm = lemming_connect($srv, 'inet6');
    };
    $self->assert_null($lemm);

    xlog "always at least one live lemming";
    $self->assert_deep_equals({ A => { live => 1, dead => 5 } },
	$self->lemming_census());
}

1;
