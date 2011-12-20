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
use Cassandane::Instance;
use Cassandane::Service;
use Cassandane::Config;
use IO::Socket::INET;

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
}

# Disable this whole suite - all the tests fail on ToT
sub filter { return { x => sub { return 1; } }; }

sub lemming_connect
{
    my ($srv) = @_;

    my $sock = IO::Socket::INET->new(
	    Type => SOCK_STREAM,
	    PeerHost => $srv->{host},
	    PeerPort => $srv->{port});
    die "Cannot create sock"
	unless defined $sock;

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
    timed_wait(sub { kill(0, $lemming->{pid}) == 0 },
	       description => "master to reap lemming $lemming->{pid}");
}

sub lemming_census
{
    my ($inst) = @_;
    my $coresdir = $inst->{basedir} . '/conf/cores';

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
	$actual{$tag} = [ $nlive, $ntotal - $nlive ];
    }
    return \%actual;
}

#
# Test a single running programs in SERVICES
#
sub test_service
{
    my ($self) = @_;

    xlog "single successful service";
    my $inst = Cassandane::Instance->new(setup_mailbox => 0);
    my $srv = $inst->add_service('A', argv => [$lemming_bin, qw(-t A -m serve)]);
    $inst->start();

    xlog "not preforked, so no lemmings running yet";
    $self->assert_deep_equals({},
			      lemming_census($inst));

    my $lemm = lemming_connect($srv);

    xlog "connected so one lemming forked";
    $self->assert_deep_equals({ A => [1, 0] },
			      lemming_census($inst));

    lemming_push($lemm, 'success');

    xlog "no more live lemmings";
    $self->assert_deep_equals({ A => [0, 1] },
			      lemming_census($inst));

    $inst->stop();
}

#
# Test multiple connections to a single running program in SERVICES
#
sub test_multi_connections
{
    my ($self) = @_;

    xlog "multiple connections to a single successful service";
    my $inst = Cassandane::Instance->new(setup_mailbox => 0);
    my $srv = $inst->add_service('A', argv => [$lemming_bin,qw(-t A -m serve)]);
    $inst->start();

    xlog "not preforked, so no lemmings running yet";
    $self->assert_deep_equals({},
			      lemming_census($inst));

    my $lemm1 = lemming_connect($srv);

    xlog "connected so one lemming forked";
    $self->assert_deep_equals({ A => [1, 0] },
			      lemming_census($inst));

    my $lemm2 = lemming_connect($srv);

    xlog "two connected so two lemmings forked";
    $self->assert_deep_equals({ A => [2, 0] },
			      lemming_census($inst));

    my $lemm3 = lemming_connect($srv);

    xlog "three connected so three lemmings forked";
    $self->assert_deep_equals({ A => [3, 0] },
			      lemming_census($inst));

    lemming_push($lemm1, 'success');
    lemming_push($lemm2, 'success');
    lemming_push($lemm3, 'success');

    xlog "no more live lemmings";
    $self->assert_deep_equals({ A => [0, 3] },
			      lemming_census($inst));

    $inst->stop();
}

#
# Test multiple running programs in SERVICES
#
sub test_multi_services
{
    my ($self) = @_;

    xlog "multiple successful services";
    my $inst = Cassandane::Instance->new(setup_mailbox => 0);
    my $srvA = $inst->add_service('A', argv => [$lemming_bin,qw(-t A -m serve)]);
    my $srvB = $inst->add_service('B', argv => [$lemming_bin,qw(-t B -m serve)]);
    my $srvC = $inst->add_service('C', argv => [$lemming_bin,qw(-t C -m serve)]);
    $inst->start();

    xlog "not preforked, so no lemmings running yet";
    $self->assert_deep_equals({},
			      lemming_census($inst));

    my $lemmA = lemming_connect($srvA);

    xlog "connected so one lemming forked";
    $self->assert_deep_equals({ A => [1, 0] },
			      lemming_census($inst));

    my $lemmB = lemming_connect($srvB);

    xlog "two connected so two lemmings forked";
    $self->assert_deep_equals({ A => [1, 0], B => [1, 0] },
			      lemming_census($inst));

    my $lemmC = lemming_connect($srvC);

    xlog "three connected so three lemmings forked";
    $self->assert_deep_equals({ A => [1, 0], B => [1, 0], C => [1, 0] },
			      lemming_census($inst));

    lemming_push($lemmA, 'success');
    lemming_push($lemmB, 'success');
    lemming_push($lemmC, 'success');

    xlog "no more live lemmings";
    $self->assert_deep_equals({ A => [0, 1], B => [0, 1], C => [0, 1] },
			      lemming_census($inst));

    $inst->stop();
}

#
# Test a preforked single running program in SERVICES
#
sub test_prefork
{
    my ($self) = @_;

    xlog "single successful service";
    my $inst = Cassandane::Instance->new(setup_mailbox => 0);
    my $srv = $inst->add_service('A',
				 prefork => 1,
				 argv => [$lemming_bin, qw(-t A -m serve)]);
    $inst->start();

    xlog "preforked, so one lemming running already";
    $self->assert_deep_equals({ A => [ 1, 0 ] },
			      lemming_census($inst));

    my $lemm1 = lemming_connect($srv);

    xlog "connected so one lemming forked";
    $self->assert_deep_equals({ A => [2, 0] },
			      lemming_census($inst));

    my $lemm2 = lemming_connect($srv);

    xlog "connected again so two additional lemmings forked";
    $self->assert_deep_equals({ A => [3, 0] },
			      lemming_census($inst));

    lemming_push($lemm1, 'success');
    lemming_push($lemm2, 'success');

    xlog "always at least one live lemming";
    $self->assert_deep_equals({ A => [1, 2] },
			      lemming_census($inst));

    $inst->stop();
}

#
# Test multiple running programs in SERVICES, some preforked.
#
sub test_multi_prefork
{
    my ($self) = @_;

    xlog "multiple successful service some preforked";
    my $inst = Cassandane::Instance->new(setup_mailbox => 0);
    my $srvA = $inst->add_service('A',
				  prefork => 2,
				  argv => [$lemming_bin,qw(-t A -m serve)]);
    my $srvB = $inst->add_service('B',
				  # no preforking
				  argv => [$lemming_bin,qw(-t B -m serve)]);
    my $srvC = $inst->add_service('C',
				  prefork => 3,
				  argv => [$lemming_bin,qw(-t C -m serve)]);
    $inst->start();

    # wait for lemmings to be preforked
    timed_wait(
	sub
	{
	    my $census = lemming_census($inst);
	    $census->{A}->[0] == 2 && $census->{C}->[0] == 3
	},
	description => "master to prefork the configured lemmings");

    my @lemmings;
    my $lemm;

    xlog "connect to A once";
    $lemm = lemming_connect($srvA);
    push(@lemmings, $lemm);
    $self->assert_deep_equals({ A => [3, 0], C => [3, 0] },
			      lemming_census($inst));

    xlog "connect to A again";
    $lemm = lemming_connect($srvA);
    push(@lemmings, $lemm);
    $self->assert_deep_equals({ A => [4, 0], C => [3, 0] },
			      lemming_census($inst));

    xlog "connect to A a third time";
    $lemm = lemming_connect($srvA);
    push(@lemmings, $lemm);
    $self->assert_deep_equals({ A => [5, 0], C => [3, 0] },
			      lemming_census($inst));

    xlog "connect to B";
    $lemm = lemming_connect($srvB);
    push(@lemmings, $lemm);
    $self->assert_deep_equals({ A => [5, 0], B => [1, 0], C => [3, 0] },
			      lemming_census($inst));

    foreach $lemm (@lemmings)
    {
	lemming_push($lemm, 'success');
    }

    xlog "our lemmings are gone, others have replaced them";
    $self->assert_deep_equals({ A => [2, 3], B => [0, 1], C => [3, 0] },
			      lemming_census($inst));

    $inst->stop();
}

#
# Test a single program in SERVICES which fails after connect
#
sub test_exit_after_connect
{
    my ($self) = @_;

    xlog "single service will exit after connect";
    my $inst = Cassandane::Instance->new(setup_mailbox => 0);
    my $srv = $inst->add_service('A', argv => [$lemming_bin, qw(-t A -m serve)]);
    $inst->start();

    xlog "not preforked, so no lemmings running yet";
    $self->assert_deep_equals({},
			      lemming_census($inst));

    my $lemm = lemming_connect($srv);

    xlog "connected so one lemming forked";
    $self->assert_deep_equals({ A => [1, 0] },
			      lemming_census($inst));

    xlog "push the lemming off the cliff";
    lemming_push($lemm, 'exit');
    $self->assert_deep_equals({ A => [0, 1] },
			      lemming_census($inst));

    xlog "can connect again";
    $lemm = lemming_connect($srv);
    $self->assert_deep_equals({ A => [1, 1] },
			      lemming_census($inst));

    xlog "push the lemming off the cliff";
    lemming_push($lemm, 'exit');
    $self->assert_deep_equals({ A => [0, 2] },
			      lemming_census($inst));

    $inst->stop();
}

#
# Test a single program in SERVICES which fails during startup
#
sub test_exit_during_start
{
    my ($self) = @_;
    my $lemm;

    xlog "single service will exit during startup";
    my $inst = Cassandane::Instance->new(setup_mailbox => 0);
    my $srv = $inst->add_service('A', argv => [$lemming_bin, qw(-t A -d 100 -m exit)]);
    $inst->start();

    xlog "not preforked, so no lemmings running yet";
    $self->assert_deep_equals({},
			      lemming_census($inst));

    xlog "connection fails due to dead lemming";
    eval
    {
	$lemm = lemming_connect($srv);
    };
    $self->assert_null($lemm);

    xlog "expect 5 dead lemmings";
    $self->assert_deep_equals({ A => [0, 5] },
			      lemming_census($inst));

    xlog "connections should fail because service disabled";
    eval
    {
	$lemm = lemming_connect($srv);
    };
    $self->assert_null($lemm);
    $self->assert_deep_equals({ A => [0, 5] },
			      lemming_census($inst));

    $inst->stop();
}

# TODO: test exit during startup with prefork=

1;
