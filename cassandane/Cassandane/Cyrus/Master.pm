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
use base qw(Test::Unit::TestCase);
use POSIX qw(getcwd);
use DateTime;
use Cassandane::Util::Log;
use Cassandane::Instance;
use Cassandane::Service;
use Cassandane::Config;
use IO::Socket::INET;
use Time::HiRes qw(usleep);

my $lemming_bin = getcwd() . '/utils/lemming';

sub new
{
    my $class = shift;
    my $self = $class->SUPER::new(@_);

    return $self;
}

sub lemming_connect
{
    my ($srv) = @_;

    my $sock = IO::Socket::INET->new(
	    Type => SOCK_STREAM,
	    PeerHost => $srv->{host},
	    PeerPort => $srv->{port});

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

    # Push the lemming over the metaphorical cliff.
    $lemming->{sock}->syswrite($mode . "\r\n");
    $lemming->{sock}->close();

    # Wait for the master process to wake up and reap the lemming.
    Cassandane::Instance::_timed_wait(sub { kill(0, $lemming->{pid}) == 0 });
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
    $self->assert_not_null($lemm);

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
    $self->assert_not_null($lemm1);

    xlog "connected so one lemming forked";
    $self->assert_deep_equals({ A => [1, 0] },
			      lemming_census($inst));

    my $lemm2 = lemming_connect($srv);
    $self->assert_not_null($lemm2);

    xlog "two connected so two lemmings forked";
    $self->assert_deep_equals({ A => [2, 0] },
			      lemming_census($inst));

    my $lemm3 = lemming_connect($srv);
    $self->assert_not_null($lemm3);

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

    xlog "single successful service";
    my $inst = Cassandane::Instance->new(setup_mailbox => 0);
    my $srvA = $inst->add_service('A', argv => [$lemming_bin,qw(-t A -m serve)]);
    my $srvB = $inst->add_service('B', argv => [$lemming_bin,qw(-t B -m serve)]);
    my $srvC = $inst->add_service('C', argv => [$lemming_bin,qw(-t C -m serve)]);
    $inst->start();

    xlog "not preforked, so no lemmings running yet";
    $self->assert_deep_equals({},
			      lemming_census($inst));

    my $lemmA = lemming_connect($srvA);
    $self->assert_not_null($lemmA);

    xlog "connected so one lemming forked";
    $self->assert_deep_equals({ A => [1, 0] },
			      lemming_census($inst));

    my $lemmB = lemming_connect($srvB);
    $self->assert_not_null($lemmB);

    xlog "two connected so two lemmings forked";
    $self->assert_deep_equals({ A => [1, 0], B => [1, 0] },
			      lemming_census($inst));

    my $lemmC = lemming_connect($srvC);
    $self->assert_not_null($lemmC);

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

1;
