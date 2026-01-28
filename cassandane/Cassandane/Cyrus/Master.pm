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

package Cassandane::Cyrus::Master;
use strict;
use warnings;
use File::stat;
use POSIX qw(getcwd);
use DateTime;

use base qw(Cassandane::Cyrus::TestCase);
use Cassandane::Util::Log;
use Cassandane::Util::Wait;
use Cassandane::Util::Socket;
use Cassandane::Util::Sample;
use Cassandane::Util::Metronome;
use Cassandane::Instance;
use Cassandane::Service;
use Cassandane::Config;
use Time::HiRes qw(sleep);

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
    $self->{instance} = Cassandane::Instance->new(setup_mailbox => 0,
                                                  authdaemon => 0);
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
        or die "Cannot read from lemming: " . $srv->address() . " $!";
    $pid = unpack("L", $pid);
    die "Cannot read from lemming: $!"
        unless defined $pid;

    return { sock => $sock, pid => $pid };
}

sub lemming_push
{
    my ($lemming, $mode) = @_;

#     xlog $self, "Pushing mode=$mode to pid=$lemming->{pid}";

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
        xlog $self, "found lemming tag=$tag pid=$pid";
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

    my $culled;

    return unless -d $coresdir;
    opendir LEMM,$coresdir
        or die "cannot open $coresdir for reading: $!";
    while ($_ = readdir LEMM)
    {
        my ($tag, $pid) = m/^lemming\.(\w+).(\d+)$/;
        next
            unless defined $pid;
        if (kill(9, $pid)) {
            xlog $self, "culled lemming tag=$tag pid=$pid";
            $culled++;
        }
    }
    closedir LEMM;

    return $culled;
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

sub lemming_daemon
{
    my ($self, %params) = @_;
    return $self->{instance}->add_daemon(_lemming_args(%params));
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

# TODO: test exit during startup with prefork=

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

sub XXX_test_service_primary_fail
{
    my ($self) = @_;

    my $host = 'localhost';

    my $srv = $self->lemming_service(tag => 'foo', host => undef, mode => 'exit-ipv4/serve');

    $self->start();

    xlog $self, "connection fails due to dead IPv4 lemming";
    my $lemm;
    eval
    {
        $lemm = lemming_connect($srv, 'inet');
    };
    $self->assert_null($lemm);

    xlog $self, "expect 5 dead lemmings";
    $self->assert_deep_equals({ foo => { live => 0, dead => 5 } },
        $self->lemming_census());

    xlog $self, "check the IPv4 service is really dead";
    eval
    {
        $lemm = lemming_connect($srv, 'inet');
    };
    $self->assert_null($lemm);
    $self->assert_deep_equals({ foo => { live => 0, dead => 5 } },
        $self->lemming_census());

    xlog $self, "breed one IPv6 lemming";
    $lemm = lemming_connect($srv, 'inet6');
    $self->assert_deep_equals({ foo => { live => 1, dead => 5 } },
        $self->lemming_census());

    lemming_push($lemm, 'success');

    xlog $self, "no more live lemmings";
    $self->assert_deep_equals({ foo => { live => 0, dead => 6 } },
        $self->lemming_census());

    xlog $self, "revive the dead IPv4 service";
    $self->{instance}->send_sighup();

    xlog $self, "connection fails again due to dead IPv4 lemming";
    $lemm = undef;
    eval
    {
        $lemm = lemming_connect($srv, 'inet');
    };
    $self->assert_null($lemm);

    xlog $self, "expect 5 more dead lemmings";
    $self->assert_deep_equals({ foo => { live => 0, dead => 11 } },
        $self->lemming_census());
}

sub XXX_test_service_associate_fail
{
    my ($self) = @_;

    my $host = 'localhost';

    my $srv = $self->lemming_service(tag => 'foo', host => undef, mode => 'exit-ipv6/serve');

    $self->start();

    xlog $self, "connection fails due to dead IPv6 lemming";
    my $lemm;
    eval
    {
        $lemm = lemming_connect($srv, 'inet6');
    };
    $self->assert_null($lemm);

    xlog $self, "expect 5 dead lemmings";
    $self->assert_deep_equals({ foo => { live => 0, dead => 5 } },
        $self->lemming_census());

    xlog $self, "check the IPv6 service is really dead";
    eval
    {
        $lemm = lemming_connect($srv, 'inet6');
    };
    $self->assert_null($lemm);
    $self->assert_deep_equals({ foo => { live => 0, dead => 5 } },
        $self->lemming_census());

    xlog $self, "breed one IPv4 lemming";
    $lemm = lemming_connect($srv, 'inet');
    $self->assert_deep_equals({ foo => { live => 1, dead => 5 } },
        $self->lemming_census());

    lemming_push($lemm, 'success');

    xlog $self, "no more live lemmings";
    $self->assert_deep_equals({ foo => { live => 0, dead => 6 } },
        $self->lemming_census());

    xlog $self, "revive the dead IPv6 service";
    $self->{instance}->send_sighup();

    xlog $self, "connection fails again due to dead IPv6 lemming";
    $lemm = undef;
    eval
    {
        $lemm = lemming_connect($srv, 'inet6');
    };
    $self->assert_null($lemm);

    xlog $self, "expect 5 dead lemmings";
    $self->assert_deep_equals({ foo => { live => 0, dead => 11 } },
        $self->lemming_census());
}

use Cassandane::Tiny::Loader 'tiny-tests/Master';

1;
