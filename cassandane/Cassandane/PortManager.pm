# SPDX-License-Identifier: BSD-3-Clause-CMU
# See COPYING file at the root of the distribution for more details.

package Cassandane::PortManager;
use strict;
use warnings;

use Cassandane::Cassini;
use IO::Socket::IP;
use POSIX qw(EADDRINUSE);

my $base_port;
my $max_ports = 20;
my $next_port = 0;
my %allocated;

sub alloc
{
    my $host = shift;

    if (!defined $base_port)
    {
        my $workerid = $ENV{TEST_UNIT_WORKER_ID} || '1';
        die "Invalid TEST_UNIT_WORKER_ID - code not run in Worker context"
            if (defined($workerid) && $workerid eq 'invalid');
        my $cassini = Cassandane::Cassini->instance();
        my $cassandane_base_port = 0 + $cassini->val('cassandane', 'base_port', '29100');
        $base_port = $cassandane_base_port + $max_ports * ($workerid-1);
    }
    for (my $i = 0 ; $i < $max_ports ; $i++)
    {
        my $port = $base_port + (($next_port + $i) % $max_ports);
        if (!$allocated{$port} && port_is_free($host, $port))
        {
            $allocated{$port} = 1;
            $next_port++;
            return $port;
        }
    }
    die "No ports remaining";
}

sub port_is_free
{
    my $host = shift;
    my $port = shift;

    # If we can bind to the port no one else is currently using it
    my $socket = IO::Socket::IP->new(
        LocalAddr => $host,
        LocalPort => $port,
        Proto     => 'tcp',
        ReuseAddr => 1,

        # There's something odd going on with IO::Socket::IP's use of
        # getaddrinfo, such that if you provide "::1" as the local address, and
        # the loopback interface has inet6, but another (say, eth0) interface
        # does not, the behavior of AI_ADDRCONFIG will be to act as if the
        # system has no inet6 support, and so inet6 bindings should not be
        # offered.  Something seems amiss, but I'm not sure where.  Using 0
        # will allow ports on ::1 to seem available, though.
        # -- rjbs, 2024-12-14
        GetAddrInfoFlags => 0,
    );

    unless ($socket) {
        if ($! == EADDRINUSE) {
            return 0;
        }

        warn "Unknown error binding $host:$port: $!\n";
        return 0;
    }

    return 1;
}

sub free
{
    my ($port) = @_;

    return unless defined $base_port;

    $allocated{$port} = 0;
}

sub free_all
{
    return unless defined $base_port;
    my @freed;
    for (my $i = 0 ; $i < $max_ports ; $i++)
    {
        my $port = $base_port + $i;
        if ($allocated{$port})
        {
            $allocated{$port} = 0;
            push(@freed, $port);
        }
    }
    return @freed;
}

1;
