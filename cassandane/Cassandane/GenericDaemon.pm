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

package Cassandane::GenericDaemon;
use strict;
use warnings;

use lib '.';
use Cassandane::Util::Log;
use Cassandane::PortManager;

sub new
{
    my ($class, %params) = @_;

    my $host = '127.0.0.1';
    $host = delete $params{host}
        if (exists $params{host});
    my $port = delete $params{port};
    my $config = delete $params{config};
    my $argv = delete $params{argv};
    my $name = delete $params{name};

    die "Unexpected parameters: " . join(" ", keys %params)
        if scalar %params;

    return bless
    {
        name => $name,
        host => $host,
        port => $port,
        config => $config,
        argv => $argv,
    }, $class;
}

sub set_config
{
    my ($self, $config) = @_;
    $self->{config} = $config;
}

# Return the host
sub host
{
    my ($self) = @_;
    return $self->{host};
}

# Return the port
sub port
{
    my ($self) = @_;

    $self->set_port($self->{port});

    return $self->{port};
}

sub set_port
{
    my ($self, $port) = @_;

    if (defined $port &&
        defined $self->{config})
    {
        # expand @basedir@ et al
        $port = $self->{config}->substitute($port);
    }

    $port ||= Cassandane::PortManager::alloc();
    $self->{port} = $port;
}

# Return a hash of parameters for connecting to the daemon.
# These will ultimately go through to MessageStoreFactory::create.
sub connection_params
{
    my ($self, %params) = @_;

    $params{address_family} = $self->{address_family};
    $params{host} = $self->host();
    $params{port} = $self->port();
    $params{verbose} ||= get_verbose();
    return \%params;
}

sub address
{
    my ($self) = @_;
    my @parts;

    my $port = $self->port();
    if (defined $self->{host} && !($port =~ m/^\//))
    {
        # Cyrus uses the syntax '[ipv6address]:port' to specify
        # an IPv6 address (which will contain the : character)
        # as the host part.
        push(@parts, '[') if ($self->{host} =~ m/:/);
        push(@parts, $self->{host});
        push(@parts, ']') if ($self->{host} =~ m/:/);
        push(@parts, ':');
    }
    push(@parts, $port);
    return join('', @parts);
}

sub parse_address
{
    my ($s) = @_;
    my $host;
    my $port;

    if ($s =~ m/^\//)
    {
        # UNIX domain socket
        $port = $s;
    }
    if (!defined $port)
    {
        # syntax '[ipv6address]:port'
        ($host, $port) = ($s =~ m/^\[([^]]+)\]:([^:]+)$/);
    }
    if (!defined $port)
    {
        # syntax 'host:port'
        ($host, $port) = ($s =~ m/^([^:]+):([^:]+)$/);
    }
    if (!defined $port)
    {
        # syntax 'port'
        ($port) = ($s =~ m/^([^:]+)$/);
    }
    if (!defined $port)
    {
        die "Cannot parse \"$s\" as socket address"
    }

    return { host => $host, port => $port };
}

my %netstat_parse = (
    #     # netstat -ln -Ainet
    #     Active Internet connections (only servers)
    #     Proto Recv-Q Send-Q Local Address           Foreign Address State
    #     tcp        0      0 0.0.0.0:56686           0.0.0.0:* LISTEN
    #
    #     # netstat -lnp -Ainet
    #     Proto Recv-Q Send-Q Local Address           Foreign Address         State       PID/Program name
    #     tcp        0      0 0.0.0.0:22              0.0.0.0:*               LISTEN      1058/sshd
    inet => sub
    {
        my ($line, $wantpid) = @_;

        my @a = split(/\s+/, $line);
        return unless scalar(@a) == 6 + ($wantpid ? 1 : 0);

        my ($addr, $port) = ($a[3] =~ m/^(.*):([0-9]+)$/);
        return unless defined $port;
        $addr = 'any' if ($addr eq '0.0.0.0');
        $addr = 'localhost' if ($addr eq '127.0.0.1');

        my $pid;
        my $cmd;
        ($pid, $cmd) = ($a[6] =~ m/^([0-9]+)\/(.*)$/) if ($wantpid);

        return {
            address_family => 'inet',
            protocol => $a[0],      # 'tcp'
            state => $a[5],         # 'LISTEN'
            local_addr => $addr,    # numeric
            local_port => $port,    # numeric
            pid => $pid,            # numeric or undef
            cmd => $cmd,            # string or undef
        };
    },

    #  # netstat -ln -Ainet6
    #  Active Internet connections (only servers)
    #  Proto Recv-Q Send-Q Local Address           Foreign Address         State
    #  tcp6       0      0 :::22                   :::*                    LISTEN
    #
    #  # netstat -lnp -Ainet6
    #  Proto Recv-Q Send-Q Local Address           Foreign Address         State       PID/Program name
    #  tcp6       0      0 :::22                   :::*                    LISTEN      1058/sshd
    inet6 => sub
    {
        my ($line, $wantpid) = @_;

        my @a = split(/\s+/, $line);
        return unless scalar(@a) == 6 + ($wantpid ? 1 : 0);

        my $prot = $a[0];       # tcp or tcp6
        $prot =~ s/6$//;

        my ($addr, $port) = ($a[3] =~ m/^(.*):([0-9]+)$/);
        return unless defined $port;
        $addr = 'any' if ($addr eq '::');
        $addr = 'localhost' if ($addr eq '::1');

        my $pid;
        my $cmd;
        ($pid, $cmd) = ($a[6] =~ m/^([0-9]+)\/(.*)$/) if ($wantpid);

        return {
            address_family => 'inet6',
            protocol => $prot,      # 'tcp'
            state => $a[5],         # 'LISTEN'
            local_addr => $addr,    # numeric
            local_port => $port,    # numeric
            pid => $pid,            # numeric or undef
            cmd => $cmd,            # string or undef
        };
    },

    #  # netstat -ln -Aunix
    #  Active UNIX domain sockets (only servers)
    #  Proto RefCnt Flags       Type       State         I-Node   Path
    #  unix  2      [ ACC ]     STREAM     LISTENING     7941     /var/run/dbus/system_bus_socket
    #
    #  # netstat -lnp -Aunix
    #  Active UNIX domain sockets (only servers)
    #  Proto RefCnt Flags       Type       State         I-Node   PID/Program name    Path
    #  unix  2      [ ACC ]     STREAM     LISTENING     13317    2016/gconf-helper   /tmp/orbit-gnb/linc-7e0-0-6044c14eae22e
    unix => sub
    {
        my ($line, $wantpid) = @_;

        # Compress the Flags field to eliminate spaces and make split()
        # return a predictable number of fields.
        $line =~ s/\[[^]]*\]/[]/;

        my @a = split(/\s+/, $line);
        return unless scalar(@a) == 7 + ($wantpid ? 1 : 0);

        my $state = $a[4];
        $state =~ s/^LISTENING$/LISTEN/;

        return if $a[0] ne 'unix';
        my $prot;
        $prot = 'tcp' if ($a[3] eq 'STREAM');
        $prot = 'udp' if ($a[3] eq 'DGRAM');
        return if !defined $prot;

        my $pid;
        my $cmd;
        ($pid, $cmd) = ($a[6] =~ m/^([0-9]+)\/(.*)$/) if ($wantpid);

        return {
            address_family => 'unix',
            protocol => $prot,      # 'tcp'
            state => $state,        # 'LISTEN'
            local_addr => 'any',
            local_port => $a[-1],   # bound socket path
            pid => $pid,            # numeric or undef
            cmd => $cmd,            # string or undef
        };
    },
);

sub address_family
{
    my ($self) = @_;
    my $h = $self->host();
    my $p = $self->port();

    # port being a UNIX domain socket is ok
    return 'unix' if ($p =~ m/^\//);

    # otherwise, the port has to be numeric
    die "Sorry, the port \"$p\" must be a numeric TCP port or unix path"
        unless ($p =~ m/^\d+$/);

    # undefined host is ok = inet, IPADDR_ANY
    return 'inet' if !defined $h;
    # IPv4 address is ok
    return 'inet' if ($h =~ m/^\d+\.\d+\.\d+\.\d+$/);
    # full IPv6 address is ok
    return 'inet6' if ($h =~ m/^([[:xdigit:]]{1,4}::?)+[[:xdigit:]]{1,4}$/);
    # IPv6 forms xxxx::x and ::x are ok
    return 'inet6' if ($h =~ m/^[[:xdigit:]]{4}::[[:xdigit:]]{1,4}$/);
    return 'inet6' if ($h =~ m/^::[[:xdigit:]]{1,4}$/);
    # others, not so much
    die "Sorry, the host argument \"$h\" must be a numeric IPv4 or IPv6 address";
}

sub _is_listening_af
{
    my ($self, $af) = @_;

    my @cmd = (
        'netstat',
        '-l',           # listening ports only
        '-n',           # numeric output
        );
    my $parser = $netstat_parse{$af};
    my $found = 0;
    open NETSTAT,'-|',@cmd
        or die "Cannot run netstat to check for service: $!";

    my $host = $self->{host};
    $host = 'any' if !defined $host;
    $host = 'localhost' if $host eq '127.0.0.1';
    $host = 'localhost' if $host eq '::1';

    while (<NETSTAT>)
    {
        chomp;
        my $ii = $parser->($_, 0);
        next unless $ii;
        next if ($ii->{protocol} ne 'tcp');
        next if ($ii->{state} ne 'LISTEN');
        next if ($ii->{local_port} ne "$self->{port}");
        next if ($ii->{local_addr} ne $host && $ii->{local_addr} ne 'any');
        $found = 1;
        last;
    }
    close NETSTAT;

    xlog "is_listening: service $self->{name} is " .
         "listening on " . $self->address()
        if ($found);

    return $found;
}

sub is_listening
{
    my ($self) = @_;

    my @afs;
    my $af = $self->address_family();
    push(@afs, $af);
    push(@afs, 'inet6')
        if ($af eq 'inet' && !defined $self->host());

    foreach my $af (@afs)
    {
        return 0 if (!$self->_is_listening_af($af));
    }
    return 1;
}

sub kill_processes_on_ports
{
    my (@ports) = @_;

    return if !scalar(@ports);
    xlog "checking for stray processes on ports: " . join(' ', @ports);

    my %portshash;
    map { $portshash{$_} = 1; } @ports;

    # We don't care about UNIX sockets here
    # although we probably should
    my @found;
    foreach my $af ('inet', 'inet6')
    {
        # Silly netstat -p on Linux prints a warning to stderr
        # -n        numeric output
        # -p        show pid & program
        my $cmd = "netstat -np 2>/dev/null";

        my $parser = $netstat_parse{$af};
        open NETSTAT,'-|',$cmd
            or die "Cannot run netstat to check for stray processes: $!";

        while (<NETSTAT>)
        {
            chomp;
            my $ii = $parser->($_, 1);
            next unless $ii;
            next unless $portshash{$ii->{local_port}};
# xlog "XXX stray socket: " . Data::Dumper::Dumper($ii);
            next if !defined $ii->{pid};    # we don't have permission,
                                            # or there is no process,
                                            # e.g. in TIME_WAIT state
            push(@found, $ii);
        }
        close NETSTAT;
    }

    foreach my $ii (@found)
    {
        xlog "ERROR!! killing stray process $ii->{cmd} on port $ii->{local_port}";
        Cassandane::Instance::_stop_pid($ii->{pid});
    }
    return scalar(@found);
}

sub describe
{
    my ($self) = @_;

    printf "%s listening on %s\n",
            $self->{name},
            $self->address();
}

sub set_argv
{
    my ($self, @args) = @_;
    $self->{argv} = [ @args ];
}

sub get_argv
{
    my ($self) = @_;

    my $aa = $self->{argv};
    die "No command" if (!defined $aa);
    my @argv;

    if (ref $aa eq 'CODE')
    {
        @argv = $aa->($self);
    }
    elsif (ref $aa eq 'ARRAY')
    {
        @argv = @$aa;
    }
    else
    {
        die "Unexpected command type";
    }

    map { $_ = $self->{config}->substitute($_); } @argv;

    return @argv;
}

1;
