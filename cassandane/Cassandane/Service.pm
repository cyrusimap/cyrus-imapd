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

package Cassandane::Service;
use strict;
use warnings;
use base qw(Cassandane::MasterEntry);
use Cassandane::Util::Log;
use Cassandane::MessageStoreFactory;

my $base_port;
my $max_ports = 10;
my $next_port = 0;
my %port_allocated;
sub alloc_port
{
    if (!defined $base_port)
    {
	my $workerid = $ENV{TEST_UNIT_WORKER_ID} || '1';
	die "Invalid TEST_UNIT_WORKER_ID - code not run in Worker context"
	    if (defined($workerid) && $workerid eq 'invalid');
	$base_port = 9100 + $max_ports * ($workerid-1);
    }
    for (my $i = 0 ; $i < $max_ports ; $i++)
    {
	my $port = $base_port + (($next_port + $i) % $max_ports);
	if (!$port_allocated{$port})
	{
	    $port_allocated{$port} = 1;
	    $next_port++;
	    return $port;
	}
    }
    die "No ports remaining";
}

sub free_port
{
    my ($port) = @_;
    return if ($port =~ m/^\//);
    $port_allocated{$port} = 0;
}

sub new
{
    my ($class, %params) = @_;

    my $host = '127.0.0.1';
    $host = delete $params{host}
	if (exists $params{host});
    my $port = delete $params{port};
    my $type = delete $params{type} || 'unknown';

    my $self = $class->SUPER::new(%params);

    $self->{host} = $host;
    $self->{port} = $port;
    $self->{type} = $type;

    return $self;
}

sub DESTROY
{
    my ($self) = @_;
    free_port($self->{port}) if defined $self->{port};
}

sub _otherparams
{
    my ($self) = @_;
    return ( qw(prefork maxchild maxforkrate maxfds proto babysit) );
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

    if (defined $self->{port} &&
	defined $self->{config})
    {
	# expand @basedir@ et al
	$self->{port} = $self->{config}->substitute($self->{port});
    }

    $self->{port} ||= alloc_port();
    return $self->{port};
}

# Return a hash of parameters suitable for passing
# to MessageStoreFactory::create.
sub store_params
{
    my ($self, %params) = @_;

    $params{type} ||= $self->{type};
    $params{address_family} = $self->{address_family};
    $params{host} = $self->host();
    $params{port} = $self->port();
    $params{username} ||= 'cassandane';
    $params{password} ||= 'testpw';
    $params{verbose} ||= get_verbose();
    return \%params;
}

sub create_store
{
    my ($self, @args) = @_;
    my $params = $self->store_params(@args);
    return Cassandane::MessageStoreFactory->create(%$params);
}

# Return a hash of key,value pairs which need to go into the line in the
# cyrus master config file.
sub master_params
{
    my ($self) = @_;
    my $params = $self->SUPER::master_params();
    $params->{listen} = $self->address();
    return $params;
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

my %netstat_match = (
    #     # netstat -ln -Ainet
    #     Active Internet connections (only servers)
    #     Proto Recv-Q Send-Q Local Address           Foreign Address State
    #     tcp        0      0 0.0.0.0:56686           0.0.0.0:* LISTEN
    inet => sub
    {
	my ($self, $line) = @_;

	my @a = split(/\s+/, $line);
	return 0 unless scalar(@a) == 6;
	return 0 unless $a[0] eq 'tcp';
	return 0 unless $a[5] eq 'LISTEN';
	my $host = $self->{host} || '0.0.0.0';
	return 0 unless $a[3] eq "$host:$self->{port}";
	return 1;
    },

    #  # netstat -ln -Ainet6
    #  Active Internet connections (only servers)
    #  Proto Recv-Q Send-Q Local Address           Foreign Address         State
    #  tcp6       0      0 :::22                   :::*                    LISTEN
    inet6 => sub
    {
	my ($self, $line) = @_;

	my @a = split(/\s+/, $line);
	return 0 unless scalar(@a) == 6;
	return 0 unless $a[0] eq 'tcp6';
	return 0 unless $a[5] eq 'LISTEN';
	# Note that we don't use $self->address() because it formats
	# the address in Cyrus format which is different to what netstat
	# reports, in the IPv6 case.
	my $host = $self->{host} || '::';
	return 0 unless $a[3] eq "$host:$self->{port}";
	return 1;
    },

    #  # netstat -ln -Aunix
    #  Active UNIX domain sockets (only servers)
    #  Proto RefCnt Flags       Type       State         I-Node   Path
    #  unix  2      [ ACC ]     STREAM     LISTENING     7941     /var/run/dbus/system_bus_socket
    unix => sub
    {
	my ($self, $line) = @_;

	# Compress the Flags field to eliminate spaces and make split()
	# return a predictable number of fields.
	$line =~ s/\[[^]]*\]/[]/;

	my @a = split(/\s+/, $line);
	return 0 unless scalar(@a) == 7;
	return 0 unless $a[0] eq 'unix';
	return 0 unless $a[4] eq 'LISTENING';
	return 0 unless $a[6] eq $self->{port};
	return 1;
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

sub is_listening
{
    my ($self) = @_;

    my $af = $self->address_family();

    my @cmd = (
	'netstat',
	'-l',		# listening ports only
	'-n',		# numeric output
	"-A$af",
	);

    my $matcher = $netstat_match{$af};
    my $found;
    open NETSTAT,'-|',@cmd
	or die "Cannot run netstat to check for service: $!";

    while (<NETSTAT>)
    {
	chomp;
	next unless $self->$matcher($_);
	$found = 1;
	last;
    }
    close NETSTAT;

    xlog "is_listening: service $self->{name} is " .
	 "listening on " . $self->address()
	if ($found);

    return $found;
}

sub describe
{
    my ($self) = @_;

    printf "%s listening on %s\n",
	    $self->{name},
	    $self->address();
}


1;
