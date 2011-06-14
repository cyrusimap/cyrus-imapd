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
use Cassandane::Util::Log;
use Cassandane::MessageStoreFactory;

my @otherparams = qw(prefork maxchild maxforkrate maxfds proto babysit);

my $next_port = 9100;
sub alloc_port
{
    my ($class) = @_;

    my $port = $next_port;
    $next_port++;
    return $port;
}

sub new
{
    my $class = shift;
    my $name = shift;
    my %params = @_;

    die "No name specified"
	unless defined $name;

    my $self =
    {
	name => $name,
	host => '127.0.0.1',
	port => undef,
	argv => [],
    };

    $self->{host} = $params{host}
	if defined $params{host};
    $self->{port} = $params{port}
	if defined $params{port};
    $self->{argv} = $params{argv}
	if defined $params{argv};
    foreach my $a (@otherparams)
    {
	$self->{$a} = $params{$a}
	    if defined $params{$a};
    }

    $self->{port} = Cassandane::Service->alloc_port()
	unless defined $self->{port};
    die "No binary specified"
	unless defined $self->{argv} && scalar @{$self->{argv}};

    bless $self, $class;
    return $self;
}

# Return a hash of parameters suitable for passing
# to MessageStoreFactory::create.
sub store_params
{
    my ($self, %params) = @_;

    $params{type} = 'unknown'
	unless defined $params{type};
    $params{host} = $self->{host};
    $params{port} = $self->{port};
    $params{verbose} = get_verbose
	unless defined $params{verbose};
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
    my %params = (
	cmd => $self->{argv},
	listen => $self->address(),
    );
    foreach my $a (@otherparams)
    {
	$params{$a} = $self->{$a}
	    if defined $self->{$a};
    }
    return \%params;
}

sub address
{
    my ($self) = @_;
    if ($self->{port} =~ m/^\d+$/)
    {
	return "$self->{host}:$self->{port}";
    }
    else
    {
	return $self->{port};
    }
}

sub is_listening
{
    my ($self) = @_;

    # hardcoded for TCP4
    die "Sorry, the host argument \"$self->{host}\" must be a numeric IP address"
	unless ($self->{host} =~ m/^\d+\.\d+\.\d+\.\d+$/);
    die "Sorry, the port argument \"$self->{port}\" must be a numeric TCP port or unix path"
	unless ($self->{port} =~ m/^\d+$/ or $self->{port} =~ m{^/});

    my @cmd = (
	'netstat',
	'-l',		# listening ports only
	'-n',		# numeric output
	'-Ainet',	# AF_INET only
	);

    my $found;
    if ($self->{port} =~ m/^\d+$/) {
	open NETSTAT,'-|',@cmd
	    or die "Cannot run netstat to check for port $self->{port}: $!";
	#     # netstat -ln -Ainet
	#     Active Internet connections (only servers)
	#     Proto Recv-Q Send-Q Local Address           Foreign Address State
	#     tcp        0      0 0.0.0.0:56686           0.0.0.0:* LISTEN
	while (<NETSTAT>)
	{
	    chomp;
	    my @a = split;
	    next unless scalar(@a) == 6;
	    next unless $a[0] eq 'tcp';
	    next unless $a[5] eq 'LISTEN';
	    next unless $a[3] eq $self->address();
	    $found = 1;
	    last;
	}
	close NETSTAT;
    }

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
