#!/usr/bin/perl
#
#  Copyright (c) 2011-2017 FastMail Pty Ltd.  All rights reserved.
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

package Cassandane::Service;
use strict;
use warnings;

use base qw(Cassandane::MasterEntry);
use Cassandane::GenericListener;
use Cassandane::Util::Log;
use Cassandane::MessageStoreFactory;
use Cassandane::Util::Socket;

sub new
{
    my ($class, %params) = @_;

    my $host = '127.0.0.1';
    $host = delete $params{host}
        if (exists $params{host});
    my $port = delete $params{port};
    my $type = delete $params{type} || 'unknown';
    my $instance = delete $params{instance};

    my $self = $class->SUPER::new(%params);

    # GenericListener is a bit different from MasterEntry et al, and must
    # always have a config specified, so pass through the default explicitly
    my $listener_config = $params{config} || $instance->{config};

    $self->{_listener} = Cassandane::GenericListener->new(
                            name => $params{name},
                            host => $host,
                            port => $port,
                            config => $listener_config);
    $self->{type} = $type;

    return $self;
}

sub _otherparams
{
    my ($self) = @_;
    return ( qw(prefork maxchild maxforkrate maxfds proto babysit) );
}

sub set_config
{
    my ($self, $config) = @_;
    $self->SUPER::set_config($config);
    $self->{_listener}->set_config($config);
}

# Return the host
sub host
{
    my ($self) = @_;
    return $self->{_listener}->host();
}

# Return the port
sub port
{
    my ($self) = @_;
    return $self->{_listener}->port();
}

sub set_port
{
    my ($self, $port) = @_;
    return $self->{_listener}->set_port($port);
}

sub is_ssl
{
    my ($self) = @_;

    # assume '-s' service argument indicates SSL and its absense
    # indicates plaintext
    return scalar grep { $_ eq '-s' } @{$self->{argv}};
}

# Return a hash of parameters suitable for passing
# to MessageStoreFactory::create.
sub store_params
{
    my ($self, %params) = @_;

    my $pp = $self->{_listener}->connection_params(%params);
    $pp->{type} ||= $self->{type};
    $pp->{username} ||= 'cassandane';
    $pp->{password} ||= 'testpw';
    return $pp;
}

sub create_store
{
    my ($self, @args) = @_;
    my $params = $self->store_params(@args);
    return Cassandane::MessageStoreFactory->create(%$params);
}

sub get_socket {
    my ($self) = @_;
    return create_client_socket(
        $self->address_family(),
        $self->host(),
        $self->port()
    );
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
    return $self->{_listener}->address();
}

sub address_family
{
    my ($self) = @_;
    return $self->{_listener}->address_family();
}

sub is_listening
{
    my ($self) = @_;
    return $self->{_listener}->is_listening();
}

sub describe
{
    my ($self) = @_;
    $self->{_listener}->describe();
}


1;
