# SPDX-License-Identifier: BSD-3-Clause-CMU
# See COPYING file at the root of the distribution for more details.

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
