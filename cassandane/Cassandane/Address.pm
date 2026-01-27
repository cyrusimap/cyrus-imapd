# SPDX-License-Identifier: BSD-3-Clause-CMU
# See COPYING file at the root of the distribution for more details.

package Cassandane::Address;
use strict;
use warnings;
use overload qw("") => \&as_string;

sub new
{
    my $class = shift;
    my %params = @_;
    my $self = {
        name => undef,
        localpart => undef,
        domain => undef,
    };

    $self->{name} = $params{name}
        if defined $params{name};
    $self->{localpart} = $params{localpart}
        if defined $params{localpart};
    $self->{domain} = $params{domain}
        if defined $params{domain};

    bless $self, $class;
    return $self;
}

sub name
{
    my ($self) = @_;
    return $self->{name};
}

sub localpart
{
    my ($self) = @_;
    return ($self->{localpart} || 'unknown-user');
}

sub domain
{
    my ($self) = @_;
    return ($self->{domain} || 'unspecified-domain');
}

sub address
{
    my ($self) = @_;
    return $self->localpart() . '@' . $self->domain();
}

sub as_string
{
    my ($self) = @_;
    my $s = '';
    $s .= $self->{name} . ' '
        if defined $self->{name};
    $s .= '<' . $self->address() . '>';
    return $s;
}


1;
