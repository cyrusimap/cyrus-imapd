# SPDX-License-Identifier: BSD-3-Clause-CMU
# See COPYING file at the root of the distribution for more details.

package Cassandane::MasterEntry;
use strict;
use warnings;

use Cassandane::Util::Log;

my $next_tag = 1;

sub new
{
    my ($class, %params) = @_;

    my $name = delete $params{name};
    if (!defined $name)
    {
        $name = "xx$next_tag";
        $next_tag++;
    }

    my $argv = delete $params{argv};
    die "No argv= parameter"
        unless defined $argv && scalar @$argv;

    my $config = delete $params{config};

    my $self = bless
    {
        name => $name,
        argv => $argv,
        config => $config,
    }, $class;

    foreach my $a ($self->_otherparams())
    {
        $self->{$a} = delete $params{$a}
            if defined $params{$a};
    }
    die "Unexpected parameters: " . join(" ", keys %params)
        if scalar %params;

    return $self;
}

# Return a hash of key,value pairs which need to go into the line in the
# cyrus master config file.
sub master_params
{
    my ($self) = @_;
    my $params = {};
    foreach my $a ('name', 'argv', 'config', $self->_otherparams())
    {
        $params->{$a} = $self->{$a}
            if defined $self->{$a};
    }
    return $params;
}

sub set_master_param
{
    my ($self, $param, $value) = @_;

    foreach my $a ('name', 'argv', 'config', $self->_otherparams())
    {
        $self->{$a} = $value
            if ($a eq $param);
    }
}

sub set_config
{
    my ($self, $config) = @_;
    $self->{config} = $config;
}

1;
