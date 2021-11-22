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

package Cassandane::MasterEntry;
use strict;
use warnings;

use lib '.';
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
    foreach my $a ('name', 'argv', $self->_otherparams())
    {
        $params->{$a} = $self->{$a}
            if defined $self->{$a};
    }
    return $params;
}

sub set_master_param
{
    my ($self, $param, $value) = @_;

    foreach my $a ('name', 'argv', $self->_otherparams())
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
