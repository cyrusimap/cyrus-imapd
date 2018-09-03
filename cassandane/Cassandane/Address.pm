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
