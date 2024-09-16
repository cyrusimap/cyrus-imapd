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

package Cassandane::Util::Sample;
use strict;
use warnings;
use overload qw("") => \&as_string;

sub new
{
    my ($class, @args) = @_;

    die "Unknown extra arguments"
        if scalar(@args);

    my $self =
    {
        _total => 0.0,
        _total2 => 0.0,
        _n => 0,
        _min => undef,
        _max => undef,
    };
    return bless($self, $class);
}

sub add
{
    my ($self, $x) = @_;

    $self->{_total} += $x;
    $self->{_total2} += $x * $x;
    $self->{_n}++;
    $self->{_min} = $x
        if (!defined $self->{_min} || $x < $self->{_min});
    $self->{_max} = $x
        if (!defined $self->{_max} || $x > $self->{_max});
}

sub nsamples
{
    my ($self) = @_;
    return $self->{_n};
}

sub average
{
    my ($self) = @_;
    die "No samples yet" if (!$self->{_n});
    return $self->{_total} / $self->{_n};
}

sub minimum
{
    my ($self) = @_;
    die "No samples yet" if (!$self->{_n});
    return $self->{_min};
}

sub maximum
{
    my ($self) = @_;
    die "No samples yet" if (!$self->{_n});
    return $self->{_max};
}

sub sample_deviation
{
    my ($self) = @_;
    die "No samples yet" if ($self->{_n} < 2);
    return sqrt(
        ($self->{_n} * $self->{_total2} - $self->{_total} * $self->{_total})
        /
        ($self->{_n} * ($self->{_n} - 1))
    );
}

sub as_string
{
    my ($self) = @_;
    my $s = "no samples";
    if ($self->{_n} > 0)
    {
        $s = "count " . $self->nsamples() .
             " minimum " . $self->minimum() .
             " maximum " . $self->maximum() .
             " average " . $self->average();
        if ($self->{_n} > 1)
        {
            $s .= " sample_deviation " . $self->sample_deviation();
        }
    }
    return $s;
}

1;
