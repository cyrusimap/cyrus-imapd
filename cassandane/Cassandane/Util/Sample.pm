# SPDX-License-Identifier: BSD-3-Clause-CMU
# See COPYING file at the root of the distribution for more details.

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
