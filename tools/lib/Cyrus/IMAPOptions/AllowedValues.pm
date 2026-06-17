# SPDX-License-Identifier: BSD-3-Clause-CMU
# See COPYING file at the root of the distribution for more details.
package Cyrus::IMAPOptions::AllowedValues;
use experimental 'signatures';
use Moo;

use Types::Standard qw(ArrayRef HashRef Maybe Str Undef);

has _order => (
    isa => ArrayRef[Str],
    is => 'ro',
    required => 1,
);

has _values => (
    isa => HashRef[Maybe[ArrayRef[Str]]],
    is => 'ro',
    required => 1,
);

has _aliases => (
    isa => HashRef[Undef],
    is => 'ro',
    predicate => 'has_aliases',
);

around BUILDARGS => sub ($orig, $class, @args)
{
    my $args = $class->$orig(@args);

    if (my $str = delete $args->{from_string}) {
        _from_string($args, $str);
    }

    return $args;
};

sub _from_string ($args, $str)
{
    my @raw = split qr/\s+/, $str;

    my @order;
    my %values;
    my %aliases;

    foreach my $r (@raw) {
        my ($v, @a) = split qr/=/, $r;

        die "'$v' defined twice"
            if exists $values{$v} or exists $aliases{$v};

        push @order, $v;

        if (@a) {
            $values{$v} = [ @a ];

            # not '$a' because that evades strict vars protections
            foreach my $x (@a) {
                die "'$x' defined twice"
                    if exists $values{$x} or exists $aliases{$x};
                $aliases{$x} = undef;
            }
        }
        else {
            $values{$v} = undef;
        }
    }

    $args->{_order} = \@order;
    $args->{_values} = \%values;
    $args->{_aliases} = \%aliases if %aliases;
}

sub values ($self)
{
    return $self->_order->@*;
}

sub values_and_aliases ($self)
{
    my @tuples;

    foreach my $value ($self->_order->@*) {
        push @tuples, [ $value, $self->_values->{$value} ];
    }

    return @tuples;
}

sub values_and_aliases_flat ($self)
{
    my @flat;

    foreach my $value ($self->_order->@*) {
        push @flat, $value;
        push @flat, $self->_values->{$value}->@*
            if $self->_values->{$value};
    }

    return @flat;
}

sub value_alias_strings ($self)
{
    my @strings;

    foreach my $value ($self->_order->@*) {
        my @aliases = @{$self->_values->{$value} || []};

        push @strings, join '=', $value, @aliases;
    }

    return @strings;
}

sub count ($self)
{
    my $count = keys $self->_values->%*;
    $count += keys $self->_aliases->%* if $self->has_aliases;

    return $count;
}

sub allows ($self, $value)
{
    return exists $self->_values->{$value}
           || ($self->has_aliases && exists $self->_aliases->{$value});
}

1;
