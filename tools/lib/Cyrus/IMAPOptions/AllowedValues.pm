# SPDX-License-Identifier: BSD-3-Clause-CMU
# See COPYING file at the root of the distribution for more details.
package Cyrus::IMAPOptions::AllowedValues;
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

around BUILDARGS => sub
{
    my ($orig, $class, @args) = @_;

    my $args = $class->$orig(@args);

    if (my $str = delete $args->{from_string}) {
        _from_string($args, $str);
    }

    return $args;
};

sub _from_string
{
    my ($args, $str) = @_;

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

            foreach my $a (@a) {
                die "'$a' defined twice"
                    if exists $values{$a} or exists $aliases{$a};
                $aliases{$a} = undef;
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

sub values
{
    return shift->_order->@*;
}

sub values_and_aliases
{
    my ($self) = @_;

    my @tuples;

    foreach my $value ($self->_order->@*) {
        push @tuples, [ $value, $self->_values->{$value} ];
    }

    return @tuples;
}

sub value_alias_strings
{
    my ($self) = @_;

    my @strings;

    foreach my $value ($self->_order->@*) {
        # XXX postfix deref?
        my @aliases = @{$self->_values->{$value} || []};

        push @strings, join '=', $value, @aliases;
    }

    return @strings;
}

sub count
{
    my ($self) = @_;

    my $count = keys $self->_values->%*;
    $count += keys $self->_aliases->%* if $self->has_aliases;

    return $count;
}

sub allows
{
    my ($self, $value) = @_;

    return exists $self->_values->{$value}
           || ($self->has_aliases && exists $self->_aliases->{$value});
}

1;
