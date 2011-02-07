#!/usr/bin/perl

package Cassandane::Message;
use strict;
use warnings;
use overload qw("") => \&as_string;

sub new
{
    my $class = shift;
    my $self = {
	headers => [],
	headers_by_name => {},
	body => undef,
    };

    bless $self, $class;
    return $self;
}

sub _canon_name($)
{
    my ($name) = @_;

    my @cc = split(/-/, lc($name));
    map
    {
	$_ = ucfirst($_);
	$_ = 'ID' if m/^Id$/;
    } @cc;
    return join('-', @cc);
}

sub get_headers
{
    my ($self, $name) = @_;
    $name = lc($name);
    return $self->{headers_by_name}->{$name};
}

sub set_headers
{
    my ($self, $name, @values) = @_;

    $name = lc($name);
    map { $_ = "" . $_ } @values;
    $self->{headers_by_name}->{$name} = \@values;
    my @headers = grep { $_->{name} ne $name } @{$self->{headers}};
    foreach my $v (@values)
    {
	push(@headers, { name => $name, value => "" . $v });
    }
    $self->{headers} = \@headers;
}

sub remove_headers
{
    my ($self, $name) = @_;

    $name = lc($name);
    delete $self->{headers_by_name}->{$name};
    my @headers = grep { $_->{name} ne $name } @{$self->{headers}};
    $self->{headers} = \@headers;
}

sub add_header
{
    my ($self, $name, $value) = @_;

    $value = "" . $value;

    $name = lc($name);
    my $values = $self->{headers_by_name}->{$name} || [];
    push(@$values, $value);
    $self->{headers_by_name}->{$name} = $values;

    push(@{$self->{headers}}, { name => $name, value => $value });
}

sub set_body
{
    my ($self, $text) = @_;
    $self->{body} = $text;
}

sub get_body
{
    my ($self) = @_;
    return $self->{body};
}

sub as_string
{
    my ($self) = @_;
    my $s = '';

    foreach my $h (@{$self->{headers}})
    {
	$s .= _canon_name($h->{name}) . ": " . $h->{value} . "\r\n";
    }
    $s .= "\r\n";
    $s .= $self->{body}
	if defined $self->{body};

    return $s;
}

1;
