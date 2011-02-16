#!/usr/bin/perl

package Cassandane::Config;
use strict;
use warnings;

my $default;

sub new
{
    my $class = shift;
    my $self = {
	parent => undef,
	params => { @_ },
    };

    bless $self, $class;
    return $self;
}

sub default
{
    $default = Cassandane::Config->new()
	unless defined $default;
    return $default;
}

sub clone
{
    my ($self) = @_;

    my $child = Cassandane::Config->new();
    $child->{parent} = $self;
    return $child;
}

sub set
{
    my ($self, %nv) = @_;
    while (my ($n, $v) = each %nv)
    {
	if (defined $v)
	{
	    $self->{params}->{$n} = $v;
	}
	else
	{
	    delete $self->{params}->{$n};
	}
    }
}

sub get
{
    my ($self, $n) = @_;
    while (defined $self)
    {
	my $v = $self->{params}->{$n};
	return $v
	    if defined $v;
	$self = $self->{parent};
    }
    return undef;
}

sub _flatten
{
    my ($self) = @_;
    my %nv;
    while (defined $self)
    {
	while (my ($n, $v) = each %{$self->{params}})
	{
	    $nv{$n} = $v
		unless defined $nv{$n};
	}
	$self = $self->{parent};
    }
    return \%nv;
}

sub generate
{
    my ($self, $filename) = @_;
    my $nv = $self->_flatten();

    open CONF,'>',$filename
	or die "Cannot open $filename for writing: $!";
    while (my ($n, $v) = each %$nv)
    {
	print CONF "$n: $v\n";
    }
    close CONF;
}

1;
