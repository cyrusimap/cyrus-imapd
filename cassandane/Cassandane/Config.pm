#!/usr/bin/perl

package Cassandane::Config;
use strict;
use warnings;
use Cassandane::Util::Log;

my $default;

sub new
{
    my $class = shift;
    my $self = {
	parent => undef,
	variables => {},
	params => { @_ },
    };

    bless $self, $class;
    return $self;
}

sub default
{
    $default = Cassandane::Config->new(
	    configdirectory => '@basedir@/conf',
	    syslog_prefix => '@name@',
	    sievedir => '@basedir@/conf/sieve',
	    defaultpartition => 'default',
	    'partition-default' => '@basedir@/data',
	    sasl_mech_list => 'PLAIN LOGIN DIGEST-MD5',
	    allowplaintext => 'yes',
	    sasl_pwcheck_method => 'alwaystrue',
	)
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

sub set_variables
{
    my ($self, %nv) = @_;
    while (my ($n, $v) = each %nv)
    {
	$self->{variables}->{$n} = $v;
    }
}

sub _get_variable
{
    my ($self, $n) = @_;
    $n =~ s/@//g;
    while (defined $self)
    {
	my $v = $self->{variables}->{$n};
	return $v if defined $v;
	$self = $self->{parent};
    }
    die "Variable $n not defined";
}

sub _substitute
{
    my ($self, $s) = @_;

    my $r = '';
    while (defined $s)
    {
	my ($pre, $ref, $post) = ($s =~ m/(.*)(@[a-z]+@)(.*)/);
	if (defined $ref)
	{
	    $r .= $pre . $self->_get_variable($ref);
	    $s = $post;
	}
	else
	{
	    $r .= $s;
	    last;
	}
    }
    return $r;
}

sub _flatten
{
    my ($self) = @_;
    my %nv;
    for (my $conf = $self ; defined $conf ; $conf = $conf->{parent})
    {
	while (my ($n, $v) = each %{$conf->{params}})
	{
	    $nv{$n} = $self->_substitute($v)
		unless defined $nv{$n};
	}
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
