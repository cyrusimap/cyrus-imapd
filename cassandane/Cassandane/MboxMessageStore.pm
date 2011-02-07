#!/usr/bin/perl

package Cassandane::MboxMessageStore;
use strict;
use warnings;
use Cassandane::Util::DateTime qw(to_rfc822);

# TODO: isa Cassandane::MessageStore

sub new
{
    my $class = shift;
    my %params = @_;
    my $self = {
	filename => undef,
	fh => undef,
	ourfh => 0,
    };

    $self->{filename} = $params{filename}
	if defined $params{filename};

    bless $self, $class;
    return $self;
}

sub begin
{
    my ($self) = @_;
    if (defined $self->{filename})
    {
	my $fh;
	open $fh,'>>',$self->{filename}
	    or die "Cannot open $self->{filename} for appending: $!";
	$self->{fh} = \$fh;
	$self->{ourfh} = 1;
    }
    else
    {
	$self->{fh} = \*STDOUT;
	$self->{ourfh} = 0;
    }
}

sub message
{
    my ($self, $msg) = @_;
    my $datestr = $msg->get_headers('date')->[0];
    my $fh = $self->{fh};
    print $fh "From - " . $datestr . "\r\n" . $msg;
}

sub end
{
    my ($self) = @_;
    if ($self->{ourfh})
    {
	close $self->{fh};
    }
    $self->{fh} = undef;
}

1;
