#!/usr/bin/perl

package Cassandane::MboxMessageStore;
use strict;
use warnings;
use Cassandane::Util::DateTime qw(to_rfc822 from_rfc822);
use POSIX qw(strftime);
use Cassandane::Message;

# TODO: isa Cassandane::MessageStore

sub new
{
    my $class = shift;
    my %params = @_;
    my $self = {
	filename => undef,
	fh => undef,
	ourfh => 0,
	lineno => undef,
    };

    $self->{filename} = $params{filename}
	if defined $params{filename};

    bless $self, $class;
    return $self;
}

sub write_begin
{
    my ($self) = @_;
    if (defined $self->{filename})
    {
	my $fh;
	open $fh,'>>',$self->{filename}
	    or die "Cannot open $self->{filename} for appending: $!";
	$self->{fh} = $fh;
	$self->{ourfh} = 1;
    }
    else
    {
	$self->{fh} = \*STDOUT;
	$self->{ourfh} = 0;
    }
}

sub write_message
{
    my ($self, $msg) = @_;
    my $fh = $self->{fh};

    my $from = $msg->get_header('from');
    $from =~ s/^.*<//;
    $from =~ s/>.*$//;

    my $dt = from_rfc822($msg->get_header('date'));
    my $date = 'Mon Dec  1 00:03:08 2008';
    $date = strftime("%a %b %d %T %Y", localtime($dt->epoch))
	if defined $dt;

    printf $fh "From %s %s\r\n%s", $from, $date, $msg;
}

sub write_end
{
    my ($self) = @_;
    if ($self->{ourfh})
    {
	close $self->{fh};
    }
    $self->{fh} = undef;
}

sub read_begin
{
    my ($self) = @_;
    if (defined $self->{filename})
    {
	my $fh;

	if ($self->{filename} =~ m/\.gz$/)
	{
	    open $fh,'-|',('gunzip', '-dc', $self->{filename})
		or die "Cannot gunzip $self->{filename} for reading: $!";
	}
	else
	{
	    open $fh,'<',$self->{filename}
		or die "Cannot open $self->{filename} for reading: $!";
	}
	$self->{fh} = $fh;
	$self->{ourfh} = 1;
    }
    else
    {
	$self->{fh} = \*STDIN;
	$self->{ourfh} = 0;
    }
    $self->{lineno} = 0;
}

sub read_message
{
    my ($self) = @_;
    my @lines;

    my $fh = $self->{fh};
    while (<$fh>)
    {
	$self->{lineno}++;

	if ($self->{lineno} == 1)
	{
	    die "Bad mbox format - missing From line"
		unless m/^From /;
	    next;
	}
	last if m/^From /;

	push(@lines, $_);
    }

    return Cassandane::Message->new(lines => \@lines);
}

sub read_end
{
    my ($self) = @_;
    if ($self->{ourfh})
    {
	close $self->{fh};
    }
    $self->{fh} = undef;
    $self->{lineno} = undef;
}

sub remove
{
    my ($self) = @_;

    if (defined $self->{filename})
    {
	my $r = unlink($self->{filename});
	die "unlink failed: $!"
	    if (!$r && ! $!{ENOENT} );
    }
}

sub get_client
{
    my ($self) = @_;

    die "No client object for Mbox";
}

1;
