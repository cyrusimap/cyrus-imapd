#!/usr/bin/perl

package Cassandane::MaildirMessageStore;
use strict;
use warnings;
use File::Path qw(mkpath);
use Cassandane::Util::DateTime qw(to_rfc822);

# TODO: isa Cassandane::MessageStore

sub new
{
    my $class = shift;
    my %params = @_;
    my $self = {
	directory => undef,
	next_uid => 1,
    };

    $self->{directory} = $params{directory}
	if defined $params{directory};
    $self->{next_uid} = $params{next_uid}
	if defined $params{next_uid};

    bless $self, $class;
    return $self;
}

sub write_begin
{
    my ($self) = @_;

    if (defined $self->{directory} && ! -d $self->{directory})
    {
	mkpath($self->{directory})
	    or die "Couldn't make path $self->{directory}";
    }
}

sub write_message
{
    my ($self, $msg) = @_;

    # find a filename which doesn't exist -- we're appending
    my $directory = ($self->{directory} || ".");
    my $filename;
    for (;;)
    {
	my $uid = $self->{next_uid};
	$self->{next_uid} = $self->{next_uid} + 1;
	$filename = "$directory/$uid.";
	last unless ( -f $filename );
    }

    my $fh;
    open $fh,'>',$filename
	or die "Cannot open $filename for writing: $!";
    print $fh $msg;
    close $fh;
}

sub write_end
{
}

1;
