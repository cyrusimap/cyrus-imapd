# SPDX-License-Identifier: BSD-3-Clause-CMU
# See COPYING file at the root of the distribution for more details.

package Cassandane::MaildirMessageStore;
use strict;
use warnings;
use File::Path qw(mkpath rmtree);

use base qw(Cassandane::MessageStore);

sub new
{
    my ($class, %params) = @_;
    my %bits = (
        directory => delete $params{directory},
        next_uid => 0 + (delete $params{next_uid} || 1),
        uids_to_read => [],
    );
    my $self = $class->SUPER::new(%params);
    map { $self->{$_} = $bits{$_}; } keys %bits;
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
    my ($self) = @_;
    # Nothing to do
}

sub read_begin
{
    my ($self) = @_;

    die "No such directory: $self->{directory}"
        if (defined $self->{directory} && ! -d $self->{directory});

    # Scan the directory for filenames.  We need to read the
    # whole directory and sort the results because the messages
    # need to be returned in uid order not directory order.
    $self->{uids_to_read} = [];
    my @uids;
    my $directory = ($self->{directory} || ".");
    my $fh;
    opendir $fh,$directory
        or die "Cannot open directory $directory for reading: $!";

    while (my $e = readdir $fh)
    {
        my ($uid) = ($e =~ m/^(\d+)\.$/);
        next unless defined $uid;
        push(@uids, 0+$uid);
    }

    @uids = sort { $a <=> $b } @uids;
    $self->{uids_to_read} = \@uids;
    closedir $fh;
}

sub read_message
{
    my ($self) = @_;

    my $directory = ($self->{directory} || ".");
    my $filename;

    for (;;)
    {
        my $uid = shift(@{$self->{uids_to_read}});
        return undef
            unless defined $uid;
        $filename = "$directory/$uid.";
        # keep trying if a message disappeared
        last if ( -f $filename );
    }

    my $fh;
    open $fh,'<',$filename
        or die "Cannot open $filename for reading: $!";
    my $msg = Cassandane::Message->new(fh => $fh);
    close $fh;

    return $msg;
}

sub read_end
{
    my ($self) = @_;

    $self->{uids_to_read} = [];
}

sub remove
{
    my ($self) = @_;

    if (defined $self->{directory})
    {
        my $r = rmtree($self->{directory});
        die "rmtree failed: $!"
            if (!$r && ! $!{ENOENT} );
    }
}

1;
