#!/usr/bin/perl
#
#  Copyright (c) 2011-2017 FastMail Pty Ltd.  All rights reserved.
#
#  Redistribution and use in source and binary forms, with or without
#  modification, are permitted provided that the following conditions
#  are met:
#
#  1. Redistributions of source code must retain the above copyright
#     notice, this list of conditions and the following disclaimer.
#
#  2. Redistributions in binary form must reproduce the above copyright
#     notice, this list of conditions and the following disclaimer in
#     the documentation and/or other materials provided with the
#     distribution.
#
#  3. The name "Fastmail Pty Ltd" must not be used to
#     endorse or promote products derived from this software without
#     prior written permission. For permission or any legal
#     details, please contact
#      FastMail Pty Ltd
#      PO Box 234
#      Collins St West 8007
#      Victoria
#      Australia
#
#  4. Redistributions of any form whatsoever must retain the following
#     acknowledgment:
#     "This product includes software developed by Fastmail Pty. Ltd."
#
#  FASTMAIL PTY LTD DISCLAIMS ALL WARRANTIES WITH REGARD TO THIS SOFTWARE,
#  INCLUDING ALL IMPLIED WARRANTIES OF MERCHANTABILITY  AND FITNESS, IN NO
#  EVENT SHALL OPERA SOFTWARE AUSTRALIA BE LIABLE FOR ANY SPECIAL, INDIRECT
#  OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES WHATSOEVER RESULTING FROM LOSS OF
#  USE, DATA OR PROFITS, WHETHER IN AN ACTION OF CONTRACT, NEGLIGENCE OR OTHER
#  TORTIOUS ACTION, ARISING OUT OF OR IN CONNECTION WITH THE USE OR PERFORMANCE
#  OF THIS SOFTWARE.
#

package Cassandane::MboxMessageStore;
use strict;
use warnings;
use POSIX qw(strftime);

use lib '.';
use base qw(Cassandane::MessageStore);
use Cassandane::Util::DateTime qw(from_rfc822);
use Cassandane::Message;

sub new
{
    my ($class, %params) = @_;
    my %bits = (
        filename => delete $params{filename},
        fh => undef,
        ourfh => 0,
        lineno => undef,
    );
    my $self = $class->SUPER::new(%params);
    map { $self->{$_} = $bits{$_}; } keys %bits;
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
        return Cassandane::Message->new(lines => \@lines)
            if m/^From /;

        push(@lines, $_);
    }

    return undef;
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

1;
