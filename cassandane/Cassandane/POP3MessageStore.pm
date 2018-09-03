#!/usr/bin/perl
#
#  Copyright (c) 2011-2017 FastMail Pty Ltd. All rights reserved.
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

package Cassandane::POP3MessageStore;
use strict;
use warnings;
use Net::POP3;

use lib '.';
use base qw(Cassandane::MessageStore);
use Cassandane::Util::Log;

sub new
{
    my ($class, %params) = @_;
    my %bits = (
        host => delete $params{host} || 'localhost',
        port => 0 + (delete $params{port} || 110),
        folder => delete $params{folder} || 'INBOX',
        username => delete $params{username},
        password => delete $params{password},
        client => undef,
        # state for streaming read
        next_id => undef,
        last_id => undef,
    );

    # Sadly, it seems the version of Net::POP3 I'm using has
    # neither support for specifying inet6 nor a way of passing
    # an already connected socket.  So, no IPv6 for us.
    my $af = delete $params{address_family};
    die "Sorry, only INET supported for POP3"
        if (defined $af && $af ne 'inet');

    my $self = $class->SUPER::new(%params);
    map { $self->{$_} = $bits{$_}; } keys %bits;
    return $self;
}

sub connect
{
    my ($self) = @_;

    # if already successfully connected, do nothing
    return
        if (defined $self->{client});

    # xlog "connect: creating POP3 object";
    my %opts;
    $opts{Debug} = $self->{verbose}
        if $self->{verbose};
    my $client = Net::POP3->new("$self->{host}:$self->{port}", %opts)
        or die "Cannot create Net::POP3 object";

    my ($uu, $ud) = split(/@/, $self->{username});

    $ud = (defined $ud ? "\@$ud" : "");

    my $ff = $self->{folder};
    if ($ff =~ m/^inbox$/i)
    {
        $ff = '';
    }
    elsif ($ff =~ m/^inbox\./i)
    {
        $ff =~ s/^inbox\./+/i;
    }
    else
    {
        $ff = "+$ff";
    }

    my $pop3_username = "$uu$ff$ud";
    # xlog "connect: pop3_username=\"$pop3_username\"", ;
    # xlog "connect: password=\"" . $self->{password} . "\"";

    my $res = $client->login($pop3_username, $self->{password})
        or die "Cannot login via POP3";
    $res = 0 if ($res eq '0E0');
    $res = 0 + $res;

    xlog "connect: found $res messages";

    $self->{last_id} = $res;
    $self->{client} = $client;
}

sub disconnect
{
    my ($self) = @_;

    if (defined $self->{client})
    {
        $self->{client}->quit();
        $self->{client} = undef;
    }
}

sub read_begin
{
    my ($self) = @_;

    $self->connect();
    $self->{next_id} = 1;
}

sub read_message
{
    my ($self) = @_;

    my $id = $self->{next_id};
    return undef
        if ($id > $self->{last_id});
    $self->{next_id}++;

    return Cassandane::Message->new(fh => $self->{client}->getfh($id));
}

sub read_end
{
    my ($self) = @_;

    $self->disconnect();
    $self->{next_id} = undef;
}

sub get_client
{
    my ($self) = @_;

    $self->connect();
    return $self->{client};
}

1;
