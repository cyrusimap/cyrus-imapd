#!/usr/bin/perl
#
#  Copyright (c) 2011 Opera Software Australia Pty. Ltd.  All rights
#  reserved.
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
#  3. The name "Opera Software Australia" must not be used to
#     endorse or promote products derived from this software without
#     prior written permission. For permission or any legal
#     details, please contact
# 	Opera Software Australia Pty. Ltd.
# 	Level 50, 120 Collins St
# 	Melbourne 3000
# 	Victoria
# 	Australia
#
#  4. Redistributions of any form whatsoever must retain the following
#     acknowledgment:
#     "This product includes software developed by Opera Software
#     Australia Pty. Ltd."
#
#  OPERA SOFTWARE AUSTRALIA DISCLAIMS ALL WARRANTIES WITH REGARD TO
#  THIS SOFTWARE, INCLUDING ALL IMPLIED WARRANTIES OF MERCHANTABILITY
#  AND FITNESS, IN NO EVENT SHALL OPERA SOFTWARE AUSTRALIA BE LIABLE
#  FOR ANY SPECIAL, INDIRECT OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES
#  WHATSOEVER RESULTING FROM LOSS OF USE, DATA OR PROFITS, WHETHER IN
#  AN ACTION OF CONTRACT, NEGLIGENCE OR OTHER TORTIOUS ACTION, ARISING
#  OUT OF OR IN CONNECTION WITH THE USE OR PERFORMANCE OF THIS SOFTWARE.
#

package Cassandane::POP3MessageStore;
use strict;
use warnings;
use Net::POP3;
use Cassandane::Util::Log;
# use Cassandane::Util::DateTime qw(to_rfc822);
# use Data::Dumper;

# TODO: isa Cassandane::MessageStore

sub new
{
    my $class = shift;
    my %params = @_;
    my $self = {
	host => 'localhost',
	port => 110,
	folder => 'INBOX',
	username => undef,
	password => undef,
	verbose => 0,
	client => undef,
	# state for streaming read
	next_id => undef,
	last_id => undef,
    };

    $self->{host} = $params{host}
	if defined $params{host};
    $self->{port} = 0 + $params{port}
	if defined $params{port};
    $self->{folder} = $params{folder}
	if defined $params{folder};
    $self->{username} = $params{username}
	if defined $params{username};
    $self->{password} = $params{password}
	if defined $params{password};
    $self->{verbose} = 0 + $params{verbose}
	if defined $params{verbose};

    bless $self, $class;
    return $self;
}

sub _connect
{
    my ($self) = @_;

    # if already successfully connected, do nothing
    return
	if (defined $self->{client});

    # xlog "_connect: creating POP3 object";
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
    # xlog "_connect: pop3_username=\"$pop3_username\"", ;
    # xlog "_connect: password=\"" . $self->{password} . "\"";

    my $res = $client->login($pop3_username, $self->{password})
	or die "Cannot login via POP3";
    $res = 0 if ($res eq '0E0');
    $res = 0 + $res;

    # xlog "_connect: found $res messages";

    $self->{last_id} = $res;
    $self->{client} = $client;
}

sub _disconnect
{
    my ($self) = @_;

    $self->{client}->quit();
    $self->{client} = undef;
}

sub write_begin
{
    my ($self) = @_;

    die "cannot write messages to POP3 server";
}

sub write_message
{
    my ($self, $msg) = @_;

    die "cannot write messages to POP3 server";
}

sub write_end
{
    my ($self) = @_;

    die "cannot write messages to POP3 server";
}

sub read_begin
{
    my ($self) = @_;
    my $r;

    $self->_connect();
    $self->{next_id} = 1;
}

sub read_message
{
    my ($self, $msg) = @_;

    my $id = $self->{next_id};
    return undef
	if ($id > $self->{last_id});
    $self->{next_id}++;

    return Cassandane::Message->new(fh => $self->{client}->getfh($id));
}

sub read_end
{
    my ($self) = @_;

    $self->_disconnect();
    $self->{next_id} = undef;
}

sub remove
{
    my ($self) = @_;

    die "cannot remove folder with POP3 server";
}

sub get_client
{
    my ($self) = @_;

    $self->_connect();
    return $self->{client};
}

1;
