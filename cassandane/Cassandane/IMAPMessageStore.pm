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

package Cassandane::IMAPMessageStore;
use strict;
use warnings;
use Mail::IMAPTalk;
use Cwd qw(abs_path);

# runtime dependency of Mail::IMAPTalk. make sure we have it!
require IO::Socket::SSL;

use lib '.';
use base qw(Cassandane::MessageStore);
use Cassandane::Util::Log;
use Cassandane::Util::DateTime qw(to_rfc822);
use Cassandane::Util::Socket;

our $BATCHSIZE = 10;

sub new
{
    my ($class, %params) = @_;
    my %bits = (
        address_family => delete $params{address_family} || 'inet',
        host => delete $params{host} || 'localhost',
        port => 0 + (delete $params{port} || 143),
        folder => delete $params{folder} || 'INBOX',
        username => delete $params{username},
        password => delete $params{password},
        client => undef,
        banner => undef,
        # state for streaming read
        next_uid => undef,
        last_uid => undef,
        last_batch_uid => undef,
        batch => undef,
        fetch_attrs => { uid => 1, 'body.peek[]' => 1 },
        # state for XCONVFETCH
        fetched => undef,
        ssl => delete $params{ssl} || 0,
    );
    my $self = $class->SUPER::new(%params);
    map { $self->{$_} = $bits{$_}; } keys %bits;
    return $self;
}

sub connect
{
    my ($self) = @_;

    # if already successfully connected, do nothing
    return
        if (defined $self->{client} &&
            ($self->{client}->state() == Mail::IMAPTalk::Authenticated ||
             $self->{client}->state() == Mail::IMAPTalk::Selected));

    $self->disconnect();

    my $client;

    if ($self->{ssl}) {
        my $ca_file = abs_path("data/certs/cacert.pem");
        $client = Mail::IMAPTalk->new(
                      Server => $self->{host},
                      Port => $self->{port},
                      UseSSL => $self->{ssl},
                      SSL_ca_file => $ca_file,
                      UseBlocking => 1,  # must be blocking for SSL
                      Pedantic => 1,
                      PreserveINBOX => 1,
                      Uid => 0,
                  )
            or die "Cannot connect to server: $@";
    }
    else {
        my $sock = create_client_socket(
                        $self->{address_family},
                        $self->{host}, $self->{port})
            or die "Cannot create client socket: $@";

        $client = Mail::IMAPTalk->new(
                      Socket => $sock,
                      Pedantic => 1,
                      PreserveINBOX => 1,
                      Uid => 0,
                  )
            or die "Cannot connect to server: $@";
    }

    $client->set_tracing(1)
        if $self->{verbose};

    my $banner = $client->get_response_code('remainder');
    $client->login($self->{username}, $self->{password})
        or die "Cannot login to server \"$self->{host}:$self->{port}\": $@";

    # Make Mail::IMAPTalk just stfu
    $client->set_unicode_folders(1);

    $client->parse_mode(Envelope => 1);

    $self->{client} = $client;
    $self->{banner} = $banner;
}

sub disconnect
{
    my ($self) = @_;

    # We don't care if the LOGOUT fails.  Really.
    eval
    {
        local $SIG{__DIE__};
        $self->{client}->logout()
            if defined $self->{client};
    };
    $self->{client} = undef;
}

sub _select
{
    my ($self) = @_;

    if ($self->{client}->state() == Mail::IMAPTalk::Selected)
    {
        $self->{client}->unselect()
            or die "Cannot unselect: $@";
    }
    return $self->{client}->select($self->{folder});
}

sub write_begin
{
    my ($self) = @_;
    my $r;

    $self->connect();

    $r = $self->_select();
    if (!defined $r)
    {
        die "Cannot select folder \"$self->{folder}\": $@"
            unless $self->{client}->get_last_error() =~ m/does not exist/;
        $self->{client}->create($self->{folder})
            or die "Cannot create folder \"$self->{folder}\": $@"
    }
}

sub write_message
{
    my ($self, $msg, %opts) = @_;

    my @extra;
    if ($opts{flags}) {
        push @extra, '(' . join(' ', @{$opts{flags}}) . ')';
    }
    if ($msg->has_attribute('internaldate')) {
        push @extra, $msg->get_attribute('internaldate');
    }

    $self->{client}->append($self->{folder}, @extra,
                            { Literal => $msg->as_string() } )
                            || die "$@";

    # if we know the uid and uidvalidity, update the msg object
    my $appenduid = $self->{client}->get_response_code('appenduid');
    if (defined $appenduid and ref $appenduid eq 'ARRAY') {
        $msg->set_attribute(uidvalidity => $appenduid->[0]);
        $msg->set_attribute(uid => $appenduid->[1]);
    }
}

sub write_end
{
    my ($self) = @_;
}

sub set_fetch_attributes
{
    my ($self, @attrs) = @_;

    $self->{fetch_attrs} = { uid => 1, 'body.peek[]' => 1 };
    foreach my $attr (@attrs)
    {
        $attr = lc($attr);
        die "Bad fetch attribute \"$attr\""
            unless ($attr =~ m/^annotation\s+\(\S+\s+value\.(shared|priv)\)$/i ||
                    $attr =~ m/^[a-z0-9.\[\]<>]+$/);
        next
            if ($attr =~ m/^body/);
        $self->{fetch_attrs}->{$attr} = 1;
    }
}

sub read_begin
{
    my ($self) = @_;

    $self->connect();

    $self->_select()
        or die "Cannot select folder \"$self->{folder}\": $@";

    $self->{next_uid} = 1;
    $self->{last_uid} = -1 + $self->{client}->get_response_code('uidnext');
    $self->{last_batch_uid} = undef;
    $self->{batch} = undef;
}

sub read_message
{
    my ($self, $msg) = @_;

    for (;;)
    {
        while (defined $self->{batch})
        {
            my $uid = $self->{next_uid};
            last if $uid > $self->{last_batch_uid};
            $self->{next_uid}++;
            my $rr = $self->{batch}->{$uid};
            next unless defined $rr;
            delete $self->{batch}->{$uid};

            # xlog "found uid=$uid in batch";
            # xlog "rr=" . Dumper($rr);
            my $raw = $rr->{'body'};
            delete $rr->{'body'};
            return Cassandane::Message->new(raw => $raw,
                                            attrs => { id => $uid, %$rr });
        }
        $self->{batch} = undef;

        # xlog "batch empty or no batch available";

        for (;;)
        {
            my $first_uid = $self->{next_uid};
            return undef
                if $first_uid > $self->{last_uid};  # EOF
            my $last_uid = $first_uid + $BATCHSIZE - 1;
            $last_uid = $self->{last_uid}
                if $last_uid > $self->{last_uid};
            # xlog "fetching batch range $first_uid:$last_uid";
            my $attrs = join(' ', keys %{$self->{fetch_attrs}});
            $self->{batch} = $self->{client}->fetch("$first_uid:$last_uid",
                                                    "($attrs)");
            $self->{last_batch_uid} = $last_uid;
            last if (defined $self->{batch} && scalar $self->{batch} > 0);
            $self->{next_uid} = $last_uid + 1;
        }
        # xlog "have a batch, next_uid=$self->{next_uid}";
    }

    return undef;
}

sub read_end
{
    my ($self) = @_;

    $self->{next_uid} = undef;
    $self->{last_uid} = undef;
    $self->{last_batch_uid} = undef;
    $self->{batch} = undef;
}

sub remove
{
    my ($self) = @_;

    $self->connect();
    my $r = $self->{client}->delete($self->{folder});
    die "IMAP DELETE failed: $@"
        if (!defined $r && !($self->{client}->get_last_error() =~ m/does not exist/));
}

sub get_client
{
    my ($self) = @_;

    $self->connect();
    return $self->{client};
}

sub get_server_name
{
    my ($self) = @_;

    $self->connect();

    # Cyrus returns the servername config variable in the first
    # word of the untagged OK reponse sent on connection.  We
    # Capture the non-response code part of that in {banner}.
    # which looks like
    # slott02 Cyrus IMAP git2.5.0+0-git-work-6640 server ready
    my ($servername) = ($self->{banner} =~ m/^(\S+)\s+Cyrus\s+IMAP\s+/);
    return $servername;
}

sub as_string
{
    my ($self) = @_;

    return 'imap://' . $self->{host} . ':' . $self->{port} . '/' .  $self->{folder};
}

sub set_folder
{
    my ($self, $folder) = @_;

    if ($self->{folder} ne $folder)
    {
        $self->{folder} = $folder;
    }
}

sub _kvlist_to_hash
{
    my (@kvlist) = @_;
    my $h = {};
    while (my $k = shift @kvlist)
    {
        my $v = shift @kvlist;
        $h->{lc($k)} = $v;
    }
    return $h;
}

sub xconvfetch_begin
{
    my ($self, $cid, $changedsince) = @_;
    my @args = ( $cid, $changedsince || 0, [ keys %{$self->{fetch_attrs}} ] );

    my $results =
    {
        xconvmeta => {},
    };
    $self->{fetched} = undef;
    my %handlers =
    (
        xconvmeta => sub
        {
            # expecting: * XCONVMETA d55a42549e674b82 (MODSEQ 29)
            my ($response, $rr) = @_;
#           xlog "XCONVMETA rr=" . Dumper($rr);
            $results->{xconvmeta}->{$rr->[0]} = _kvlist_to_hash(@{$rr->[1]});
        },
        fetch => sub
        {
            my ($response, $rr) = @_;
#           xlog "FETCH rr=" . Dumper($rr);
            push(@{$self->{fetched}}, $rr);
        }
    );

    $self->connect();

    $self->{client}->_imap_cmd("xconvfetch", 0, \%handlers, @args)
        or return undef;

    return $results;
}

sub xconvfetch_message
{
    my ($self) = @_;

    my $rr = shift @{$self->{fetched}};
    return undef
        if !defined $rr;

    my $raw = $rr->{'body'};
    delete $rr->{'body'};
    return Cassandane::Message->new(raw => $raw, attrs => $rr);
}

sub xconvfetch_end
{
    my ($self) = @_;
    $self->{fetched} = undef;
}

#
# Begin idling.  Sends the IDLE command and waits for the server to
# respond with the "+ idling" response.  Returns undef and sets $@
# on error, or dies on timeout.
#
sub idle_begin
{
    my ($self) = @_;

    my $talk = $self->get_client();

    $talk->_send_cmd('idle');

    my $got_idling = 0;
    my $handlers = { idling => sub { $got_idling = 1; } };

    # Await the "+ idling" response

    # temporarily set Timeout
    my $old_tout = $talk->{Timeout};
    $talk->{Timeout} = 5;

    # hack to force a line read
    $talk->{ReadLine} = undef;

    # temporarily replace CmdId with '+' so that
    # _parse_response() will think it's a tag.
    my $cmd_id = $talk->{CmdId};
    $talk->{CmdId} = '+';

    # Will die if timedout - failing the test
    $talk->_parse_response($handlers);

    # replace CmdId, Timeout
    $talk->{CmdId} = $cmd_id;
    $talk->{Timeout} = $old_tout;

    if (!$got_idling)
    {
        $@ = "Did not receive expected \"idling\" response";
        return undef;
    }

    return 1;
}

#
# Read any unsolicited responses from the server.  The $handlers is
# argument is like the one passed to Mail::IMAPTalk->_imap_cmd().  The
# $tout argument is a timeout in seconds indicating how long to wait if
# no responses have yet been received, with 0 specifically meaning "just
# poll, do not block".  Returns true if at a response was read.
#
sub idle_response
{
    my ($self, $handlers, $tout) = @_;
    my $talk = $self->get_client();

    # Temporarily set the Timeout for _parse_response
    my $old_tout = $talk->{Timeout};
    $talk->{Timeout} = $tout;

    # Temporarily set CmdId to fool _parse_response into returning as
    # soon as it sees the first unsolicited response instead of waiting
    # for the actual tagged response, which might be a very long time
    # coming.
    my $cmd_id = $talk->{CmdId};
    $talk->{CmdId} = '*';

    my $got = 0;
    eval
    {
        $talk->_parse_response($handlers);
        $got = 1;
    };

    # Restore old values of CmdId and Timeout
    $talk->{CmdId} = $cmd_id;
    $talk->{Timeout} = $old_tout;

    return $got;
}

sub idle_end
{
    my ($self, $handlers) = @_;

    my $talk = $self->get_client();

    # Send the "DONE" continuation which cancels the IDLE command
    $talk->_imap_socket_out("DONE\n");

    # Get the final tagged response including any unsolicited responses not yet seen
    $talk->_parse_response($handlers);

    # Prepare for the next command
    $talk->{CmdId}++;
}

1;
