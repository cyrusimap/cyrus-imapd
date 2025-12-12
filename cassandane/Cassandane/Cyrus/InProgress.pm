#!/usr/bin/perl
#
#  Copyright (c) 2011-2023 FastMail Pty Ltd. All rights reserved.
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

package Cassandane::Cyrus::InProgress;
use strict;
use warnings;
use DateTime;
use JSON;
use JSON::XS;
use Data::Dumper;
use Storable 'dclone';
use File::Basename;
use IO::File;
use Cwd qw(abs_path getcwd);

use base qw(Cassandane::Cyrus::TestCase);
use Cassandane::Util::Log;

use charnames ':full';

sub new
{
    my $class = shift;

    my $config = Cassandane::Config->default()->clone();
    $config->set(mailbox_legacy_dirs => 'yes');
    $config->set(singleinstancestore => 'no');
    $config->set(imap_inprogress_interval => '1s');

    my $self = $class->SUPER::new({
        adminstore => 1,
        config => $config,
        services => ['imap'],
    }, @_);

    $self->needs('component', 'slowio');
    return $self;
}

sub set_up
{
    my ($self) = @_;
    $self->SUPER::set_up();
}

sub tear_down
{
    my ($self) = @_;
    $self->SUPER::tear_down();
}

sub test_xrename
    :SlowIO :NoAltNameSpace
{
    my ($self) = @_;

    my @resp;
    my %handlers =
    (
        ok => sub
        {
            my (undef, $ok) = @_;
            push(@resp, $ok);
        },
    );

    xlog $self, "Create some personal folders";
    my $talk = $self->{store}->get_client();
    $self->setup_mailbox_structure($talk, [
        [ 'create' => [qw( INBOX.src INBOX.src.child INBOX.src.child.grand)] ],
    ]);

    xlog $self, "rename mailbox tree";
    @resp = ();
    $talk->_imap_cmd('XRENAME', 0, \%handlers, "INBOX.src", "INBOX.dst");
    $self->assert_str_equals('ok', $talk->get_last_completion_response());
    $self->assert_str_equals('[INPROGRESS', $resp[0][0]);
    # we shouldn't have a count or total
    $self->assert_null($resp[0][1][1]);
    $self->assert_null($resp[0][1][2]);
    $self->assert_str_equals('rename', $resp[0][3]);
    $self->assert_str_equals('INBOX.src', $resp[0][4]);
    $self->assert_str_equals('INBOX.dst', $resp[0][5]);
    $self->assert_str_equals('INBOX.src.child', $resp[1][4]);
    $self->assert_str_equals('INBOX.dst.child', $resp[1][5]);
    $self->assert_str_equals('INBOX.src.child.grand', $resp[2][4]);
    $self->assert_str_equals('INBOX.dst.child.grand', $resp[2][5]);
}

sub test_copy
    :SlowIO :NoAltNameSpace
{
    my ($self) = @_;

    my @resp;
    my %handlers =
    (
        ok => sub
        {
            my (undef, $ok) = @_;
            push(@resp, $ok);
        },
    );

    xlog "generate some test messages";
    foreach (1..100) {
        $self->make_message("Message $_", size => 128_000);
    }

    xlog $self, "Create another folder";
    my $talk = $self->{store}->get_client();
    $talk->create("INBOX.dst");
    $self->assert_str_equals('ok', $talk->get_last_completion_response());

    xlog $self, "copy messages";
    @resp = ();
    $talk->select("INBOX");
    $talk->_imap_cmd('COPY', 0, \%handlers, '1:100', 'INBOX.dst');
    $self->assert_str_equals('ok', $talk->get_last_completion_response());
    $self->assert_str_equals('[INPROGRESS', $resp[0][0]);
    # we don't know what the exact count will be, be we know the total
    $self->assert_matches(qr/^[0-9]+$/, $resp[0][1][1]);
    $self->assert_str_equals('100', $resp[0][1][2]);
}

sub test_search
    :SlowIO :NoAltNameSpace
{
    my ($self) = @_;

    my @resp;
    my %handlers =
    (
        ok => sub
        {
            my (undef, $ok) = @_;
            push(@resp, $ok);
        },
    );

    xlog "generate some test messages";
    foreach (1..100) {
        $self->make_message("Message $_", size => 128_000);
    }

    xlog $self, "search messages";
    my $talk = $self->{store}->get_client();
    @resp = ();
    $talk->_imap_cmd('SEARCH', 0, \%handlers, 'RETURN', '(PARTIAL -1:-500)', '1:100', 'BODY', 'needle');
    $self->assert_str_equals('ok', $talk->get_last_completion_response());
    $self->assert_str_equals('[INPROGRESS', $resp[0][0]);
    # we don't know what the exact count will be, be we know the total
    $self->assert_matches(qr/^[0-9]+$/, $resp[0][1][1]);
    $self->assert_str_equals('100', $resp[0][1][2]);
}

sub test_esearch_selected
    :SlowIO :NoAltNameSpace
{
    my ($self) = @_;

    my @resp;
    my %handlers =
    (
        ok => sub
        {
            my (undef, $ok) = @_;
            push(@resp, $ok);
        },
    );

    xlog "generate some test messages";
    foreach (1..100) {
        $self->make_message("Message $_", size => 128_000);
    }

    xlog $self, "esearch selected mailbox";
    my $talk = $self->{store}->get_client();
    @resp = ();
    $talk->_imap_cmd('ESEARCH', 0, \%handlers,
                     'IN', '(SELECTED)', '1:100', 'BODY', 'needle');
    $self->assert_str_equals('ok', $talk->get_last_completion_response());
    $self->assert_str_equals('[INPROGRESS', $resp[0][0]);
    # we don't know what the exact count will be, be we know the total
    $self->assert_matches(qr/^[0-9]+$/, $resp[0][1][1]);
    $self->assert_str_equals('100', $resp[0][1][2]);
}

sub test_esearch_multiple
    :SlowIO :NoAltNameSpace
{
    my ($self) = @_;

    my @resp;
    my %handlers =
    (
        ok => sub
        {
            my (undef, $ok) = @_;
            push(@resp, $ok);
        },
    );

    xlog "generate some test messages";
    foreach (1..100) {
        $self->make_message("Message $_", size => 128_000);
    }

    xlog $self, "Create another folder";
    my $talk = $self->{store}->get_client();
    $talk->create("INBOX.dst");
    $self->assert_str_equals('ok', $talk->get_last_completion_response());

    xlog $self, "copy messages";
    @resp = ();
    $talk->select("INBOX");
    $talk->_imap_cmd('COPY', 0, \%handlers, '1:100', 'INBOX.dst');
    $self->assert_str_equals('ok', $talk->get_last_completion_response());
    $self->assert_str_equals('[INPROGRESS', $resp[0][0]);
    # we don't know what the exact count will be, be we know the total
    $self->assert_matches(qr/^[0-9]+$/, $resp[0][1][1]);
    $self->assert_str_equals('100', $resp[0][1][2]);

    xlog $self, "esearch multiple mailboxes";
    @resp = ();
    $talk->_imap_cmd('ESEARCH', 0, \%handlers,
                     'IN', '(PERSONAL)', '1:100', 'BODY', 'needle');
    $self->assert_str_equals('ok', $talk->get_last_completion_response());
    $self->assert_str_equals('[INPROGRESS', $resp[0][0]);
    # we shouldn't have a count or total
    $self->assert_null($resp[0][1][1]);
    $self->assert_null($resp[0][1][2]);
}

sub test_sort
    :SlowIO :NoAltNameSpace
{
    my ($self) = @_;

    my @resp;
    my %handlers =
    (
        ok => sub
        {
            my (undef, $ok) = @_;
            push(@resp, $ok);
        },
    );

    xlog "generate some test messages";
    foreach (1..100) {
        $self->make_message("Message $_", size => 128_000);
    }

    xlog $self, "sort messages";
    my $talk = $self->{store}->get_client();
    @resp = ();
    $talk->_imap_cmd('SORT', 0, \%handlers,
                     '(ARRIVAL)', 'US-ASCII', '1:100', 'BODY', 'needle');
    $self->assert_str_equals('ok', $talk->get_last_completion_response());
    $self->assert_str_equals('[INPROGRESS', $resp[0][0]);
    # we don't know what the exact count will be, be we know the total
    $self->assert_matches(qr/^[0-9]+$/, $resp[0][1][1]);
    $self->assert_str_equals('100', $resp[0][1][2]);
}

sub test_thread
    :SlowIO :NoAltNameSpace
{
    my ($self) = @_;

    my @resp;
    my %handlers =
    (
        ok => sub
        {
            my (undef, $ok) = @_;
            push(@resp, $ok);
        },
    );

    xlog "generate some test messages";
    foreach (1..100) {
        $self->make_message("Message $_", size => 128_000);
    }

    xlog $self, "thread messages";
    my $talk = $self->{store}->get_client();
    @resp = ();
    $talk->_imap_cmd('THREAD', 0, \%handlers,
                     'REFERENCES', 'US-ASCII', '1:100', 'BODY', 'needle');
    $self->assert_str_equals('ok', $talk->get_last_completion_response());
    $self->assert_str_equals('[INPROGRESS', $resp[0][0]);
    # we don't know what the exact count will be, be we know the total
    $self->assert_matches(qr/^[0-9]+$/, $resp[0][1][1]);
    $self->assert_str_equals('100', $resp[0][1][2]);
}

sub test_rename
    :SlowIO :NoAltNameSpace
{
    my ($self) = @_;

    my @resp;
    my %handlers =
    (
        ok => sub
        {
            my (undef, $ok) = @_;
            push(@resp, $ok);
        },
    );

    xlog "generate some test messages";
    foreach (1..100) {
        $self->make_message("Message $_", size => 128_000);
    }

    xlog $self, "rename INBOX";
    my $talk = $self->{store}->get_client();
    @resp = ();
    $talk->_imap_cmd('RENAME', 0, \%handlers, 'INBOX', 'INBOX.Archive');
    $self->assert_str_equals('ok', $talk->get_last_completion_response());
    $self->assert_str_equals('[INPROGRESS', $resp[0][0]);
    # we don't know what the exact count will be, be we know the total
    $self->assert_matches(qr/^[0-9]+$/, $resp[0][1][1]);
    $self->assert_str_equals('100', $resp[0][1][2]);
}

1;
