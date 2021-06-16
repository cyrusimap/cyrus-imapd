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

package Cassandane::Cyrus::Pop3;
use strict;
use warnings;
use DateTime;
use Net::POP3;

use lib '.';
use base qw(Cassandane::Cyrus::TestCase);
use Cassandane::Util::Log;

Cassandane::Cyrus::TestCase::magic(PopSubFolders => sub {
    shift->config_set(popsubfolders => 1);
});

sub new
{
    my ($class, @args) = @_;
    return $class->SUPER::new({
        # We need IMAP to be able to create the mailbox for POP
        services => ['imap', 'pop3'],
    }, @args);
}

sub set_up
{
    my ($self) = @_;
    $self->SUPER::set_up();

    my $svc = $self->{instance}->get_service('pop3');
    if (defined $svc)
    {
        $self->{pop_store} = $svc->create_store();
    }
}

sub tear_down
{
    my ($self) = @_;

    if (defined $self->{pop_store})
    {
        $self->{pop_store}->disconnect();
        $self->{pop_store} = undef;
    }

    $self->SUPER::tear_down();
}

sub test_top_args
{
    my ($self) = @_;

    xlog $self, "Testing whether the TOP command checks its arguments [Bug 3641]";
    # Note, the POP client checks its arguments before sending
    # them so we have to reach around it to do bad things.

    xlog $self, "Ensure a message exists, before logging in to POP";
    my %exp;
    $exp{A} = $self->make_message('Message A');

    my $client = $self->{pop_store}->get_client();

    xlog $self, "TOP with no arguments should return an error";
    my $r = $client->command('TOP')->response();
    $self->assert_equals($r, Net::Cmd::CMD_ERROR);
    $self->assert_equals($client->code(), 500);
    $self->assert_matches(qr/Missing argument/, $client->message());

    xlog $self, "TOP with 1 argument should return an error";
    $r = $client->command('TOP', 1)->response();
    $self->assert_equals($r, Net::Cmd::CMD_ERROR);
    $self->assert_equals($client->code(), 500);
    $self->assert_matches(qr/Missing argument/, $client->message());

    xlog $self, "TOP with 2 correct arguments should actually work";
    $r = $client->command('TOP', 1, 2)->response();
    $self->assert_equals($r, Net::Cmd::CMD_OK);
    $self->assert_equals($client->code(), 200);
    my $lines = $client->read_until_dot();
    my %actual;
    $actual{'Message A'} = Cassandane::Message->new(lines => $lines,
                                                    attrs => { uid => 1 });
    $self->check_messages(\%exp, actual => \%actual);

    xlog $self, "TOP with 2 arguments, first one not a number, should return an error";
    $r = $client->command('TOP', '1xyz', 2)->response();
    $self->assert_equals($r, Net::Cmd::CMD_ERROR);
    $self->assert_equals($client->code(), 500);

    xlog $self, "TOP with 2 arguments, second one not a number, should return an error";
    $r = $client->command('TOP', 1, '2xyz')->response();
    $self->assert_equals($r, Net::Cmd::CMD_ERROR);
    $self->assert_equals($client->code(), 500);

    xlog $self, "TOP with 3 arguments should return an error";
    $r = $client->command('TOP', 1, 2, 3)->response();
    $self->assert_equals($r, Net::Cmd::CMD_ERROR);
    $self->assert_equals($client->code(), 500);
    $self->assert_matches(qr/Unexpected extra argument/, $client->message());
}

sub test_subfolder_login
    :PopSubFolders :NoAltNameSpace
{
    my ($self) = @_;

    xlog $self, "Testing whether + address login gets subfolder";

    my $imapclient = $self->{store}->get_client();

    xlog $self, "Ensure a messages exist";
    my %exp;
    $exp{A} = $self->make_message('Message A');

    $imapclient->create('INBOX.sub');
    $self->{store}->set_folder('INBOX.sub');
    # different mailbox, so reset generator's expected uid sequence
    $self->{gen}->set_next_uid(1);

    my %subexp;
    $subexp{B} = $self->make_message('Message B');

    my $popclient = $self->{pop_store}->get_client();

    xlog $self, "Test regular TOP gets the right message";
    my $r = $popclient->command('TOP', 1, 2)->response();
    $self->assert_equals($r, Net::Cmd::CMD_OK);
    $self->assert_equals($popclient->code(), 200);
    my $lines = $popclient->read_until_dot();
    my %actual;
    $actual{'Message A'} = Cassandane::Message->new(lines => $lines,
                                                    attrs => { uid => 1 });
    $self->check_messages(\%exp, actual => \%actual);

    my $svc = $self->{instance}->get_service('pop3');
    my $substore = $svc->create_store(folder => 'INBOX.sub');

    # create a new client
    my $subclient = $substore->get_client();


    xlog $self, "Test subfolder TOP gets the right message";
    my $subr = $subclient->command('TOP', 1, 2)->response();
    $self->assert_equals($subr, Net::Cmd::CMD_OK);
    $self->assert_equals($subclient->code(), 200);
    my $sublines = $subclient->read_until_dot();
    my %subactual;
    $subactual{'Message B'} = Cassandane::Message->new(lines => $sublines,
                                                       attrs => { uid => 1 });
    $self->check_messages(\%subexp, actual => \%subactual);
}

1;

