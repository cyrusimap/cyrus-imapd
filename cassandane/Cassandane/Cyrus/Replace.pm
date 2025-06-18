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

package Cassandane::Cyrus::Replace;
use strict;
use warnings;
use DateTime;
use Data::Dumper;

use lib '.';
use base qw(Cassandane::Cyrus::TestCase);
use Cassandane::Util::Log;
use Cassandane::Generator;
use Cassandane::MessageStoreFactory;
use Cassandane::Instance;

sub new
{
    my $class = shift;
    return  $class->SUPER::new({adminstore => 1}, @_);
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

sub test_replace_same_mailbox
    :min_version_3_9 :Conversations
{
    my ($self) = @_;

    my $talk = $self->{store}->get_client();

    my %exp;
    $exp{A} = $self->make_message("Message A", store => $self->{store});
    $self->check_messages(\%exp);

    $talk->select('INBOX');

    %exp = ();
    $exp{B} = $self->{gen}->generate(subject => "Message B");

    # REPLACE
    $talk->_imap_cmd('REPLACE', 0, '', "1", "INBOX",
                     { Literal => $exp{B}->as_string() });
    $self->check_messages(\%exp);

    %exp = ();
    $exp{C} = $self->{gen}->generate(subject => "Message C");

    # UID REPLACE
    $talk->_imap_cmd('UID', 0, '', 'REPLACE', "2", "INBOX",
                     "(\\flagged)", " 7-Feb-1994 22:43:04 -0800",
                     { Literal => $exp{C}->as_string() });
    $self->check_messages(\%exp);

    my $res = $talk->fetch('1', '(UID INTERNALDATE)');
    $self->assert_matches(qr/1994/, $res->{1}{internaldate});

    # REPLACE same content with different INTERNALDATE - should change
    $talk->_imap_cmd('REPLACE', 0, '', "1", "INBOX",
                     "()", " 7-Feb-2004 22:43:04 -0800",
                     { Literal => $exp{C}->as_string() });
    $res = $talk->fetch('1:*', '(UID INTERNALDATE)');
    $self->assert_matches(qr/2004/, $res->{1}{internaldate});

    # APPEND same content with different INTERNALDATE - should use existing
    $talk->append("INBOX", "()", " 7-Feb-2014 22:43:04 -0800",
                     { Literal => $exp{C}->as_string() });
    $res = $talk->fetch('1:*', '(UID INTERNALDATE)');
    $self->assert_matches(qr/2004/, $res->{1}{internaldate});
    $self->assert_matches(qr/2004/, $res->{2}{internaldate});

    # REPLACE same content with different INTERNALDATE - should use existing
    $talk->_imap_cmd('REPLACE', 0, '', "1", "INBOX",
                     "()", " 7-Feb-2014 22:43:04 -0800",
                     { Literal => $exp{C}->as_string() });
    $res = $talk->fetch('1:*', '(UID INTERNALDATE)');
    $self->assert_matches(qr/2004/, $res->{1}{internaldate});
    $self->assert_matches(qr/2004/, $res->{2}{internaldate});
}

sub test_replace_different_mailbox
    :min_version_3_9
{
    my ($self) = @_;

    my $talk = $self->{store}->get_client();

    my %exp;
    $exp{A} = $self->make_message("Message A", store => $self->{store});
    $self->check_messages(\%exp);

    $talk->create("INBOX.foo");
    $talk->select('INBOX');

    %exp = ();
    $exp{B} = $self->{gen}->generate(subject => "Message B", uid => 1);

    $talk->_imap_cmd('REPLACE', 0, '', "1", "INBOX.foo",
                     { Literal => $exp{B}->as_string() });
    $self->check_messages({});

    $self->{store}->set_folder("INBOX.foo");
    $self->check_messages(\%exp);
}

1;
