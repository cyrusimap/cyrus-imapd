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

package Cassandane::Cyrus::List;
use strict;
use warnings;
use DateTime;
use Data::Dumper;

use base qw(Cassandane::Cyrus::TestCase);
use Cassandane::Util::Log;
use Cassandane::Generator;
use Cassandane::MessageStoreFactory;
use Cassandane::Instance;

$Data::Dumper::Sortkeys = 1;

sub new
{
    my ($class, @args) = @_;

    my $config = Cassandane::Config->default()->clone();

    return $class->SUPER::new({ config => $config, adminstore => 1 }, @args);
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

# tests based on rfc 5258 examples:
# https://tools.ietf.org/html/rfc5258#section-5

# TODO not sure how to set up test data for remote mailboxes...
#sub test_rfc5258_ex04_remote_children
#{
#    my ($self) = @_;
#    $self->assert(0, 'XXX test not implemented');
#}

#sub test_rfc5258_ex05_remote_subscribed
#{
#    my ($self) = @_;
#    $self->assert(0, 'XXX test not implemented');
#}

#sub test_rfc5258_ex06_remote_return_subscribed
#{
#    my ($self) = @_;
#    $self->assert(0, 'XXX test not implemented');
#}

#sub test_rfc5258_ex09_childinfo
#{
#    my ($self) = @_;
#    $self->assert(0, 'XXX test not implemented');
#}

#sub test_rfc5258_ex10_multiple_mailbox_patterns_childinfo
#{
#    my ($self) = @_;
#    $self->assert(0, 'XXX test not implemented');
#}

#sub test_rfc5258_ex11_missing_hierarchy_elements
#{
#    my ($self) = @_;
#    $self->assert(0, 'XXX test not implemented');
#}

# tests based on rfc 6154 examples:
# https://tools.ietf.org/html/rfc6154#section-5

# "An IMAP server that supports this extension MAY include any or all of the
# following attributes in responses to the non-extended IMAP LIST command."
#
# Cyrus does not (at least, not at the moment), so this test is disabled.
sub bogus_test_rfc6154_ex01_list_non_extended
    :UnixHierarchySep :AltNamespace
{
    my ($self) = @_;

    my $imaptalk = $self->{store}->get_client();

    $self->setup_mailbox_structure($imaptalk, [
        [ 'create' => [qw( ToDo Projects Projects/Foo SentMail MyDrafts Trash) ] ],
    ]);

    $imaptalk->setmetadata("SentMail", "/private/specialuse", "\\Sent");
    $self->assert_equals('ok', $imaptalk->get_last_completion_response());

    $imaptalk->setmetadata("MyDrafts", "/private/specialuse", "\\Drafts");
    $self->assert_equals('ok', $imaptalk->get_last_completion_response());

    $imaptalk->setmetadata("Trash", "/private/specialuse", "\\Trash");
    $self->assert_equals('ok', $imaptalk->get_last_completion_response());

    my $alldata = $imaptalk->list("", "%");

    $self->assert_mailbox_structure($alldata, '/', {
        'INBOX'                 => [qw( \\HasNoChildren )],
        'ToDo'                  => [qw( \\HasNoChildren )],
        'Projects'              => [qw( \\HasChildren )],
        'SentMail'              => [qw( \\Sent \\HasNoChildren )],
        'MyDrafts'              => [qw( \\Drafts \\HasNoChildren )],
        'Trash'                 => [qw( \\Trash \\HasNoChildren )],
    });
}

use Cassandane::Tiny::Loader 'tiny-tests/List';

1;
