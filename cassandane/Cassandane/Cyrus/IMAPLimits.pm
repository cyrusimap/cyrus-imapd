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

package Cassandane::Cyrus::IMAPLimits;
use strict;
use warnings;
use Mail::JMAPTalk 0.13;
use Data::Dumper;

use base qw(Cassandane::Cyrus::TestCase);
use Cassandane::Util::Log;

my $email = <<EOF;
Subject: foo
Date: bar
From: <foobar\@example.com>

Body
EOF

$email =~ s/\r?\n/\r\n/gs;

my $toobig_email = $email . "X" x 100;

# Check that we got an untagged BYE [TOOBIG] response
sub assert_bye_toobig
{
    my ($self, $store) = @_;

    $store = $self->{store} if (!defined $store);

    # We want to override Mail::IMAPTalk's builtin handling of the BYE
    # untagged response, as it will 'die' immediately without parsing
    # the remainder of the line and especially without picking out the
    # [TOOBIG] response code that we want to see.
    my $got_toobig = 0;
    my $handlers =
    {
        bye => sub
        {
            my (undef, $resp) = @_;
            $got_toobig = 1 if (uc($resp->[0]) eq '[TOOBIG]');
        }
    };

    $store->idle_response($handlers, 1);
    $self->assert_num_equals(1, $got_toobig);
}

# Send a command and expect an untagged BYE [TOOBIG] response
sub assert_cmd_bye_toobig
{
    my $self = shift;
    my $cmd = shift;

    my $talk = $self->{store}->get_client();
    $talk->enable('qresync'); # IMAPTalk requires lower-case
    $talk->select('INBOX');

    $talk->_send_cmd($cmd, @_);
    $self->assert_bye_toobig();
}

# Check that we got a tagged NO [TOOBIG] response
sub assert_no_toobig
{
    my ($self, $talk) = @_;

    my $got_toobig = 0;
    my $handlers =
    {
        'no' => sub
        {
            my (undef, $resp) = @_;
            $got_toobig = 1 if (uc($resp->[0]) eq '[TOOBIG]');
        }
    };

    eval {
        $talk->_parse_response($handlers);
    };

    $self->assert_num_equals(1, $got_toobig);
}

# Send a command and expect a tagged NO [TOOBIG] response
sub assert_cmd_no_toobig
{
    my $self = shift;
    my $talk = shift;
    my $cmd = shift;

    $talk->_send_cmd($cmd, @_);
    $self->assert_no_toobig($talk);
}

sub new
{
    my $class = shift;

    my $config = Cassandane::Config->default()->clone();
    $config->set(maxword => 25);
    $config->set(maxquoted => 25);
    $config->set(maxliteral => 25);
    $config->set(literalminus => 1);
    $config->set(maxargssize => 45);
    $config->set(maxmessagesize => 100);
    $config->set(event_groups => "message mailbox applepushservice");
    $config->set(aps_topic => "mail");

    return $class->SUPER::new({
        adminstore => 1,
        config => $config,
        services => ['imap'],
    }, @_);
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

sub test_maxword
{
    my ($self) = @_;

    # Oversized command name
    $self->assert_cmd_bye_toobig("X" x 26);
}

sub test_maxword_astring
{
    my ($self) = @_;

    # Oversized mailbox name
    $self->assert_cmd_bye_toobig('SELECT', "X" x 26);
}

sub test_maxquoted
{
    my ($self) = @_;

    # Oversized mailbox name
    $self->assert_cmd_bye_toobig('SELECT', { Quote => "X" x 26 });
}

sub test_maxliteral_nosync
{
    my ($self) = @_;

    my $talk = $self->{store}->get_client();
    # Do this by brute force until we have IMAPTalk v4.06+
    $talk->_imap_socket_out($talk->{CmdId}++ . " SELECT {26+}\015\012");
    $self->assert_bye_toobig();
}

sub test_maxliteral_sync
{
    my ($self) = @_;

    # Unlike oversized non-sync literals which fatal() in one central location,
    # oversized sync literals fail with a NO response in multiple places,
    # so we test as many of those places as possible.
    # Having said that, arguments parsed in cmdloop() or in get_search_criterion()
    # are mostly handled centrally.

    # Authenticated State

    # Synchronizing literals are the default in IMAPTalk v4.05 (and earlier)
    my $talk = $self->{store}->get_client(NoLiteralPlus => 1);

    $self->assert_cmd_no_toobig($talk, 'SELECT',
                                { Literal => "X" x 26 });

    $self->assert_cmd_no_toobig($talk, 'ID',
                                [ { Literal => "X" x 26 } ]);

    $self->assert_cmd_no_toobig($talk, 'ID',
                                [ { Quote => 'foo' }, { Literal => "X" x 26 } ] );

    $self->assert_cmd_no_toobig($talk, 'LIST',
                                { Literal => "X" x 26 });

    $self->assert_cmd_no_toobig($talk, 'LIST',
                                { Quote => '' }, { Literal => "X" x 26 });

    $self->assert_cmd_no_toobig($talk, 'NOTIFY',
                                'SET', [ 'MAILBOXES', [ { Literal => "X" x 26 } ] ] );

    $self->assert_cmd_no_toobig($talk, 'LISTRIGHTS',
                                'INBOX', { Literal => "X" x 26 });

    $self->assert_cmd_no_toobig($talk, 'SETACL',
                                'INBOX', 'anyone', { Literal => "X" x 26 });

    $self->assert_cmd_no_toobig($talk, 'GETMETADATA',
                                'INBOX', { Literal => "X" x 26 } );

    $self->assert_cmd_no_toobig($talk, 'GETMETADATA',
                                'INBOX', [ { Literal => "X" x 26 } ] );

    $self->assert_cmd_no_toobig($talk, 'SETMETADATA',
                                'INBOX', [ { Literal => "X" x 26 } ] );

    $self->assert_cmd_no_toobig($talk, 'SETMETADATA',
                                'INBOX', [ '/comment', { Literal => "X" x 26 } ] );

    $self->assert_cmd_no_toobig($talk, 'XAPPLEPUSHSERVICE',
                                { Literal => "X" x 26 });

    $self->assert_cmd_no_toobig($talk, 'XAPPLEPUSHSERVICE',
                                'FOO', { Literal => "X" x 26 });

    # Selected State
    $talk->select('INBOX');

    $self->assert_cmd_no_toobig($talk, 'FETCH',
                                '1', [ 'ANNOTATION',
                                       [ { Literal => "X" x 26 } ] ] );

    $self->assert_cmd_no_toobig($talk, 'FETCH',
                                '1', [ 'BODY[HEADER.FIELDS',
                                       [ { Literal => "X" x 26 } ] ] );

    $self->assert_cmd_no_toobig($talk, 'FETCH',
                                '1', [ 'RFC822.HEADER.LINES',
                                       [ { Literal => "X" x 26 } ] ] );

    $self->assert_cmd_no_toobig($talk, 'STORE',
                                '1', 'ANNOTATION', [ { Literal => "X" x 26 } ] );

    $self->assert_cmd_no_toobig($talk, 'STORE',
                                '1', 'ANNOTATION',
                                [ { Quote => '/comment' },
                                  [ { Literal => "X" x 26 } ] ] );

    $self->assert_cmd_no_toobig($talk, 'STORE',
                                '1', 'ANNOTATION',
                                [ { Quote => '/comment' },
                                  [ { Quote => 'value' },
                                    { Literal => "X" x 26 } ] ] );

    $self->assert_cmd_no_toobig($talk, 'SEARCH',
                                'HEADER', { Literal => "X" x 26 } );

    $self->assert_cmd_no_toobig($talk, 'SEARCH',
                                'HEADER', 'SUBJECT', { Literal => "X" x 26 } );

    $self->assert_cmd_no_toobig($talk, 'SEARCH',
                                'ANNOTATION', { Literal => "X" x 26 } );

    $self->assert_cmd_no_toobig($talk, 'SEARCH',
                                'ANNOTATION', '/comment', { Literal => "X" x 26 } );

    $self->assert_cmd_no_toobig($talk, 'SEARCH',
                                'ANNOTATION', '/comment',
                                'value', { Literal => "X" x 26 } );

    $self->assert_cmd_no_toobig($talk, 'ESEARCH',
                                'IN', [ 'MAILBOXES', { Literal => "X" x 26 } ] );
}

sub test_maxargssize_append_flags
{
    my ($self) = @_;

    $self->assert_cmd_bye_toobig('APPEND', 'INBOX',
                                 [ "X" x 25, "X" x 25 ], { Literal => $email } );
}

sub test_maxargssize_append_annot
{
    my ($self) = @_;

    # Use MULTIAPPEND, fail the second
    $self->assert_cmd_bye_toobig('APPEND', 'INBOX',
                                 { Literal => $email },
                                 'ANNOTATION',
                                 [ "X" x 25, [ 'VALUE', { Quote => "X" x 25 } ] ],
                                 { Literal => $email } );
}

sub test_maxargssize_create
{
    my ($self) = @_;

    $self->assert_cmd_bye_toobig('CREATE', "X" x 25, [ "X" x 25 ] );
}

sub test_maxargssize_create_ext
{
    my ($self) = @_;

    $self->assert_cmd_bye_toobig('CREATE',
                                 "X" x 5, [ "X" x 5, [ "X" x 25, "X" x 25 ] ] );
}

sub test_maxargssize_fetch
{
    my ($self) = @_;

    $self->assert_cmd_bye_toobig('FETCH', '1',
                                 [ 'BODY', 'ENVELOPE', 'FLAGS',
                                   'INTERNALDATE', 'RFC822.SIZE' ]);
}

sub test_maxargssize_fetch_annot
{
    my ($self) = @_;

    $self->assert_cmd_bye_toobig('FETCH', '1',
                                 [ 'ANNOTATION',
                                   [ [ "X" x 25, "X" x 25 ] ], "X" x 5 ] );
}

sub test_maxargssize_fetch_annot2
{
    my ($self) = @_;

    $self->assert_cmd_bye_toobig('FETCH', '1',
                                 [ 'ANNOTATION',
                                   [ "X" x 5, [ "X" x 25, "X" x 25 ] ] ] );
}

sub test_maxargssize_fetch_headers
{
    my ($self) = @_;

    $self->assert_cmd_bye_toobig('FETCH', '1',
                                 [ 'BODY[HEADER.FIELDS', [ "X" x 25, "X" x 25 ] ] );
}

sub test_maxargssize_getmetadata
{
    my ($self) = @_;

    $self->assert_cmd_bye_toobig('GETMETADATA', 'INBOX', [ "X" x 25, "X" x 25 ] );
}

sub test_maxargssize_list_multi
{
    my ($self) = @_;

    $self->assert_cmd_bye_toobig('LIST', { Quote => '' }, [ "X" x 25, "X" x 25 ]);
}

sub test_maxargssize_list_select
{
    my ($self) = @_;

    $self->assert_cmd_bye_toobig('LIST',
                                 [ 'SUBSCRIBED', 'REMOTE',
                                   'RECURSIVEMATCH', 'SPECIAL-USE' ],
                                 { Quote => '' }, '*');
}

sub test_maxargssize_list_return
{
    my ($self) = @_;

    $self->assert_cmd_bye_toobig('LIST',
                                 { Quote => '' }, '*', 'RETURN',
                                 [ 'SUBSCRIBED', 'CHILDREN',
                                   'MYRIGHTS', 'SPECIAL-USE' ] );
}

sub test_maxargssize_notify_events
{
    my ($self) = @_;

    $self->assert_cmd_bye_toobig('NOTIFY', 'SET',
                                 [ 'SELECTED',
                                   [ 'MessageNew', 'MessageExpunge', 'FlagChange' ] ] );
}

sub test_maxargssize_notify_multi
{
    my ($self) = @_;

    $self->assert_cmd_bye_toobig('NOTIFY', 'SET',
                                 [ 'PERSONAL', 'NONE' ],
                                 [ 'SELECTED', 'NONE' ],
                                 [ 'SUBSCRIBED', 'NONE' ] );
}

sub test_maxargssize_notify_subtree
{
    my ($self) = @_;

    $self->assert_cmd_bye_toobig('NOTIFY', 'SET',
                                 [ 'SUBTREE', [ "X" x 25, "X" x 25 ] ] );
}

sub test_maxargssize_search
{
    my ($self) = @_;

    $self->assert_cmd_bye_toobig('SEARCH',
                                 'TEXT', "X" x 25, 'TEXT', { Quote => "X" x 25 } );
}

sub test_maxargssize_multisearch
{
    my ($self) = @_;

    $self->assert_cmd_bye_toobig('ESEARCH',
                                 'IN', [ 'MAILBOXES', [ "X" x 25, "X" x 25 ] ]);
}

sub test_maxargssize_select
{
    my ($self) = @_;

    $self->assert_cmd_bye_toobig('SELECT', 'INBOX',
                                 [ 'QRESYNC', [ '1234567890', '1234567890' ],
                                   'ANNOTATE' ] );
}

sub test_maxargssize_setmetadata
{
    my ($self) = @_;

    $self->assert_cmd_bye_toobig('SETMETADATA', 'INBOX',
                                 [ "X" x 25, { Quote => "X" x 25 } ] );
}

sub test_maxargssize_setmetadata2
{
    my ($self) = @_;

    $self->assert_cmd_bye_toobig('SETMETADATA', 'INBOX',
                                 [ '/shared', { Quote => "X" x 25 },
                                   '/shared', { Quote => "X" x 25 } ] );
}

sub test_maxargssize_setquota
{
    my ($self) = @_;

    my $store = $self->{adminstore};
    my $talk = $store->get_client();

    $talk->_send_cmd('SETQUOTA', 'user.cassandane',
                     [ 'STORAGE', '1234567890',
                       'MESSAGE', '1234567890',
                       'MAILBOX', '1234567890' ] );
    $self->assert_bye_toobig($store);
}

sub test_maxargssize_sort
{
    my ($self) = @_;

    $self->assert_cmd_bye_toobig('SORT',
                                 [ 'ARRIVAL', 'CC', 'DATE',
                                   'FROM', 'REVERSE', 'SIZE', 'TO' ],
                                 'UTF-8', 'ALL');
}

sub test_maxargssize_status
{
    my ($self) = @_;

    $self->assert_cmd_bye_toobig('STATUS', 'INBOX',
                                 [ 'MESSAGES', 'UIDNEXT',
                                   'UIDVALIDITY', 'UNSEEN', 'SIZE' ] );
}

sub test_maxargssize_store_annot
{
    my ($self) = @_;

    $self->assert_cmd_bye_toobig('STORE', '1', 'ANNOTATION',
                                 [ "X" x 25, [ 'VALUE', { Quote => "X" x 25 } ] ] );
}

sub test_maxargssize_store_annot2
{
    my ($self) = @_;

    $self->assert_cmd_bye_toobig('STORE', '1', 'ANNOTATION',
                                 [ "X" x 5, [ 'VALUE', { Quote => "X" x 25 } ],
                                   "X" x 5, [ 'VALUE', { Quote => "X" x 25 } ] ] );
}

sub test_append_zero
{
    my ($self) = @_;

    my $talk = $self->{store}->get_client();
    $talk->_imap_cmd('APPEND', 0, '', 'INBOX', { Literal => '' } );
    $self->assert_str_equals('no', $talk->get_last_completion_response());
}

sub test_maxmessagesize_sync_literal
{
    my ($self) = @_;

    # Synchronizing literals are the default in IMAPTalk v4.05 (and earlier)
    my $talk = $self->{store}->get_client(NoLiteralPlus => 1);

    $self->assert_cmd_no_toobig($talk, 'APPEND',
                                'INBOX', { Literal => $toobig_email } );
}

sub test_maxmessagesize_nosync_literal
{
    my ($self) = @_;

    my $talk = $self->{store}->get_client();
    # Do this by brute force until we have IMAPTalk v4.06+
    $talk->_imap_socket_out($talk->{CmdId}++ . " APPEND INBOX {101+}\015\012");
    $self->assert_no_toobig($talk);
    $self->assert_bye_toobig();
}

sub test_literal_minus
{
    my ($self) = @_;

    my $talk = $self->{store}->get_client();
    $talk->_imap_socket_out($talk->{CmdId}++ . " APPEND INBOX {4097+}\015\012");
    $self->assert_no_toobig($talk);
    $self->assert_bye_toobig();
}

1;
