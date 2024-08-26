#!/usr/bin/perl
#
#  Copyright (c) 2011-2022 Fastmail Pty Ltd. All rights reserved.
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

package Cassandane::Cyrus::IMAP4rev2;
use strict;
use warnings;
use Cwd qw(abs_path);
use File::Path qw(mkpath);
use DateTime;
use Data::Dumper;

use lib '.';
use base qw(Cassandane::Cyrus::TestCase);
use Cassandane::Util::Log;
use Cassandane::Util::NetString;


sub new
{
    my $class = shift;
    return $class->SUPER::new({ adminstore => 1, services => ['imap'] }, @_);
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

sub test_basic
    :NoAltNameSpace :min_version_3_7
{
    my ($self) = @_;

    xlog $self, "Make some messages";
    my $uid = 1;
    my %msgs;
    for (1..20)
    {
        $msgs{$uid} = $self->make_message("Message $uid");
        $msgs{$uid}->set_attribute('uid', $uid);
        $uid++;
    }

    my $talk = $self->{store}->get_client();
    $talk->unselect();

    xlog $self, "Create mailbox with mUTF7 encoded name";
    my $res = $talk->_imap_cmd('CREATE', 0, "", "INBOX.&JgA-");
    $self->assert_str_equals('ok', $talk->get_last_completion_response());

    xlog $self, "ENABLE IMAP4rev2";
    $res = $talk->_imap_cmd('ENABLE', 0, "enabled", "IMAP4rev2");
    $self->assert_num_equals(1, $res->{imap4rev2});

    xlog $self, "Verify that LIST responses use UTF8 mailbox names";
    $res = $talk->list("", "*");
    $self->assert_mailbox_structure($res, '.', {
        'INBOX'    => [qw( \\HasChildren )],
        "INBOX.☀" => [qw( \\HasNoChildren )],
    });

    xlog $self, "EXAMINE mailbox with UTF8 mailbox name";
    $res = $talk->_imap_cmd('EXAMINE', 0, "", "INBOX.☀");
    $self->assert_str_equals('ok', $talk->get_last_completion_response());

    xlog $self, "Verify that LIST response is returned with UTF8 mailbox name";
    my @list = $talk->get_response_code('list');
    $self->assert_str_equals("INBOX.☀", $list[0][0][2]);

    xlog $self, "Mark some messages \\Deleted";
    $talk->select('INBOX');
    $res = $talk->store('5:9', '+flags', '(\\Deleted)');

    xlog $self, "Verify that FETCH responses include UID";
    $self->assert_str_equals("5", $res->{5}->{uid});
    $self->assert_str_equals("6", $res->{6}->{uid});
    $self->assert_str_equals("7", $res->{7}->{uid});
    $self->assert_str_equals("8", $res->{8}->{uid});
    $self->assert_str_equals("9", $res->{9}->{uid});

    xlog $self, "Check STATUS (DELETED)";
    $res = $talk->status('INBOX', [ 'deleted' ]);
    $self->assert_str_equals('ok', $talk->get_last_completion_response());
    $self->assert_str_equals("5", $res->{deleted});

    xlog $self, "SEARCH DELETED";
    my @results = ();
    my %handlers =
    (
        esearch => sub
        {
            my (undef, $esearch) = @_;
            push(@results, $esearch);
        },
    );
    $res = $talk->_imap_cmd('SEARCH', 0, \%handlers, 'DELETED');
    $self->assert_str_equals('ok', $talk->get_last_completion_response());

    xlog $self, "Verify that ESEARCH response is returned";
    $self->assert_num_equals(1, scalar @results);
    $self->assert_str_equals('5:9', $results[0][2]);

    xlog $self, "COPY a deleted message to mailbox with UTF8 name";
    $res = $talk->_imap_cmd('COPY', 0, "", '5', "INBOX.☀");
    $self->assert_str_equals('ok', $talk->get_last_completion_response());

    xlog $self, "ESEARCH IN (PERSONAL) DELETED";
    @results = ();
    $res = $talk->_imap_cmd('ESEARCH', 0, \%handlers,
                            'IN', '(PERSONAL)', 'DELETED');

    xlog $self, "Verify that ESEARCH response uses UTF8 mailbox name";
    $self->assert_str_equals('ok', $talk->get_last_completion_response());
    $self->assert_num_equals(2, scalar @results);
    $self->assert_str_equals("INBOX", $results[0][0][3]);
    $self->assert_str_equals('5:9', $results[0][3]);
    $self->assert_str_equals("INBOX.☀", $results[1][0][3]);
    $self->assert_str_equals('1', $results[1][3]);
}

sub test_oldname
    :NoAltNameSpace :min_version_3_7
{
    my ($self) = @_;

    xlog $self, "Make some messages";
    my $uid = 1;
    my %msgs;
    for (1..20)
    {
        $msgs{$uid} = $self->make_message("Message $uid");
        $msgs{$uid}->set_attribute('uid', $uid);
        $uid++;
    }

    my $talk = $self->{store}->get_client();
    $talk->unselect();

    xlog $self, "ENABLE IMAP4rev2";
    my $res = $talk->_imap_cmd('ENABLE', 0, "enabled", "IMAP4rev2");
    $self->assert_num_equals(1, $res->{imap4rev2});

    my @results = ();
    my %handlers =
    (
        list => sub
        {
            my (undef, $list) = @_;
            push(@results, $list);
        },
    );

    xlog $self, "Create a mailbox with denormalized mailbox name";
    $res = $talk->_imap_cmd('CREATE', 0, \%handlers, "INBOX.Å");
    $self->assert_str_equals('ok', $talk->get_last_completion_response());

    xlog $self, "Verify that LIST response is returned with OLDNAME";
    $self->assert_str_equals("INBOX.Å", $results[0][2]);
    $self->assert_str_equals('OLDNAME', $results[0][3][0]);
    $self->assert_str_equals('INBOX.Å', $results[0][3][1][0]);

    xlog $self, "Create a child mailbox with normalized mailbox name";
    @results = ();
    $res = $talk->_imap_cmd('CREATE', 0, \%handlers, "INBOX.Å.B");
    $self->assert_str_equals('ok', $talk->get_last_completion_response());

    xlog $self, "Verify that there is no LIST response";
    $self->assert_null($results[0]);

    xlog $self, "Append to mailbox with denormalized mailbox name";
    my $MsgTxt = <<EOF;
From: blah\@xyz.com
To: whoever\@whereever.com

Hello
EOF
    $MsgTxt =~ s/\n/\015\012/g;
    @results = ();
    $res = $talk->_imap_cmd('APPEND', 0, \%handlers, "INBOX.Å", { Literal => $MsgTxt });
    $self->assert_str_equals('ok', $talk->get_last_completion_response());

    xlog $self, "Verify that LIST response is returned with OLDNAME";
    $self->assert_str_equals("INBOX.Å", $results[0][2]);
    $self->assert_str_equals('OLDNAME', $results[0][3][0]);
    $self->assert_str_equals('INBOX.Å', $results[0][3][1][0]);

    xlog $self, "EXAMINE mailbox with denormalized mailbox name";
    @results = ();
    $res = $talk->_imap_cmd('EXAMINE', 0, \%handlers, "INBOX.Å");
    $self->assert_str_equals('ok', $talk->get_last_completion_response());

    xlog $self, "Verify that LIST response is returned with OLDNAME";
    $self->assert_str_equals("INBOX.Å", $results[0][2]);
    $self->assert_str_equals('OLDNAME', $results[0][3][0]);
    $self->assert_str_equals('INBOX.Å', $results[0][3][1][0]);

    $talk->unselect();

    xlog $self, "RENAME mailbox with denormalized mailbox names";
    @results = ();
    $res = $talk->_imap_cmd('RENAME', 0, \%handlers, "INBOX.Å", "INBOX.Ω");
    $self->assert_str_equals('ok', $talk->get_last_completion_response());

    xlog $self, "Verify that LIST responses are returned with OLDNAMEs";
    $self->assert_str_equals("\\NonExistent", $results[0][0][0]);
    $self->assert_str_equals("INBOX.Å", $results[0][2]);
    $self->assert_str_equals('OLDNAME', $results[0][3][0]);
    $self->assert_str_equals('INBOX.Å', $results[0][3][1][0]);
    $self->assert_str_equals("\\HasChildren", $results[1][0][0]);
    $self->assert_str_equals("INBOX.Ω", $results[1][2]);
    $self->assert_str_equals('OLDNAME', $results[1][3][0]);
    $self->assert_str_equals('INBOX.Ω', $results[1][3][1][0]);

    xlog $self, "LIST renamed mailbox";
    @results = ();
    $res = $talk->_imap_cmd('LIST', 0, \%handlers, "", "INBOX.Ω");
    $self->assert_str_equals('ok', $talk->get_last_completion_response());

    xlog $self, "Verify that OLDNAME appears in LIST response";
    $self->assert_str_equals('OLDNAME', $results[0][3][0]);
    $self->assert_str_equals('INBOX.Å', $results[0][3][1][0]);

    xlog $self, "DELETE a child mailbox with normalized mailbox name";
    @results = ();
    $res = $talk->_imap_cmd('DELETE', 0, \%handlers, "INBOX.Ω.B");
    $self->assert_str_equals('ok', $talk->get_last_completion_response());

    xlog $self, "Verify that there is no LIST response";
    $self->assert_null($results[0]);

    xlog $self, "DELETE mailbox with denormalized mailbox name";
    @results = ();
    $res = $talk->_imap_cmd('DELETE', 0, \%handlers, "INBOX.Ω");
    $self->assert_str_equals('ok', $talk->get_last_completion_response());

    xlog $self, "Verify that LIST response is returned with OLDNAME";
    $self->assert_str_equals("\\NonExistent", $results[0][0][0]);
    $self->assert_str_equals("INBOX.Ω", $results[0][2]);
    $self->assert_str_equals('OLDNAME', $results[0][3][0]);
    $self->assert_str_equals('INBOX.Ω', $results[0][3][1][0]);
}

1;
