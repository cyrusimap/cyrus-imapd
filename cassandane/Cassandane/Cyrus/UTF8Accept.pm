# SPDX-License-Identifier: BSD-3-Clause-CMU
# See COPYING file at the root of the distribution for more details.

package Cassandane::Cyrus::UTF8Accept;
use strict;
use warnings;
use Cwd qw(abs_path);
use File::Path qw(mkpath);
use DateTime;
use Data::Dumper;

use base qw(Cassandane::Cyrus::TestCase);
use Cassandane::Util::Log;
use Cassandane::Util::NetString;


sub new
{
    my $class = shift;
    my $config = Cassandane::Config->default()->clone();

    # Make sure the server will advertise support for UTF8=ACCEPT
    $config->set(reject8bit => 'off');
    $config->set(munge8bit => 'off');

    return $class->SUPER::new({ services => ['imap'], config => $config }, @_);
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

sub test_mboxname
    :NoAltNameSpace :min_version_3_9
{
    my ($self) = @_;

    my $talk = $self->{store}->get_client();

    xlog $self, "Create mailbox with mUTF7 encoded name";
    my $res = $talk->_imap_cmd('CREATE', 0, "", "INBOX.&JgA-");
    $self->assert_str_equals('ok', $talk->get_last_completion_response());

    xlog $self, "ENABLE UTF8=ACCEPT";
    $res = $talk->_imap_cmd('ENABLE', 0, "enabled", "UTF8=ACCEPT");
    $self->assert_num_equals(1, $res->{'utf8=accept'});

    xlog $self, "Create a mailbox with denormalized mailbox name";
    $res = $talk->_imap_cmd('CREATE', 0, "", "INBOX.Å");
    $self->assert_str_equals('ok', $talk->get_last_completion_response());

    xlog $self, "Create a child mailbox with normalized mailbox name";
    $res = $talk->_imap_cmd('CREATE', 0, "", "INBOX.Å.B");
    $self->assert_str_equals('ok', $talk->get_last_completion_response());

    xlog $self, "Verify that LIST responses use UTF8 mailbox names";
    $res = $talk->list("", "*");
    $self->assert_mailbox_structure($res, '.', {
        'INBOX'     => [qw( \\HasChildren )],
        'INBOX.☀'  => [qw( \\HasNoChildren )],
        'INBOX.Å'   => [qw( \\HasChildren )],
        "INBOX.Å.B" => [qw( \\HasNoChildren )],
    });

    xlog $self, "EXAMINE mailbox with UTF8 mailbox name";
    $res = $talk->_imap_cmd('EXAMINE', 0, "", "INBOX.☀");
    $self->assert_str_equals('ok', $talk->get_last_completion_response());
    $talk->unselect();

    xlog $self, "RENAME mailbox with denormalized mailbox names";
    $res = $talk->_imap_cmd('RENAME', 0, "", "INBOX.Å", "INBOX.Ω");
    $self->assert_str_equals('ok', $talk->get_last_completion_response());

    xlog $self, "DELETE a child mailbox with normalized mailbox name";
    $res = $talk->_imap_cmd('DELETE', 0, "", "INBOX.Ω.B");
    $self->assert_str_equals('ok', $talk->get_last_completion_response());

    xlog $self, "Verify that LIST responses use UTF8 mailbox names";
    $res = $talk->list("", "*");
    $self->assert_mailbox_structure($res, '.', {
        'INBOX'    => [qw( \\HasChildren )],
        'INBOX.☀' => [qw( \\HasNoChildren )],
        "INBOX.Ω"  => [qw( \\HasNoChildren )],
    });
}

sub test_append
    :NoAltNameSpace :min_version_3_9
{
    my ($self) = @_;

    my $talk = $self->{store}->get_client();

    my $MsgTxt = <<EOF;
From: blah\@xyz.com
To: whoever\@whereever.com
Subject: you are a ☀

Hello
EOF
    $MsgTxt =~ s/\n/\015\012/g;

    xlog $self, "Create mailbox with mUTF7 encoded name";
    my $res = $talk->_imap_cmd('CREATE', 0, "", "INBOX.&JgA-");
    $self->assert_str_equals('ok', $talk->get_last_completion_response());

    # Using UTF8 before UTF8=ACCEPT should fail
    xlog $self, "Attempt to append message with UTF-8 header to mailbox";
    $res = $talk->_imap_cmd('APPEND', 0, "", "INBOX.&JgA-",
                            'UTF8', [ { Literal => $MsgTxt } ]);
    $self->assert_str_equals('bad', $talk->get_last_completion_response());

    xlog $self, "ENABLE UTF8=ACCEPT";
    $res = $talk->_imap_cmd('ENABLE', 0, "enabled", "UTF8=ACCEPT");
    $self->assert_num_equals(1, $res->{'utf8=accept'});

    xlog $self, "Append message with UTF-8 header to mailbox";
    $res = $talk->_imap_cmd('APPEND', 0, "", "INBOX.☀",
                            'UTF8', [ { Literal => $MsgTxt } ]);
    $self->assert_str_equals('ok', $talk->get_last_completion_response());

    xlog $self, "Catenate message with UTF-8 header to mailbox";
    $res = $talk->_imap_cmd('APPEND', 0, "", "INBOX.☀",
                            'CATENATE', [ 'UTF8', [ { Literal => $MsgTxt } ] ]);
    $self->assert_str_equals('ok', $talk->get_last_completion_response());
}

sub test_search_sort_thread
    :NoAltNameSpace :min_version_3_9
{
    my ($self) = @_;

    xlog $self, "Make some messages";
    my $uid = 1;
    my %msgs;
    for (1..10)
    {
        $msgs{$uid} = $self->make_message("Message $uid");
        $msgs{$uid}->set_attribute('uid', $uid);
        $uid++;
    }

    my $talk = $self->{store}->get_client();

    # Verify that pre-ENABLE search/sort/thread work as expected
    my $uids = $talk->search('charset', 'us-ascii', 'all');
    $self->assert_str_equals('ok', $talk->get_last_completion_response());

    $uids = $talk->sort('(size)', 'us-ascii', 'all');
    $self->assert_str_equals('ok', $talk->get_last_completion_response());

    $uids = $talk->thread('orderedsubject', 'us-ascii', 'all');
    $self->assert_str_equals('ok', $talk->get_last_completion_response());

    xlog $self, "ENABLE UTF8=ACCEPT";
    my $res = $talk->_imap_cmd('ENABLE', 0, "enabled", "UTF8=ACCEPT");
    $self->assert_num_equals(1, $res->{'utf8=accept'});

    # Using CHARSET after UTF8=ACCEPT should fail
    $uids = $talk->search('charset', 'us-ascii', 'all');
    $self->assert_str_equals('bad', $talk->get_last_completion_response());

    $uids = $talk->search('all');
    $self->assert_str_equals('ok', $talk->get_last_completion_response());

    # Using CHARSET other than UTF-8 after UTF8=ACCEPT should fail
    $uids = $talk->sort('(size)', 'us-ascii', 'all');
    $self->assert_str_equals('bad', $talk->get_last_completion_response());

    $uids = $talk->sort('(size)', 'utf8', 'all');
    $self->assert_str_equals('ok', $talk->get_last_completion_response());

    # Using CHARSET other than UTF-8 after UTF8=ACCEPT should fail
    $uids = $talk->thread('orderedsubject', 'us-ascii', 'all');
    $self->assert_str_equals('bad', $talk->get_last_completion_response());

    $uids = $talk->thread('orderedsubject', 'utf8', 'all');
    $self->assert_str_equals('ok', $talk->get_last_completion_response());
}

1;
