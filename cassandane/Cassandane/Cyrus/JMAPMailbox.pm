#!/usr/bin/perl
#
#  Copyright (c) 2017 FastMail Pty Ltd  All rights reserved.
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
#  FASTMAIL PTY LTD DISCLAIMS ALL WARRANTIES WITH REGARD TO
#  THIS SOFTWARE, INCLUDING ALL IMPLIED WARRANTIES OF MERCHANTABILITY
#  AND FITNESS, IN NO EVENT SHALL OPERA SOFTWARE AUSTRALIA BE LIABLE
#  FOR ANY SPECIAL, INDIRECT OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES
#  WHATSOEVER RESULTING FROM LOSS OF USE, DATA OR PROFITS, WHETHER IN
#  AN ACTION OF CONTRACT, NEGLIGENCE OR OTHER TORTIOUS ACTION, ARISING
#  OUT OF OR IN CONNECTION WITH THE USE OR PERFORMANCE OF THIS SOFTWARE.
#

package Cassandane::Cyrus::JMAPMailbox;
use strict;
use warnings;
use DateTime;
use JSON::XS;
use Net::CalDAVTalk 0.09;
use Net::CardDAVTalk 0.03;
use Mail::JMAPTalk 0.13;
use Data::Dumper;
use Storable 'dclone';
use MIME::Base64 qw(encode_base64);
use Cwd qw(abs_path getcwd);

use lib '.';
use base qw(Cassandane::Cyrus::TestCase);
use Cassandane::Util::Log;

use charnames ':full';

sub new
{
    my ($class, @args) = @_;

    my $config = Cassandane::Config->default()->clone();
    $config->set(caldav_realm => 'Cassandane',
                 conversations => 'yes',
                 conversations_counted_flags => "\\Draft \\Flagged \$IsMailingList \$IsNotification \$HasAttachment",
                 httpmodules => 'carddav caldav jmap',
                 specialuse_extra => '\\XSpecialUse \\XChats \\XTemplates \\XNotes',
                 notesmailbox => 'Notes',
                 httpallowcompress => 'no');

    return $class->SUPER::new({
        config => $config,
        jmap => 1,
        adminstore => 1,
        services => [ 'imap', 'http' ]
    }, @args);
}

sub set_up
{
    my ($self) = @_;
    $self->SUPER::set_up();
    $self->{jmap}->DefaultUsing([
        'urn:ietf:params:jmap:core',
        'urn:ietf:params:jmap:mail',
    ]);
}

sub getinbox
{
    my ($self, $args) = @_;

    $args = {} unless $args;

    my $jmap = $self->{jmap};

    xlog $self, "get existing mailboxes";
    my $res = $jmap->CallMethods([['Mailbox/get', $args, "R1"]]);
    $self->assert_not_null($res);

    my %m = map { $_->{name} => $_ } @{$res->[0][1]{list}};
    return $m{"Inbox"};
}


sub test_mailbox_get
    :min_version_3_1 :needs_component_jmap :NoAltNameSpace
{
    my ($self) = @_;

    my $jmap = $self->{jmap};
    my $imaptalk = $self->{store}->get_client();

    $imaptalk->create("INBOX.foo")
        or die "Cannot create mailbox INBOX.foo: $@";

    $imaptalk->create("INBOX.foo.bar")
        or die "Cannot create mailbox INBOX.foo.bar: $@";

    xlog $self, "get existing mailboxes";
    my $res = $jmap->CallMethods([['Mailbox/get', {}, "R1"]]);
    $self->assert_not_null($res);
    $self->assert_str_equals('Mailbox/get', $res->[0][0]);
    $self->assert_str_equals('R1', $res->[0][2]);

    my %m = map { $_->{name} => $_ } @{$res->[0][1]{list}};
    $self->assert_num_equals(3, scalar keys %m);
    my $inbox = $m{"Inbox"};
    my $foo = $m{"foo"};
    my $bar = $m{"bar"};

    # INBOX
    $self->assert_str_equals("Inbox", $inbox->{name});
    $self->assert_null($inbox->{parentId});
    $self->assert_str_equals("inbox", $inbox->{role});
    $self->assert_num_equals(1, $inbox->{sortOrder});
    $self->assert_equals(JSON::true, $inbox->{myRights}->{mayReadItems});
    $self->assert_equals(JSON::true, $inbox->{myRights}->{mayAddItems});
    $self->assert_equals(JSON::true, $inbox->{myRights}->{mayRemoveItems});
    $self->assert_equals(JSON::true, $inbox->{myRights}->{mayCreateChild});
    $self->assert_equals(JSON::false, $inbox->{myRights}->{mayRename});
    $self->assert_equals(JSON::false, $inbox->{myRights}->{mayDelete});
    $self->assert_equals(JSON::true, $inbox->{myRights}->{maySetSeen});
    $self->assert_equals(JSON::true, $inbox->{myRights}->{maySetKeywords});
    $self->assert_equals(JSON::true, $inbox->{myRights}->{maySubmit});
    $self->assert_num_equals(0, $inbox->{totalEmails});
    $self->assert_num_equals(0, $inbox->{unreadEmails});
    $self->assert_num_equals(0, $inbox->{totalThreads});
    $self->assert_num_equals(0, $inbox->{unreadThreads});

    # INBOX.foo
    $self->assert_str_equals("foo", $foo->{name});
    $self->assert_null($foo->{parentId});
    $self->assert_null($foo->{role});
    $self->assert_num_equals(10, $foo->{sortOrder});
    $self->assert_equals(JSON::true, $foo->{myRights}->{mayReadItems});
    $self->assert_equals(JSON::true, $foo->{myRights}->{mayAddItems});
    $self->assert_equals(JSON::true, $foo->{myRights}->{mayRemoveItems});
    $self->assert_equals(JSON::true, $foo->{myRights}->{mayCreateChild});
    $self->assert_equals(JSON::true, $foo->{myRights}->{mayRename});
    $self->assert_equals(JSON::true, $foo->{myRights}->{mayDelete});
    $self->assert_num_equals(0, $foo->{totalEmails});
    $self->assert_num_equals(0, $foo->{unreadEmails});
    $self->assert_num_equals(0, $foo->{totalThreads});
    $self->assert_num_equals(0, $foo->{unreadThreads});

    # INBOX.foo.bar
    $self->assert_str_equals("bar", $bar->{name});
    $self->assert_str_equals($foo->{id}, $bar->{parentId});
    $self->assert_null($bar->{role});
    $self->assert_num_equals(10, $bar->{sortOrder});
    $self->assert_equals(JSON::true, $bar->{myRights}->{mayReadItems});
    $self->assert_equals(JSON::true, $bar->{myRights}->{mayAddItems});
    $self->assert_equals(JSON::true, $bar->{myRights}->{mayRemoveItems});
    $self->assert_equals(JSON::true, $bar->{myRights}->{mayCreateChild});
    $self->assert_equals(JSON::true, $bar->{myRights}->{mayRename});
    $self->assert_equals(JSON::true, $bar->{myRights}->{mayDelete});
    $self->assert_num_equals(0, $bar->{totalEmails});
    $self->assert_num_equals(0, $bar->{unreadEmails});
    $self->assert_num_equals(0, $bar->{totalThreads});
    $self->assert_num_equals(0, $bar->{unreadThreads});
}

sub test_mailbox_get_inbox_sub
    :min_version_3_1 :needs_component_jmap :NoAltNameSpace
{
    my ($self) = @_;

    my $jmap = $self->{jmap};
    my $imaptalk = $self->{store}->get_client();

    $imaptalk->create("INBOX.INBOX.foo")
        or die "Cannot create mailbox INBOX.INBOX.foo: $@";

    $imaptalk->create("INBOX.INBOX.foo.bar")
        or die "Cannot create mailbox INBOX.INBOX.foo.bar: $@";

    xlog $self, "get existing mailboxes";
    my $res = $jmap->CallMethods([['Mailbox/get', {}, "R1"]]);
    $self->assert_not_null($res);
    $self->assert_str_equals('Mailbox/get', $res->[0][0]);
    $self->assert_str_equals('R1', $res->[0][2]);

    my %m = map { $_->{name} => $_ } @{$res->[0][1]{list}};
    $self->assert_num_equals(3, scalar keys %m);
    my $inbox = $m{"Inbox"};
    my $foo = $m{"foo"};
    my $bar = $m{"bar"};

    # INBOX
    $self->assert_str_equals("Inbox", $inbox->{name});
    $self->assert_null($inbox->{parentId});
    $self->assert_str_equals("inbox", $inbox->{role});
    $self->assert_num_equals(1, $inbox->{sortOrder});
    $self->assert_equals(JSON::true, $inbox->{myRights}->{mayReadItems});
    $self->assert_equals(JSON::true, $inbox->{myRights}->{mayAddItems});
    $self->assert_equals(JSON::true, $inbox->{myRights}->{mayRemoveItems});
    $self->assert_equals(JSON::true, $inbox->{myRights}->{mayCreateChild});
    $self->assert_equals(JSON::false, $inbox->{myRights}->{mayRename});
    $self->assert_equals(JSON::false, $inbox->{myRights}->{mayDelete});
    $self->assert_equals(JSON::true, $inbox->{myRights}->{maySetSeen});
    $self->assert_equals(JSON::true, $inbox->{myRights}->{maySetKeywords});
    $self->assert_equals(JSON::true, $inbox->{myRights}->{maySubmit});
    $self->assert_num_equals(0, $inbox->{totalEmails});
    $self->assert_num_equals(0, $inbox->{unreadEmails});
    $self->assert_num_equals(0, $inbox->{totalThreads});
    $self->assert_num_equals(0, $inbox->{unreadThreads});

    # INBOX.INBOX.foo
    $self->assert_str_equals("foo", $foo->{name});
    $self->assert_str_equals($inbox->{id}, $foo->{parentId});
    $self->assert_null($foo->{role});
    $self->assert_num_equals(10, $foo->{sortOrder});
    $self->assert_equals(JSON::true, $foo->{myRights}->{mayReadItems});
    $self->assert_equals(JSON::true, $foo->{myRights}->{mayAddItems});
    $self->assert_equals(JSON::true, $foo->{myRights}->{mayRemoveItems});
    $self->assert_equals(JSON::true, $foo->{myRights}->{mayCreateChild});
    $self->assert_equals(JSON::true, $foo->{myRights}->{mayRename});
    $self->assert_equals(JSON::true, $foo->{myRights}->{mayDelete});
    $self->assert_num_equals(0, $foo->{totalEmails});
    $self->assert_num_equals(0, $foo->{unreadEmails});
    $self->assert_num_equals(0, $foo->{totalThreads});
    $self->assert_num_equals(0, $foo->{unreadThreads});

    # INBOX.INBOX.foo.bar
    $self->assert_str_equals("bar", $bar->{name});
    $self->assert_str_equals($foo->{id}, $bar->{parentId});
    $self->assert_null($bar->{role});
    $self->assert_num_equals(10, $bar->{sortOrder});
    $self->assert_equals(JSON::true, $bar->{myRights}->{mayReadItems});
    $self->assert_equals(JSON::true, $bar->{myRights}->{mayAddItems});
    $self->assert_equals(JSON::true, $bar->{myRights}->{mayRemoveItems});
    $self->assert_equals(JSON::true, $bar->{myRights}->{mayCreateChild});
    $self->assert_equals(JSON::true, $bar->{myRights}->{mayRename});
    $self->assert_equals(JSON::true, $bar->{myRights}->{mayDelete});
    $self->assert_num_equals(0, $bar->{totalEmails});
    $self->assert_num_equals(0, $bar->{unreadEmails});
    $self->assert_num_equals(0, $bar->{totalThreads});
    $self->assert_num_equals(0, $bar->{unreadThreads});
}

sub test_mailbox_get_specialuse
    :min_version_3_1 :needs_component_jmap :NoAltNameSpace
{
    my ($self) = @_;

    my $jmap = $self->{jmap};
    my $imaptalk = $self->{store}->get_client();

    $imaptalk->create("INBOX.Archive", "(USE (\\Archive))") || die;
    $imaptalk->create("INBOX.Drafts", "(USE (\\Drafts))") || die;
    $imaptalk->create("INBOX.Spam", "(USE (\\Junk))") || die;
    $imaptalk->create("INBOX.Sent", "(USE (\\Sent))") || die;
    $imaptalk->create("INBOX.Trash", "(USE (\\Trash))") || die;

    xlog $self, "get mailboxes";
    my $res = $jmap->CallMethods([['Mailbox/get', {}, "R1"]]);
    $self->assert_not_null($res);
    $self->assert_str_equals('Mailbox/get', $res->[0][0]);
    $self->assert_str_equals('R1', $res->[0][2]);

    my %m = map { $_->{name} => $_ } @{$res->[0][1]{list}};
    my $inbox = $m{"Inbox"};
    my $archive = $m{"Archive"};
    my $drafts = $m{"Drafts"};
    my $junk = $m{"Spam"};
    my $sent = $m{"Sent"};
    my $trash = $m{"Trash"};

    $self->assert_str_equals("Archive", $archive->{name});
    $self->assert_str_equals("archive", $archive->{role});

    $self->assert_str_equals("Drafts", $drafts->{name});
    $self->assert_null($drafts->{parentId});
    $self->assert_str_equals("drafts", $drafts->{role});

    $self->assert_str_equals("Spam", $junk->{name});
    $self->assert_null($junk->{parentId});
    $self->assert_str_equals("junk", $junk->{role});

    $self->assert_str_equals("Sent", $sent->{name});
    $self->assert_null($sent->{parentId});
    $self->assert_str_equals("sent", $sent->{role});

    $self->assert_str_equals("Trash", $trash->{name});
    $self->assert_null($trash->{parentId});
    $self->assert_str_equals("trash", $trash->{role});
}

sub test_mailbox_get_properties
    :min_version_3_1 :needs_component_jmap
{
    my ($self) = @_;

    my $jmap = $self->{jmap};

    xlog $self, "get mailboxes with name property";
    my $res = $jmap->CallMethods([['Mailbox/get', { properties => ["name"]}, "R1"]]);
    $self->assert_not_null($res);
    $self->assert_str_equals('Mailbox/get', $res->[0][0]);
    $self->assert_str_equals('R1', $res->[0][2]);

    my $inbox = $res->[0][1]{list}[0];
    $self->assert_str_equals("Inbox", $inbox->{name});
    $self->assert_num_equals(2, scalar keys %{$inbox}); # id and name

    xlog $self, "get mailboxes with erroneous property";
    $res = $jmap->CallMethods([['Mailbox/get', { properties => ["name", 123]}, "R1"]]);
    $self->assert_not_null($res);
    $self->assert_str_equals('error', $res->[0][0]);
    $self->assert_str_equals('R1', $res->[0][2]);

    my $err = $res->[0][1];
    $self->assert_str_equals("invalidArguments", $err->{type});
    $self->assert_str_equals("properties[1]", $err->{arguments}[0]);

    xlog $self, "get mailboxes with unknown property";
    $res = $jmap->CallMethods([['Mailbox/get', { properties => ["name", "123"]}, "R1"]]);
    $self->assert_not_null($res);
    $self->assert_str_equals('error', $res->[0][0]);
    $self->assert_str_equals('R1', $res->[0][2]);

    $err = $res->[0][1];
    $self->assert_str_equals("invalidArguments", $err->{type});
    $self->assert_str_equals("properties[1:123]", $err->{arguments}[0]);
}

sub test_mailbox_get_ids
    :min_version_3_1 :needs_component_jmap
{
    my ($self) = @_;

    my $jmap = $self->{jmap};
    my $imaptalk = $self->{store}->get_client();

    $imaptalk->create("INBOX.foo") || die;

    xlog $self, "get all mailboxes";
    my $res = $jmap->CallMethods([['Mailbox/get', { }, "R1"]]);
    $self->assert_not_null($res);
    $self->assert_str_equals('Mailbox/get', $res->[0][0]);
    $self->assert_str_equals('R1', $res->[0][2]);

    my %m = map { $_->{name} => $_ } @{$res->[0][1]{list}};
    my $inbox = $m{"Inbox"};
    my $foo = $m{"foo"};
    $self->assert_not_null($inbox);
    $self->assert_not_null($foo);

    xlog $self, "get foo and unknown mailbox";
    $res = $jmap->CallMethods([['Mailbox/get', { ids => [$foo->{id}, "nope"] }, "R1"]]);
    $self->assert_str_equals($foo->{id}, $res->[0][1]{list}[0]->{id});
    $self->assert_str_equals("nope", $res->[0][1]{notFound}[0]);

    xlog $self, "get mailbox with erroneous id";
    $res = $jmap->CallMethods([['Mailbox/get', { ids => [123]}, "R1"]]);
    $self->assert_not_null($res);
    $self->assert_str_equals('error', $res->[0][0]);
    $self->assert_str_equals('R1', $res->[0][2]);

    my $err = $res->[0][1];
    $self->assert_str_equals('invalidArguments', $err->{type});
    $self->assert_str_equals('ids[0]', $err->{arguments}[0]);
}

sub test_mailbox_get_nocalendars
    :min_version_3_1 :needs_component_jmap :JMAPExtensions
{
    my ($self) = @_;

    # asserts that changes on special mailboxes such as calendars
    # aren't listed as regular mailboxes

    my $jmap = $self->{jmap};
    my $caldav = $self->{caldav};

    my $using = [
        'urn:ietf:params:jmap:core',
        'urn:ietf:params:jmap:mail',
        'urn:ietf:params:jmap:calendars',
        'https://cyrusimap.org/ns/jmap/calendars',
    ];

    xlog $self, "get existing mailboxes";
    my $res = $jmap->CallMethods([['Mailbox/get', {}, "R1"]], $using);
    $self->assert_not_null($res);
    $self->assert_str_equals('Mailbox/get', $res->[0][0]);
    $self->assert_str_equals('R1', $res->[0][2]);
    my $mboxes = $res->[0][1]{list};

    xlog $self, "create calendar";
    $res = $jmap->CallMethods([
            ['Calendar/set', { create => { "1" => {
                            name => "foo",
                            color => "coral",
                            sortOrder => 2,
                            isVisible => \1
             }}}, "R1"]
    ], $using);
    $self->assert_not_null($res->[0][1]{created});

    xlog $self, "get updated mailboxes";
    $res = $jmap->CallMethods([['Mailbox/get', {}, "R1"]], $using);
    $self->assert_not_null($res);
    $self->assert_num_equals(scalar @{$mboxes}, scalar @{$res->[0][1]{list}});
}

sub test_mailbox_get_shared
    :min_version_3_1 :needs_component_jmap :NoAltNameSpace
{
    my ($self) = @_;

    my $jmap = $self->{jmap};

    my $imaptalk = $self->{store}->get_client();
    my $admintalk = $self->{adminstore}->get_client();

    # Create user and share mailbox
    $self->{instance}->create_user("foo");
    $admintalk->setacl("user.foo", "cassandane", "lr") or die;
    $admintalk->create("user.foo.box1") or die;
    $admintalk->setacl("user.foo.box1", "cassandane", "lr") or die;

    $self->{instance}->create_user("foobar");
    $admintalk->setacl("user.foobar", "cassandane", "lr") or die;
    $admintalk->create("user.foobar.box2") or die;
    $admintalk->setacl("user.foobar.box2", "cassandane", "lr") or die;

    # Create user but do not share mailbox
    $self->{instance}->create_user("bar");

    # Get our own Inbox id
    my $inbox = $self->getinbox();

    my $foostore = Cassandane::IMAPMessageStore->new(
        host => $self->{store}->{host},
        port => $self->{store}->{port},
        username => 'foo',
        password => 'testpw',
        verbose => $self->{store}->{verbose},
    );
    my $footalk = $foostore->get_client();

    $footalk->setmetadata("INBOX.box1", "/private/specialuse", "\\Trash");
    $self->assert_equals('ok', $footalk->get_last_completion_response());

    xlog $self, "get mailboxes for foo account";
    my $res = $jmap->CallMethods([['Mailbox/get', { accountId => "foo" }, "R1"]]);
    $self->assert_num_equals(2, scalar @{$res->[0][1]{list}});

    my %m = map { lc($_->{name}) => $_ } @{$res->[0][1]{list}};
    my $fooInbox = $m{'inbox'};
    $self->assert_str_not_equals($inbox->{id}, $fooInbox->{id});
    $self->assert_str_equals('inbox', $fooInbox->{role});
    my $box1 = $m{'box1'};
    $self->assert_str_equals('trash', $box1->{role});

    xlog $self, "get mailboxes for inaccessible bar account";
    $res = $jmap->CallMethods([['Mailbox/get', { accountId => "bar" }, "R1"]]);
    $self->assert_str_equals("error", $res->[0][0]);
    $self->assert_str_equals("accountNotFound", $res->[0][1]{type});

    xlog $self, "get mailboxes for inexistent account";
    $res = $jmap->CallMethods([['Mailbox/get', { accountId => "baz" }, "R1"]]);
    $self->assert_str_equals("error", $res->[0][0]);
    $self->assert_str_equals("accountNotFound", $res->[0][1]{type});

    xlog $self, "get mailboxes for visible account";
    $res = $jmap->CallMethods([['Mailbox/get', { accountId => "foobar" }, "R1"]]);
    $self->assert_num_equals(2, scalar @{$res->[0][1]{list}});
    %m = map { lc($_->{name}) => $_ } @{$res->[0][1]{list}};
    $self->assert_not_null($m{inbox});
    $self->assert_not_null($m{box2});
    $self->assert_null($m{inbox}{parentId});
    $self->assert_null($m{box2}{parentId});

    $self->assert_equals(JSON::true, $m{inbox}{myRights}{mayReadItems});
    $self->assert_equals(JSON::true, $m{box2}{myRights}{mayReadItems});
    $self->assert_equals(JSON::false, $m{inbox}{myRights}{mayAddItems});
    $self->assert_equals(JSON::false, $m{box2}{myRights}{mayAddItems});
}

sub test_mailbox_get_shared_inbox
    :min_version_3_1 :needs_component_jmap :NoAltNameSpace
{
    my ($self) = @_;

    my $jmap = $self->{jmap};

    my $imaptalk = $self->{store}->get_client();
    my $admintalk = $self->{adminstore}->get_client();

    # Create user and share mailbox
    $self->{instance}->create_user("foo");
    $admintalk->setacl("user.foo", "cassandane", "lr") or die;
    $admintalk->create("user.foo.box1") or die;
    $admintalk->setacl("user.foo.box1", "cassandane", "lr") or die;

    $self->{instance}->create_user("foobar");
    $admintalk->create("user.foobar.INBOX.box2") or die;
    $admintalk->setacl("user.foobar.INBOX.box2", "cassandane", "lr") or die;

    # Create user but do not share mailbox
    $self->{instance}->create_user("bar");

    # Get our own Inbox id
    my $inbox = $self->getinbox();

    my $foostore = Cassandane::IMAPMessageStore->new(
        host => $self->{store}->{host},
        port => $self->{store}->{port},
        username => 'foo',
        password => 'testpw',
        verbose => $self->{store}->{verbose},
    );
    my $footalk = $foostore->get_client();

    $footalk->setmetadata("INBOX.box1", "/private/specialuse", "\\Trash");
    $self->assert_equals('ok', $footalk->get_last_completion_response());

    xlog $self, "get mailboxes for foo account";
    my $res = $jmap->CallMethods([['Mailbox/get', { accountId => "foo" }, "R1"]]);
    $self->assert_num_equals(2, scalar @{$res->[0][1]{list}});

    my %m = map { lc($_->{name}) => $_ } @{$res->[0][1]{list}};
    my $fooInbox = $m{'inbox'};
    $self->assert_str_not_equals($inbox->{id}, $fooInbox->{id});
    $self->assert_str_equals('inbox', $fooInbox->{role});
    my $box1 = $m{'box1'};
    $self->assert_str_equals('trash', $box1->{role});

    xlog $self, "get mailboxes for inaccessible bar account";
    $res = $jmap->CallMethods([['Mailbox/get', { accountId => "bar" }, "R1"]]);
    $self->assert_str_equals("error", $res->[0][0]);
    $self->assert_str_equals("accountNotFound", $res->[0][1]{type});

    xlog $self, "get mailboxes for inexistent account";
    $res = $jmap->CallMethods([['Mailbox/get', { accountId => "baz" }, "R1"]]);
    $self->assert_str_equals("error", $res->[0][0]);
    $self->assert_str_equals("accountNotFound", $res->[0][1]{type});

    xlog $self, "get mailboxes for visible account";
    $res = $jmap->CallMethods([['Mailbox/get', { accountId => "foobar" }, "R1"]]);
    %m = map { lc($_->{name}) => $_ } @{$res->[0][1]{list}};
    $self->assert_num_equals(2, scalar @{$res->[0][1]{list}});
    $self->assert_not_null($m{inbox});
    $self->assert_not_null($m{box2});
    $self->assert_equals(JSON::false, $m{inbox}{myRights}{mayReadItems});
    $self->assert_equals(JSON::true, $m{box2}{myRights}{mayReadItems});
    $self->assert_equals(JSON::false, $m{inbox}{myRights}{mayAddItems});
    $self->assert_equals(JSON::false, $m{box2}{myRights}{mayAddItems});
    $self->assert_null($m{inbox}{parentId});
    $self->assert_str_equals($m{inbox}{id}, $m{box2}{parentId});
}

sub test_mailbox_query
    :min_version_3_1 :needs_component_jmap
{
    my ($self) = @_;

    my $jmap = $self->{jmap};
    my $imaptalk = $self->{store}->get_client();

    xlog $self, "list mailboxes without filter";
    my $res = $jmap->CallMethods([['Mailbox/query', {}, "R1"]]);
    $self->assert_num_equals(1, scalar @{$res->[0][1]->{ids}});
    $self->assert_str_equals('Mailbox/query', $res->[0][0]);
    $self->assert_str_equals('R1', $res->[0][2]);

    xlog $self, "create mailboxes";
    $imaptalk->create("INBOX.A") || die;
    $imaptalk->create("INBOX.B") || die;

    xlog $self, "fetch mailboxes";
    $res = $jmap->CallMethods([['Mailbox/get', { }, 'R1' ]]);
    my %mboxids = map { $_->{name} => $_->{id} } @{$res->[0][1]{list}};

    xlog $self, "list mailboxes without filter and sort by name ascending";
    $res = $jmap->CallMethods([['Mailbox/query', {
        sort => [{ property => "name" }]},
    "R1"]]);
    $self->assert_num_equals(3, scalar @{$res->[0][1]->{ids}});
    $self->assert_str_equals($mboxids{'A'}, $res->[0][1]{ids}[0]);
    $self->assert_str_equals($mboxids{'B'}, $res->[0][1]{ids}[1]);
    $self->assert_str_equals($mboxids{'Inbox'}, $res->[0][1]{ids}[2]);

    xlog $self, "list mailboxes without filter and sort by name descending";
    $res = $jmap->CallMethods([['Mailbox/query', {
        sort => [{ property => "name", isAscending => JSON::false}],
    }, "R1"]]);
    $self->assert_num_equals(3, scalar @{$res->[0][1]->{ids}});
    $self->assert_str_equals($mboxids{'Inbox'}, $res->[0][1]{ids}[0]);
    $self->assert_str_equals($mboxids{'B'}, $res->[0][1]{ids}[1]);
    $self->assert_str_equals($mboxids{'A'}, $res->[0][1]{ids}[2]);

    xlog $self, "filter mailboxes by hasAnyRole == true";
    $res = $jmap->CallMethods([['Mailbox/query', {filter => {hasAnyRole => JSON::true}}, "R1"]]);
    $self->assert_num_equals(1, scalar @{$res->[0][1]->{ids}});
    $self->assert_str_equals($mboxids{'Inbox'}, $res->[0][1]{ids}[0]);

    xlog $self, "filter mailboxes by hasAnyRole == false";
    $res = $jmap->CallMethods([['Mailbox/query', {
        filter => {hasAnyRole => JSON::false},
        sort => [{ property => "name"}],
    }, "R1"]]);
    $self->assert_num_equals(2, scalar @{$res->[0][1]->{ids}});
    $self->assert_str_equals($mboxids{'A'}, $res->[0][1]{ids}[0]);
    $self->assert_str_equals($mboxids{'B'}, $res->[0][1]{ids}[1]);

    xlog $self, "create mailbox underneath A";
    $imaptalk->create("INBOX.A.AA") || die;

    xlog $self, "(re)fetch mailboxes";
    $res = $jmap->CallMethods([['Mailbox/get', { }, 'R1' ]]);
    %mboxids = map { $_->{name} => $_->{id} } @{$res->[0][1]{list}};

    xlog $self, "filter mailboxes by parentId";
    $res = $jmap->CallMethods([['Mailbox/query', {filter => {parentId => $mboxids{'A'}}}, "R1"]]);
    $self->assert_num_equals(1, scalar @{$res->[0][1]->{ids}});
    $self->assert_str_equals($mboxids{'AA'}, $res->[0][1]{ids}[0]);

    # Without windowing the name-sorted results are: A, AA, B, Inbox

    xlog $self, "list mailboxes (with limit)";
    $res = $jmap->CallMethods([
        ['Mailbox/query', {
            sort => [{ property => "name" }],
            limit => 1,
        }, "R1"]
    ]);
    $self->assert_num_equals(1, scalar @{$res->[0][1]->{ids}});
    $self->assert_str_equals($mboxids{'A'}, $res->[0][1]{ids}[0]);
    $self->assert_num_equals(0, $res->[0][1]->{position});

    xlog $self, "list mailboxes (with anchor and limit)";
    $res = $jmap->CallMethods([
        ['Mailbox/query', {
            sort => [{ property => "name" }],
            anchor => $mboxids{'B'},
            limit => 2,
        }, "R1"]
    ]);
    $self->assert_num_equals(2, scalar @{$res->[0][1]->{ids}});
    $self->assert_str_equals($mboxids{'B'}, $res->[0][1]{ids}[0]);
    $self->assert_str_equals($mboxids{'Inbox'}, $res->[0][1]{ids}[1]);
    $self->assert_num_equals(2, $res->[0][1]->{position});

    xlog $self, "list mailboxes (with positive anchor offset)";
    $res = $jmap->CallMethods([
        ['Mailbox/query', {
            sort => [{ property => "name" }],
            anchor => $mboxids{'AA'},
            anchorOffset => 1,
        }, "R1"]
    ]);
    $self->assert_num_equals(2, scalar @{$res->[0][1]->{ids}});
    $self->assert_str_equals($mboxids{'B'}, $res->[0][1]{ids}[0]);
    $self->assert_str_equals($mboxids{'Inbox'}, $res->[0][1]{ids}[1]);
    $self->assert_num_equals(2, $res->[0][1]->{position});

    xlog $self, "list mailboxes (with negative anchor offset)";
    $res = $jmap->CallMethods([
        ['Mailbox/query', {
            sort => [{ property => "name" }],
            anchor => $mboxids{'B'},
            anchorOffset => -1,
        }, "R1"]
    ]);
    $self->assert_num_equals(3, scalar @{$res->[0][1]->{ids}});
    $self->assert_str_equals($mboxids{'AA'}, $res->[0][1]{ids}[0]);
    $self->assert_str_equals($mboxids{'B'}, $res->[0][1]{ids}[1]);
    $self->assert_str_equals($mboxids{'Inbox'}, $res->[0][1]{ids}[2]);
    $self->assert_num_equals(1, $res->[0][1]->{position});

    xlog $self, "list mailboxes (with position)";
    $res = $jmap->CallMethods([
        ['Mailbox/query', {
            sort => [{ property => "name" }],
            position => 3,
        }, "R1"]
    ]);
    $self->assert_num_equals(1, scalar @{$res->[0][1]->{ids}});
    $self->assert_str_equals($mboxids{'Inbox'}, $res->[0][1]{ids}[0]);

    xlog $self, "list mailboxes (with negative position)";
    $res = $jmap->CallMethods([
        ['Mailbox/query', {
            sort => [{ property => "name" }],
            position => -2,
        }, "R1"]
    ]);
    $self->assert_num_equals(2, scalar @{$res->[0][1]->{ids}});
    $self->assert_str_equals($mboxids{'B'}, $res->[0][1]{ids}[0]);
    $self->assert_str_equals($mboxids{'Inbox'}, $res->[0][1]{ids}[1]);
}

sub test_mailbox_query_sortastree
    :min_version_3_1 :needs_component_jmap :NoAltNameSpace
{
    my ($self) = @_;

    my $jmap = $self->{jmap};
    my $imaptalk = $self->{store}->get_client();

    $imaptalk->create("INBOX.A") || die;
    $imaptalk->create("INBOX.A.A1") || die;
    $imaptalk->create("INBOX.A.A2") || die;
    $imaptalk->create("INBOX.A.A2.A2A") || die;
    $imaptalk->create("INBOX.B") || die;
    $imaptalk->create("INBOX.C") || die;
    $imaptalk->create("INBOX.C.C1") || die;
    $imaptalk->create("INBOX.C.C1.C1A") || die;
    $imaptalk->create("INBOX.C.C2") || die;
    $imaptalk->create("INBOX.D") || die;

    my $res = $jmap->CallMethods([['Mailbox/get', { properties => ["name"] }, 'R1' ]]);
    $self->assert_num_equals(11, scalar @{$res->[0][1]{list}});
    my %mboxIds = map { $_->{name} => $_->{id} } @{$res->[0][1]{list}};

    $res = $jmap->CallMethods([
        ['Mailbox/query', {
            sortAsTree => JSON::true,
            sort => [{ property => 'name' }]
        }, "R1"]
    ]);

    my $wantMboxIds = [
        $mboxIds{'A'}, $mboxIds{'A1'}, $mboxIds{'A2'}, $mboxIds{'A2A'},
        $mboxIds{'B'},
        $mboxIds{'C'}, $mboxIds{'C1'}, $mboxIds{'C1A'}, $mboxIds{'C2'},
        $mboxIds{'D'},
        $mboxIds{'Inbox'},
    ];
    $self->assert_deep_equals($wantMboxIds, $res->[0][1]->{ids});

    $res = $jmap->CallMethods([
        ['Mailbox/query', {
            sortAsTree => JSON::true,
            sort => [{ property => 'name', isAscending => JSON::false }]
        }, "R1"]
    ]);
    $wantMboxIds = [
        $mboxIds{'Inbox'},
        $mboxIds{'D'},
        $mboxIds{'C'}, $mboxIds{'C2'}, $mboxIds{'C1'}, $mboxIds{'C1A'},
        $mboxIds{'B'},
        $mboxIds{'A'}, $mboxIds{'A2'}, $mboxIds{'A2A'}, $mboxIds{'A1'},
    ];
    $self->assert_deep_equals($wantMboxIds, $res->[0][1]->{ids});
}

sub test_mailbox_query_filterastree
    :min_version_3_1 :needs_component_jmap :NoAltNameSpace
{
    my ($self) = @_;

    my $jmap = $self->{jmap};
    my $imaptalk = $self->{store}->get_client();

    $imaptalk->create("INBOX.A") || die;
    $imaptalk->create("INBOX.A.A1") || die;
    $imaptalk->create("INBOX.B") || die;
    $imaptalk->create("INBOX.B.X") || die;
    $imaptalk->create("INBOX.C") || die;
    $imaptalk->create("INBOX.C.C1") || die;

    my $res = $jmap->CallMethods([['Mailbox/get', { properties => ["name"] }, 'R1' ]]);
    $self->assert_num_equals(7, scalar @{$res->[0][1]{list}});
    my %mboxIds = map { $_->{name} => $_->{id} } @{$res->[0][1]{list}};

    $res = $jmap->CallMethods([
        ['Mailbox/query', {
            filter => {
                operator => 'NOT',
                conditions => [{
                    name => 'B'
                }]
            },
            filterAsTree => JSON::true,
            sort => [{ property => 'name' }],
            sortAsTree => JSON::true,
        }, "R1"]
    ]);

    my $wantMboxIds = [
        $mboxIds{'A'}, $mboxIds{'A1'}, $mboxIds{'C'}, $mboxIds{'C1'},
    ];
    $self->assert_deep_equals($wantMboxIds, $res->[0][1]->{ids});

    $res = $jmap->CallMethods([
        ['Mailbox/query', {
            filter => {
                name => '1',
            },
            filterAsTree => JSON::true,
            sort => [{ property => 'name' }],
            sortAsTree => JSON::true,
        }, "R1"]
    ]);

    $wantMboxIds = [ ]; # Can't match anything because top-level is missing
    $self->assert_deep_equals($wantMboxIds, $res->[0][1]->{ids});
}

sub test_mailbox_query_limit_zero
    :min_version_3_1 :needs_component_jmap
{
    my ($self) = @_;

    my $jmap = $self->{jmap};
    my $imaptalk = $self->{store}->get_client();

    xlog $self, "list mailboxes with limit 0";
    my $res = $jmap->CallMethods([
        ['Mailbox/query', { limit => 0 }, "R1"]
    ]);
    $self->assert_deep_equals([], $res->[0][1]->{ids});
}

sub test_mailbox_query_parentid_null
    :min_version_3_1 :needs_component_jmap :NoAltNameSpace
{
    my ($self) = @_;

    my $jmap = $self->{jmap};
    my $imaptalk = $self->{store}->get_client();

    xlog $self, "create mailbox tree";
    $imaptalk->create("INBOX.Ham") || die;
    $imaptalk->create("INBOX.Spam", "(USE (\\Junk))") || die;
    $imaptalk->create("INBOX.Ham.Zonk") || die;
    $imaptalk->create("INBOX.Ham.Bonk") || die;

    xlog $self, "(re)fetch mailboxes";
    my $res = $jmap->CallMethods([['Mailbox/get', { properties => ["name"] }, 'R1' ]]);
    $self->assert_num_equals(5, scalar @{$res->[0][1]{list}});
    my %mboxids = map { $_->{name} => $_->{id} } @{$res->[0][1]{list}};
    $self->assert(exists $mboxids{'Inbox'});

    xlog $self, "list mailboxes, filtered by parentId null";
    $res = $jmap->CallMethods([
        ['Mailbox/query', {
            filter => { parentId => undef },
            sort => [{ property => "name" }],
        }, "R1"]
    ]);
    $self->assert_num_equals(3, scalar @{$res->[0][1]->{ids}});
    $self->assert_str_equals($mboxids{'Ham'}, $res->[0][1]{ids}[0]);
    $self->assert_str_equals($mboxids{'Inbox'}, $res->[0][1]{ids}[1]);
    $self->assert_str_equals($mboxids{'Spam'}, $res->[0][1]{ids}[2]);
}

sub test_mailbox_query_name
    :min_version_3_1 :needs_component_jmap :NoAltNameSpace
{
    my ($self) = @_;

    my $jmap = $self->{jmap};
    my $imaptalk = $self->{store}->get_client();

    $imaptalk->create("INBOX.Ham") || die;
    $imaptalk->create("INBOX.Spam", "(USE (\\Junk))") || die;
    $imaptalk->create("INBOX.Ham.Zonk") || die;
    $imaptalk->create("INBOX.Ham.Bonk") || die;

    my $res = $jmap->CallMethods([['Mailbox/get', { properties => ["name"] }, 'R1' ]]);
    $self->assert_num_equals(5, scalar @{$res->[0][1]{list}});
    my %mboxids = map { $_->{name} => $_->{id} } @{$res->[0][1]{list}};
    $self->assert(exists $mboxids{'Inbox'});

    $res = $jmap->CallMethods([
        ['Mailbox/query', {
            filter => { name => 'onk' },
            sort => [{ property => "name" }],
        }, "R1"]
    ]);
    $self->assert_num_equals(2, scalar @{$res->[0][1]->{ids}});
    $self->assert_str_equals($mboxids{'Bonk'}, $res->[0][1]{ids}[0]);
    $self->assert_str_equals($mboxids{'Zonk'}, $res->[0][1]{ids}[1]);
}

sub test_mailbox_query_filteroperator
    :min_version_3_1 :needs_component_jmap
{
    my ($self) = @_;
    return;

    my $jmap = $self->{jmap};
    my $imaptalk = $self->{store}->get_client();

    xlog $self, "create mailbox tree";
    $imaptalk->create("INBOX.Ham") || die;
    $imaptalk->create("INBOX.Spam", "(USE (\\Junk))") || die;
    $imaptalk->create("INBOX.Ham.Zonk") || die;
    $imaptalk->create("INBOX.Ham.Bonk") || die;

    xlog $self, "(re)fetch mailboxes";
    my $res = $jmap->CallMethods([['Mailbox/get', { properties => ["name"] }, 'R1' ]]);
    $self->assert_num_equals(5, scalar @{$res->[0][1]{list}});
    my %mboxids = map { $_->{name} => $_->{id} } @{$res->[0][1]{list}};
    $self->assert(exists $mboxids{'Inbox'});

    xlog $self, "Subscribe mailbox Ham";
    $res = $jmap->CallMethods([
        ['Mailbox/set', {
            update => {
                $mboxids{'Ham'} => {
                    isSubscribed => JSON::true,
                },
            },
        }, 'R1']
    ]);
    $self->assert(exists $res->[0][1]{updated}{$mboxids{'Ham'}});

    xlog $self, "list mailboxes filtered by parentId OR role";
    $res = $jmap->CallMethods([['Mailbox/query', {
        filter => {
            operator => "OR",
            conditions => [{
                parentId => $mboxids{'Ham'},
            }, {
                hasAnyRole => JSON::true,
            }],
        },
        sort => [{ property => "name" }],
    }, "R1"]]);
    $self->assert_num_equals(3, scalar @{$res->[0][1]->{ids}});
    $self->assert_str_equals($mboxids{'Bonk'}, $res->[0][1]{ids}[0]);
    $self->assert_str_equals($mboxids{'Spam'}, $res->[0][1]{ids}[1]);
    $self->assert_str_equals($mboxids{'Zonk'}, $res->[0][1]{ids}[2]);

    xlog $self, "list mailboxes filtered by name";
    $res = $jmap->CallMethods([['Mailbox/query', {
        filter => {
            name => 'Zonk',
        },
    }, "R1"]]);
    $self->assert_num_equals(1, scalar @{$res->[0][1]->{ids}});
    $self->assert_str_equals($mboxids{'Zonk'}, $res->[0][1]{ids}[0]);

    xlog $self, "list mailboxes filtered by isSubscribed";
    $res = $jmap->CallMethods([['Mailbox/query', {
        filter => {
            isSubscribed => JSON::true,
        },
    }, "R1"]]);
    $self->assert_num_equals(1, scalar @{$res->[0][1]->{ids}});
    $self->assert_str_equals($mboxids{'Zonk'}, $res->[0][1]{ids}[0]);

    xlog $self, "list mailboxes filtered by isSubscribed is false";
    $res = $jmap->CallMethods([['Mailbox/query', {
        filter => {
            isSubscribed => JSON::false,
        },
        sort => [{ property => "name" }],
    }, "R1"]]);
    $self->assert_num_equals(4, scalar @{$res->[0][1]->{ids}});
    $self->assert_str_equals($mboxids{'Bonk'}, $res->[0][1]{ids}[0]);
    $self->assert_str_equals($mboxids{'Inbox'}, $res->[0][1]{ids}[1]);
    $self->assert_str_equals($mboxids{'Spam'}, $res->[0][1]{ids}[2]);
    $self->assert_str_equals($mboxids{'Zonk'}, $res->[0][1]{ids}[3]);

    xlog $self, "list mailboxes filtered by parentId AND hasAnyRole false";
    $res = $jmap->CallMethods([['Mailbox/query', {
        filter => {
            operator => "AND",
            conditions => [{
                parentId => $mboxids{'Inbox'},
            }, {
                hasAnyRole => JSON::false,
            }],
        },
        sort => [{ property => "name" }],
    }, "R1"]]);
    $self->assert_num_equals(1, scalar @{$res->[0][1]->{ids}});
    $self->assert_str_equals($mboxids{'Ham'}, $res->[0][1]{ids}[0]);

    xlog $self, "list mailboxes filtered by NOT (parentId AND role)";
    $res = $jmap->CallMethods([['Mailbox/query', {
        filter => {
            operator => "NOT",
            conditions => [
                operator => "AND",
                conditions => [{
                    parentId => $mboxids{'Inbox'},
                }, {
                    hasAnyRole => JSON::true,
                }],
            ],
        },
        sort => [{ property => "name" }],
    }, "R1"]]);
    $self->assert_num_equals(4, scalar @{$res->[0][1]->{ids}});
    $self->assert_str_equals($mboxids{'Bonk'}, $res->[0][1]{ids}[0]);
    $self->assert_str_equals($mboxids{'Inbox'}, $res->[0][1]{ids}[1]);
    $self->assert_str_equals($mboxids{'Spam'}, $res->[0][1]{ids}[2]);
    $self->assert_str_equals($mboxids{'Zonk'}, $res->[0][1]{ids}[3]);
}

sub test_mailbox_query_issue2286
    :min_version_3_1 :needs_component_jmap
{
    my ($self) = @_;

    my $jmap = $self->{jmap};
    my $imaptalk = $self->{store}->get_client();

    xlog $self, "list mailboxes without filter";
    my $res = $jmap->CallMethods([['Mailbox/query', { limit => -5 }, "R1"]]);
    $self->assert_str_equals('error', $res->[0][0]);
    $self->assert_str_equals('invalidArguments', $res->[0][1]{type});
}

sub test_mailbox_querychanges_name
    :min_version_3_1 :needs_component_jmap
{
    my ($self) = @_;
    my $jmap = $self->{jmap};
    my $inboxId = $self->getinbox()->{id};

    my $res = $jmap->CallMethods([['Mailbox/set', {
        create => {
            1 => {
                parentId => $inboxId,
                name => 'A',
            },
            2 => {
                parentId => $inboxId,
                name => 'B',
            },
            3 => {
                parentId => $inboxId,
                name => 'C',
            },
        },
    }, "R1"]]);
    my $mboxId1 = $res->[0][1]{created}{1}{id};
    my $mboxId2 = $res->[0][1]{created}{2}{id};
    my $mboxId3 = $res->[0][1]{created}{3}{id};
    $self->assert_not_null($mboxId1);
    $self->assert_not_null($mboxId2);
    $self->assert_not_null($mboxId3);

    $res = $jmap->CallMethods([['Mailbox/query', {
        filter => { parentId => $inboxId },
        sort => [{ property => "name" }],
    }, "R1"],
    [
        'Mailbox/get', { '#ids' => {
                resultOf => 'R1',
                name => 'Mailbox/query',
                path => '/ids'
            },
        }, 'R2'
    ]]);
    my $state = $res->[0][1]->{queryState};
    $self->assert_not_null($state);
    $self->assert_equals(JSON::true, $res->[0][1]->{canCalculateChanges});

    $res = $jmap->CallMethods([['Mailbox/queryChanges', {
        sinceQueryState => $state,
        filter => { parentId => $inboxId },
        sort => [{ property => "name" }],
    }, "R1"]]);
    $self->assert_str_equals($state, $res->[0][1]->{newQueryState});

    # Move mailbox 1 to end of the list
    $res = $jmap->CallMethods([['Mailbox/set', {
        update => {
            $mboxId1 => {
                name => 'Z',
            },
        },
    }, "R1"]]);
    $self->assert(exists $res->[0][1]{updated}{$mboxId1});

    $res = $jmap->CallMethods([['Mailbox/queryChanges', {
        sinceQueryState => $state,
        filter => { parentId => $inboxId },
        sort => [{ property => "name" }],
    }, "R1"]]);
    $self->assert_str_not_equals($state, $res->[0][1]->{newQueryState});
    $self->assert_num_equals(1, scalar @{$res->[0][1]{removed}});
    $self->assert_str_equals($mboxId1, $res->[0][1]{removed}[0]);
    $self->assert_num_equals(1, scalar @{$res->[0][1]{added}});
    $self->assert_str_equals($mboxId1, $res->[0][1]{added}[0]{id});

    # position 0 -> the tombstone from 'A'
    # position 1 -> keep 'B'
    # position 2 -> keep 'Z'
    # position 3 -> new mailbox name 'Z'
    $self->assert_num_equals(3, $res->[0][1]{added}[0]{index});
    $state = $res->[0][1]->{newQueryState};

    # Keep mailbox 2 at start of the list and remove mailbox 3
    $res = $jmap->CallMethods([['Mailbox/set', {
        update => {
            $mboxId2 => {
                name => 'Y',
            },
        },
        destroy => [$mboxId3],
    }, "R1"]]);
    $self->assert(exists $res->[0][1]{updated}{$mboxId2});
    $self->assert_str_equals($mboxId3, $res->[0][1]{destroyed}[0]);

    $res = $jmap->CallMethods([['Mailbox/queryChanges', {
        sinceQueryState => $state,
        filter => { parentId => $inboxId },
        sort => [{ property => "name" }],
    }, "R1"]]);

    $self->assert_str_not_equals($state, $res->[0][1]->{newQueryState});
    $self->assert_num_equals(2, scalar @{$res->[0][1]{removed}});
    my %removed = map { $_ => 1 } @{$res->[0][1]{removed}};
    $self->assert(exists $removed{$mboxId2});
    $self->assert(exists $removed{$mboxId3});

    # position 0 -> null
    # position 1 -> tombstone from 'B'
    # position 2 -> deleted 'C'
    # position 3 -> splice in 'Y'
    # position 4 -> new position of 'Z'
    $self->assert_num_equals(1, scalar @{$res->[0][1]{added}});
    $self->assert_str_equals($mboxId2, $res->[0][1]{added}[0]{id});
    $self->assert_num_equals(3, $res->[0][1]{added}[0]{index});
}

sub test_mailbox_querychanges_role
    :min_version_3_1 :needs_component_jmap
{
    my ($self) = @_;
    my $jmap = $self->{jmap};
    my $inboxId = $self->getinbox()->{id};

    my $res = $jmap->CallMethods([['Mailbox/set', {
        create => {
            1 => {
                parentId => $inboxId,
                name => 'A',
            },
            2 => {
                parentId => $inboxId,
                name => 'B',
                role => 'xspecialuse',
            },
            3 => {
                parentId => $inboxId,
                name => 'C',
                role => 'junk',
            },
        },
    }, "R1"]]);
    my $mboxId1 = $res->[0][1]{created}{1}{id};
    my $mboxId2 = $res->[0][1]{created}{2}{id};
    my $mboxId3 = $res->[0][1]{created}{3}{id};
    $self->assert_not_null($mboxId1);
    $self->assert_not_null($mboxId2);
    $self->assert_not_null($mboxId3);

    my $filter = { hasAnyRole => JSON::true, };
    my $sort = [{ property => "name" }];

    $res = $jmap->CallMethods([['Mailbox/query', {
        filter => $filter, sort => $sort,
    }, "R1"]]);
    my $state = $res->[0][1]->{queryState};
    $self->assert_not_null($state);
    $self->assert_equals(JSON::true, $res->[0][1]->{canCalculateChanges});

    $res = $jmap->CallMethods([['Mailbox/queryChanges', {
        sinceQueryState => $state,
        filter => $filter, sort => $sort,
    }, "R1"]]);
    $self->assert_str_equals($state, $res->[0][1]->{newQueryState});

    # Remove mailbox 2 from results and add mailbox 1
    $res = $jmap->CallMethods([['Mailbox/set', {
        update => {
            $mboxId1 => {
                role => 'trash',
            },
            $mboxId2 => {
                role => undef,
            },
        },
    }, "R1"]]);
    $self->assert(exists $res->[0][1]{updated}{$mboxId1});
    $self->assert(exists $res->[0][1]{updated}{$mboxId2});

    $res = $jmap->CallMethods([['Mailbox/queryChanges', {
        sinceQueryState => $state,
        filter => $filter, sort => $sort,
    }, "R1"]]);

    $self->assert_str_not_equals($state, $res->[0][1]->{newQueryState});
    $self->assert_num_equals(2, scalar @{$res->[0][1]{removed}});
    my %removed = map { $_ => 1 } @{$res->[0][1]{removed}};
    $self->assert(exists $removed{$mboxId1});
    $self->assert(exists $removed{$mboxId2});

    $self->assert_num_equals(1, scalar @{$res->[0][1]{added}});
    $self->assert_str_equals($mboxId1, $res->[0][1]{added}[0]{id});
    $self->assert_num_equals(0, $res->[0][1]{added}[0]{index});
}

sub test_mailbox_set
    :min_version_3_1 :needs_component_jmap
{
    my ($self) = @_;

    my $jmap = $self->{jmap};

    xlog $self, "get inbox";
    my $res = $jmap->CallMethods([['Mailbox/get', { }, "R1"]]);
    my $inbox = $res->[0][1]{list}[0];
    $self->assert_str_equals("Inbox", $inbox->{name});

    my $state = $res->[0][1]{state};

    xlog $self, "create mailbox";
    $res = $jmap->CallMethods([
            ['Mailbox/set', { create => { "1" => {
                            name => "foo",
                            role => undef
             }}}, "R1"]
    ]);
    $self->assert_str_equals('Mailbox/set', $res->[0][0]);
    $self->assert_str_equals('R1', $res->[0][2]);
    $self->assert_str_not_equals($state, $res->[0][1]{newState});
    $self->assert_not_null($res->[0][1]{created});
    my $id = $res->[0][1]{created}{"1"}{id};

    xlog $self, "get mailbox $id";
    $res = $jmap->CallMethods([['Mailbox/get', { ids => [$id] }, "R1"]]);
    $self->assert_str_equals($id, $res->[0][1]{list}[0]->{id});

    my $mbox = $res->[0][1]{list}[0];
    $self->assert_str_equals("foo", $mbox->{name});
    $self->assert_null($mbox->{parentId});
    $self->assert_null($mbox->{role});
    $self->assert_num_equals(10, $mbox->{sortOrder});
    $self->assert_equals(JSON::true, $mbox->{myRights}->{mayReadItems});
    $self->assert_equals(JSON::true, $mbox->{myRights}->{mayAddItems});
    $self->assert_equals(JSON::true, $mbox->{myRights}->{mayRemoveItems});
    $self->assert_equals(JSON::true, $mbox->{myRights}->{mayCreateChild});
    $self->assert_equals(JSON::true, $mbox->{myRights}->{mayRename});
    $self->assert_equals(JSON::true, $mbox->{myRights}->{mayDelete});
    $self->assert_num_equals(0, $mbox->{totalEmails});
    $self->assert_num_equals(0, $mbox->{unreadEmails});
    $self->assert_num_equals(0, $mbox->{totalThreads});
    $self->assert_num_equals(0, $mbox->{unreadThreads});

    xlog $self, "update mailbox";
    $res = $jmap->CallMethods([
            ['Mailbox/set', { update => { $id => {
                            name => "bar",
                            sortOrder => 20
             }}}, "R1"]
    ]);

    $self->assert_str_equals('Mailbox/set', $res->[0][0]);
    $self->assert_str_equals('R1', $res->[0][2]);
    $self->assert_str_not_equals($state, $res->[0][1]{newState});
    $self->assert(exists $res->[0][1]{updated}{$id});

    xlog $self, "get mailbox $id";
    $res = $jmap->CallMethods([['Mailbox/get', { ids => [$id] }, "R1"]]);
    $self->assert_str_equals($id, $res->[0][1]{list}[0]->{id});
    $mbox = $res->[0][1]{list}[0];
    $self->assert_str_equals("bar", $mbox->{name});
    $self->assert_num_equals(20, $mbox->{sortOrder});

    xlog $self, "destroy mailbox";
    $res = $jmap->CallMethods([
            ['Mailbox/set', { destroy => [ $id ] }, "R1"]
    ]);
    $self->assert_str_equals('Mailbox/set', $res->[0][0]);
    $self->assert_str_equals('R1', $res->[0][2]);
    $self->assert_str_not_equals($state, $res->[0][1]{newState});
    $self->assert_str_equals($id, $res->[0][1]{destroyed}[0]);

    xlog $self, "get mailbox $id";
    $res = $jmap->CallMethods([['Mailbox/get', { ids => [$id] }, "R1"]]);
    $self->assert_str_equals($id, $res->[0][1]{notFound}[0]);
}

sub test_mailbox_set_order
    :min_version_3_1 :needs_component_jmap
{
    my ($self) = @_;

    my $jmap = $self->{jmap};

    # Assert mailboxes are created in the right order.
    my $RawRequest = {
        headers => {
            'Authorization' => $jmap->auth_header(),
            'Content-Type' => 'application/json',
            'Accept' => 'application/json',
        },
        content => '{
            "using" : ["urn:ietf:params:jmap:mail"],
            "methodCalls" : [["Mailbox/set", {
                "create" : {
                    "C" : {
                        "name" : "C", "parentId" : "#B", "role" : null
                    },
                    "B" : {
                        "name" : "B", "parentId" : "#A", "role" : null
                    },
                    "A" : {
                        "name" : "A", "parentId" : null, "role" : null
                    }
                }
            }, "R1"]]
        }',
    };
    my $RawResponse = $jmap->ua->post($jmap->uri(), $RawRequest);
    if ($ENV{DEBUGJMAP}) {
        warn "JMAP " . Dumper($RawRequest, $RawResponse);
    }
    $self->assert($RawResponse->{success});

    my $res = eval { decode_json($RawResponse->{content}) };
    $res = $res->{methodResponses};
    $self->assert_not_null($res->[0][1]{created}{A});
    $self->assert_not_null($res->[0][1]{created}{B});
    $self->assert_not_null($res->[0][1]{created}{C});

    # Assert mailboxes are destroyed in the right order.
    $res = $jmap->CallMethods([['Mailbox/set', {
        destroy => [
            $res->[0][1]{created}{A}{id},
            $res->[0][1]{created}{B}{id},
            $res->[0][1]{created}{C}{id},
        ]
    }, "R1"]]);
    $self->assert_num_equals(3, scalar @{$res->[0][1]{destroyed}});
    $self->assert_null($res->[0][1]{notDestroyed});
}

sub test_mailbox_set_inbox_children
    :min_version_3_1 :needs_component_jmap :NoAltNameSpace
{
    my ($self) = @_;

    my $jmap = $self->{jmap};
    my $imaptalk = $self->{store}->get_client();

    $imaptalk->create("INBOX.top")
        or die "Cannot create mailbox INBOX.top: $@";

    $imaptalk->create("INBOX.INBOX.foo")
        or die "Cannot create mailbox INBOX.INBOX.foo: $@";

    $imaptalk->create("INBOX.INBOX.foo.bar")
        or die "Cannot create mailbox INBOX.INBOX.foo.bar: $@";

    xlog $self, "get existing mailboxes";
    my $res = $jmap->CallMethods([['Mailbox/get', { properties => ['name', 'parentId']}, "R1"]]);
    $self->assert_not_null($res);
    $self->assert_str_equals('Mailbox/get', $res->[0][0]);
    $self->assert_str_equals('R1', $res->[0][2]);

    my %m = map { $_->{name} => $_ } @{$res->[0][1]{list}};
    $self->assert_num_equals(4, scalar keys %m);
    my $inbox = $m{"Inbox"};
    my $top = $m{"top"};
    my $foo = $m{"foo"};
    my $bar = $m{"bar"};

    # INBOX
    $self->assert_null($inbox->{parentId});
    $self->assert_null($top->{parentId});
    $self->assert_str_equals($inbox->{id}, $foo->{parentId});
    $self->assert_str_equals($foo->{id}, $bar->{parentId});

    $res = $jmap->CallMethods([['Mailbox/set', {
        create => {
           'a' => { name => 'tl', parentId => undef },
           'b' => { name => 'sl', parentId => $inbox->{id} },
        },
        update => {
            $top->{id} => { name => 'B', parentId => $inbox->{id} },
            $foo->{id} => { name => 'C', parentId => undef },
        },
    }, "R1"]]);

    $res = $jmap->CallMethods([['Mailbox/get', { properties => ['name', 'parentId']}, "R1"]]);
    $self->assert_not_null($res);
    $self->assert_str_equals('Mailbox/get', $res->[0][0]);
    $self->assert_str_equals('R1', $res->[0][2]);

    %m = map { $_->{name} => $_ } @{$res->[0][1]{list}};
    $self->assert_num_equals(6, scalar keys %m);
    $inbox = $m{"Inbox"};
    my $b = $m{"B"};
    my $c = $m{"C"};
    $bar = $m{"bar"};
    my $tl = $m{"tl"};
    my $sl = $m{"sl"};

    # INBOX
    $self->assert_null($inbox->{parentId});
    $self->assert_str_equals($inbox->{id}, $b->{parentId});
    $self->assert_null($c->{parentId});
    $self->assert_str_equals($c->{id}, $bar->{parentId});
    $self->assert_str_equals($inbox->{id}, $sl->{parentId});
    $self->assert_null($tl->{parentId});

    my $list = $imaptalk->list("", "*");

    my $mb = join(',', sort map { $_->[2] } @$list);

    $self->assert_str_equals("INBOX,INBOX.C,INBOX.C.bar,INBOX.INBOX.B,INBOX.INBOX.sl,INBOX.tl", $mb);
}

sub test_mailbox_set_nameclash
    :min_version_3_1 :needs_component_jmap
{
    my ($self) = @_;

    my $jmap = $self->{jmap};

    # Test name-clash at top-level
    my $res = $jmap->CallMethods([['Mailbox/set', {
        create => {
            A1 => {
                name => 'A', parentId => undef, role => undef,
            },
            A2 => {
                name => 'A', parentId => undef, role => undef,
            },
        },
    }, "R1"]]);
    $self->assert_num_equals(1, scalar keys %{$res->[0][1]{created}});
    $self->assert_num_equals(1, scalar keys %{$res->[0][1]{notCreated}});

    # Test name-clash at lower lever
    my $parentA = (values %{$res->[0][1]{created}})[0]{id};
    $self->assert_not_null($parentA);
    $res = $jmap->CallMethods([['Mailbox/set', {
        create => {
            B1 => {
                name => 'B', parentId => $parentA, role => undef,
            },
            B2 => {
                name => 'B', parentId => $parentA, role => undef,
            },
        },
    }, "R1"]]);
    $self->assert_num_equals(1, scalar keys %{$res->[0][1]{created}});
    $self->assert_num_equals(1, scalar keys %{$res->[0][1]{notCreated}});
}

sub test_mailbox_set_name_swap
    :min_version_3_1 :needs_component_jmap
{
    my ($self) = @_;

    my $jmap = $self->{jmap};

    my $res = $jmap->CallMethods([['Mailbox/set', {
        create => {
            A => {
                name => 'A', parentId => undef, role => undef,
            },
            B => {
                name => 'B', parentId => undef, role => undef,
            },
        },
    }, "R1"]]);
    my $idA =$res->[0][1]{created}{A}{id};
    my $idB =$res->[0][1]{created}{B}{id};
    $self->assert_not_null($idA);
    $self->assert_not_null($idB);

    $res = $jmap->CallMethods([['Mailbox/set', {
        update => {
            $idA => { name => 'B' },
            $idB => { name => 'A' },
        },
    }, "R1"]]);
    $self->assert(exists $res->[0][1]{updated}{$idA});
    $self->assert(exists $res->[0][1]{updated}{$idB});
}

sub test_mailbox_set_order2
    :min_version_3_1 :needs_component_jmap
{
    my ($self) = @_;

    my $jmap = $self->{jmap};
    my $imaptalk = $self->{store}->get_client();

    # Create and get mailbox tree.
    $imaptalk->create("INBOX.A") or die;
    $imaptalk->create("INBOX.A.B") or die;
    my $res = $jmap->CallMethods([['Mailbox/get', {}, "R1"]]);
    my %m = map { $_->{name} => $_ } @{$res->[0][1]{list}};
    my ($idA, $idB) = ($m{"A"}{id}, $m{"B"}{id});

    # Use a non-trivial, but correct operations order: this
    # asserts that name clashes and mailboxHasChild conflicts
    # are resolved appropriately: the create depends on the
    # deletion of current mailbox A, which depends on the
    # update to move away the child from A, which requires
    # the create to set the parentId. Fun times.
    $res = $jmap->CallMethods([['Mailbox/set', {
        create => {
            Anew => {
                name => 'A',
                parentId => undef,
                role => undef,
            },
        },
        update => {
            $idB => {
                parentId => '#Anew',
            },
        },
        destroy => [
            $idA,
        ]
    }, "R1"]]);
    $self->assert(exists $res->[0][1]{created}{'Anew'});
    $self->assert(exists $res->[0][1]{updated}{$idB});
    $self->assert_str_equals($idA, $res->[0][1]{destroyed}[0]);
}

sub test_mailbox_set_cycle_in_create
    :min_version_3_1 :needs_component_jmap
{
    my ($self) = @_;
    my $jmap = $self->{jmap};

    # Attempt to create cyclic mailboxes. This should fail.
    my $res = $jmap->CallMethods([['Mailbox/set', {
        create => {
            A => {
                name => 'A',
                parentId => '#C',
                role => undef,
            },
            B => {
                name => 'B',
                parentId => '#A',
                role => undef,
            },
            C => {
                name => 'C',
                parentId => '#B',
                role => undef,
            }
        }
    }, "R1"]]);
    $self->assert_num_equals(3, scalar keys %{$res->[0][1]{notCreated}});
    $self->assert(exists $res->[0][1]{notCreated}{'A'});
    $self->assert(exists $res->[0][1]{notCreated}{'B'});
    $self->assert(exists $res->[0][1]{notCreated}{'C'});
}

sub test_mailbox_set_cycle_in_update
    :min_version_3_1 :needs_component_jmap
{
    my ($self) = @_;

    my $jmap = $self->{jmap};
    my $imaptalk = $self->{store}->get_client();

    # Create and get mailbox tree.
    $imaptalk->create("INBOX.A") or die;
    $imaptalk->create("INBOX.B") or die;
    my $res = $jmap->CallMethods([['Mailbox/get', {}, "R1"]]);
    my %m = map { $_->{name} => $_ } @{$res->[0][1]{list}};
    my ($idA, $idB) = ($m{"A"}{id}, $m{"B"}{id});

    # Introduce a cycle in the mailbox tree. Since both
    # operations could create the cycle, one operation must
    # fail and the other succeed. It's not deterministic
    # which will, resulting in mailboxes (A, A.B) or (B, B.A).
    $res = $jmap->CallMethods([['Mailbox/set', {
        update => {
            $idB => {
                parentId => $idA,
            },
            $idA => {
                parentId => $idB,
            },
        },
    }, "R1"]]);
    $self->assert_num_equals(1, scalar keys %{$res->[0][1]{notUpdated}});
    $self->assert_num_equals(1, scalar keys %{$res->[0][1]{updated}});
    $self->assert(
        (exists $res->[0][1]{notUpdated}{$idA} and exists $res->[0][1]{updated}{$idB}) or
        (exists $res->[0][1]{notUpdated}{$idB} and exists $res->[0][1]{updated}{$idA})
    );
}

sub test_mailbox_set_cycle_in_mboxtree
    :min_version_3_1 :needs_component_jmap
{
    my ($self) = @_;

    my $jmap = $self->{jmap};
    my $imaptalk = $self->{store}->get_client();

    # Create and get mailbox tree.
    $imaptalk->create("INBOX.A") or die;
    $imaptalk->create("INBOX.A.B") or die;
    my $res = $jmap->CallMethods([['Mailbox/get', {}, "R1"]]);
    my %m = map { $_->{name} => $_ } @{$res->[0][1]{list}};
    my ($idA, $idB) = ($m{"A"}{id}, $m{"B"}{id});

    # Introduce a cycle in the mailbox tree. This should fail.
    $res = $jmap->CallMethods([['Mailbox/set', {
        update => {
            $idA => {
                parentId => $idB,
            },
        },
    }, "R1"]]);
    $self->assert(exists $res->[0][1]{notUpdated}{$idA});
}

sub test_mailbox_get_shared_parents
    :min_version_3_1 :needs_component_jmap
{
    my ($self) = @_;

    my $jmap = $self->{jmap};

    my $imaptalk = $self->{store}->get_client();
    my $admintalk = $self->{adminstore}->get_client();

    # Create shared account and mailboxes
    $self->{instance}->create_user("foo");
    $admintalk->create("user.foo.box1") or die;
    $admintalk->create("user.foo.box1.box11") or die;
    $admintalk->create("user.foo.box1.box11.box111") or die;
    $admintalk->create("user.foo.box1.box12") or die;
    $admintalk->create("user.foo.box2") or die;
    $admintalk->create("user.foo.box3") or die;
    $admintalk->create("user.foo.box3.box31") or die;
    $admintalk->create("user.foo.box3.box32") or die;

    # Share mailboxes
    $admintalk->setacl("user.foo.box1.box11", "cassandane", "lr") or die;
    $admintalk->setacl("user.foo.box3.box32", "cassandane", "lr") or die;

    xlog $self, "get mailboxes for foo account";
    my $res = $jmap->CallMethods([['Mailbox/get', { accountId => "foo" }, "R1"]]);
    $self->assert_num_equals(4, scalar @{$res->[0][1]{list}});

    # Assert rights
    my %m = map { lc($_->{name}) => $_ } @{$res->[0][1]{list}};
    $self->assert_equals(JSON::false, $m{box1}->{myRights}->{mayReadItems});
    $self->assert_equals(JSON::true, $m{box11}->{myRights}->{mayReadItems});
    $self->assert_equals(JSON::false, $m{box3}->{myRights}->{mayReadItems});
    $self->assert_equals(JSON::true, $m{box32}->{myRights}->{mayReadItems});
}

sub test_mailbox_set_name_missing
    :min_version_3_1 :needs_component_jmap
{
    my ($self) = @_;

    my $jmap = $self->{jmap};

    xlog $self, "create mailbox";
    my $res = $jmap->CallMethods([
        ['Mailbox/set', { create => {
                "1" => { role => undef },
                "2" => { role => undef, name => "\t " },
        }}, "R1"]
    ]);
    $self->assert_str_equals('Mailbox/set', $res->[0][0]);
    $self->assert_str_equals('invalidProperties', $res->[0][1]{notCreated}{1}{type});
    $self->assert_str_equals('name', $res->[0][1]{notCreated}{1}{properties}[0]);
    $self->assert_str_equals('invalidProperties', $res->[0][1]{notCreated}{2}{type});
    $self->assert_str_equals('name', $res->[0][1]{notCreated}{2}{properties}[0]);
}


sub test_mailbox_set_name_collision
    :min_version_3_1 :needs_component_jmap
{
    my ($self) = @_;

    my $jmap = $self->{jmap};

    xlog $self, "get inbox";
    my $res = $jmap->CallMethods([['Mailbox/get', { }, "R1"]]);
    my $inbox = $res->[0][1]{list}[0];
    $self->assert_str_equals("Inbox", $inbox->{name});

    my $state = $res->[0][1]{state};

    xlog $self, "create three mailboxes named foo (two will fail)";
    $res = $jmap->CallMethods([
        ['Mailbox/set', { create => {
            "1" => {
                name => "foo",
                parentId => $inbox->{id},
                role => undef
            },
            "2" => {
                name => "foo",
                parentId => $inbox->{id},
                role => undef
            },
            "3" => {
                name => "foo",
                parentId => $inbox->{id},
                role => undef
            }
        }}, "R1"]
    ]);
    $self->assert_num_equals(1, scalar keys %{$res->[0][1]{created}});
    $self->assert_num_equals(2, scalar keys %{$res->[0][1]{notCreated}});

    my $fooid = $res->[0][1]{created}{(keys %{$res->[0][1]{created}})[0]}{id};
    $self->assert_not_null($fooid);

    xlog $self, "create mailbox bar";
    $res = $jmap->CallMethods([
        ['Mailbox/set', { create => {
            "1" => {
                name => "bar",
                parentId => $inbox->{id},
                role => undef
            }
        }}, 'R1'],
    ]);
    my $barid = $res->[0][1]{created}{"1"}{id};
    $self->assert_not_null($barid);

    # This MUST work per spec, but Cyrus /set does not support
    # invalid interim states...
    xlog $self, "rename bar to foo and foo to bar";
    $res = $jmap->CallMethods([
        ['Mailbox/set', { update => {
            $fooid => {
                name => "bar",
            },
            $barid => {
                name => "foo",
            },
        }}, 'R1'],
    ]);
    $self->assert_num_equals(2, scalar keys %{$res->[0][1]{updated}});

    xlog $self, "get mailboxes";
    $res = $jmap->CallMethods([['Mailbox/get', { ids => [$fooid, $barid] }, "R1"]]);

    # foo is bar
    $self->assert_str_equals($fooid, $res->[0][1]{list}[0]->{id});
    $self->assert_str_equals("bar", $res->[0][1]{list}[0]->{name});

    # and bar is foo
    $self->assert_str_equals($barid, $res->[0][1]{list}[1]->{id});
    $self->assert_str_equals("foo", $res->[0][1]{list}[1]->{name});
}

sub test_mailbox_set_name_interop
    :min_version_3_1 :needs_component_jmap
{
    my ($self) = @_;

    my $jmap = $self->{jmap};
    my $imaptalk = $self->{store}->get_client();

    xlog $self, "create mailbox via IMAP";
    $imaptalk->create("INBOX.foo")
        or die "Cannot create mailbox INBOX.foo: $@";

    xlog $self, "get foo mailbox";
    my $res = $jmap->CallMethods([['Mailbox/get', {}, "R1"]]);
    my %m = map { $_->{name} => $_ } @{$res->[0][1]{list}};
    my $foo = $m{"foo"};
    my $id = $foo->{id};
    $self->assert_str_equals("foo", $foo->{name});

    xlog $self, "rename mailbox foo to oof via JMAP";
    $res = $jmap->CallMethods([
            ['Mailbox/set', { update => { $id => { name => "oof" }}}, "R1"]
    ]);
    $self->assert_not_null($res->[0][1]{updated});

    xlog $self, "get mailbox via IMAP";
    my $data = $imaptalk->list("INBOX.oof", "%");
    $self->assert_num_equals(1, scalar @{$data});

    xlog $self, "rename mailbox oof to bar via IMAP";
    $imaptalk->rename("INBOX.oof", "INBOX.bar")
        or die "Cannot rename mailbox: $@";

    xlog $self, "get mailbox $id";
    $res = $jmap->CallMethods([['Mailbox/get', { ids => [$id] }, "R1"]]);
    $self->assert_str_equals("bar", $res->[0][1]{list}[0]->{name});

    xlog $self, "rename mailbox bar to baz via JMAP";
    $res = $jmap->CallMethods([
            ['Mailbox/set', { update => { $id => { name => "baz" }}}, "R1"]
    ]);
    $self->assert_not_null($res->[0][1]{updated});

    xlog $self, "get mailbox via IMAP";
    $data = $imaptalk->list("INBOX.baz", "%");
    $self->assert_num_equals(1, scalar @{$data});

    xlog $self, "rename mailbox baz to IFeel\N{WHITE SMILING FACE} via IMAP";
    $imaptalk->rename("INBOX.baz", "INBOX.IFeel\N{WHITE SMILING FACE}")
        or die "Cannot rename mailbox: $@";

    xlog $self, "get mailbox $id";
    $res = $jmap->CallMethods([['Mailbox/get', { ids => [$id] }, "R1"]]);
    $self->assert_str_equals("IFeel\N{WHITE SMILING FACE}", $res->[0][1]{list}[0]->{name});
}

sub test_mailbox_set_name_unicode_nfc
    :min_version_3_1 :needs_component_jmap
{
    my ($self) = @_;

    my $jmap = $self->{jmap};

    xlog $self, "get inbox";
    my $res = $jmap->CallMethods([['Mailbox/get', { }, "R1"]]);
    my $inbox = $res->[0][1]{list}[0];
    $self->assert_str_equals("Inbox", $inbox->{name});

    my $state = $res->[0][1]{state};

    my $name = "\N{ANGSTROM SIGN}ngstr\N{LATIN SMALL LETTER O WITH DIAERESIS}m";
    my $want = "\N{LATIN CAPITAL LETTER A WITH RING ABOVE}ngstr\N{LATIN SMALL LETTER O WITH DIAERESIS}m";

    xlog $self, "create mailboxes with name not conforming to Net Unicode (NFC)";
    $res = $jmap->CallMethods([['Mailbox/set', { create => { "1" => {
        name => "\N{ANGSTROM SIGN}ngstr\N{LATIN SMALL LETTER O WITH DIAERESIS}m",
        parentId => $inbox->{id},
        role => undef
    }}}, "R1"]]);
    $self->assert_not_null($res->[0][1]{created}{1});
    my $id = $res->[0][1]{created}{1}{id};

    xlog $self, "get mailbox $id";
    $res = $jmap->CallMethods([['Mailbox/get', { ids => [$id] }, "R1"]]);
    $self->assert_str_equals($want, $res->[0][1]{list}[0]->{name});
}

sub test_mailbox_set_role_create
    :min_version_3_3 :needs_component_jmap :NoAltNameSpace
{
    my ($self) = @_;
    my $jmap = $self->{jmap};

    xlog "create mailboxes with roles";
    my $res = $jmap->CallMethods([
        ['Mailbox/get', {
            properties => ['role', 'name'],
        }, 'R1'],
        ['Mailbox/set', {
            create => {
                mboxA => {
                    name => 'A',
                    role => 'trash',
                },
                mboxB => {
                    name => 'B',
                    role => 'junk',
                },
            },
        }, "R2"],
        ['Mailbox/get', {
            properties => ['role', 'name'],
        }, 'R3'],
    ]);
    my $inbox = $res->[0][1]{list}[0]{id};
    $self->assert_not_null($inbox);
    my $mboxA = $res->[1][1]{created}{mboxA}{id};
    $self->assert_not_null($mboxA);
    my $mboxB = $res->[1][1]{created}{mboxB}{id};
    $self->assert_not_null($mboxB);
    my %roleByMbox = map { $_->{id} => $_->{role} } @{$res->[2][1]{list}};
    $self->assert_deep_equals({
        $inbox => 'inbox',
        $mboxA => 'trash',
        $mboxB => 'junk',
    }, \%roleByMbox);
}

sub test_mailbox_set_role_dups_existingrole
    :min_version_3_3 :needs_component_jmap :NoAltNameSpace
{
    my ($self) = @_;
    my $jmap = $self->{jmap};

    my $res = $jmap->CallMethods([
        ['Mailbox/get', {
            properties => ['role', 'name'],
        }, 'R1'],
        ['Mailbox/set', {
            create => {
                mboxA => {
                    name => 'A',
                    role => 'junk',
                },
            },
        }, "R2"],
    ]);
    my $inbox = $res->[0][1]{list}[0]{id};
    $self->assert_not_null($inbox);
    my $mboxA = $res->[1][1]{created}{mboxA}{id};
    $self->assert_not_null($mboxA);

    xlog "Can't create a mailbox with a duplicate role";
    $res = $jmap->CallMethods([
        ['Mailbox/set', {
            create => {
                mboxB => {
                    name => 'B',
                    role => 'junk',
                },
            },
        }, "R1"],
    ]);
    $self->assert_deep_equals(['role'], $res->[0][1]{notCreated}{'mboxB'}{properties});

    xlog "Can't update a mailbox with a duplicate role";
    # create it first
    $res = $jmap->CallMethods([
        ['Mailbox/set', {
            create => {
                mboxB => {
                    name => 'B',
                },
            },
        }, "R1"],
    ]);
    my $mboxB = $res->[0][1]{created}{mboxB}{id};
    $self->assert_not_null($mboxB);
    # now update
    $res = $jmap->CallMethods([
        ['Mailbox/set', {
            update => {
                $mboxB => {
                    name => 'B',
                    role => 'junk',
                },
            },
        }, "R1"],
        ['Mailbox/get', {
            properties => ['role', 'name'],
        }, 'R2'],
    ]);
    $self->assert_deep_equals(['role'], $res->[0][1]{notUpdated}{$mboxB}{properties});
    my %roleByMbox = map { $_->{id} => $_->{role} } @{$res->[1][1]{list}};
    $self->assert_deep_equals({
        $inbox => 'inbox',
        $mboxA => 'junk',
        $mboxB => undef,
    }, \%roleByMbox);
}

sub test_mailbox_set_role_dups_createrole
    :min_version_3_3 :needs_component_jmap :NoAltNameSpace
{
    my ($self) = @_;
    my $jmap = $self->{jmap};

    xlog "Can't create two mailboxes with the same role";

    my $res = $jmap->CallMethods([
        ['Mailbox/get', {
            properties => ['role', 'name'],
        }, 'R1'],
        ['Mailbox/set', {
            create => {
                mboxNope1 => {
                    name => 'nope1',
                    role => 'drafts',
                },
                mboxNope2=> {
                    name => 'nope2',
                    role => 'drafts',
                },
            },
        }, "R2"],
        ['Mailbox/get', {
            properties => ['role', 'name'],
        }, 'R3'],
    ]);
    my $inbox = $res->[0][1]{list}[0]{id};
    $self->assert_not_null($inbox);
    $self->assert_deep_equals(['role'], $res->[1][1]{notCreated}{'mboxNope1'}{properties});
    $self->assert_deep_equals(['role'], $res->[1][1]{notCreated}{'mboxNope2'}{properties});
    my %roleByMbox = map { $_->{id} => $_->{role} } @{$res->[2][1]{list}};
    $self->assert_deep_equals({
        $inbox => 'inbox',
    }, \%roleByMbox);
}

sub test_mailbox_set_role_move_update
    :min_version_3_3 :needs_component_jmap :NoAltNameSpace
{
    my ($self) = @_;
    my $jmap = $self->{jmap};

    my $res = $jmap->CallMethods([
        ['Mailbox/get', {
            properties => ['role', 'name'],
        }, 'R1'],
        ['Mailbox/set', {
            create => {
                mboxA => {
                    name => 'A',
                    role => 'trash',
                },
                mboxB => {
                    name => 'B',
                },
            },
        }, "R2"],
    ]);
    my $inbox = $res->[0][1]{list}[0]{id};
    $self->assert_not_null($inbox);
    my $mboxA = $res->[1][1]{created}{mboxA}{id};
    $self->assert_not_null($mboxA);
    my $mboxB = $res->[1][1]{created}{mboxB}{id};
    $self->assert_not_null($mboxB);

    xlog "move trash role by update";
    $res = $jmap->CallMethods([
        ['Mailbox/set', {
            update => {
                $mboxA => {
                    role => undef,
                },
                $mboxB => {
                    role => 'trash',
                },
            },
        }, "R1"],
        ['Mailbox/get', {
            properties => ['role', 'name'],
        }, 'R2'],
    ]);
    $self->assert(exists $res->[0][1]{updated}{$mboxA});
    $self->assert(exists $res->[0][1]{updated}{$mboxB});
    my %roleByMbox = map { $_->{id} => $_->{role} } @{$res->[1][1]{list}};
    $self->assert_deep_equals({
        $inbox => 'inbox',
        $mboxA => undef,
        $mboxB => 'trash',
    }, \%roleByMbox);
}

sub test_mailbox_set_role_move_destroy
    :min_version_3_3 :needs_component_jmap :NoAltNameSpace
{
    my ($self) = @_;
    my $jmap = $self->{jmap};

    xlog "move role by destroy";

    my $res = $jmap->CallMethods([
        ['Mailbox/get', {
            properties => ['role', 'name'],
        }, 'R1'],
        ['Mailbox/set', {
            create => {
                mboxA => {
                    name => 'A',
                    role => 'trash',
                },
            },
        }, "R2"],
    ]);
    my $inbox = $res->[0][1]{list}[0]{id};
    $self->assert_not_null($inbox);
    my $mboxA = $res->[1][1]{created}{mboxA}{id};
    $self->assert_not_null($mboxA);

    $res = $jmap->CallMethods([
        ['Mailbox/set', {
            create => {
                mboxB => {
                    name => 'B',
                    role => 'trash',
                },
            },
            destroy => [$mboxA],
        }, "R1"],
        ['Mailbox/get', {
            properties => ['role', 'name'],
        }, 'R2'],
    ]);
    $self->assert_deep_equals([$mboxA], $res->[0][1]{destroyed});
    my $mboxB = $res->[0][1]{created}{mboxB}{id};
    $self->assert_not_null($mboxB);
    my %roleByMbox = map { $_->{id} => $_->{role} } @{$res->[1][1]{list}};
    $self->assert_deep_equals({
        $inbox => 'inbox',
        $mboxB => 'trash',
    }, \%roleByMbox);
}

sub test_mailbox_set_role_protected_destroy
    :min_version_3_3 :needs_component_jmap :NoAltNameSpace
{
    my ($self) = @_;
    my $jmap = $self->{jmap};

    xlog "create protected and unprotected roles";
    my $res = $jmap->CallMethods([
        ['Mailbox/get', {
            properties => ['role', 'name'],
        }, 'R1'],
        ['Mailbox/set', {
            create => {
                mboxA => {
                    name => 'A',
                    role => 'drafts',
                },
                mboxB => {
                    name => 'B',
                    role => 'xspecialuse',
                },
            },
        }, "R2"],
        ['Mailbox/get', {
            properties => ['role', 'name'],
        }, 'R3'],
    ]);
    my $inbox = $res->[0][1]{list}[0]{id};
    $self->assert_not_null($inbox);
    my $mboxA = $res->[1][1]{created}{mboxA}{id};
    $self->assert_not_null($mboxA);
    my $mboxB = $res->[1][1]{created}{mboxB}{id};
    $self->assert_not_null($mboxB);
    my %roleByMbox = map { $_->{id} => $_->{role} } @{$res->[2][1]{list}};
    $self->assert_deep_equals({
        $inbox => 'inbox',
        $mboxA => 'drafts',
        $mboxB => 'xspecialuse',
    }, \%roleByMbox);

    xlog "destroy protected and unprotected roles in one method";
    $res = $jmap->CallMethods([
        ['Mailbox/set', {
            destroy => [$mboxA, $mboxB],
        }, 'R1'],
    ]);
    $self->assert_str_equals('serverFail', $res->[0][1]{notDestroyed}{$mboxA}{type});
    $self->assert_str_equals('serverFail', $res->[0][1]{notDestroyed}{$mboxB}{type});

    xlog "destroy protected and unprotected roles in separate method";
    $res = $jmap->CallMethods([
        ['Mailbox/set', {
            destroy => [$mboxA],
        }, 'R1'],
        ['Mailbox/set', {
            destroy => [$mboxB],
        }, 'R2'],
        ['Mailbox/get', {
            properties => ['role', 'name'],
        }, 'R3'],
    ]);
    $self->assert_str_equals('serverFail', $res->[0][1]{notDestroyed}{$mboxA}{type});
    $self->assert_deep_equals([$mboxB], $res->[1][1]{destroyed});
    %roleByMbox = map { $_->{id} => $_->{role} } @{$res->[2][1]{list}};
    $self->assert_deep_equals({
        $inbox => 'inbox',
        $mboxA => 'drafts',
    }, \%roleByMbox);
}

sub test_mailbox_set_protected_move_parent
    :min_version_3_3 :needs_component_jmap :NoAltNameSpace
{
    my ($self) = @_;
    my $jmap = $self->{jmap};

    xlog "create protected and unprotected roles";
    my $res = $jmap->CallMethods([
        ['Mailbox/set', {
            create => {
                mboxA => {
                    name => 'A',
                    role => 'drafts',
                },
                mboxB => {
                    name => 'B',
                    role => 'xspecialuse',
                },
                mboxC => {
                    name => 'C',
                },
            },
        }, "R2"],
        ['Mailbox/get', {
            properties => ['role', 'name'],
        }, 'R3'],
    ]);
    my $mboxA = $res->[0][1]{created}{mboxA}{id};
    $self->assert_not_null($mboxA);
    my $mboxB = $res->[0][1]{created}{mboxB}{id};
    $self->assert_not_null($mboxB);
    my $mboxC = $res->[0][1]{created}{mboxC}{id};
    $self->assert_not_null($mboxC);
    xlog "move protected and unprotected roles in one method";
    $res = $jmap->CallMethods([
        ['Mailbox/set', {
            update => {
                $mboxA => {
                    parentId => $mboxC,
                },
                $mboxB => {
                    parentId => $mboxC,
                },
            },
        }, 'R1'],
    ]);
    $self->assert_str_equals('invalidProperties', $res->[0][1]{notUpdated}{$mboxA}{type});
    $self->assert_str_equals('invalidProperties', $res->[0][1]{notUpdated}{$mboxB}{type});

    xlog "move protected and unprotected roles in separate method";
    $res = $jmap->CallMethods([
        ['Mailbox/set', {
            update => {
                $mboxA => {
                    parentId => $mboxC,
                },
            },
        }, 'R1'],
        ['Mailbox/set', {
            update => {
                $mboxB => {
                    parentId => $mboxC,
                },
            },
        }, 'R2'],
    ]);
    $self->assert_str_equals('invalidProperties', $res->[0][1]{notUpdated}{$mboxA}{type});
    $self->assert(exists $res->[1][1]{updated}{$mboxB});
}

sub test_mailbox_set_no_outbox_role
    :min_version_3_1 :needs_component_jmap
{
    my ($self) = @_;
    my $jmap = $self->{jmap};

    # Regression test to make sure the non-standard 'outbox'
    # role is rejected for mailboxes.

    my $res = $jmap->CallMethods([
        ['Mailbox/set', { create => {
            "1" => { name => "foo", parentId => undef, role => "outbox" },
        }}, "R1"]
    ]);
    $self->assert_str_equals("role", $res->[0][1]{notCreated}{1}{properties}[0]);
}


sub test_mailbox_set_parent
    :min_version_3_1 :needs_component_jmap
{
    my ($self) = @_;

    my $jmap = $self->{jmap};

    # Create mailboxes
    xlog $self, "create mailbox foo";
    my $res = $jmap->CallMethods([['Mailbox/set', {
        create => {
            "1" => {
                name => "foo",
                parentId => undef,
                role => undef }
        }
    }, "R1"]]);
    my $id1 = $res->[0][1]{created}{"1"}{id};
    xlog $self, "create mailbox foo.bar";
    $res = $jmap->CallMethods([['Mailbox/set', {
        create => {
            "2" => {
                name => "bar",
                parentId => $id1,
                role => undef }
        }
    }, "R1"]]);
    my $id2 = $res->[0][1]{created}{"2"}{id};
    xlog $self, "create mailbox foo.bar.baz";
    $res = $jmap->CallMethods([['Mailbox/set', {
        create => {
            "3" => {
                name => "baz",
                parentId => $id2,
                role => undef
            }
        }
    }, "R1"]]);
    my $id3 = $res->[0][1]{created}{"3"}{id};

    # All set up?
    $res = $jmap->CallMethods([['Mailbox/get', { ids => [$id1] }, "R1"]]);
    $self->assert_null($res->[0][1]{list}[0]->{parentId});
    $res = $jmap->CallMethods([['Mailbox/get', { ids => [$id2] }, "R1"]]);
    $self->assert_str_equals($id1, $res->[0][1]{list}[0]->{parentId});
    $res = $jmap->CallMethods([['Mailbox/get', { ids => [$id3] }, "R1"]]);
    $self->assert_str_equals($id2, $res->[0][1]{list}[0]->{parentId});

    xlog $self, "move foo.bar to bar";
    $res = $jmap->CallMethods([['Mailbox/set', {
        update => {
            $id2 => {
                name => "bar",
                parentId => undef,
                role => undef }
        }
    }, "R1"]]);
    $res = $jmap->CallMethods([['Mailbox/get', { ids => [$id2] }, "R1"]]);
    $self->assert_null($res->[0][1]{list}[0]->{parentId});

    xlog $self, "move bar.baz to foo.baz";
    $res = $jmap->CallMethods([['Mailbox/set', {
        update => {
            $id3 => {
                name => "baz",
                parentId => $id1,
                role => undef
            }
        }
    }, "R1"]]);
    $res = $jmap->CallMethods([['Mailbox/get', { ids => [$id3] }, "R1"]]);
    $self->assert_str_equals($id1, $res->[0][1]{list}[0]->{parentId});

    xlog $self, "move foo to bar.foo";
    $res = $jmap->CallMethods([['Mailbox/set', {
        update => {
            $id1 => {
                name => "foo",
                parentId => $id2,
                role => undef
            }
        }
    }, "R1"]]);
    $res = $jmap->CallMethods([['Mailbox/get', { ids => [$id1] }, "R1"]]);
    $self->assert_str_equals($id2, $res->[0][1]{list}[0]->{parentId});

    xlog $self, "move foo to non-existent parent";
    $res = $jmap->CallMethods([['Mailbox/set', {
        update => {
            $id1 => {
                name => "foo",
                parentId => "nope",
                role => undef
            }
        }
    }, "R1"]]);
    my $errType = $res->[0][1]{notUpdated}{$id1}{type};
    my $errProp = $res->[0][1]{notUpdated}{$id1}{properties};
    $self->assert_str_equals("invalidProperties", $errType);
    $self->assert_deep_equals([ "parentId" ], $errProp);
    $res = $jmap->CallMethods([['Mailbox/get', { ids => [$id1] }, "R1"]]);
    $self->assert_str_equals($id2, $res->[0][1]{list}[0]->{parentId});

    xlog $self, "attempt to destroy bar (which has child foo)";
    $res = $jmap->CallMethods([['Mailbox/set', {
        destroy => [$id2]
    }, "R1"]]);
    $errType = $res->[0][1]{notDestroyed}{$id2}{type};
    $self->assert_str_equals("mailboxHasChild", $errType);
    $res = $jmap->CallMethods([['Mailbox/get', { ids => [$id2] }, "R1"]]);
    $self->assert_null($res->[0][1]{list}[0]->{parentId});

    xlog $self, "destroy all";
    $res = $jmap->CallMethods([['Mailbox/set', {
        destroy => [$id3, $id1, $id2]
    }, "R1"]]);
    $self->assert_num_equals(3, scalar @{$res->[0][1]{destroyed}});
    $self->assert(grep {$_ eq $id1} @{$res->[0][1]{destroyed}});
    $self->assert(grep {$_ eq $id2} @{$res->[0][1]{destroyed}});
    $self->assert(grep {$_ eq $id3} @{$res->[0][1]{destroyed}});
}

sub test_mailbox_set_parent_acl
    :min_version_3_1 :needs_component_jmap
{
    my ($self) = @_;

    my $jmap = $self->{jmap};
    my $admintalk = $self->{adminstore}->get_client();

    xlog $self, "get inbox";
    my $res = $jmap->CallMethods([['Mailbox/get', { }, "R1"]]);
    my $inbox = $res->[0][1]{list}[0];
    $self->assert_str_equals("Inbox", $inbox->{name});

    xlog $self, "get inbox ACL";
    my $parentacl = $admintalk->getacl("user.cassandane");

    xlog $self, "create mailbox";
    $res = $jmap->CallMethods([
            ['Mailbox/set', { create => { "1" => {
                            name => "foo",
                            role => undef
             }}}, "R1"]
    ]);
    $self->assert_not_null($res->[0][1]{created});

    xlog $self, "get new mailbox ACL";
    my $myacl = $admintalk->getacl("user.cassandane.foo");

    xlog $self, "assert ACL matches parent ACL";
    $self->assert_deep_equals($parentacl, $myacl);
}

sub test_mailbox_set_destroy_empty
    :min_version_3_1 :needs_component_jmap
{
    my ($self) = @_;
    my $jmap = $self->{jmap};

    my $store = $self->{store};
    my $talk = $store->get_client();

    xlog $self, "Generate a email in INBOX via IMAP";
    $self->make_message("Email A") || die;

    xlog $self, "get email list";
    my $res = $jmap->CallMethods([['Email/query', {}, "R1"]]);
    $self->assert_num_equals(1, scalar @{$res->[0][1]->{ids}});
    my $msgid = $res->[0][1]->{ids}[0];

    xlog $self, "get inbox";
    $res = $jmap->CallMethods([['Mailbox/get', { }, "R1"]]);
    my $inbox = $res->[0][1]{list}[0];
    $self->assert_str_equals("Inbox", $inbox->{name});

    my $state = $res->[0][1]{state};

    xlog $self, "create mailbox";
    $res = $jmap->CallMethods([
            ['Mailbox/set', { create => { "1" => {
                            name => "foo",
                            parentId => $inbox->{id},
                            role => undef
             }}}, "R1"]
    ]);
    $self->assert_str_equals('Mailbox/set', $res->[0][0]);
    $self->assert_str_equals('R1', $res->[0][2]);
    $self->assert_str_not_equals($state, $res->[0][1]{newState});
    $self->assert_not_null($res->[0][1]{created});
    my $mboxid = $res->[0][1]{created}{"1"}{id};

    xlog $self, "copy email to newly created mailbox";
    $res = $jmap->CallMethods([['Email/set', {
        update => { $msgid => { mailboxIds => {
            $inbox->{id} => JSON::true,
            $mboxid => JSON::true,
        }}},
    }, "R1"]]);
    $self->assert_not_null($res->[0][1]{updated});

    xlog $self, "attempt to destroy mailbox with email";
    $res = $jmap->CallMethods([
            ['Mailbox/set', { destroy => [ $mboxid ] }, "R1"]
    ]);
    $self->assert_not_null($res->[0][1]{notDestroyed}{$mboxid});
    $self->assert_str_equals('mailboxHasEmail', $res->[0][1]{notDestroyed}{$mboxid}{type});

    xlog $self, "remove email from mailbox";
    $res = $jmap->CallMethods([['Email/set', {
        update => { $msgid => { mailboxIds => {
            $inbox->{id} => JSON::true,
        }}},
    }, "R1"]]);
    $self->assert_not_null($res->[0][1]{updated});

    xlog $self, "destroy empty mailbox";
    $res = $jmap->CallMethods([
            ['Mailbox/set', { destroy => [ $mboxid ] }, "R1"]
    ]);
    $self->assert_str_equals($mboxid, $res->[0][1]{destroyed}[0]);
}

sub test_mailbox_set_destroy_removemsgs
    :min_version_3_1 :needs_component_jmap
{
    my ($self) = @_;
    my $jmap = $self->{jmap};

    xlog "Create email in inbox and another mailbox";
    my $res = $jmap->CallMethods([
        ['Mailbox/query', { }, 'R1'],
        ['Mailbox/set', {
            create => {
                mbox => {
                    name => 'A',
                },
            },
        }, 'R2'],
        ['Email/set', {
            create => {
                email => {
                    mailboxIds => {
                        '$inbox' => JSON::true,
                        '#mbox' => JSON::true,
                    },
                    subject => 'email',
                    bodyStructure => {
                        type => 'text/plain',
                        partId => '1',
                    },
                    bodyValues => {
                        1 => {
                            value => 'email',
                        }
                    },
                },
            },
        }, 'R3'],
    ]);
    my $inboxId = $res->[0][1]{ids}[0];
    $self->assert_not_null($inboxId);
    my $mboxId = $res->[1][1]{created}{mbox}{id};
    $self->assert_not_null($mboxId);
    my $emailId = $res->[2][1]{created}{email}{id};
    $self->assert_not_null($emailId);

    $self->{instance}->getsyslog();

    xlog "Destroy mailbox with onDestroyRemoveEmails";
    $res = $jmap->CallMethods([
        ['Mailbox/set', {
            destroy => [$mboxId],
            onDestroyRemoveEmails => JSON::true,
        }, 'R1'],
        ['Email/get', {
            ids => [$emailId],
            properties => ['mailboxIds'],
        }, 'R2'],
    ]);
    $self->assert_deep_equals([$mboxId], $res->[0][1]{destroyed});
    $self->assert_deep_equals({ $inboxId => JSON::true },
        $res->[1][1]{list}[0]{mailboxIds});

    my ($maj, $min) = Cassandane::Instance->get_version();
    if ($maj > 3 || ($maj == 3 && $min >= 7)) {
        my @lines = $self->{instance}->getsyslog();
        $self->assert(grep /Destroyed mailbox: mboxid=<$mboxId> msgcount=<1>/, @lines);
    }
}

sub test_mailbox_set_shared
    :min_version_3_1 :needs_component_jmap
{
    my ($self) = @_;
    my $jmap = $self->{jmap};

    my $imaptalk = $self->{store}->get_client();
    my $admintalk = $self->{adminstore}->get_client();

    # Create account
    $self->{instance}->create_user("foo");

    # Share inbox but do not allow to create subfolders
    $admintalk->setacl("user.foo", "cassandane", "lr") or die;

    xlog $self, "get mailboxes for foo account";
    my $res = $jmap->CallMethods([['Mailbox/get', { accountId => "foo" }, "R1"]]);
    my $inboxId = $res->[0][1]{list}[0]{id};

    my $update = ['Mailbox/set', {
        accountId => "foo",
        update => {
            $inboxId => {
                name => "UpdatedInbox",
            }
        }
    }, "R1"];

    xlog $self, "update shared INBOX (should fail)";
    $res = $jmap->CallMethods([ $update ]);
    $self->assert(exists $res->[0][1]{notUpdated}{$inboxId});

    xlog $self, "Add update ACL rights to shared INBOX";
    $admintalk->setacl("user.foo", "cassandane", "lrw") or die;

    xlog $self, "update shared INBOX (should succeed)";
    $res = $jmap->CallMethods([ $update ]);
    $self->assert(exists $res->[0][1]{updated}{$inboxId});

    my $create = ['Mailbox/set', {
        accountId => "foo",
        create => {
            "1" => {
                name => "x",
            }
        }
    }, "R1"];

    xlog $self, "create mailbox child (should fail)";
    $res = $jmap->CallMethods([ $create ]);
    $self->assert_not_null($res->[0][1]{notCreated}{1});

    xlog $self, "Add update ACL rights to shared INBOX";
    $admintalk->setacl("user.foo", "cassandane", "lrwk") or die;

    xlog $self, "create mailbox child (should succeed)";
    $res = $jmap->CallMethods([ $create ]);
    $self->assert_not_null($res->[0][1]{created}{1});
    my $childId = $res->[0][1]{created}{1}{id};

    my $destroy = ['Mailbox/set', {
        accountId => "foo",
        destroy => [ $childId ],
    }, 'R1' ];

    xlog $self, "destroy shared mailbox child (should fail)";
    $res = $jmap->CallMethods([ $destroy ]);
    $self->assert(exists $res->[0][1]{notDestroyed}{$childId});

    xlog $self, "Add delete ACL rights";
    $admintalk->setacl("user.foo.x", "cassandane", "lrwkx") or die;

    xlog $self, "destroy shared mailbox child (should succeed)";
    $res = $jmap->CallMethods([ $destroy ]);
    $self->assert_num_equals(1, scalar @{$res->[0][1]{destroyed}});
}

sub test_mailbox_set_issubscribed
    :min_version_3_1 :needs_component_jmap
{
    my ($self) = @_;
    my $jmap = $self->{jmap};

    my $res = $jmap->CallMethods([
        ['Mailbox/set', {
            create => {
                "A" => {
                    name => "A",
                },
                "B" => {
                    name => "B",
                    isSubscribed => JSON::true,
                }
            }
        }, "R1"]
    ]);
    $self->assert_equals(JSON::false, $res->[0][1]{created}{A}{isSubscribed});
    $self->assert(not exists $res->[0][1]{created}{B}{isSubscribed});
    my $mboxIdA = $res->[0][1]{created}{A}{id};
    my $mboxIdB = $res->[0][1]{created}{B}{id};

    $res = $jmap->CallMethods([
        ['Mailbox/get', {
            ids => [$mboxIdA, $mboxIdB],
            properties => ['isSubscribed'],
        }, 'R1']
    ]);
    $self->assert_equals($mboxIdA, $res->[0][1]{list}[0]{id});
    $self->assert_equals(JSON::false, $res->[0][1]{list}[0]{isSubscribed});
    $self->assert_equals($mboxIdB, $res->[0][1]{list}[1]{id});
    $self->assert_equals(JSON::true, $res->[0][1]{list}[1]{isSubscribed});

    $res = $jmap->CallMethods([
        ['Mailbox/set', {
            update => {
                $mboxIdA => {
                    isSubscribed => JSON::true,
                },
                $mboxIdB => {
                    isSubscribed => JSON::false,
                },
            }
        }, "R1"]
    ]);
    $res = $jmap->CallMethods([
        ['Mailbox/get', {
            ids => [$mboxIdA, $mboxIdB],
            properties => ['isSubscribed'],
        }, 'R1']
    ]);
    $self->assert_equals($mboxIdA, $res->[0][1]{list}[0]{id});
    $self->assert_equals(JSON::true, $res->[0][1]{list}[0]{isSubscribed});
    $self->assert_equals($mboxIdB, $res->[0][1]{list}[1]{id});
    $self->assert_equals(JSON::false, $res->[0][1]{list}[1]{isSubscribed});
}

sub test_mailbox_set_extendedprops
    :min_version_3_3 :needs_component_jmap :JMAPExtensions
{
    my ($self) = @_;
    my $jmap = $self->{jmap};

    # we need 'https://cyrusimap.org/ns/jmap/mail' capability for
    # isSeenShared property
    my @using = @{ $jmap->DefaultUsing() };
    push @using, 'https://cyrusimap.org/ns/jmap/mail';
    $jmap->DefaultUsing(\@using);

    my $res = $jmap->CallMethods([
        ['Mailbox/set', {
            create => {
                "A" => {
                    name => "A",
                },
                "B" => {
                    name => "B",
                    isSeenShared => JSON::true,
                    color => '#ABCDEF',
                    showAsLabel => JSON::false,
                }
            }
        }, "R1"]
    ]);
    $self->assert_equals(JSON::false, $res->[0][1]{created}{A}{isSeenShared});
    $self->assert(not exists $res->[0][1]{created}{B}{isSeenShared});
    $self->assert_null($res->[0][1]{created}{A}{color});
    $self->assert(not exists $res->[0][1]{created}{B}{color});
    $self->assert_equals(JSON::true, $res->[0][1]{created}{A}{showAsLabel});
    $self->assert(not exists $res->[0][1]{created}{B}{showAsLabel});
    my $mboxIdA = $res->[0][1]{created}{A}{id};
    my $mboxIdB = $res->[0][1]{created}{B}{id};

    $res = $jmap->CallMethods([
        ['Mailbox/get', {
            ids => [$mboxIdA, $mboxIdB],
            properties => ['isSeenShared', 'color', 'showAsLabel'],
        }, 'R1']
    ]);
    $self->assert_equals($mboxIdA, $res->[0][1]{list}[0]{id});
    $self->assert_equals(JSON::false, $res->[0][1]{list}[0]{isSeenShared});
    $self->assert_null($res->[0][1]{list}[0]{color});
    $self->assert_equals(JSON::true, $res->[0][1]{list}[0]{showAsLabel});
    $self->assert_equals($mboxIdB, $res->[0][1]{list}[1]{id});
    $self->assert_equals(JSON::true, $res->[0][1]{list}[1]{isSeenShared});
    $self->assert_str_equals('#ABCDEF', $res->[0][1]{list}[1]{color});
    $self->assert_equals(JSON::false, $res->[0][1]{list}[1]{showAsLabel});

    $res = $jmap->CallMethods([
        ['Mailbox/set', {
            update => {
                $mboxIdA => {
                    isSeenShared => JSON::true,
                    color => '#123456',
                    showAsLabel => JSON::false,
                },
                $mboxIdB => {
                    isSeenShared => JSON::false,
                    showAsLabel => JSON::false,
                },
            }
        }, "R1"]
    ]);
    $res = $jmap->CallMethods([
        ['Mailbox/get', {
            ids => [$mboxIdA, $mboxIdB],
            properties => ['isSeenShared', 'color', 'showAsLabel'],
        }, 'R1']
    ]);
    $self->assert_equals($mboxIdA, $res->[0][1]{list}[0]{id});
    $self->assert_equals(JSON::true, $res->[0][1]{list}[0]{isSeenShared});
    $self->assert_str_equals('#123456', $res->[0][1]{list}[0]{color});
    $self->assert_equals(JSON::false, $res->[0][1]{list}[0]{showAsLabel});
    $self->assert_equals($mboxIdB, $res->[0][1]{list}[1]{id});
    $self->assert_equals(JSON::false, $res->[0][1]{list}[1]{isSeenShared});
    $self->assert_str_equals('#ABCDEF', $res->[0][1]{list}[1]{color});
    $self->assert_equals(JSON::false, $res->[0][1]{list}[1]{showAsLabel});
}

sub test_mailbox_changes
    :min_version_3_1 :needs_component_jmap
{
    my ($self) = @_;

    my $jmap = $self->{jmap};
    my $imaptalk = $self->{store}->get_client();
    my $state;
    my $res;
    my %m;
    my $inbox;
    my $foo;
    my $drafts;

    xlog $self, "get mailbox list";
    $res = $jmap->CallMethods([['Mailbox/get', {}, "R1"]]);
    $state = $res->[0][1]->{state};
    $self->assert_not_null($state);
    %m = map { $_->{name} => $_ } @{$res->[0][1]{list}};
    $inbox = $m{"Inbox"}->{id};
    $self->assert_not_null($inbox);

    xlog $self, "get mailbox updates (expect error)";
    $res = $jmap->CallMethods([['Mailbox/changes', { sinceState => 0 }, "R1"]]);
    $self->assert_str_equals("cannotCalculateChanges", $res->[0][1]->{type});

    xlog $self, "get mailbox updates (expect no changes)";
    $res = $jmap->CallMethods([['Mailbox/changes', { sinceState => $state }, "R1"]]);
    $self->assert_str_equals($state, $res->[0][1]->{oldState});
    $self->assert_str_equals($state, $res->[0][1]->{newState});
    $self->assert_equals(JSON::false, $res->[0][1]->{hasMoreChanges});
    $self->assert_deep_equals([], $res->[0][1]{created});
    $self->assert_deep_equals([], $res->[0][1]{updated});
    $self->assert_deep_equals([], $res->[0][1]{destroyed});
    $self->assert_null($res->[0][1]{updatedProperties});

    xlog $self, "create mailbox via IMAP";
    $imaptalk->create("INBOX.foo")
        or die "Cannot create mailbox INBOX.foo: $@";

    xlog $self, "get mailbox list";
    $res = $jmap->CallMethods([['Mailbox/get', {}, "R1"]]);
    %m = map { $_->{name} => $_ } @{$res->[0][1]{list}};
    $foo = $m{"foo"}->{id};
    $self->assert_not_null($foo);

    xlog $self, "get mailbox updates";
    $res = $jmap->CallMethods([['Mailbox/changes', { sinceState => $state }, "R1"]]);
    $self->assert_str_equals($state, $res->[0][1]->{oldState});
    $self->assert_str_not_equals($state, $res->[0][1]->{newState});
    $self->assert_equals(JSON::false, $res->[0][1]->{hasMoreChanges});
    $self->assert_num_equals(1, scalar @{$res->[0][1]{created}});
    $self->assert_str_equals($foo, $res->[0][1]{created}[0]);
    $self->assert_deep_equals([], $res->[0][1]{updated});
    $self->assert_deep_equals([], $res->[0][1]{destroyed});
    $self->assert_null($res->[0][1]{updatedProperties});
    $state = $res->[0][1]->{newState};

    xlog $self, "create drafts mailbox";
    $res = $jmap->CallMethods([
            ['Mailbox/set', { create => { "1" => {
                            name => "drafts",
                            parentId => undef,
                            role => "drafts"
             }}}, "R1"]
    ]);
    $drafts = $res->[0][1]{created}{"1"}{id};
    $self->assert_not_null($drafts);

    xlog $self, "get mailbox updates";
    $res = $jmap->CallMethods([['Mailbox/changes', { sinceState => $state }, "R1"]]);
    $self->assert_str_equals($state, $res->[0][1]->{oldState});
    $self->assert_str_not_equals($state, $res->[0][1]->{newState});
    $self->assert_equals(JSON::false, $res->[0][1]->{hasMoreChanges});
    $self->assert_num_equals(1, scalar @{$res->[0][1]{created}});
    $self->assert_str_equals($drafts, $res->[0][1]{created}[0]);
    $self->assert_deep_equals([], $res->[0][1]{updated});
    $self->assert_deep_equals([], $res->[0][1]{destroyed});
    $self->assert_null($res->[0][1]{updatedProperties});
    $state = $res->[0][1]->{newState};

    xlog $self, "rename mailbox foo to bar";
    $res = $jmap->CallMethods([
            ['Mailbox/set', { update => { $foo => {
                            name => "bar",
                            sortOrder => 20
             }}}, "R1"]
    ]);
    $self->assert_num_equals(1, scalar keys %{$res->[0][1]{updated}});

    xlog $self, "get mailbox updates";
    $res = $jmap->CallMethods([['Mailbox/changes', { sinceState => $state }, "R1"]]);
    $self->assert_str_equals($state, $res->[0][1]->{oldState});
    $self->assert_str_not_equals($state, $res->[0][1]->{newState});
    $self->assert_equals(JSON::false, $res->[0][1]->{hasMoreChanges});
    $self->assert_deep_equals([], $res->[0][1]{created});
    $self->assert_num_equals(1, scalar @{$res->[0][1]{updated}});
    $self->assert_str_equals($foo, $res->[0][1]{updated}[0]);
    $self->assert_deep_equals([], $res->[0][1]{destroyed});
    $self->assert_null($res->[0][1]{updatedProperties});
    $state = $res->[0][1]->{newState};

    xlog $self, "delete mailbox bar";
    $res = $jmap->CallMethods([
            ['Mailbox/set', {
                    destroy => [ $foo ],
             }, "R1"]
    ]);
    $self->assert_num_equals(1, scalar @{$res->[0][1]{destroyed}});

    xlog $self, "rename mailbox drafts to stfard";
    $res = $jmap->CallMethods([
            ['Mailbox/set', {
                    update => { $drafts => { name => "stfard" } },
             }, "R1"]
    ]);
    $self->assert_num_equals(1, scalar keys %{$res->[0][1]{updated}});

    xlog $self, "get mailbox updates, limit to 1";
    $res = $jmap->CallMethods([['Mailbox/changes', { sinceState => $state, maxChanges => 1 }, "R1"]]);
    $self->assert_str_equals($state, $res->[0][1]->{oldState});
    $self->assert_str_not_equals($state, $res->[0][1]->{newState});
    $self->assert_equals(JSON::true, $res->[0][1]->{hasMoreChanges});
    $self->assert_deep_equals([], $res->[0][1]{created});
    $self->assert_deep_equals([], $res->[0][1]{updated});
    $self->assert_num_equals(1, scalar @{$res->[0][1]{destroyed}});
    $self->assert_str_equals($foo, $res->[0][1]{destroyed}[0]);
    $self->assert_null($res->[0][1]{updatedProperties});
    $state = $res->[0][1]->{newState};

    xlog $self, "get mailbox updates, limit to 1";
    $res = $jmap->CallMethods([['Mailbox/changes', { sinceState => $state, maxChanges => 1 }, "R1"]]);
    $self->assert_str_equals($state, $res->[0][1]->{oldState});
    $self->assert_str_not_equals($state, $res->[0][1]->{newState});
    $self->assert_equals(JSON::false, $res->[0][1]->{hasMoreChanges});
    $self->assert_deep_equals([], $res->[0][1]{created});
    $self->assert_num_equals(1, scalar @{$res->[0][1]{updated}});
    $self->assert_str_equals($drafts, $res->[0][1]{updated}[0]);
    $self->assert_deep_equals([], $res->[0][1]{destroyed});
    $self->assert_null($res->[0][1]{updatedProperties});
    $state = $res->[0][1]->{newState};

    xlog $self, "get mailbox updates (expect no changes)";
    $res = $jmap->CallMethods([['Mailbox/changes', { sinceState => $state }, "R1"]]);
    $self->assert_str_equals($state, $res->[0][1]->{oldState});
    $self->assert_str_equals($state, $res->[0][1]->{newState});
    $self->assert_equals(JSON::false, $res->[0][1]->{hasMoreChanges});
    $self->assert_deep_equals([], $res->[0][1]{created});
    $self->assert_deep_equals([], $res->[0][1]{updated});
    $self->assert_deep_equals([], $res->[0][1]{destroyed});
    $self->assert_null($res->[0][1]{updatedProperties});
}

sub test_mailbox_changes_counts
    :min_version_3_1 :needs_component_jmap
{
    my ($self) = @_;
    my $jmap = $self->{jmap};

    xlog $self, "create drafts mailbox";
    my $res = $jmap->CallMethods([
            ['Mailbox/set', { create => { "1" => {
                            name => "drafts",
                            parentId => undef,
                            role => "drafts"
             }}}, "R1"]
    ]);
    $self->assert_str_equals('Mailbox/set', $res->[0][0]);
    $self->assert_str_equals('R1', $res->[0][2]);
    $self->assert_not_null($res->[0][1]{created});
    my $mboxid = $res->[0][1]{created}{"1"}{id};
    my $state = $res->[0][1]{newState};

    my $draft =  {
        mailboxIds => { $mboxid => JSON::true },
        from => [ { name => "Yosemite Sam", email => "sam\@acme.local" } ] ,
        to => [
            { name => "Bugs Bunny", email => "bugs\@acme.local" },
        ],
        subject => "Memo",
        textBody => [{partId=>'1'}],
        bodyValues => { 1 => { value => "foo" }},
        keywords => {
            '$draft' => JSON::true,
        },
    };

    xlog $self, "get mailbox updates";
    $res = $jmap->CallMethods([['Mailbox/changes', { sinceState => $state }, "R1"]]);
    $state = $res->[0][1]{newState};

    xlog $self, "Create a draft";
    $res = $jmap->CallMethods([['Email/set', { create => { "1" => $draft }}, "R1"]]);
    my $msgid = $res->[0][1]{created}{"1"}{id};

    xlog $self, "update email";
    $res = $jmap->CallMethods([['Email/set', {
            update => { $msgid => {
                    keywords => {
                        '$draft' => JSON::true,
                        '$seen' => JSON::true
                    }
                }
            }
    }, "R1"]]);
    $self->assert(exists $res->[0][1]->{updated}{$msgid});

    xlog $self, "get mailbox updates";
    $res = $jmap->CallMethods([['Mailbox/changes', { sinceState => $state }, "R1"]]);
    $self->assert_str_not_equals($state, $res->[0][1]{newState});
    $self->assert_not_null($res->[0][1]{updatedProperties});
    $self->assert_deep_equals([], $res->[0][1]{created});
    $self->assert_num_not_equals(0, scalar @{$res->[0][1]{updated}});
    $self->assert_deep_equals([], $res->[0][1]{destroyed});
    $state = $res->[0][1]{newState};

    xlog $self, "update mailbox";
    $res = $jmap->CallMethods([['Mailbox/set', { update => { $mboxid => { name => "bar" }}}, "R1"]]);

    xlog $self, "get mailbox updates";
    $res = $jmap->CallMethods([['Mailbox/changes', { sinceState => $state }, "R1"]]);
    $self->assert_str_not_equals($state, $res->[0][1]{newState});
    $self->assert_null($res->[0][1]{updatedProperties});
    $self->assert_deep_equals([], $res->[0][1]{created});
    $self->assert_num_not_equals(0, scalar @{$res->[0][1]{updated}});
    $self->assert_deep_equals([], $res->[0][1]{destroyed});
    $state = $res->[0][1]{newState};

    xlog $self, "update email";
    $res = $jmap->CallMethods([['Email/set', { update => { $msgid => { 'keywords/$flagged' => JSON::true }}
    }, "R1"]]);
    $self->assert(exists $res->[0][1]->{updated}{$msgid});

    xlog $self, "get mailbox updates";
    $res = $jmap->CallMethods([['Mailbox/changes', { sinceState => $state }, "R1"]]);
    $self->assert_str_not_equals($state, $res->[0][1]{newState});
    $self->assert_not_null($res->[0][1]{updatedProperties});
    $self->assert_deep_equals([], $res->[0][1]{created});
    $self->assert_num_not_equals(0, scalar @{$res->[0][1]{updated}});
    $self->assert_deep_equals([], $res->[0][1]{destroyed});
    $state = $res->[0][1]{newState};

    xlog $self, "update mailbox";
    $res = $jmap->CallMethods([['Mailbox/set', { update => { $mboxid => { name => "baz" }}}, "R1"]]);

    xlog $self, "get mailbox updates";
    $res = $jmap->CallMethods([['Mailbox/changes', { sinceState => $state }, "R1"]]);
    $self->assert_str_not_equals($state, $res->[0][1]{newState});
    $self->assert_null($res->[0][1]{updatedProperties});
    $self->assert_deep_equals([], $res->[0][1]{created});
    $self->assert_num_not_equals(0, scalar @{$res->[0][1]{updated}});
    $self->assert_deep_equals([], $res->[0][1]{destroyed});
    $state = $res->[0][1]{newState};

    xlog $self, "get mailbox updates (expect no changes)";
    $res = $jmap->CallMethods([['Mailbox/changes', { sinceState => $state }, "R1"]]);
    $self->assert_str_equals($state, $res->[0][1]{newState});
    $self->assert_null($res->[0][1]{updatedProperties});
    $self->assert_deep_equals([], $res->[0][1]{created});
    $self->assert_deep_equals([], $res->[0][1]{updated});
    $self->assert_deep_equals([], $res->[0][1]{destroyed});
    $state = $res->[0][1]{newState};

    $draft->{subject} = "memo2";

    xlog $self, "Create another draft";
    $res = $jmap->CallMethods([['Email/set', { create => { "1" => $draft }}, "R1"]]);
    $msgid = $res->[0][1]{created}{"1"}{id};

    xlog $self, "get mailbox updates";
    $res = $jmap->CallMethods([['Mailbox/changes', { sinceState => $state }, "R1"]]);
    $self->assert_str_not_equals($state, $res->[0][1]{newState});
    $self->assert_not_null($res->[0][1]{updatedProperties});
    $self->assert_deep_equals([], $res->[0][1]{created});
    $self->assert_num_not_equals(0, scalar $res->[0][1]{updated});
    $self->assert_deep_equals([], $res->[0][1]{destroyed});
    $state = $res->[0][1]{newState};
}


sub test_mailbox_changes_shared
    :min_version_3_1 :needs_component_jmap
{
    my ($self) = @_;

    my $jmap = $self->{jmap};
    my $imaptalk = $self->{store}->get_client();
    my $admintalk = $self->{adminstore}->get_client();

    # Create user and share mailbox
    $self->{instance}->create_user("foo");
    $admintalk->setacl("user.foo", "cassandane", "lrwkxd") or die;

    xlog $self, "get mailbox list";
    my $res = $jmap->CallMethods([['Mailbox/get', { accountId => 'foo' }, "R1"]]);
    my $state = $res->[0][1]->{state};
    $self->assert_not_null($state);

    xlog $self, "get mailbox updates (expect no changes)";
    $res = $jmap->CallMethods([['Mailbox/changes', { accountId => 'foo', sinceState => $state }, "R1"]]);
    $self->assert_str_equals($state, $res->[0][1]->{oldState});
    $self->assert_str_equals($state, $res->[0][1]->{newState});
    $self->assert_null($res->[0][1]->{updatedProperties});

    xlog $self, "create mailbox box1 via IMAP";
    $admintalk->create("user.foo.box1") or die;
    $admintalk->setacl("user.foo.box1", "cassandane", "lrwkxd") or die;

    xlog $self, "get mailbox updates";
    $res = $jmap->CallMethods([['Mailbox/changes', { accountId => 'foo', sinceState => $state }, "R1"]]);
    $self->assert_str_equals($state, $res->[0][1]->{oldState});
    $self->assert_str_not_equals($state, $res->[0][1]->{newState});
    $self->assert_num_equals(1, scalar @{$res->[0][1]->{created}});
    $self->assert_deep_equals([], $res->[0][1]{updated});
    $self->assert_deep_equals([], $res->[0][1]{destroyed});
    $self->assert_null($res->[0][1]->{updatedProperties});
    $state = $res->[0][1]->{newState};
    my $box1 = $res->[0][1]->{created}[0];

    xlog $self, "destroy mailbox via JMAP";
    $res = $jmap->CallMethods([['Mailbox/set', { accountId => "foo", destroy => [ $box1 ] }, 'R1' ]]);
    $self->assert_str_equals($box1, $res->[0][1]{destroyed}[0]);

    xlog $self, "get mailbox updates";
    $res = $jmap->CallMethods([['Mailbox/changes', { accountId => 'foo', sinceState => $state }, "R1"]]);
    $self->assert_str_equals($state, $res->[0][1]->{oldState});
    $self->assert_str_not_equals($state, $res->[0][1]->{newState});
    $self->assert_deep_equals([], $res->[0][1]{created});
    $self->assert_deep_equals([], $res->[0][1]{updated});
    $self->assert_num_equals(1, scalar @{$res->[0][1]->{destroyed}});
    $self->assert_str_equals($box1, $res->[0][1]->{destroyed}[0]);
    $self->assert_null($res->[0][1]->{updatedProperties});
    $state = $res->[0][1]->{newState};

    xlog $self, "create mailbox box2 via IMAP";
    $admintalk->create("user.foo.box2") or die;
    $admintalk->setacl("user.foo.box2", "cassandane", "lrwkxinepd") or die;

    xlog $self, "get mailbox updates";
    $res = $jmap->CallMethods([['Mailbox/changes', { accountId => 'foo', sinceState => $state }, "R1"]]);
    $self->assert_str_equals($state, $res->[0][1]->{oldState});
    $self->assert_str_not_equals($state, $res->[0][1]->{newState});
    $self->assert_num_equals(1, scalar @{$res->[0][1]->{created}});
    $self->assert_deep_equals([], $res->[0][1]{updated});
    $self->assert_deep_equals([], $res->[0][1]{destroyed});
    $self->assert_null($res->[0][1]->{updatedProperties});
    $state = $res->[0][1]->{newState};

    my $box2 = $res->[0][1]->{created}[0];

    xlog $self, "Create a draft";
    my $draft =  {
        mailboxIds => { $box2 => JSON::true },
        from => [ { name => "Yosemite Sam", email => "sam\@acme.local" } ] ,
        to => [
            { name => "Bugs Bunny", email => "bugs\@acme.local" },
        ],
        subject => "Memo",
        textBody => [{partId=>'1'}],
        bodyValues => { 1 => { value => "foo" }},
        keywords => {
            '$draft' => JSON::true,
        },
    };
    $res = $jmap->CallMethods([['Email/set', {
        accountId => 'foo',
        create => { "1" => $draft }
    }, "R1"]]);
    my $msgid = $res->[0][1]{created}{"1"}{id};

    xlog $self, "get mailbox updates";
    $res = $jmap->CallMethods([['Mailbox/changes', { accountId => 'foo', sinceState => $state }, "R1"]]);
    $self->assert_str_equals($state, $res->[0][1]->{oldState});
    $self->assert_str_not_equals($state, $res->[0][1]->{newState});
    $self->assert_deep_equals([], $res->[0][1]{created});
    $self->assert_deep_equals([$box2], $res->[0][1]{updated});
    $self->assert_deep_equals([], $res->[0][1]{destroyed});
    $self->assert_not_null($res->[0][1]->{updatedProperties});
    $state = $res->[0][1]->{newState};

    xlog $self, "Remove lookup rights on box2";
    $admintalk->setacl("user.foo.box2", "cassandane", "") or die;

    xlog $self, "get mailbox updates";
    $res = $jmap->CallMethods([['Mailbox/changes', { accountId => 'foo', sinceState => $state }, "R1"]]);
    $self->assert_str_equals($state, $res->[0][1]->{oldState});
    $self->assert_str_not_equals($state, $res->[0][1]->{newState});
    $self->assert_deep_equals([], $res->[0][1]{created});
    $self->assert_deep_equals([], $res->[0][1]{updated});
    $self->assert_num_equals(1, scalar @{$res->[0][1]->{destroyed}});
    $self->assert_str_equals($box2, $res->[0][1]->{destroyed}[0]);
    $self->assert_null($res->[0][1]->{updatedProperties});
    $state = $res->[0][1]->{newState};

}

sub test_mailbox_set_issue2377
    :min_version_3_1 :needs_component_jmap
{
    my ($self) = @_;

    my $jmap = $self->{jmap};

    xlog $self, "get inbox";
    my $res = $jmap->CallMethods([['Mailbox/get', { }, "R1"]]);
    my $inbox = $res->[0][1]{list}[0];
    $self->assert_str_equals("Inbox", $inbox->{name});

    my $state = $res->[0][1]{state};

    xlog $self, "create mailbox";
    $res = $jmap->CallMethods([
            ['Mailbox/set', { create => { "1" => {
                            name => "foo",
                            parentId => "#",
                            role => undef
             }}}, "R1"]
    ]);
    $self->assert_not_null($res->[0][1]{notCreated}{'1'});
}

sub test_mailbox_querychanges_intermediary_added
    :min_version_3_1 :max_version_3_4 :needs_component_jmap
{
    my ($self) = @_;
    my $jmap = $self->{jmap};
    my $imap = $self->{store}->get_client();

    xlog $self, "Fetch initial mailbox state";
    my $res = $jmap->CallMethods([['Mailbox/query', {
        sort => [{ property => "name" }],
    }, "R1"]]);
    $self->assert_num_equals(1, scalar @{$res->[0][1]{ids}});
    $self->assert_equals(JSON::true, $res->[0][1]->{canCalculateChanges});
    my $state = $res->[0][1]->{queryState};
    $self->assert_not_null($state);

    xlog $self, "Create intermediate mailboxes via IMAP";
    $imap->create("INBOX.A.B.Z") or die;

    xlog $self, "Fetch updated mailbox state";
    $res = $jmap->CallMethods([['Mailbox/queryChanges', {
        sinceQueryState => $state,
        sort => [{ property => "name" }],
    }, "R1"]]);
    $self->assert_str_not_equals($state, $res->[0][1]->{newQueryState});
    my @ids = map { $_->{id} } @{$res->[0][1]->{added}};
    $self->assert_num_equals(3, scalar @ids);

    xlog $self, "Make sure intermediate mailboxes got reported";
    $res = $jmap->CallMethods([
        ['Mailbox/get', {
            ids => \@ids, properties => ['name'],
        }, "R1"]
    ]);
    $self->assert_not_null('A', $res->[0][1]{list}[0]{name});
    $self->assert_not_null('B', $res->[0][1]{list}[1]{name});
    $self->assert_not_null('Z', $res->[0][1]{list}[2]{name});
}

sub test_mailbox_querychanges_intermediary_removed
    :min_version_3_1 :max_version_3_4 :needs_component_jmap
{
    my ($self) = @_;
    my $jmap = $self->{jmap};
    my $imap = $self->{store}->get_client();

    xlog $self, "Create intermediate mailboxes via IMAP";
    $imap->create("INBOX.A.B.Z") or die;

    xlog $self, "Fetch initial mailbox state";
    my $res = $jmap->CallMethods([['Mailbox/query', {
        sort => [{ property => "name" }],
    }, "R1"]]);
    $self->assert_num_equals(4, scalar @{$res->[0][1]{ids}});
    $self->assert_equals(JSON::true, $res->[0][1]->{canCalculateChanges});
    my $state = $res->[0][1]->{queryState};
    $self->assert_not_null($state);

    xlog $self, "Delete intermediate mailboxes via IMAP";
    $imap->delete("INBOX.A.B.Z") or die;

    xlog $self, "Fetch updated mailbox state";
    $res = $jmap->CallMethods([['Mailbox/queryChanges', {
        sinceQueryState => $state,
        sort => [{ property => "name" }],
    }, "R1"]]);
    $self->assert_str_not_equals($state, $res->[0][1]->{newQueryState});
    $self->assert_num_equals(3, scalar @{$res->[0][1]->{removed}});
}

sub test_mailbox_get_intermediate
    :min_version_3_1 :max_version_3_4 :needs_component_jmap :JMAPExtensions :NoAltNameSpace
{
    my ($self) = @_;

    my $jmap = $self->{jmap};
    my $imap = $self->{store}->get_client();

    # we need 'https://cyrusimap.org/ns/jmap/mail' capability for
    # isSeenShared property
    my @using = @{ $jmap->DefaultUsing() };
    push @using, 'https://cyrusimap.org/ns/jmap/mail';
    $jmap->DefaultUsing(\@using);

    xlog $self, "Create intermediate mailbox via IMAP";
    $imap->create("INBOX.A.Z") or die;

    xlog $self, "Get mailboxes";
    my $res = $jmap->CallMethods([['Mailbox/get', {}, "R1"]]);
    $self->assert_num_equals(3, scalar @{$res->[0][1]{list}});

    my %mboxByName = map { $_->{name} => $_ } @{$res->[0][1]{list}};
    my $mboxA = $mboxByName{"A"};

    $self->assert_str_equals('A', $mboxA->{name});
    $self->assert_null($mboxA->{parentId});
    $self->assert_null($mboxA->{role});
    $self->assert_num_equals(0, $mboxA->{sortOrder}, 0);
    $self->assert_equals(JSON::true, $mboxA->{myRights}->{mayReadItems});
    $self->assert_equals(JSON::true, $mboxA->{myRights}->{mayAddItems});
    $self->assert_equals(JSON::true, $mboxA->{myRights}->{mayRemoveItems});
    $self->assert_equals(JSON::true, $mboxA->{myRights}->{mayCreateChild});
    $self->assert_equals(JSON::true, $mboxA->{myRights}->{mayRename});
    $self->assert_equals(JSON::true, $mboxA->{myRights}->{mayDelete});
    $self->assert_num_equals(0, $mboxA->{totalEmails});
    $self->assert_num_equals(0, $mboxA->{unreadEmails});
    $self->assert_num_equals(0, $mboxA->{totalThreads});
    $self->assert_num_equals(0, $mboxA->{unreadThreads});
    $self->assert_num_equals(JSON::false, $mboxA->{isSeenShared});
}

sub test_mailbox_get_inboxsub
    :min_version_3_1 :needs_component_jmap :JMAPExtensions :NoAltNameSpace
{
    my ($self) = @_;

    my $jmap = $self->{jmap};
    my $imap = $self->{store}->get_client();

    # we need 'https://cyrusimap.org/ns/jmap/mail' capability for
    # isSeenShared property
    my @using = @{ $jmap->DefaultUsing() };
    push @using, 'https://cyrusimap.org/ns/jmap/mail';
    $jmap->DefaultUsing(\@using);

    xlog $self, "Create INBOX subfolder via IMAP";
    $imap->create("INBOX.INBOX.foo") or die;

    xlog $self, "Get mailboxes";
    my $res = $jmap->CallMethods([['Mailbox/get', {}, "R1"]]);
    $self->assert_num_equals(2, scalar @{$res->[0][1]{list}});

    my %mboxByName = map { $_->{name} => $_ } @{$res->[0][1]{list}};
    my $mboxfoo = $mboxByName{"foo"};
    my $inbox = $mboxByName{"Inbox"};

    $self->assert_str_equals('foo', $mboxfoo->{name});
    $self->assert_str_equals($inbox->{id}, $mboxfoo->{parentId});
    $self->assert_null($mboxfoo->{role});
    $self->assert_num_equals(10, $mboxfoo->{sortOrder});
    $self->assert_equals(JSON::true, $mboxfoo->{myRights}->{mayReadItems});
    $self->assert_equals(JSON::true, $mboxfoo->{myRights}->{mayAddItems});
    $self->assert_equals(JSON::true, $mboxfoo->{myRights}->{mayRemoveItems});
    $self->assert_equals(JSON::true, $mboxfoo->{myRights}->{mayCreateChild});
    $self->assert_equals(JSON::true, $mboxfoo->{myRights}->{mayRename});
    $self->assert_equals(JSON::true, $mboxfoo->{myRights}->{mayDelete});
    $self->assert_num_equals(0, $mboxfoo->{totalEmails});
    $self->assert_num_equals(0, $mboxfoo->{unreadEmails});
    $self->assert_num_equals(0, $mboxfoo->{totalThreads});
    $self->assert_num_equals(0, $mboxfoo->{unreadThreads});
    $self->assert_num_equals(JSON::false, $mboxfoo->{isSeenShared});
}

sub test_mailbox_intermediary_imaprename_preservetree
    :min_version_3_1 :max_version_3_4 :needs_component_jmap :NoAltNameSpace
{
    my ($self) = @_;

    my $jmap = $self->{jmap};
    my $imap = $self->{store}->get_client();

    xlog $self, "Create mailboxes";
    $imap->create("INBOX.i1.i2.i3.foo") or die;
    $imap->create("INBOX.i1.i2.bar") or die;
    my $res = $jmap->CallMethods([['Mailbox/get', {
        properties => ['name', 'parentId'],
    }, "R1"]]);

    xlog $self, "Assert mailbox tree";
    my %mboxByName = map { $_->{name} => $_ } @{$res->[0][1]{list}};
    $self->assert_num_equals(6, scalar keys %mboxByName);
    $self->assert_not_null($mboxByName{'Inbox'});
    $self->assert_not_null($mboxByName{'i1'});
    $self->assert_not_null($mboxByName{'i2'});
    $self->assert_not_null($mboxByName{'i3'});
    $self->assert_not_null($mboxByName{'foo'});
    $self->assert_not_null($mboxByName{'bar'});
    $self->assert_null($mboxByName{i1}->{parentId});
    $self->assert_str_equals($mboxByName{i1}->{id}, $mboxByName{i2}->{parentId});
    $self->assert_str_equals($mboxByName{i2}->{id}, $mboxByName{i3}->{parentId});
    $self->assert_str_equals($mboxByName{i3}->{id}, $mboxByName{foo}->{parentId});
    $self->assert_str_equals($mboxByName{i2}->{id}, $mboxByName{bar}->{parentId});

    xlog $self, "Rename mailbox";
    $imap->rename("INBOX.i1.i2.i3.foo", "INBOX.i1.i4.baz") or die;

    xlog $self, "Assert mailbox tree";
    $res = $jmap->CallMethods([['Mailbox/get', {
        properties => ['name', 'parentId'],
    }, "R1"]]);
    %mboxByName = map { $_->{name} => $_ } @{$res->[0][1]{list}};
    $self->assert_num_equals(6, scalar keys %mboxByName);
    $self->assert_not_null($mboxByName{'Inbox'});
    $self->assert_not_null($mboxByName{'i1'});
    $self->assert_not_null($mboxByName{'i2'});
    $self->assert_not_null($mboxByName{'i4'});
    $self->assert_not_null($mboxByName{'bar'});
    $self->assert_not_null($mboxByName{'baz'});
    $self->assert_null($mboxByName{i1}->{parentId});
    $self->assert_str_equals($mboxByName{i1}->{id}, $mboxByName{i2}->{parentId});
    $self->assert_str_equals($mboxByName{i1}->{id}, $mboxByName{i4}->{parentId});
    $self->assert_str_equals($mboxByName{i2}->{id}, $mboxByName{bar}->{parentId});
    $self->assert_str_equals($mboxByName{i4}->{id}, $mboxByName{baz}->{parentId});
}

sub test_mailbox_set_intermediary_createchild
    :min_version_3_1 :max_version_3_4 :needs_component_jmap :NoAltNameSpace
{
    my ($self) = @_;

    my $jmap = $self->{jmap};
    my $imap = $self->{store}->get_client();

    xlog $self, "Create mailboxes";
    $imap->create("INBOX.i1.i2.i3.foo") or die;
    my $res = $jmap->CallMethods([
        ['Mailbox/get', {
            properties => ['name', 'parentId'],
        }, "R1"]
    ]);
    my %mboxByName = map { $_->{name} => $_ } @{$res->[0][1]{list}};

    $res = $jmap->CallMethods([
        ['Mailbox/set', {
            create => {
                1 => {
                    name => 'bar',
                    parentId => $mboxByName{'i2'}->{id},
                },
            }
        }, 'R1']
    ]);
    $self->assert_not_null($res->[0][1]{created}{1}{id});

    xlog $self, "Assert mailbox tree";
    $res = $jmap->CallMethods([
        ['Mailbox/get', {
            properties => ['name', 'parentId'],
        }, "R1"]
    ]);
    %mboxByName = map { $_->{name} => $_ } @{$res->[0][1]{list}};
    $self->assert_num_equals(6, scalar keys %mboxByName);
    $self->assert_not_null($mboxByName{'Inbox'});
    $self->assert_not_null($mboxByName{'i1'});
    $self->assert_not_null($mboxByName{'i2'});
    $self->assert_not_null($mboxByName{'i3'});
    $self->assert_not_null($mboxByName{'foo'});
    $self->assert_not_null($mboxByName{'bar'});
    $self->assert_null($mboxByName{i1}->{parentId});
    $self->assert_str_equals($mboxByName{i1}->{id}, $mboxByName{i2}->{parentId});
    $self->assert_str_equals($mboxByName{i2}->{id}, $mboxByName{i3}->{parentId});
    $self->assert_str_equals($mboxByName{i3}->{id}, $mboxByName{foo}->{parentId});
    $self->assert_str_equals($mboxByName{i2}->{id}, $mboxByName{bar}->{parentId});
}

sub test_mailbox_set_intermediary_rename
    :min_version_3_1 :max_version_3_4 :needs_component_jmap :NoAltNameSpace
{
    my ($self) = @_;

    my $jmap = $self->{jmap};
    my $imap = $self->{store}->get_client();

    xlog $self, "Create mailboxes";
    $imap->create("INBOX.i1.i2.foo") or die;
    my $res = $jmap->CallMethods([
        ['Mailbox/get', {
            properties => ['name', 'parentId'],
        }, "R1"]
    ]);
    my %mboxByName = map { $_->{name} => $_ } @{$res->[0][1]{list}};
    my $mboxId = $mboxByName{'i2'}->{id};
    my $mboxIdParent = $mboxByName{'i2'}->{parentId};
    $self->assert_not_null($mboxIdParent);

    xlog $self, "Rename intermediate";
    $res = $jmap->CallMethods([
        ['Mailbox/set', {
            update => {
                $mboxId => {
                    name => 'i3',
                },
            }
        }, 'R1'],
        ['Mailbox/get', {
            ids => [$mboxId],
            properties => ['name', 'parentId'],
        }, 'R2'],
    ]);
    $self->assert(exists $res->[0][1]{updated}{$mboxId});
    $self->assert_str_equals('i3', $res->[1][1]{list}[0]{name});
    $self->assert_str_equals($mboxIdParent, $res->[1][1]{list}[0]{parentId});

    xlog $self, "Assert mailbox tree";
    $res = $jmap->CallMethods([
        ['Mailbox/get', {
            properties => ['name', 'parentId'],
        }, "R1"]
    ]);
    %mboxByName = map { $_->{name} => $_ } @{$res->[0][1]{list}};
    $self->assert_num_equals(4, scalar keys %mboxByName);
    $self->assert_not_null($mboxByName{'Inbox'});
    $self->assert_not_null($mboxByName{'i1'});
    $self->assert_not_null($mboxByName{'i3'});
    $self->assert_not_null($mboxByName{'foo'});
    $self->assert_null($mboxByName{i1}->{parentId});
    $self->assert_str_equals($mboxByName{i1}->{id}, $mboxByName{i3}->{parentId});
    $self->assert_str_equals($mboxByName{i3}->{id}, $mboxByName{foo}->{parentId});
}

sub test_mailbox_set_intermediary_annotation
    :min_version_3_1 :max_version_3_4 :needs_component_jmap :NoAltNameSpace
{
    my ($self) = @_;

    my $jmap = $self->{jmap};
    my $imap = $self->{store}->get_client();

    xlog $self, "Create mailboxes";
    $imap->create("INBOX.i1.foo") or die;
    my $res = $jmap->CallMethods([
        ['Mailbox/get', {
            properties => ['name', 'parentId', 'sortOrder'],
        }, "R1"]
    ]);
    my %mboxByName = map { $_->{name} => $_ } @{$res->[0][1]{list}};
    my $mboxId = $mboxByName{'i1'}->{id};
    $self->assert_num_equals(0, $mboxByName{'i1'}->{sortOrder});
    $self->assert_null($mboxByName{'i1'}->{parentId});

    xlog $self, "Set annotation on intermediate";
    $res = $jmap->CallMethods([
        ['Mailbox/set', {
            update => {
                $mboxId => {
                    sortOrder => 7,
                },
            }
        }, 'R1'],
        ['Mailbox/get', {
            ids => [$mboxId],
            properties => ['name', 'parentId', 'sortOrder'],
        }, 'R2'],
    ]);
    $self->assert(exists $res->[0][1]{updated}{$mboxId});
    $self->assert_num_equals(7, $res->[1][1]{list}[0]->{sortOrder});

    xlog $self, "Assert mailbox tree";
    $res = $jmap->CallMethods([
        ['Mailbox/get', {
            properties => ['name', 'parentId'],
        }, "R1"]
    ]);
    %mboxByName = map { $_->{name} => $_ } @{$res->[0][1]{list}};
    $self->assert_num_equals(3, scalar keys %mboxByName);
    $self->assert_not_null($mboxByName{'Inbox'});
    $self->assert_not_null($mboxByName{'i1'});
    $self->assert_not_null($mboxByName{'foo'});
    $self->assert_null($mboxByName{i1}->{parentId});
    $self->assert_str_equals($mboxByName{i1}->{id}, $mboxByName{foo}->{parentId});
}

sub test_mailbox_set_intermediary_destroy_child
    :min_version_3_1 :max_version_3_4 :needs_component_jmap :NoAltNameSpace
{
    my ($self) = @_;

    my $jmap = $self->{jmap};
    my $imap = $self->{store}->get_client();

    xlog $self, "Create mailboxes";
    $imap->create("INBOX.i1.i2.foo") or die;
    my $res = $jmap->CallMethods([
        ['Mailbox/get', {
            properties => ['name', 'parentId'],
        }, "R1"]
    ]);
    my %mboxByName = map { $_->{name} => $_ } @{$res->[0][1]{list}};
    my $mboxIdFoo = $mboxByName{'foo'}->{id};
    my $mboxId1 = $mboxByName{'i1'}->{id};
    my $mboxId2 = $mboxByName{'i2'}->{id};
    my $state = $res->[0][1]{state};

    xlog $self, "Destroy child of intermediate";
    $res = $jmap->CallMethods([
        ['Mailbox/set', {
            destroy => [$mboxIdFoo],
        }, 'R1'],
    ]);
    $self->assert_str_equals($mboxIdFoo, $res->[0][1]{destroyed}[0]);
    $self->assert_str_not_equals($state, $res->[0][1]{newState});
    $state = $res->[0][1]{newState};

    xlog $self, "Assert mailbox tree and changes";
    $res = $jmap->CallMethods([
        ['Mailbox/get', {
            properties => ['name', 'parentId'],
        }, "R1"],
        ['Mailbox/changes', {
            sinceState => $state,
        }, 'R2'],
    ]);

    # All intermediaries without real children are gone.
    %mboxByName = map { $_->{name} => $_ } @{$res->[0][1]{list}};
    $self->assert_num_equals(1, scalar keys %mboxByName);
    $self->assert_not_null($mboxByName{'Inbox'});

    # But Mailbox/changes reports the implicitly destroyed mailboxes.
    $self->assert_num_equals(2, scalar @{$res->[1][1]{destroyed}});
    my %destroyed = map { $_ => 1 } @{$res->[1][1]{destroyed}};
    $self->assert_not_null($destroyed{$mboxId1});
    $self->assert_not_null($destroyed{$mboxId2});
}

sub test_mailbox_set_intermediary_move_child
    :min_version_3_1 :max_version_3_4 :needs_component_jmap :NoAltNameSpace
{
    my ($self) = @_;

    my $jmap = $self->{jmap};
    my $imap = $self->{store}->get_client();

    xlog $self, "Create mailboxes";
    $imap->create("INBOX.i1.i2.foo") or die;
    $imap->create("INBOX.i1.i3.bar") or die;
    my $res = $jmap->CallMethods([
        ['Mailbox/get', {
            properties => ['name', 'parentId'],
        }, "R1"]
    ]);
    my %mboxByName = map { $_->{name} => $_ } @{$res->[0][1]{list}};
    my $mboxIdFoo = $mboxByName{'foo'}->{id};
    my $mboxId1 = $mboxByName{'i1'}->{id};
    my $mboxId2 = $mboxByName{'i2'}->{id};
    my $mboxId3 = $mboxByName{'i3'}->{id};
    my $mboxIdBar = $mboxByName{'bar'}->{id};
    my $state = $res->[0][1]{state};

    xlog $self, "Move child of intermediary to another intermediary";
    $res = $jmap->CallMethods([
        ['Mailbox/set', {
            update => {
                $mboxIdBar => {
                    parentId => $mboxId2,
                },
            },
        }, 'R1'],
    ]);
    $self->assert(exists $res->[0][1]{updated}{$mboxIdBar});
    $self->assert_str_not_equals($state, $res->[0][1]{newState});
    $state = $res->[0][1]{newState};

    xlog $self, "Assert mailbox tree and changes";
    $res = $jmap->CallMethods([
        ['Mailbox/get', {
            properties => ['name', 'parentId'],
        }, "R1"],
        ['Mailbox/changes', {
            sinceState => $state,
        }, 'R2'],
    ]);

    # All intermediaries without real children are gone.
    %mboxByName = map { $_->{name} => $_ } @{$res->[0][1]{list}};
    $self->assert_num_equals(5, scalar keys %mboxByName);
    $self->assert_not_null($mboxByName{'Inbox'});
    $self->assert_not_null($mboxByName{'i1'});
    $self->assert_not_null($mboxByName{'i2'});
    $self->assert_not_null($mboxByName{'foo'});
    $self->assert_not_null($mboxByName{'bar'});
    $self->assert_null($mboxByName{i1}->{parentId});
    $self->assert_str_equals($mboxByName{i1}->{id}, $mboxByName{i2}->{parentId});
    $self->assert_str_equals($mboxByName{i2}->{id}, $mboxByName{foo}->{parentId});
    $self->assert_str_equals($mboxByName{i2}->{id}, $mboxByName{bar}->{parentId});

    # But Mailbox/changes reports the implicitly destroyed mailboxes.
    $self->assert_num_equals(1, scalar @{$res->[1][1]{destroyed}});
    $self->assert_str_equals($mboxId3, $res->[1][1]{destroyed}[0]);
}

sub test_mailbox_set_intermediary_destroy
    :min_version_3_1 :max_version_3_4 :needs_component_jmap :NoAltNameSpace
{
    my ($self) = @_;

    my $jmap = $self->{jmap};
    my $imap = $self->{store}->get_client();

    xlog $self, "Create mailboxes";
    $imap->create("INBOX.i1.i2.foo") or die;
    $imap->create("INBOX.i1.bar") or die;
    my $res = $jmap->CallMethods([
        ['Mailbox/get', {
            properties => ['name', 'parentId'],
        }, "R1"]
    ]);
    my %mboxByName = map { $_->{name} => $_ } @{$res->[0][1]{list}};
    my $mboxIdFoo = $mboxByName{'foo'}->{id};
    my $mboxId2 = $mboxByName{'i2'}->{id};

    xlog $self, "Destroy intermediate";
    $res = $jmap->CallMethods([
        ['Mailbox/set', {
            destroy => [$mboxId2, $mboxIdFoo],
        }, 'R1'],
    ]);
    $self->assert_num_equals(2, scalar @{$res->[0][1]{destroyed}});

    xlog $self, "Assert mailbox tree and changes";
    $res = $jmap->CallMethods([
        ['Mailbox/get', {
            properties => ['name', 'parentId'],
        }, "R1"],
    ]);

    # Intermediaries with real children are kept.
    %mboxByName = map { $_->{name} => $_ } @{$res->[0][1]{list}};
    $self->assert_num_equals(3, scalar keys %mboxByName);
    $self->assert_not_null($mboxByName{'Inbox'});
    $self->assert_not_null($mboxByName{'i1'});
    $self->assert_not_null($mboxByName{'bar'});
    $self->assert_null($mboxByName{i1}->{parentId});
    $self->assert_str_equals($mboxByName{i1}->{id}, $mboxByName{bar}->{parentId});
}

sub test_mailbox_set_subscriptions_destroy
    :min_version_3_1 :needs_component_jmap :NoAltNameSpace
{
    my ($self) = @_;

    my $jmap = $self->{jmap};
    my $imap = $self->{store}->get_client();

    my $res = $jmap->CallMethods([['Mailbox/set', {
        create => {
            A => {
                name => 'A', parentId => undef, role => undef,
            },
        },
    }, "R1"]]);
    my $idA =$res->[0][1]{created}{A}{id};
    $self->assert_not_null($idA);

    my $subdata = $imap->list([qw(SUBSCRIBED)], "", "*");
    $self->assert_num_equals(0, scalar @{$subdata});

    $imap->subscribe("INBOX.A") || die;

    $subdata = $imap->list([qw(SUBSCRIBED)], "", "*");
    $self->assert_num_equals(1, scalar @{$subdata});
    $self->assert_str_equals('INBOX.A', $subdata->[0][2]);

    $res = $jmap->CallMethods([['Mailbox/set', {
        destroy => [$idA],
    }, "R1"]]);
    $self->assert_str_equals($idA, $res->[0][1]{destroyed}[0]);

    $subdata = $imap->list([qw(SUBSCRIBED)], "", "*");
    $self->assert_num_equals(0, scalar @{$subdata});
}

sub test_mailbox_set_subscriptions_rename
    :min_version_3_1 :needs_component_jmap :NoAltNameSpace
{
    my ($self) = @_;

    my $jmap = $self->{jmap};
    my $imap = $self->{store}->get_client();

    my $res = $jmap->CallMethods([['Mailbox/set', {
        create => {
            A => {
                name => 'A', parentId => undef, role => undef,
            },
        },
    }, "R1"]]);
    my $idA =$res->[0][1]{created}{A}{id};
    $self->assert_not_null($idA);
    $imap->subscribe("INBOX.A") || die;

    my $subdata = $imap->list([qw(SUBSCRIBED)], "", "*");
    $self->assert_num_equals(1, scalar @{$subdata});
    $self->assert_str_equals('INBOX.A', $subdata->[0][2]);

    $res = $jmap->CallMethods([['Mailbox/set', {
        update => {
            $idA => {
                name => 'B',
            },
        },
    }, "R1"]]);
    $subdata = $imap->list([qw(SUBSCRIBED)], "", "*");
    $self->assert_num_equals(1, scalar @{$subdata});
    $self->assert_str_equals('INBOX.B', $subdata->[0][2]);
}

sub test_mailbox_set_subscriptions_rename_children
    :min_version_3_1 :needs_component_jmap :NoAltNameSpace
{
    my ($self) = @_;

    my $jmap = $self->{jmap};
    my $imap = $self->{store}->get_client();

    my $res = $jmap->CallMethods([['Mailbox/set', {
        create => {
            A => {
                name => 'A', parentId => undef, role => undef,
            },
            C => {
                name => 'C', parentId => '#A', role => undef,
            },
        },
    }, "R1"]]);
    my $idA =$res->[0][1]{created}{A}{id};
    $self->assert_not_null($idA);
    $imap->subscribe("INBOX.A.C") || die;

    my $subdata = $imap->list([qw(SUBSCRIBED)], "", "*");
    $self->assert_num_equals(1, scalar @{$subdata});
    $self->assert_str_equals('INBOX.A.C', $subdata->[0][2]);

    $res = $jmap->CallMethods([['Mailbox/set', {
        update => {
            $idA => {
                name => 'B',
            },
        },
    }, "R1"]]);
    $subdata = $imap->list([qw(SUBSCRIBED)], "", "*");
    $self->assert_num_equals(1, scalar @{$subdata});
    $self->assert_str_equals('INBOX.B.C', $subdata->[0][2]);
}

sub test_mailbox_set_create_serverset_props
    :min_version_3_1 :needs_component_jmap
{
    my ($self) = @_;

    my $jmap = $self->{jmap};

    xlog "can't create mailbox with server-set props";
    my $res = $jmap->CallMethods([
        ['Mailbox/set', {
            create => {
                mboxB => {
                    name => 'A',
                    role => undef,
					# server-set properties
                    totalEmails => 0,
                    unreadEmails => 0,
                    totalThreads => 0,
                    unreadThreads => 0,
                    myRights => {
                        mayReadItems => JSON::true,
                        mayAddItems =>  JSON::true,
                        mayRemoveItems => JSON::true,
						mayCreateChild => JSON::true,
						mayDelete => JSON::true,
						maySubmit => JSON::true,
                        maySetSeen => JSON::true,
                        maySetKeywords => JSON::true,
                        mayAdmin => JSON::true,
                        mayRename => JSON::true,
                    },
                },
            },
        }, 'R1'],
    ]);
    $self->assert_str_equals('invalidProperties',
        $res->[0][1]{notCreated}{mboxB}{type});
    my @wantInvalidProps = (
        'myRights',
        'totalEmails',
        'unreadEmails',
        'totalThreads',
        'unreadThreads',
    );
    my @gotInvalidProps = @{$res->[0][1]{notCreated}{mboxB}{properties}};
    @wantInvalidProps = sort @wantInvalidProps;
    @gotInvalidProps = sort @gotInvalidProps;
    $self->assert_deep_equals(\@wantInvalidProps, \@gotInvalidProps);
}

sub test_mailbox_set_update_serverset_props
    :min_version_3_1 :needs_component_jmap
{
    my ($self) = @_;

    my $jmap = $self->{jmap};

    xlog "create mailbox";
    my $res = $jmap->CallMethods([
        ['Mailbox/set', {
            create => {
                mboxA => {
                    name => 'A',
                    role => undef,
                },
            },
        }, 'R1'],
        ['Mailbox/get', {
            ids => ['#mboxA'],
        }, 'R2'],
    ]);
    my $mboxIdA = $res->[0][1]{created}{mboxA}{id};
    $self->assert_not_null($mboxIdA);
    my $mboxA = $res->[1][1]{list}[0];
    $self->assert_not_null($mboxA);

    xlog "update with matching server-set properties";
    $mboxA->{name} = 'XA';
    $res = $jmap->CallMethods([
        ['Mailbox/set', {
            update => {
                $mboxIdA => $mboxA,
            },
        }, 'R1'],
    ]);
    $self->assert(exists $res->[0][1]{updated}{$mboxIdA});

    xlog "update with matching server-set properties";
    # Assert default values before we change them.
    $self->assert_num_equals(0, $mboxA->{totalEmails});
    $self->assert_num_equals(0, $mboxA->{unreadEmails});
    $self->assert_num_equals(0, $mboxA->{totalThreads});
    $self->assert_num_equals(0, $mboxA->{unreadThreads});
    $self->assert_deep_equals({
        mayReadItems => JSON::true,
        mayAddItems =>  JSON::true,
        mayRemoveItems => JSON::true,
        mayCreateChild => JSON::true,
        mayDelete => JSON::true,
        maySubmit => JSON::true,
        maySetSeen => JSON::true,
        maySetKeywords => JSON::true,
        mayAdmin => JSON::true,
        mayRename => JSON::true,
    }, $mboxA->{myRights});
    $res = $jmap->CallMethods([
        ['Mailbox/set', {
            update => {
                $mboxIdA => {
                    totalEmails => 1,
                    unreadEmails => 1,
                    totalThreads => 1,
                    unreadThreads => 1,
                    myRights => {
                        mayReadItems => JSON::false,
                        mayAddItems =>  JSON::false,
                        mayRemoveItems => JSON::false,
                        mayCreateChild => JSON::false,
                        mayDelete => JSON::false,
                        maySubmit => JSON::false,
                        maySetSeen => JSON::false,
                        maySetKeywords => JSON::false,
                        mayAdmin => JSON::false,
                        mayRename => JSON::false,
                    },
                },
            },
        }, 'R1'],
    ]);
    $self->assert_str_equals('invalidProperties',
        $res->[0][1]{notUpdated}{$mboxIdA}{type});
    my @wantInvalidProps = (
        'myRights',
        'totalEmails',
        'unreadEmails',
        'totalThreads',
        'unreadThreads',
    );
    my @gotInvalidProps = @{$res->[0][1]{notUpdated}{$mboxIdA}{properties}};
    @wantInvalidProps = sort @wantInvalidProps;
    @gotInvalidProps = sort @gotInvalidProps;
    $self->assert_deep_equals(\@wantInvalidProps, \@gotInvalidProps);

    xlog "update with unknown mailbox right";
    $res = $jmap->CallMethods([
        ['Mailbox/set', {
            update => {
                $mboxIdA => {
                    'myRights/mayXxx' => JSON::false,
                },
            },
        }, 'R1'],
    ]);
    $self->assert_str_equals('invalidProperties',
        $res->[0][1]{notUpdated}{$mboxIdA}{type});
    $self->assert_deep_equals(['myRights'],
        $res->[0][1]{notUpdated}{$mboxIdA}{properties})
}

sub _check_one_count {
    my $self = shift;
    my $want = shift;
    my $have = shift;
    my $name = shift;
    $self->assert_num_equals($want, $have);
}

sub _check_counts
{
    my $self = shift;
    my $name = shift;
    my %expect = @_;

    my $jmap = $self->{jmap};

    my $res = $jmap->CallMethods([['Mailbox/get', {}, 'R']]);

    #  "totalEmails": 3,
    #  "unreadEmails": 1,
    #  "totalThreads": 3,
    #  "unreadThreads": 1,

    for my $folder (@{$res->[0][1]{list}}) {
        my $want = $expect{$folder->{name}};
        next unless $want;
        $self->_check_one_count($want->[0], $folder->{totalEmails}, "$folder->{name} totalEmails");
        $self->_check_one_count($want->[1], $folder->{unreadEmails}, "$folder->{name} unreadEmails");
        $self->_check_one_count($want->[2], $folder->{totalThreads}, "$folder->{name} totalThreads");
        $self->_check_one_count($want->[3], $folder->{unreadThreads}, "$folder->{name} unreadThreads");
    }
}

sub test_mailbox_counts
    :min_version_3_1 :needs_component_jmap :NoAltNameSpace
{
    my ($self) = @_;
    my $jmap = $self->{jmap};
    my $imap = $self->{store}->get_client();
    $imap->uid(1);
    my ($maj, $min) = Cassandane::Instance->get_version();

    xlog "Set up mailboxes";
    my $res = $jmap->CallMethods([
        ['Mailbox/query', { }, 'R1'],
        ['Mailbox/set', {
            create => {
                "a" => { name => "a", parentId => undef },
                "b" => { name => "b", parentId => undef },
                "trash" => {
                    name => "Trash",
                    parentId => undef,
                    role => "trash"
                }
            },
        }, 'R2'],
    ]);
    my %ids = map { $_ => $res->[1][1]{created}{$_}{id} }
              keys %{$res->[1][1]{created}};

    xlog "Append same message twice to inbox";
    my %raw = (
        A => <<"EOF",
From: <from\@local>\r
To: to\@local\r
Subject: test\r
Message-Id: <messageid1\@foo>\r
Date: Wed, 7 Dec 2019 22:11:11 +1100\r
MIME-Version: 1.0\r
Content-Type: text/plain\r
\r
test A\r
EOF
        B => <<"EOF",
From: <from\@local>\r
To: to\@local\r
Subject: test\r
Message-Id: <messageid1\@foo>\r
Date: Wed, 7 Dec 2019 22:11:11 +1100\r
MIME-Version: 1.0\r
Content-Type: text/plain\r
Message-Id: <reply2\@foo>\r
In-Reply-To: <messageid1\@foo>\r
\r
test B\r
EOF
        C => <<"EOF",
From: <from\@local>\r
To: to\@local\r
Subject: test\r
Message-Id: <messageid1\@foo>\r
Date: Wed, 7 Dec 2019 22:11:11 +1100\r
MIME-Version: 1.0\r
Content-Type: text/plain\r
Message-Id: <reply2\@foo>\r
In-Reply-To: <messageid1\@foo>\r
\r
test C\r
EOF
        D => <<"EOF",
From: <from\@local>\r
To: to\@local\r
Subject: test2\r
Message-Id: <messageid2\@foo>\r
Date: Wed, 7 Dec 2019 22:11:11 +1100\r
MIME-Version: 1.0\r
Content-Type: text/plain\r
\r
test D\r
EOF
        E => <<"EOF",
From: <from\@local>\r
To: to\@local\r
Subject: test3\r
Message-Id: <messageid3\@foo>\r
In-Reply-To: <messageid2\@foo>\r
Date: Wed, 7 Dec 2019 22:11:11 +1100\r
MIME-Version: 1.0\r
Content-Type: text/plain\r
\r
test E\r
EOF
        F => <<"EOF",
From: <from\@local>\r
To: to\@local\r
Subject: test2\r
Message-Id: <messageid4\@foo>\r
Date: Wed, 7 Dec 2019 22:11:11 +1100\r
MIME-Version: 1.0\r
Content-Type: text/plain\r
\r
test F\r
EOF
        G => <<"EOF",
From: <from\@local>\r
To: to\@local\r
Subject: test2\r
Message-Id: <messageid5\@foo>\r
In-Reply-To: <messageid4\@foo>\r
Date: Wed, 7 Dec 2019 22:11:11 +1100\r
MIME-Version: 1.0\r
Content-Type: text/plain\r
\r
test D\r
EOF
    );

    # threads:
    # T1: A B C
    # T2: D
    # T3: E
    # T4: F G (in-reply-to E, but different subject)

    xlog $self, "Set up all the emails in all the folders";
    $imap->append('INBOX.a', "(\\Seen)", $raw{A}) || die $@;
    $imap->append('INBOX.a', "()", $raw{A}) || die $@;
    $imap->append('INBOX.a', "(\\Seen)", $raw{C}) || die $@;
    $imap->append('INBOX.a', "(\\Seen)", $raw{D}) || die $@;
    $imap->append('INBOX.a', "()", $raw{E}) || die $@;
    $imap->append('INBOX.a', "(\\Seen)", $raw{F}) || die $@;
    $imap->append('INBOX.b', "()", $raw{B}) || die $@;
    $imap->append('INBOX.b', "(\\Seen)", $raw{C}) || die $@;
    $imap->append('INBOX.b', "(\\Seen)", $raw{E}) || die $@;
    $imap->append('INBOX.Trash', "(\\Seen)", $raw{G}) || die $@;

    # expectation:
    # A (a:1, seen - a:2, unseen) == unseen
    # B (b:1, unseen)
    # C (a:3, seen - b:2, seen)
    # D (a:4, seen)
    # E (a:5, unseen - b:3, seen) == unseen
    # F (a:6, seen)
    # G (trash:1, seen)

    # T1 in (a,b) unseen
    # T2 in a, seen
    # T3 in (a,b) unseen
    # T4 in (a,trash) seen

    if ($maj > 3 || ($maj == 3 && $min >= 6)) {
        $self->_check_counts('Initial Test',
            a => [ 5, 2, 4, 2 ],
            b => [ 3, 2, 2, 2 ],
            trash => [ 1, 0, 1, 0 ],
        );
    } else {
        $self->_check_counts('Initial Test',
            a => [ 5, 2, 4, 2 ],
            b => [ 3, 1, 2, 2 ],
            trash => [ 1, 0, 1, 0 ],
        );
    }

    xlog $self, "Move half an email to Trash";
    $imap->select("INBOX.a");
    $imap->move("2", "INBOX.Trash");

    # expectation:
    # A (a:1, seen - trash:2, unseen) == unseen in trash, seen in inbox
    # B (b:1, unseen)
    # C (a:3, seen - b:2, seen)
    # D (a:4, seen)
    # E (a:5, unseen - b:3, seen) == unseen
    # F (a:6, seen)
    # G (trash:1, seen)

    if ($maj > 3 || ($maj == 3 && $min >= 6)) {
        $self->_check_counts('After first move',
            a => [ 5, 1, 4, 2 ],
            b => [ 3, 2, 2, 2 ],
            trash => [ 2, 1, 2, 1 ],
        );
    } else {
        $self->_check_counts('After first move',
            a => [ 5, 1, 4, 2 ],
            b => [ 3, 1, 2, 2 ],
            trash => [ 2, 1, 2, 1 ],
        );
    }

    xlog $self, "Mark the bits of the thread OUTSIDE Trash all seen";
    $imap->select("INBOX.b");
    $imap->store("1", "+flags", "(\\Seen)");

    # expectation:
    # A (a:1, seen - trash:2, unseen) == unseen in trash, seen in inbox
    # B (b:1, seen)
    # C (a:3, seen - b:2, seen)
    # D (a:4, seen)
    # E (a:5, unseen - b:3, seen) == unseen
    # F (a:6, seen)
    # G (trash:1, seen)

    if ($maj > 3 || ($maj == 3 && $min >= 6)) {
        $self->_check_counts('Second change',
            a => [ 5, 1, 4, 1 ],
            b => [ 3, 1, 2, 1 ],
            trash => [ 2, 1, 2, 1 ],
        );
    } else {
        $self->_check_counts('Second change',
            a => [ 5, 1, 4, 1 ],
            b => [ 3, 0, 2, 1 ],
            trash => [ 2, 1, 2, 1 ],
        );
    }

    xlog $self, "Delete a message we don't care about";
    $imap->select("INBOX.b");
    $imap->store("1", "+flags", "(\\Deleted)");
    $imap->expunge();

    # expectation:
    # A (a:1, seen - trash:2, unseen) == unseen in trash, seen in inbox
    # C (a:3, seen - b:2, seen)
    # D (a:4, seen)
    # E (a:5, unseen - b:3, seen) == unseen
    # F (a:6, seen)
    # G (trash:1, seen)

    if ($maj > 3 || ($maj == 3 && $min >= 6)) {
        $self->_check_counts('Third change',
            a => [ 5, 1, 4, 1 ],
            b => [ 2, 1, 2, 1 ],
            trash => [ 2, 1, 2, 1 ],
        );
    } else {
        $self->_check_counts('Third change',
            a => [ 5, 1, 4, 1 ],
            b => [ 2, 0, 2, 1 ],
            trash => [ 2, 1, 2, 1 ],
        );
    }

    xlog $self, "Delete some more";
    $imap->select("INBOX.a");
    $imap->store("1,3,6", "+flags", "(\\Deleted)");
    $imap->expunge();

    # expectation:
    # A (trash:2, unseen) == unseen in trash
    # C (b:2, seen)
    # D (a:4, seen)
    # E (a:5, unseen - b:3, seen) == unseen
    # G (trash:1, seen)

    if ($maj > 3 || ($maj == 3 && $min >= 6)) {
        $self->_check_counts('Forth change',
            a => [ 2, 1, 2, 1 ],
            b => [ 2, 1, 2, 1 ],
            trash => [ 2, 1, 2, 1 ],
        );
    } else {
        $self->_check_counts('Forth change',
            a => [ 2, 1, 2, 1 ],
            b => [ 2, 0, 2, 1 ],
            trash => [ 2, 1, 2, 1 ],
        );
    }
}

sub test_mailbox_counts_add_remove
    :min_version_3_1 :needs_component_jmap :NoAltNameSpace
{
    my ($self) = @_;
    my $jmap = $self->{jmap};
    my $imap = $self->{store}->get_client();
    $imap->uid(1);

    xlog "Set up mailboxes";
    my $res = $jmap->CallMethods([
        ['Mailbox/query', { }, 'R1'],
        ['Mailbox/set', {
            create => {
                "a" => { name => "a", parentId => undef },
                "b" => { name => "b", parentId => undef },
            },
        }, 'R2'],
    ]);
    my %ids = map { $_ => $res->[1][1]{created}{$_}{id} }
              keys %{$res->[1][1]{created}};

    xlog "Set up messages";
    my %raw = (
        A => <<"EOF",
From: <from\@local>\r
To: to\@local\r
Subject: test\r
Message-Id: <messageid1\@foo>\r
Date: Wed, 7 Dec 2019 22:11:11 +1100\r
MIME-Version: 1.0\r
Content-Type: text/plain\r
\r
test A\r
EOF
        B => <<"EOF",
From: <from\@local>\r
To: to\@local\r
Subject: test\r
Message-Id: <messageid1\@foo>\r
Date: Wed, 7 Dec 2019 22:11:11 +1100\r
MIME-Version: 1.0\r
Content-Type: text/plain\r
Message-Id: <reply2\@foo>\r
In-Reply-To: <messageid1\@foo>\r
\r
test B\r
EOF
        C => <<"EOF",
From: <from\@local>\r
To: to\@local\r
Subject: test\r
Message-Id: <messageid1\@foo>\r
Date: Wed, 7 Dec 2019 22:11:11 +1100\r
MIME-Version: 1.0\r
Content-Type: text/plain\r
Message-Id: <reply2\@foo>\r
In-Reply-To: <messageid1\@foo>\r
\r
test C\r
EOF
        D => <<"EOF",
From: <from\@local>\r
To: to\@local\r
Subject: test2\r
Message-Id: <messageid2\@foo>\r
Date: Wed, 7 Dec 2019 22:11:11 +1100\r
MIME-Version: 1.0\r
Content-Type: text/plain\r
\r
test D\r
EOF
    );

    # threads:
    # T1: A B C
    # T2: D

    xlog $self, "Set up all the emails in all the folders";
    $imap->append('INBOX.a', "(\\Seen)", $raw{A}) || die $@;
    $imap->append('INBOX.a', "()", $raw{B}) || die $@;
    $imap->append('INBOX.a', "(\\Seen)", $raw{C}) || die $@;
    $imap->append('INBOX.a', "()", $raw{D}) || die $@;

    # expectation:
    # A (a:1, seen)
    # B (a:2, unseen)
    # C (a:3, seen)
    # D (a:4 unseen)

    $self->_check_counts('Initial Test',
        a => [ 4, 2, 2, 2 ],
        b => [ 0, 0, 0, 0 ],
    );

    xlog $self, "Move email to b";
    $imap->select("INBOX.a");
    $imap->move("3", "INBOX.b");

    # expectation:
    # A (a:1, seen)
    # B (a:2, unseen)
    # C (b:1, seen)
    # D (a:4 unseen)

    $self->_check_counts('After first move',
        a => [ 3, 2, 2, 2 ],
        b => [ 1, 0, 1, 1 ],
    );

    xlog $self, "mark seen";
    $imap->store(2, "+flags", "\\Seen");

    # expectation:
    # A (a:1, seen)
    # B (a:2, seen)
    # C (b:1, seen)
    # D (a:4 unseen)

    $self->_check_counts('After mark seen',
        a => [ 3, 1, 2, 1 ],
        b => [ 1, 0, 1, 0 ],
    );

    xlog $self, "move other";
    $imap->move("4", "INBOX.b");

    # expectation:
    # A (a:1, seen)
    # B (a:2, seen)
    # C (b:1, seen)
    # D (b:2 unseen)

    $self->_check_counts('After move other',
        a => [ 2, 0, 1, 0 ],
        b => [ 2, 1, 2, 1 ],
    );

    xlog $self, "move first back";
    $imap->select("INBOX.b");
    $imap->move("1", "INBOX.a");

    # expectation:
    # A (a:1, seen)
    # B (a:2, seen)
    # C (a:5, seen)
    # D (b:2 unseen)

    $self->_check_counts('After move first back',
        a => [ 3, 0, 1, 0 ],
        b => [ 1, 1, 1, 1 ],
    );

    xlog $self, "mark unseen again (different email)";
    $imap->select("INBOX.a");
    $imap->store(1, "-flags", "\\Seen");

    # expectation:
    # A (a:1, unseen)
    # B (a:2, seen)
    # C (a:5, seen)
    # D (b:2 unseen)

    $self->_check_counts('After mark unseen again',
        a => [ 3, 1, 1, 1 ],
        b => [ 1, 1, 1, 1 ],
    );
}

sub test_mailbox_trash_counts_ondelete
    :min_version_3_3 :needs_component_jmap :NoAltNameSpace
{
    my ($self) = @_;
    my $jmap = $self->{jmap};
    my $imap = $self->{store}->get_client();
    $imap->uid(1);

    xlog "Set up mailboxes";
    my $res = $jmap->CallMethods([
        ['Mailbox/query', { }, 'R1'],
        ['Mailbox/set', {
            create => {
                "a" => { name => "a", parentId => undef },
                "b" => { name => "b", parentId => undef },
                "trash" => { name => "Trash", parentId => undef, role => "trash" },
            },
        }, 'R2'],
    ]);
    my %ids = map { $_ => $res->[1][1]{created}{$_}{id} }
              keys %{$res->[1][1]{created}};

    xlog "Set up messages";
    my %raw = (
        A => <<"EOF",
From: <from\@local>\r
To: to\@local\r
Subject: test\r
Message-Id: <messageid1\@foo>\r
Date: Wed, 7 Dec 2019 22:11:11 +1100\r
MIME-Version: 1.0\r
Content-Type: text/plain\r
\r
test A\r
EOF
        B => <<"EOF",
From: <from\@local>\r
To: to\@local\r
Subject: test\r
Message-Id: <messageid1\@foo>\r
Date: Wed, 7 Dec 2019 22:11:11 +1100\r
MIME-Version: 1.0\r
Content-Type: text/plain\r
Message-Id: <reply2\@foo>\r
In-Reply-To: <messageid1\@foo>\r
\r
test B\r
EOF
        C => <<"EOF",
From: <from\@local>\r
To: to\@local\r
Subject: test\r
Message-Id: <messageid1\@foo>\r
Date: Wed, 7 Dec 2019 22:11:11 +1100\r
MIME-Version: 1.0\r
Content-Type: text/plain\r
Message-Id: <reply2\@foo>\r
In-Reply-To: <messageid1\@foo>\r
\r
test C\r
EOF
        D => <<"EOF",
From: <from\@local>\r
To: to\@local\r
Subject: test2\r
Message-Id: <messageid2\@foo>\r
Date: Wed, 7 Dec 2019 22:11:11 +1100\r
MIME-Version: 1.0\r
Content-Type: text/plain\r
\r
test D\r
EOF
    );

    # threads:
    # T1: A B C
    # T2: D

    xlog $self, "Set up all the emails in all the folders";
    $imap->append('INBOX.a', "(\\Seen)", $raw{A}) || die $@;
    $imap->append('INBOX.a', "()", $raw{B}) || die $@;
    $imap->append('INBOX.a', "(\\Seen)", $raw{C}) || die $@;
    $imap->append('INBOX.a', "()", $raw{D}) || die $@;

    $self->_check_counts('Initial Test',
        a => [ 4, 2, 2, 2 ],
        b => [ 0, 0, 0, 0 ],
        Trash => [ 0, 0, 0, 0 ],
    );

    xlog $self, "Move everything to trash";
    $imap->select("INBOX.a");
    $imap->move("1:*", "INBOX.Trash");
    $self->_check_counts('After move all to Trash',
        a => [ 0, 0, 0, 0 ],
        b => [ 0, 0, 0, 0 ],
        Trash => [ 4, 2, 2, 2 ],
    );

    xlog $self, "Destroy everything via JMAP";

    $res = $jmap->CallMethods([['Email/query', {}, "R1"]]);
    my $ids = $res->[0][1]->{ids};
    $res = $jmap->CallMethods([['Email/set', { destroy => $ids }, "R1"]]);

    $self->_check_counts('After Destroy Everything',
        a => [ 0, 0, 0, 0 ],
        b => [ 0, 0, 0, 0 ],
        Trash => [ 0, 0, 0, 0 ],
    );
}

sub test_mailbox_set_destroy_movetomailbox
    :min_version_3_3 :needs_component_jmap :JMAPExtensions
{
    my ($self) = @_;
    my $jmap = $self->{jmap};
    my $store = $self->{store};

    my $using = [
        'urn:ietf:params:jmap:core',
        'urn:ietf:params:jmap:mail',
        'https://cyrusimap.org/ns/jmap/mail',
    ];

    xlog "Create mailboxes";
    my $res = $jmap->CallMethods([
        ['Mailbox/set', {
            create => {
                mboxA => {
                    name => 'A',
                },
                mboxB => {
                    name => 'B',
                },
                mboxC => {
                    name => 'C',
                },
            },
        }, 'R1'],
        ['Email/set', {
            create => {
                emailA => {
                    mailboxIds => {
                        '#mboxA' => JSON::true,
                    },
                    subject => 'emailA',
                    bodyStructure => {
                        type => 'text/plain',
                        partId => '1',
                    },
                    bodyValues => {
                        1 => {
                            value => 'emailA',
                        }
                    },
                },
                emailAB => {
                    mailboxIds => {
                        '#mboxA' => JSON::true,
                        '#mboxB' => JSON::true,
                    },
                    subject => 'emailAB',
                    bodyStructure => {
                        type => 'text/plain',
                        partId => '1',
                    },
                    bodyValues => {
                        1 => {
                            value => 'emailAB',
                        }
                    },
                },
            },
        }, 'R2'],
    ], $using);
    my $mboxIdA = $res->[0][1]{created}{mboxA}{id};
    $self->assert_not_null($mboxIdA);
    my $mboxIdB = $res->[0][1]{created}{mboxB}{id};
    $self->assert_not_null($mboxIdB);
    my $mboxIdC = $res->[0][1]{created}{mboxC}{id};
    $self->assert_not_null($mboxIdC);
    my $emailIdA = $res->[1][1]{created}{emailA}{id};
    $self->assert_not_null($emailIdA);
    my $emailIdAB = $res->[1][1]{created}{emailAB}{id};
    $self->assert_not_null($emailIdAB);

    xlog "Destroy mailbox A and move emails to C";
    $res = $jmap->CallMethods([
        ['Mailbox/set', {
            destroy => [$mboxIdA],
            onDestroyMoveToMailboxIfNoMailbox => $mboxIdC,
        }, 'R1'],
        ['Email/get', {
            ids => [$emailIdA],
            properties => ['mailboxIds'],
        }, 'R2'],
        ['Email/get', {
            ids => [$emailIdAB],
            properties => ['mailboxIds'],
        }, 'R3'],
    ], $using);
    $self->assert_deep_equals([$mboxIdA],
        $res->[0][1]{destroyed});
    $self->assert_deep_equals({$mboxIdC => JSON::true},
        $res->[1][1]{list}[0]{mailboxIds});
    $self->assert_deep_equals({$mboxIdB => JSON::true},
        $res->[2][1]{list}[0]{mailboxIds});
}

sub test_mailbox_set_destroy_movetomailbox_empty
    :min_version_3_3 :needs_component_jmap :JMAPExtensions
{
    my ($self) = @_;
    my $jmap = $self->{jmap};
    my $store = $self->{store};

    my $using = [
        'urn:ietf:params:jmap:core',
        'urn:ietf:params:jmap:mail',
        'https://cyrusimap.org/ns/jmap/mail',
    ];

    xlog "Create mailboxes";
    my $res = $jmap->CallMethods([
        ['Mailbox/set', {
            create => {
                mboxA => {
                    name => 'A',
                },
                mboxB => {
                    name => 'B',
                },
                mboxC => {
                    name => 'C',
                },
            },
        }, 'R1'],
        ['Email/set', {
            create => {
                emailA => {
                    mailboxIds => {
                        '#mboxA' => JSON::true,
                    },
                    subject => 'emailA',
                    bodyStructure => {
                        type => 'text/plain',
                        partId => '1',
                    },
                    bodyValues => {
                        1 => {
                            value => 'emailA',
                        }
                    },
                },
            },
        }, 'R2'],
    ], $using);
    my $mboxIdA = $res->[0][1]{created}{mboxA}{id};
    $self->assert_not_null($mboxIdA);
    my $mboxIdB = $res->[0][1]{created}{mboxB}{id};
    $self->assert_not_null($mboxIdB);
    my $mboxIdC = $res->[0][1]{created}{mboxC}{id};
    $self->assert_not_null($mboxIdC);
    my $emailIdA = $res->[1][1]{created}{emailA}{id};
    $self->assert_not_null($emailIdA);

    xlog "Destroy mailbox B and move emails to C";
    $res = $jmap->CallMethods([
        ['Mailbox/set', {
            destroy => [$mboxIdB],
            onDestroyMoveToMailboxIfNoMailbox => $mboxIdC,
        }, 'R1'],
        ['Email/get', {
            ids => [$emailIdA],
            properties => ['mailboxIds'],
        }, 'R2'],
    ], $using);
    $self->assert_deep_equals([$mboxIdB],
        $res->[0][1]{destroyed});
    $self->assert_deep_equals({$mboxIdA => JSON::true},
        $res->[1][1]{list}[0]{mailboxIds});
}

sub test_mailbox_set_destroy_movetomailbox_errors
    :min_version_3_3 :needs_component_jmap :JMAPExtensions
{
    my ($self) = @_;

    my $jmap = $self->{jmap};

    my $using = [
        'urn:ietf:params:jmap:core',
        'urn:ietf:params:jmap:mail',
        'https://cyrusimap.org/ns/jmap/mail',
    ];

    xlog "Create mailboxes";
    my $res = $jmap->CallMethods([
        ['Mailbox/set', {
            create => {
                mboxA => {
                    name => 'A',
                },
                mboxB => {
                    name => 'B',
                },
            },
        }, 'R1'],
    ], $using);
    my $mboxIdA = $res->[0][1]{created}{mboxA}{id};
    $self->assert_not_null($mboxIdA);
    my $mboxIdB = $res->[0][1]{created}{mboxB}{id};
    $self->assert_not_null($mboxIdB);

    xlog "Can't move emails to updated or destroyed mailbox";
    $res = $jmap->CallMethods([
        ['Mailbox/set', {
            destroy => [$mboxIdA],
            onDestroyMoveToMailboxIfNoMailbox => $mboxIdA,
        }, 'R1'],
        ['Mailbox/set', {
            update => {
                $mboxIdB => {
                    role => 'trash',
                },
            },
            destroy => [$mboxIdA],
            onDestroyMoveToMailboxIfNoMailbox => $mboxIdB,
        }, 'R2'],
    ], $using);
    $self->assert_str_equals('invalidArguments', $res->[0][1]{type});
    $self->assert_deep_equals(['onDestroyMoveToMailboxIfNoMailbox'],
            $res->[0][1]{arguments});
    $self->assert_str_equals('invalidArguments', $res->[1][1]{type});
    $self->assert_deep_equals(['onDestroyMoveToMailboxIfNoMailbox'],
            $res->[1][1]{arguments});
}

# This is to test for a bug where a query against an intermediate mailbox was returning all emails!
sub test_mailbox_intermediate_no_emails
    :min_version_3_1 :needs_component_jmap
{
    my ($self) = @_;
    my $jmap = $self->{jmap};

    my $store = $self->{store};
    my $talk = $store->get_client();

    xlog $self, "Generate emails in INBOX via IMAP";
    $self->make_message("Email A") || die;
    $self->make_message("Email B") || die;
    $self->make_message("Email C") || die;

    xlog $self, "Create a deep folder";
    $talk->create("INBOX.Inter.Mediate");

    xlog $self, "Generate one email in the deep mailbox via IMAP";
    $store->set_folder("INBOX.Inter.Mediate");
    $self->make_message("Email D") || die;

    xlog $self, "get mailboxes";
    my $res = $jmap->CallMethods([['Mailbox/get', { }, "R1"]]);
    my %byname = map { $_->{name} => $_->{id} } @{$res->[0][1]{list}};

    xlog $self, "three emails in the Inbox";
    $res = $jmap->CallMethods([['Email/query',
                                { filter => { inMailbox => $byname{Inbox} },
                                  calculateTotal => JSON::true }, "R1"]]);
    $self->assert_num_equals(3, $res->[0][1]{total});
    $self->assert_num_equals(3, scalar @{$res->[0][1]{ids}});

    xlog $self, "no emails in the Intermediate mailbox";
    $res = $jmap->CallMethods([['Email/query',
                                { filter => { inMailbox => $byname{Inter} },
                                  calculateTotal => JSON::true }, "R1"]]);
    $self->assert_num_equals(0, $res->[0][1]{total});
    $self->assert_num_equals(0, scalar @{$res->[0][1]{ids}});

    xlog $self, "one email in the deep mailbox";
    $res = $jmap->CallMethods([['Email/query',
                                { filter => { inMailbox => $byname{Mediate} },
                                  calculateTotal => JSON::true }, "R1"]]);
    $self->assert_num_equals(1, $res->[0][1]{total});
    $self->assert_num_equals(1, scalar @{$res->[0][1]{ids}});
}

sub test_mailbox_changes_rename
    :min_version_3_5 :needs_component_jmap :NoAltNameSpace
{
    my ($self) = @_;
    my $jmap = $self->{jmap};
    my $imap = $self->{store}->get_client();


    $imap->create('INBOX.foo');

    my $res = $jmap->CallMethods([
        ['Mailbox/get', { }, 'R1'],
    ]);
    my $fooId;
    if ($res->[0][1]{list}[0]{name} eq 'foo') {
        $fooId = $res->[0][1]{list}[0]{id};
    }
    else {
        $fooId = $res->[0][1]{list}[1]{id};
    }
    $self->assert_not_null($fooId);
    my $state = $res->[0][1]{state};
    $self->assert_not_null($state);

    $imap->create('INBOX.bar');

    $res = $jmap->CallMethods([
        ['Mailbox/changes', {
            sinceState => $state,
        }, 'R1'],
    ]);
    my $barId = $res->[0][1]{created}[0];
    $self->assert_not_null($barId);
    $state = $res->[0][1]{newState};
    $self->assert_not_null($state);


    $imap->rename('INBOX.foo', 'INBOX.bar.foo');

    $res = $jmap->CallMethods([
        ['Mailbox/changes', {
            sinceState => $state,
        }, 'R1'],
    ]);
    $self->assert_deep_equals([], $res->[0][1]{created});
    $self->assert_deep_equals([$fooId], $res->[0][1]{updated});
    $self->assert_deep_equals([], $res->[0][1]{destroyed});
}

sub test_mailbox_set_sharewith
    :min_version_3_3 :needs_component_jmap :NoAltNameSpace :JMAPExtensions
{
    my ($self) = @_;

    my $jmap = $self->{jmap};
    my $imap = $self->{store}->get_client();
    my $admin = $self->{adminstore}->get_client();

    my $using = [
        'urn:ietf:params:jmap:core',
        'urn:ietf:params:jmap:mail',
        'https://cyrusimap.org/ns/jmap/mail',
    ];

    my $inboxId = $self->getinbox()->{id};
    $self->assert_not_null($inboxId);

    $self->{instance}->create_user("sharee");

    xlog $self, "Overwrite shareWith";
    my $res = $jmap->CallMethods([
        ['Mailbox/get', {
            ids => [$inboxId],
            properties => ['shareWith'],
        }, 'R1'],
        ['Mailbox/set', {
            update => {
                $inboxId => {
                    shareWith => {
                        sharee => {
                            mayRead => JSON::true,
                        },
                    },
                },
            },
        }, 'R2'],
        ['Mailbox/get', {
            ids => [$inboxId],
            properties => ['shareWith'],
        }, 'R3'],
    ], $using);

    $self->assert_null($res->[0][1]{list}[0]{shareWith});
    $self->assert_deep_equals({
        sharee => {
            mayRead => JSON::true,
            mayWrite => JSON::false,
            mayAdmin => JSON::false,
        },
    }, $res->[2][1]{list}[0]{shareWith});
    my $acl = $admin->getacl("user.cassandane");
    my %map = @$acl;
    $self->assert_str_equals('lr', $map{sharee});

    xlog $self, "Patch shareWith";
    $res = $jmap->CallMethods([
        ['Mailbox/set', {
            update => {
                $inboxId => {
                    'shareWith/sharee/mayWrite' => JSON::true,
                },
            },
        }, 'R1'],
        ['Mailbox/get', {
            ids => [$inboxId],
            properties => ['shareWith'],
        }, 'R2'],
    ], $using);

    $self->assert_deep_equals({
        sharee => {
            mayRead => JSON::true,
            mayWrite => JSON::true,
            mayAdmin => JSON::false,
        },
    }, $res->[1][1]{list}[0]{shareWith});
    $acl = $admin->getacl("user.cassandane");
    %map = @$acl;
    $self->assert_str_equals('lrswitedn', $map{sharee});

    xlog $self, "Patch shareWith with unknown right";
    $res = $jmap->CallMethods([
        ['Mailbox/set', {
            update => {
                $inboxId => {
                    'shareWith/sharee/unknownRight' => JSON::true,
                },
            },
        }, 'R1'],
    ], $using);
    $self->assert_str_equals('invalidProperties',
        $res->[0][1]{notUpdated}{$inboxId}{type});
    $self->assert_deep_equals(['shareWith/sharee/unknownRight'],
        $res->[0][1]{notUpdated}{$inboxId}{properties});
}

sub test_mailbox_set_sharewith_acl
    :min_version_3_5 :needs_component_jmap :JMAPExtensions
{
    my ($self) = @_;
    my $jmap = $self->{jmap};
    my $admin = $self->{adminstore}->get_client();
    my $imap = $self->{store}->get_client();

    $imap->create("A") or die;
    my $res = $jmap->CallMethods([
        ['Mailbox/query', {
            filter => {
                name => 'A',
            },
        }, 'R1'],
    ]);
    my $mboxId = $res->[0][1]{ids}[0];
    $self->assert_not_null($mboxId);

    $admin->create("user.sharee");

    my @testCases = ({
        rights => {
            mayAdmin => JSON::true,
        },
        acl => 'kxca',
    }, {
        rights => {
            mayWrite => JSON::true,
        },
        acl => 'switedn',
    }, {
        rights => {
            mayRead => JSON::true,
        },
        acl => 'lr',
    });

    foreach(@testCases) {

        xlog "Run test for acl $_->{acl}";

        $res = $jmap->CallMethods([
            ['Mailbox/set', {
                update => {
                    $mboxId => {
                        shareWith => {
                            sharee => $_->{rights},
                        },
                    },
                },
            }, 'R1'],
            ['Mailbox/get', {
                ids => [$mboxId],
                properties => ['shareWith'],
            }, 'R2'],
        ], [
        'urn:ietf:params:jmap:core',
        'urn:ietf:params:jmap:mail',
        'https://cyrusimap.org/ns/jmap/mail'
        ]) ;

        $_->{wantRights} ||= $_->{rights};

        my %mergedrights = ((
            mayAdmin => JSON::false,
            mayWrite => JSON::false,
            mayRead => JSON::false,
        ), %{$_->{wantRights}});

        $self->assert_deep_equals(\%mergedrights,
            $res->[1][1]{list}[0]{shareWith}{sharee});
        my %acl = @{$admin->getacl("user.cassandane.A")};
        $self->assert_str_equals($_->{acl}, $acl{sharee});
    }
}

sub test_mailbox_changes_notes
    :min_version_3_7 :needs_component_jmap :JMAPExtensions
{
    my ($self) = @_;

    my $jmap = $self->{jmap};
    my $state;
    my $res;
    my %m;
    my $inbox;

    xlog $self, "get mailbox list";
    $res = $jmap->CallMethods([['Mailbox/get', {}, "R1"]]);
    $state = $res->[0][1]->{state};
    $self->assert_not_null($state);
    %m = map { $_->{name} => $_ } @{$res->[0][1]{list}};
    $inbox = $m{"Inbox"}->{id};
    $self->assert_not_null($inbox);

    # we need 'https://cyrusimap.org/ns/jmap/notes' capability
    my @using = @{ $jmap->DefaultUsing() };
    push @using, 'https://cyrusimap.org/ns/jmap/notes';
    $jmap->DefaultUsing(\@using);

    # force creation of notes mailbox prior to creating notes
    $res = $jmap->CallMethods([
        ['Note/set', {
         }, "R0"]
    ]);

    xlog "create note";
    $res = $jmap->CallMethods([['Note/set',
                                { create => { "1" => {title => "foo"}, } },
                                "R1"]]);
    $self->assert_not_null($res);

    xlog $self, "get mailbox updates (expect no changes)";
    $res = $jmap->CallMethods([['Mailbox/changes', { sinceState => $state }, "R1"]]);
    $self->assert_str_equals($state, $res->[0][1]->{oldState});
    $self->assert_str_equals($state, $res->[0][1]->{newState});
    $self->assert_equals(JSON::false, $res->[0][1]->{hasMoreChanges});
    $self->assert_deep_equals([], $res->[0][1]{created});
    $self->assert_deep_equals([], $res->[0][1]{updated});
    $self->assert_deep_equals([], $res->[0][1]{destroyed});
    $self->assert_null($res->[0][1]{updatedProperties});
}

sub test_mailbox_ignore_notes_subfolders
    :min_version_3_7 :needs_component_jmap :JMAPExtensions
{
    my ($self) = @_;

    my $jmap = $self->{jmap};
    my $imap = $self->{store}->get_client();

    xlog 'Fetch inbox id';
    my $res = $jmap->CallMethods([
        ['Mailbox/query', { }, 'R1']
    ]);
    $self->assert_num_equals(1, scalar @{$res->[0][1]{ids}});
    my $inboxId = $res->[0][1]{ids}[0];

    xlog 'Create Notes mailbox';
    $imap->create("Notes", "(USE (\\XNotes))") or die "$!";

    xlog 'Assert Notes folder is invisible';
    $res = $jmap->CallMethods([
        ['Mailbox/query', { }, 'R1'],
        ['Mailbox/get', { }, 'R2']
    ]);
    $self->assert_deep_equals([$inboxId], $res->[0][1]{ids});
    $self->assert_num_equals(1, scalar @{$res->[1][1]{list}});
    $self->assert_str_equals($inboxId, $res->[1][1]{list}[0]{id});

    xlog 'Create subfolder in Notes folder';
    $imap->create("Notes.Sub") or die "$!";

    xlog 'Assert Notes folders are invisible';
    $res = $jmap->CallMethods([
        ['Mailbox/query', { }, 'R1'],
        ['Mailbox/get', { }, 'R2']
    ]);
    $self->assert_deep_equals([$inboxId], $res->[0][1]{ids});
    $self->assert_num_equals(1, scalar @{$res->[1][1]{list}});
    $self->assert_str_equals($inboxId, $res->[1][1]{list}[0]{id});
}

1;
