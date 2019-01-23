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
use Mail::JMAPTalk 0.12;
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
                 httpallowcompress => 'no');

    return $class->SUPER::new({
        config => $config,
        jmap => 1,
        adminstore => 1,
        services => [ 'imap', 'http' ]
    }, @args);
}

sub getinbox
{
    my ($self, $args) = @_;

    $args = {} unless $args;

    my $jmap = $self->{jmap};

    xlog "get existing mailboxes";
    my $res = $jmap->CallMethods([['Mailbox/get', $args, "R1"]]);
    $self->assert_not_null($res);

    my %m = map { $_->{name} => $_ } @{$res->[0][1]{list}};
    return $m{"Inbox"};
}


sub test_mailbox_get
    :min_version_3_1 :needs_component_jmap
{
    my ($self) = @_;

    my $jmap = $self->{jmap};
    my $imaptalk = $self->{store}->get_client();

    $imaptalk->create("INBOX.foo")
        or die "Cannot create mailbox INBOX.foo: $@";

    $imaptalk->create("INBOX.foo.bar")
        or die "Cannot create mailbox INBOX.foo.bar: $@";

    xlog "get existing mailboxes";
    my $res = $jmap->CallMethods([['Mailbox/get', {}, "R1"]]);
    $self->assert_not_null($res);
    $self->assert_str_equals($res->[0][0], 'Mailbox/get');
    $self->assert_str_equals($res->[0][2], 'R1');

    my %m = map { $_->{name} => $_ } @{$res->[0][1]{list}};
    $self->assert_num_equals(scalar keys %m, 3);
    my $inbox = $m{"Inbox"};
    my $foo = $m{"foo"};
    my $bar = $m{"bar"};

    # INBOX
    $self->assert_str_equals($inbox->{name}, "Inbox");
    $self->assert_null($inbox->{parentId});
    $self->assert_str_equals($inbox->{role}, "inbox");
    $self->assert_num_equals($inbox->{sortOrder}, 0);
    $self->assert_equals($inbox->{myRights}->{mayReadItems}, JSON::true);
    $self->assert_equals($inbox->{myRights}->{mayAddItems}, JSON::true);
    $self->assert_equals($inbox->{myRights}->{mayRemoveItems}, JSON::true);
    $self->assert_equals($inbox->{myRights}->{mayCreateChild}, JSON::true);
    $self->assert_equals($inbox->{myRights}->{mayRename}, JSON::false);
    $self->assert_equals($inbox->{myRights}->{mayDelete}, JSON::false);
    $self->assert_equals($inbox->{myRights}->{maySetSeen}, JSON::true);
    $self->assert_equals($inbox->{myRights}->{maySetKeywords}, JSON::true);
    $self->assert_equals($inbox->{myRights}->{maySubmit}, JSON::true);
    $self->assert_num_equals($inbox->{totalEmails}, 0);
    $self->assert_num_equals($inbox->{unreadEmails}, 0);
    $self->assert_num_equals($inbox->{totalThreads}, 0);
    $self->assert_num_equals($inbox->{unreadThreads}, 0);

    # INBOX.foo
    $self->assert_str_equals($foo->{name}, "foo");
    $self->assert_null($foo->{parentId});
    $self->assert_null($foo->{role});
    $self->assert_num_equals($foo->{sortOrder}, 0);
    $self->assert_equals($foo->{myRights}->{mayReadItems}, JSON::true);
    $self->assert_equals($foo->{myRights}->{mayAddItems}, JSON::true);
    $self->assert_equals($foo->{myRights}->{mayRemoveItems}, JSON::true);
    $self->assert_equals($foo->{myRights}->{mayCreateChild}, JSON::true);
    $self->assert_equals($foo->{myRights}->{mayRename}, JSON::true);
    $self->assert_equals($foo->{myRights}->{mayDelete}, JSON::true);
    $self->assert_num_equals($foo->{totalEmails}, 0);
    $self->assert_num_equals($foo->{unreadEmails}, 0);
    $self->assert_num_equals($foo->{totalThreads}, 0);
    $self->assert_num_equals($foo->{unreadThreads}, 0);

    # INBOX.foo.bar
    $self->assert_str_equals($bar->{name}, "bar");
    $self->assert_str_equals($bar->{parentId}, $foo->{id});
    $self->assert_null($bar->{role});
    $self->assert_num_equals($bar->{sortOrder}, 0);
    $self->assert_equals($bar->{myRights}->{mayReadItems}, JSON::true);
    $self->assert_equals($bar->{myRights}->{mayAddItems}, JSON::true);
    $self->assert_equals($bar->{myRights}->{mayRemoveItems}, JSON::true);
    $self->assert_equals($bar->{myRights}->{mayCreateChild}, JSON::true);
    $self->assert_equals($bar->{myRights}->{mayRename}, JSON::true);
    $self->assert_equals($bar->{myRights}->{mayDelete}, JSON::true);
    $self->assert_num_equals($bar->{totalEmails}, 0);
    $self->assert_num_equals($bar->{unreadEmails}, 0);
    $self->assert_num_equals($bar->{totalThreads}, 0);
    $self->assert_num_equals($bar->{unreadThreads}, 0);
}

sub test_mailbox_get_inbox_sub
    :min_version_3_1 :needs_component_jmap
{
    my ($self) = @_;

    my $jmap = $self->{jmap};
    my $imaptalk = $self->{store}->get_client();

    $imaptalk->create("INBOX.INBOX.foo")
        or die "Cannot create mailbox INBOX.INBOX.foo: $@";

    $imaptalk->create("INBOX.INBOX.foo.bar")
        or die "Cannot create mailbox INBOX.INBOX.foo.bar: $@";

    xlog "get existing mailboxes";
    my $res = $jmap->CallMethods([['Mailbox/get', {}, "R1"]]);
    $self->assert_not_null($res);
    $self->assert_str_equals($res->[0][0], 'Mailbox/get');
    $self->assert_str_equals($res->[0][2], 'R1');

    my %m = map { $_->{name} => $_ } @{$res->[0][1]{list}};
    $self->assert_num_equals(scalar keys %m, 3);
    my $inbox = $m{"Inbox"};
    my $foo = $m{"foo"};
    my $bar = $m{"bar"};

    # INBOX
    $self->assert_str_equals($inbox->{name}, "Inbox");
    $self->assert_null($inbox->{parentId});
    $self->assert_str_equals($inbox->{role}, "inbox");
    $self->assert_num_equals($inbox->{sortOrder}, 0);
    $self->assert_equals($inbox->{myRights}->{mayReadItems}, JSON::true);
    $self->assert_equals($inbox->{myRights}->{mayAddItems}, JSON::true);
    $self->assert_equals($inbox->{myRights}->{mayRemoveItems}, JSON::true);
    $self->assert_equals($inbox->{myRights}->{mayCreateChild}, JSON::true);
    $self->assert_equals($inbox->{myRights}->{mayRename}, JSON::false);
    $self->assert_equals($inbox->{myRights}->{mayDelete}, JSON::false);
    $self->assert_equals($inbox->{myRights}->{maySetSeen}, JSON::true);
    $self->assert_equals($inbox->{myRights}->{maySetKeywords}, JSON::true);
    $self->assert_equals($inbox->{myRights}->{maySubmit}, JSON::true);
    $self->assert_num_equals($inbox->{totalEmails}, 0);
    $self->assert_num_equals($inbox->{unreadEmails}, 0);
    $self->assert_num_equals($inbox->{totalThreads}, 0);
    $self->assert_num_equals($inbox->{unreadThreads}, 0);

    # INBOX.INBOX.foo
    $self->assert_str_equals($foo->{name}, "foo");
    $self->assert_str_equals($foo->{parentId}, $inbox->{id});
    $self->assert_null($foo->{role});
    $self->assert_num_equals($foo->{sortOrder}, 0);
    $self->assert_equals($foo->{myRights}->{mayReadItems}, JSON::true);
    $self->assert_equals($foo->{myRights}->{mayAddItems}, JSON::true);
    $self->assert_equals($foo->{myRights}->{mayRemoveItems}, JSON::true);
    $self->assert_equals($foo->{myRights}->{mayCreateChild}, JSON::true);
    $self->assert_equals($foo->{myRights}->{mayRename}, JSON::true);
    $self->assert_equals($foo->{myRights}->{mayDelete}, JSON::true);
    $self->assert_num_equals($foo->{totalEmails}, 0);
    $self->assert_num_equals($foo->{unreadEmails}, 0);
    $self->assert_num_equals($foo->{totalThreads}, 0);
    $self->assert_num_equals($foo->{unreadThreads}, 0);

    # INBOX.INBOX.foo.bar
    $self->assert_str_equals($bar->{name}, "bar");
    $self->assert_str_equals($bar->{parentId}, $foo->{id});
    $self->assert_null($bar->{role});
    $self->assert_num_equals($bar->{sortOrder}, 0);
    $self->assert_equals($bar->{myRights}->{mayReadItems}, JSON::true);
    $self->assert_equals($bar->{myRights}->{mayAddItems}, JSON::true);
    $self->assert_equals($bar->{myRights}->{mayRemoveItems}, JSON::true);
    $self->assert_equals($bar->{myRights}->{mayCreateChild}, JSON::true);
    $self->assert_equals($bar->{myRights}->{mayRename}, JSON::true);
    $self->assert_equals($bar->{myRights}->{mayDelete}, JSON::true);
    $self->assert_num_equals($bar->{totalEmails}, 0);
    $self->assert_num_equals($bar->{unreadEmails}, 0);
    $self->assert_num_equals($bar->{totalThreads}, 0);
    $self->assert_num_equals($bar->{unreadThreads}, 0);
}

sub test_mailbox_get_specialuse
    :min_version_3_1 :needs_component_jmap
{
    my ($self) = @_;

    my $jmap = $self->{jmap};
    my $imaptalk = $self->{store}->get_client();

    $imaptalk->create("INBOX.Archive", "(USE (\\Archive))") || die;
    $imaptalk->create("INBOX.Drafts", "(USE (\\Drafts))") || die;
    $imaptalk->create("INBOX.Spam", "(USE (\\Junk))") || die;
    $imaptalk->create("INBOX.Sent", "(USE (\\Sent))") || die;
    $imaptalk->create("INBOX.Trash", "(USE (\\Trash))") || die;

    xlog "get mailboxes";
    my $res = $jmap->CallMethods([['Mailbox/get', {}, "R1"]]);
    $self->assert_not_null($res);
    $self->assert_str_equals($res->[0][0], 'Mailbox/get');
    $self->assert_str_equals($res->[0][2], 'R1');

    my %m = map { $_->{name} => $_ } @{$res->[0][1]{list}};
    my $inbox = $m{"Inbox"};
    my $archive = $m{"Archive"};
    my $drafts = $m{"Drafts"};
    my $junk = $m{"Spam"};
    my $sent = $m{"Sent"};
    my $trash = $m{"Trash"};

    $self->assert_str_equals($archive->{name}, "Archive");
    $self->assert_str_equals($archive->{role}, "archive");

    $self->assert_str_equals($drafts->{name}, "Drafts");
    $self->assert_null($drafts->{parentId});
    $self->assert_str_equals($drafts->{role}, "drafts");

    $self->assert_str_equals($junk->{name}, "Spam");
    $self->assert_null($junk->{parentId});
    $self->assert_str_equals($junk->{role}, "junk");

    $self->assert_str_equals($sent->{name}, "Sent");
    $self->assert_null($sent->{parentId});
    $self->assert_str_equals($sent->{role}, "sent");

    $self->assert_str_equals($trash->{name}, "Trash");
    $self->assert_null($trash->{parentId});
    $self->assert_str_equals($trash->{role}, "trash");
}

sub test_mailbox_get_properties
    :min_version_3_1 :needs_component_jmap
{
    my ($self) = @_;

    my $jmap = $self->{jmap};

    xlog "get mailboxes with name property";
    my $res = $jmap->CallMethods([['Mailbox/get', { properties => ["name"]}, "R1"]]);
    $self->assert_not_null($res);
    $self->assert_str_equals($res->[0][0], 'Mailbox/get');
    $self->assert_str_equals($res->[0][2], 'R1');

    my $inbox = $res->[0][1]{list}[0];
    $self->assert_str_equals($inbox->{name}, "Inbox");
    $self->assert_num_equals(scalar keys %{$inbox}, 2); # id and name

    xlog "get mailboxes with erroneous property";
    $res = $jmap->CallMethods([['Mailbox/get', { properties => ["name", 123]}, "R1"]]);
    $self->assert_not_null($res);
    $self->assert_str_equals('error', $res->[0][0]);
    $self->assert_str_equals('R1', $res->[0][2]);

    my $err = $res->[0][1];
    $self->assert_str_equals("invalidArguments", $err->{type});
    $self->assert_str_equals("properties[1]", $err->{arguments}[0]);

    xlog "get mailboxes with unknown property";
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

    xlog "get all mailboxes";
    my $res = $jmap->CallMethods([['Mailbox/get', { }, "R1"]]);
    $self->assert_not_null($res);
    $self->assert_str_equals($res->[0][0], 'Mailbox/get');
    $self->assert_str_equals($res->[0][2], 'R1');

    my %m = map { $_->{name} => $_ } @{$res->[0][1]{list}};
    my $inbox = $m{"Inbox"};
    my $foo = $m{"foo"};
    $self->assert_not_null($inbox);
    $self->assert_not_null($foo);

    xlog "get foo and unknown mailbox";
    $res = $jmap->CallMethods([['Mailbox/get', { ids => [$foo->{id}, "nope"] }, "R1"]]);
    $self->assert_str_equals($res->[0][1]{list}[0]->{id}, $foo->{id});
    $self->assert_str_equals($res->[0][1]{notFound}[0], "nope");

    xlog "get mailbox with erroneous id";
    $res = $jmap->CallMethods([['Mailbox/get', { ids => [123]}, "R1"]]);
    $self->assert_not_null($res);
    $self->assert_str_equals('error', $res->[0][0]);
    $self->assert_str_equals('R1', $res->[0][2]);

    my $err = $res->[0][1];
    $self->assert_str_equals('invalidArguments', $err->{type});
    $self->assert_str_equals('ids[0]', $err->{arguments}[0]);
}

sub test_mailbox_get_nocalendars
    :min_version_3_1 :needs_component_jmap
{
    my ($self) = @_;

    # asserts that changes on special mailboxes such as calendars
    # aren't listed as regular mailboxes

    my $jmap = $self->{jmap};
    my $caldav = $self->{caldav};

    xlog "get existing mailboxes";
    my $res = $jmap->CallMethods([['Mailbox/get', {}, "R1"]]);
    $self->assert_not_null($res);
    $self->assert_str_equals($res->[0][0], 'Mailbox/get');
    $self->assert_str_equals($res->[0][2], 'R1');
    my $mboxes = $res->[0][1]{list};

    xlog "create calendar";
    $res = $jmap->CallMethods([
            ['Calendar/set', { create => { "1" => {
                            name => "foo",
                            color => "coral",
                            sortOrder => 2,
                            isVisible => \1
             }}}, "R1"]
    ]);
    $self->assert_not_null($res->[0][1]{created});

    xlog "get updated mailboxes";
    $res = $jmap->CallMethods([['Mailbox/get', {}, "R1"]]);
    $self->assert_not_null($res);
    $self->assert_num_equals(scalar @{$res->[0][1]{list}}, scalar @{$mboxes});
}

sub test_mailbox_get_shared
    :min_version_3_1 :needs_component_jmap
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

    xlog "get mailboxes for foo account";
    my $res = $jmap->CallMethods([['Mailbox/get', { accountId => "foo" }, "R1"]]);
    $self->assert_num_equals(2, scalar @{$res->[0][1]{list}});

    my %m = map { lc($_->{name}) => $_ } @{$res->[0][1]{list}};
    my $fooInbox = $m{'inbox'};
    $self->assert_str_not_equals($inbox->{id}, $fooInbox->{id});
    $self->assert_str_equals('inbox', $fooInbox->{role});
    my $box1 = $m{'box1'};
    $self->assert_str_equals('trash', $box1->{role});

    xlog "get mailboxes for inaccessible bar account";
    $res = $jmap->CallMethods([['Mailbox/get', { accountId => "bar" }, "R1"]]);
    $self->assert_str_equals("error", $res->[0][0]);
    $self->assert_str_equals("accountNotFound", $res->[0][1]{type});

    xlog "get mailboxes for inexistent account";
    $res = $jmap->CallMethods([['Mailbox/get', { accountId => "baz" }, "R1"]]);
    $self->assert_str_equals("error", $res->[0][0]);
    $self->assert_str_equals("accountNotFound", $res->[0][1]{type});

    xlog "get mailboxes for visible account";
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
    :min_version_3_1 :needs_component_jmap
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

    xlog "get mailboxes for foo account";
    my $res = $jmap->CallMethods([['Mailbox/get', { accountId => "foo" }, "R1"]]);
    $self->assert_num_equals(2, scalar @{$res->[0][1]{list}});

    my %m = map { lc($_->{name}) => $_ } @{$res->[0][1]{list}};
    my $fooInbox = $m{'inbox'};
    $self->assert_str_not_equals($inbox->{id}, $fooInbox->{id});
    $self->assert_str_equals('inbox', $fooInbox->{role});
    my $box1 = $m{'box1'};
    $self->assert_str_equals('trash', $box1->{role});

    xlog "get mailboxes for inaccessible bar account";
    $res = $jmap->CallMethods([['Mailbox/get', { accountId => "bar" }, "R1"]]);
    $self->assert_str_equals("error", $res->[0][0]);
    $self->assert_str_equals("accountNotFound", $res->[0][1]{type});

    xlog "get mailboxes for inexistent account";
    $res = $jmap->CallMethods([['Mailbox/get', { accountId => "baz" }, "R1"]]);
    $self->assert_str_equals("error", $res->[0][0]);
    $self->assert_str_equals("accountNotFound", $res->[0][1]{type});

    xlog "get mailboxes for visible account";
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
    $self->assert_str_equals($m{box2}{parentId}, $m{inbox}{id});
}

sub test_mailbox_query
    :min_version_3_1 :needs_component_jmap
{
    my ($self) = @_;

    my $jmap = $self->{jmap};
    my $imaptalk = $self->{store}->get_client();

    xlog "list mailboxes without filter";
    my $res = $jmap->CallMethods([['Mailbox/query', {}, "R1"]]);
    $self->assert_num_equals(1, scalar @{$res->[0][1]->{ids}});
    $self->assert_str_equals('Mailbox/query', $res->[0][0]);
    $self->assert_str_equals('R1', $res->[0][2]);

    xlog "create mailboxes";
    $imaptalk->create("INBOX.A") || die;
    $imaptalk->create("INBOX.B") || die;

    xlog "fetch mailboxes";
    $res = $jmap->CallMethods([['Mailbox/get', { }, 'R1' ]]);
    my %mboxids = map { $_->{name} => $_->{id} } @{$res->[0][1]{list}};

    xlog "list mailboxes without filter and sort by name ascending";
    $res = $jmap->CallMethods([['Mailbox/query', {
        sort => [{ property => "name" }]},
    "R1"]]);
    $self->assert_num_equals(3, scalar @{$res->[0][1]->{ids}});
    $self->assert_str_equals($mboxids{'A'}, $res->[0][1]{ids}[0]);
    $self->assert_str_equals($mboxids{'B'}, $res->[0][1]{ids}[1]);
    $self->assert_str_equals($mboxids{'Inbox'}, $res->[0][1]{ids}[2]);

    xlog "list mailboxes without filter and sort by name descending";
    $res = $jmap->CallMethods([['Mailbox/query', {
        sort => [{ property => "name", isAscending => JSON::false}],
    }, "R1"]]);
    $self->assert_num_equals(3, scalar @{$res->[0][1]->{ids}});
    $self->assert_str_equals($mboxids{'Inbox'}, $res->[0][1]{ids}[0]);
    $self->assert_str_equals($mboxids{'B'}, $res->[0][1]{ids}[1]);
    $self->assert_str_equals($mboxids{'A'}, $res->[0][1]{ids}[2]);

    xlog "filter mailboxes by hasAnyRole == true";
    $res = $jmap->CallMethods([['Mailbox/query', {filter => {hasAnyRole => JSON::true}}, "R1"]]);
    $self->assert_num_equals(1, scalar @{$res->[0][1]->{ids}});
    $self->assert_str_equals($mboxids{'Inbox'}, $res->[0][1]{ids}[0]);

    xlog "filter mailboxes by hasAnyRole == false";
    $res = $jmap->CallMethods([['Mailbox/query', {
        filter => {hasAnyRole => JSON::false},
        sort => [{ property => "name"}],
    }, "R1"]]);
    $self->assert_num_equals(2, scalar @{$res->[0][1]->{ids}});
    $self->assert_str_equals($mboxids{'A'}, $res->[0][1]{ids}[0]);
    $self->assert_str_equals($mboxids{'B'}, $res->[0][1]{ids}[1]);

    xlog "create mailbox underneath A";
    $imaptalk->create("INBOX.A.AA") || die;

    xlog "(re)fetch mailboxes";
    $res = $jmap->CallMethods([['Mailbox/get', { }, 'R1' ]]);
    %mboxids = map { $_->{name} => $_->{id} } @{$res->[0][1]{list}};

    xlog "filter mailboxes by parentId";
    $res = $jmap->CallMethods([['Mailbox/query', {filter => {parentId => $mboxids{'A'}}}, "R1"]]);
    $self->assert_num_equals(1, scalar @{$res->[0][1]->{ids}});
    $self->assert_str_equals($mboxids{'AA'}, $res->[0][1]{ids}[0]);

    # Without windowing the name-sorted results are: A, AA, B, Inbox

    xlog "list mailboxes (with limit)";
    $res = $jmap->CallMethods([
        ['Mailbox/query', {
            sort => [{ property => "name" }],
            limit => 1,
        }, "R1"]
    ]);
    $self->assert_num_equals(1, scalar @{$res->[0][1]->{ids}});
    $self->assert_str_equals($mboxids{'A'}, $res->[0][1]{ids}[0]);
    $self->assert_num_equals(0, $res->[0][1]->{position});

    xlog "list mailboxes (with anchor and limit)";
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

    xlog "list mailboxes (with positive anchor offset)";
    $res = $jmap->CallMethods([
        ['Mailbox/query', {
            sort => [{ property => "name" }],
            anchor => $mboxids{'Inbox'},
            anchorOffset => 2,
        }, "R1"]
    ]);
    $self->assert_num_equals(3, scalar @{$res->[0][1]->{ids}});
    $self->assert_str_equals($mboxids{'AA'}, $res->[0][1]{ids}[0]);
    $self->assert_str_equals($mboxids{'B'}, $res->[0][1]{ids}[1]);
    $self->assert_str_equals($mboxids{'Inbox'}, $res->[0][1]{ids}[2]);
    $self->assert_num_equals(1, $res->[0][1]->{position});

    xlog "list mailboxes (with negative anchor offset)";
    $res = $jmap->CallMethods([
        ['Mailbox/query', {
            sort => [{ property => "name" }],
            anchor => $mboxids{'A'},
            anchorOffset => -2,
        }, "R1"]
    ]);
    $self->assert_num_equals(2, scalar @{$res->[0][1]->{ids}});
    $self->assert_str_equals($mboxids{'B'}, $res->[0][1]{ids}[0]);
    $self->assert_str_equals($mboxids{'Inbox'}, $res->[0][1]{ids}[1]);
    $self->assert_num_equals(2, $res->[0][1]->{position});

    xlog "list mailboxes (with position)";
    $res = $jmap->CallMethods([
        ['Mailbox/query', {
            sort => [{ property => "name" }],
            position => 3,
        }, "R1"]
    ]);
    $self->assert_num_equals(1, scalar @{$res->[0][1]->{ids}});
    $self->assert_str_equals($mboxids{'Inbox'}, $res->[0][1]{ids}[0]);

    xlog "list mailboxes (with negative position)";
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

sub test_mailbox_query_parentname
    :min_version_3_1 :needs_component_jmap
{
    my ($self) = @_;

    my $jmap = $self->{jmap};
    my $imaptalk = $self->{store}->get_client();

    xlog "create mailbox tree";
    $imaptalk->create("INBOX.Ham") || die;
    $imaptalk->create("INBOX.Spam", "(USE (\\Junk))") || die;
    $imaptalk->create("INBOX.Ham.Zonk") || die;
    $imaptalk->create("INBOX.Ham.Bonk") || die;

    xlog "(re)fetch mailboxes";
    my $res = $jmap->CallMethods([['Mailbox/get', { properties => ["name"] }, 'R1' ]]);
    $self->assert_num_equals(5, scalar @{$res->[0][1]{list}});
    my %mboxids = map { $_->{name} => $_->{id} } @{$res->[0][1]{list}};
    $self->assert(exists $mboxids{'Inbox'});

    xlog "list mailboxes sorted by parent/name";
    $res = $jmap->CallMethods([
        ['Mailbox/query', { sort => [{ property => "parent/name" }] }, "R1"]
    ]);
    $self->assert_num_equals(5, scalar @{$res->[0][1]->{ids}});
    $self->assert_str_equals($mboxids{'Inbox'}, $res->[0][1]{ids}[0]);
    $self->assert_str_equals($mboxids{'Ham'}, $res->[0][1]{ids}[1]);
    $self->assert_str_equals($mboxids{'Bonk'}, $res->[0][1]{ids}[2]);
    $self->assert_str_equals($mboxids{'Zonk'}, $res->[0][1]{ids}[3]);
    $self->assert_str_equals($mboxids{'Spam'}, $res->[0][1]{ids}[4]);

    xlog "list mailboxes sorted by parent/name, filtered by parentId";
    $res = $jmap->CallMethods([
        ['Mailbox/query', {
            sort => [{ property => "parent/name" }],
            filter => {parentId => $mboxids{'Ham'}},
        }, "R1"]
    ]);
    $self->assert_num_equals(2, scalar @{$res->[0][1]->{ids}});
    $self->assert_str_equals($mboxids{'Bonk'}, $res->[0][1]{ids}[0]);
    $self->assert_str_equals($mboxids{'Zonk'}, $res->[0][1]{ids}[1]);
}

sub test_mailbox_query_limit_zero
    :min_version_3_1 :needs_component_jmap
{
    my ($self) = @_;

    my $jmap = $self->{jmap};
    my $imaptalk = $self->{store}->get_client();

    xlog "list mailboxes with limit 0";
    my $res = $jmap->CallMethods([
        ['Mailbox/query', { limit => 0 }, "R1"]
    ]);
    $self->assert_deep_equals([], $res->[0][1]->{ids});
}

sub test_mailbox_query_parentid_null
    :min_version_3_1 :needs_component_jmap
{
    my ($self) = @_;

    my $jmap = $self->{jmap};
    my $imaptalk = $self->{store}->get_client();

    xlog "create mailbox tree";
    $imaptalk->create("INBOX.Ham") || die;
    $imaptalk->create("INBOX.Spam", "(USE (\\Junk))") || die;
    $imaptalk->create("INBOX.Ham.Zonk") || die;
    $imaptalk->create("INBOX.Ham.Bonk") || die;

    xlog "(re)fetch mailboxes";
    my $res = $jmap->CallMethods([['Mailbox/get', { properties => ["name"] }, 'R1' ]]);
    $self->assert_num_equals(5, scalar @{$res->[0][1]{list}});
    my %mboxids = map { $_->{name} => $_->{id} } @{$res->[0][1]{list}};
    $self->assert(exists $mboxids{'Inbox'});

    xlog "list mailboxes, filtered by parentId null";
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

sub test_mailbox_query_filteroperator
    :min_version_3_1 :needs_component_jmap
{
    my ($self) = @_;
    return;

    my $jmap = $self->{jmap};
    my $imaptalk = $self->{store}->get_client();

    xlog "create mailbox tree";
    $imaptalk->create("INBOX.Ham") || die;
    $imaptalk->create("INBOX.Spam", "(USE (\\Junk))") || die;
    $imaptalk->create("INBOX.Ham.Zonk") || die;
    $imaptalk->create("INBOX.Ham.Bonk") || die;

    xlog "(re)fetch mailboxes";
    my $res = $jmap->CallMethods([['Mailbox/get', { properties => ["name"] }, 'R1' ]]);
    $self->assert_num_equals(5, scalar @{$res->[0][1]{list}});
    my %mboxids = map { $_->{name} => $_->{id} } @{$res->[0][1]{list}};
    $self->assert(exists $mboxids{'Inbox'});

    xlog "Subscribe mailbox Ham";
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

    xlog "list mailboxes filtered by parentId OR role";
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

    xlog "list mailboxes filtered by name";
    $res = $jmap->CallMethods([['Mailbox/query', {
        filter => {
            name => 'Zonk',
        },
    }, "R1"]]);
    $self->assert_num_equals(1, scalar @{$res->[0][1]->{ids}});
    $self->assert_str_equals($mboxids{'Zonk'}, $res->[0][1]{ids}[0]);

    xlog "list mailboxes filtered by isSubscribed";
    $res = $jmap->CallMethods([['Mailbox/query', {
        filter => {
            isSubscribed => JSON::true,
        },
    }, "R1"]]);
    $self->assert_num_equals(1, scalar @{$res->[0][1]->{ids}});
    $self->assert_str_equals($mboxids{'Zonk'}, $res->[0][1]{ids}[0]);

    xlog "list mailboxes filtered by isSubscribed is false";
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

    xlog "list mailboxes filtered by parentId AND hasAnyRole false";
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

    xlog "list mailboxes filtered by NOT (parentId AND role)";
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

    xlog "list mailboxes without filter";
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
                role => 'trash',
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
                role => 'important',
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

    xlog "get inbox";
    my $res = $jmap->CallMethods([['Mailbox/get', { }, "R1"]]);
    my $inbox = $res->[0][1]{list}[0];
    $self->assert_str_equals($inbox->{name}, "Inbox");

    my $state = $res->[0][1]{state};

    xlog "create mailbox";
    $res = $jmap->CallMethods([
            ['Mailbox/set', { create => { "1" => {
                            name => "foo",
                            role => undef
             }}}, "R1"]
    ]);
    $self->assert_str_equals($res->[0][0], 'Mailbox/set');
    $self->assert_str_equals($res->[0][2], 'R1');
    $self->assert_str_not_equals($res->[0][1]{newState}, $state);
    $self->assert_not_null($res->[0][1]{created});
    my $id = $res->[0][1]{created}{"1"}{id};

    xlog "get mailbox $id";
    $res = $jmap->CallMethods([['Mailbox/get', { ids => [$id] }, "R1"]]);
    $self->assert_str_equals($res->[0][1]{list}[0]->{id}, $id);

    my $mbox = $res->[0][1]{list}[0];
    $self->assert_str_equals($mbox->{name}, "foo");
    $self->assert_null($mbox->{parentId});
    $self->assert_null($mbox->{role});
    $self->assert_num_equals($mbox->{sortOrder}, 0);
    $self->assert_equals($mbox->{myRights}->{mayReadItems}, JSON::true);
    $self->assert_equals($mbox->{myRights}->{mayAddItems}, JSON::true);
    $self->assert_equals($mbox->{myRights}->{mayRemoveItems}, JSON::true);
    $self->assert_equals($mbox->{myRights}->{mayCreateChild}, JSON::true);
    $self->assert_equals($mbox->{myRights}->{mayRename}, JSON::true);
    $self->assert_equals($mbox->{myRights}->{mayDelete}, JSON::true);
    $self->assert_num_equals($mbox->{totalEmails}, 0);
    $self->assert_num_equals($mbox->{unreadEmails}, 0);
    $self->assert_num_equals($mbox->{totalThreads}, 0);
    $self->assert_num_equals($mbox->{unreadThreads}, 0);

    xlog "update mailbox";
    $res = $jmap->CallMethods([
            ['Mailbox/set', { update => { $id => {
                            name => "bar",
                            sortOrder => 20
             }}}, "R1"]
    ]);

    $self->assert_str_equals($res->[0][0], 'Mailbox/set');
    $self->assert_str_equals($res->[0][2], 'R1');
    $self->assert_str_not_equals($res->[0][1]{newState}, $state);
    $self->assert(exists $res->[0][1]{updated}{$id});

    xlog "get mailbox $id";
    $res = $jmap->CallMethods([['Mailbox/get', { ids => [$id] }, "R1"]]);
    $self->assert_str_equals($res->[0][1]{list}[0]->{id}, $id);
    $mbox = $res->[0][1]{list}[0];
    $self->assert_str_equals($mbox->{name}, "bar");
    $self->assert_num_equals($mbox->{sortOrder}, 20);

    xlog "destroy mailbox";
    $res = $jmap->CallMethods([
            ['Mailbox/set', { destroy => [ $id ] }, "R1"]
    ]);
    $self->assert_str_equals($res->[0][0], 'Mailbox/set');
    $self->assert_str_equals($res->[0][2], 'R1');
    $self->assert_str_not_equals($res->[0][1]{newState}, $state);
    $self->assert_str_equals($res->[0][1]{destroyed}[0], $id);

    xlog "get mailbox $id";
    $res = $jmap->CallMethods([['Mailbox/get', { ids => [$id] }, "R1"]]);
    $self->assert_str_equals($res->[0][1]{notFound}[0], $id);
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
    :min_version_3_1 :needs_component_jmap
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

    xlog "get existing mailboxes";
    my $res = $jmap->CallMethods([['Mailbox/get', { properties => ['name', 'parentId']}, "R1"]]);
    $self->assert_not_null($res);
    $self->assert_str_equals($res->[0][0], 'Mailbox/get');
    $self->assert_str_equals($res->[0][2], 'R1');

    my %m = map { $_->{name} => $_ } @{$res->[0][1]{list}};
    $self->assert_num_equals(scalar keys %m, 4);
    my $inbox = $m{"Inbox"};
    my $top = $m{"top"};
    my $foo = $m{"foo"};
    my $bar = $m{"bar"};

    # INBOX
    $self->assert_null($inbox->{parentId});
    $self->assert_null($top->{parentId});
    $self->assert_str_equals($foo->{parentId}, $inbox->{id});
    $self->assert_str_equals($bar->{parentId}, $foo->{id});

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
    $self->assert_str_equals($res->[0][0], 'Mailbox/get');
    $self->assert_str_equals($res->[0][2], 'R1');

    %m = map { $_->{name} => $_ } @{$res->[0][1]{list}};
    $self->assert_num_equals(scalar keys %m, 6);
    $inbox = $m{"Inbox"};
    my $b = $m{"B"};
    my $c = $m{"C"};
    $bar = $m{"bar"};
    my $tl = $m{"tl"};
    my $sl = $m{"sl"};

    # INBOX
    $self->assert_null($inbox->{parentId});
    $self->assert_str_equals($b->{parentId}, $inbox->{id});
    $self->assert_null($c->{parentId});
    $self->assert_str_equals($bar->{parentId}, $c->{id});
    $self->assert_str_equals($sl->{parentId}, $inbox->{id});
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

    xlog "get mailboxes for foo account";
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

    xlog "create mailbox";
    my $res = $jmap->CallMethods([
        ['Mailbox/set', { create => {
                "1" => { role => undef },
                "2" => { role => undef, name => "\t " },
        }}, "R1"]
    ]);
    $self->assert_str_equals($res->[0][0], 'Mailbox/set');
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

    xlog "get inbox";
    my $res = $jmap->CallMethods([['Mailbox/get', { }, "R1"]]);
    my $inbox = $res->[0][1]{list}[0];
    $self->assert_str_equals($inbox->{name}, "Inbox");

    my $state = $res->[0][1]{state};

    xlog "create three mailboxes named foo (two will fail)";
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

    xlog "create mailbox bar";
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
    xlog "rename bar to foo and foo to bar";
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

    xlog "get mailboxes";
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

    xlog "create mailbox via IMAP";
    $imaptalk->create("INBOX.foo")
        or die "Cannot create mailbox INBOX.foo: $@";

    xlog "get foo mailbox";
    my $res = $jmap->CallMethods([['Mailbox/get', {}, "R1"]]);
    my %m = map { $_->{name} => $_ } @{$res->[0][1]{list}};
    my $foo = $m{"foo"};
    my $id = $foo->{id};
    $self->assert_str_equals($foo->{name}, "foo");

    xlog "rename mailbox foo to oof via JMAP";
    $res = $jmap->CallMethods([
            ['Mailbox/set', { update => { $id => { name => "oof" }}}, "R1"]
    ]);
    $self->assert_not_null($res->[0][1]{updated});

    xlog "get mailbox via IMAP";
    my $data = $imaptalk->list("INBOX.oof", "%");
    $self->assert_num_equals(scalar @{$data}, 1);

    xlog "rename mailbox oof to bar via IMAP";
    $imaptalk->rename("INBOX.oof", "INBOX.bar")
        or die "Cannot rename mailbox: $@";

    xlog "get mailbox $id";
    $res = $jmap->CallMethods([['Mailbox/get', { ids => [$id] }, "R1"]]);
    $self->assert_str_equals($res->[0][1]{list}[0]->{name}, "bar");

    xlog "rename mailbox bar to baz via JMAP";
    $res = $jmap->CallMethods([
            ['Mailbox/set', { update => { $id => { name => "baz" }}}, "R1"]
    ]);
    $self->assert_not_null($res->[0][1]{updated});

    xlog "get mailbox via IMAP";
    $data = $imaptalk->list("INBOX.baz", "%");
    $self->assert_num_equals(scalar @{$data}, 1);

    xlog "rename mailbox baz to IFeel\N{WHITE SMILING FACE} via IMAP";
    $imaptalk->rename("INBOX.baz", "INBOX.IFeel\N{WHITE SMILING FACE}")
        or die "Cannot rename mailbox: $@";

    xlog "get mailbox $id";
    $res = $jmap->CallMethods([['Mailbox/get', { ids => [$id] }, "R1"]]);
    $self->assert_str_equals($res->[0][1]{list}[0]->{name}, "IFeel\N{WHITE SMILING FACE}");
}

sub test_mailbox_set_name_unicode_nfc
    :min_version_3_1 :needs_component_jmap
{
    my ($self) = @_;

    my $jmap = $self->{jmap};

    xlog "get inbox";
    my $res = $jmap->CallMethods([['Mailbox/get', { }, "R1"]]);
    my $inbox = $res->[0][1]{list}[0];
    $self->assert_str_equals($inbox->{name}, "Inbox");

    my $state = $res->[0][1]{state};

    my $name = "\N{ANGSTROM SIGN}ngstr\N{LATIN SMALL LETTER O WITH DIAERESIS}m";
    my $want = "\N{LATIN CAPITAL LETTER A WITH RING ABOVE}ngstr\N{LATIN SMALL LETTER O WITH DIAERESIS}m";

    xlog "create mailboxes with name not conforming to Net Unicode (NFC)";
    $res = $jmap->CallMethods([['Mailbox/set', { create => { "1" => {
        name => "\N{ANGSTROM SIGN}ngstr\N{LATIN SMALL LETTER O WITH DIAERESIS}m",
        parentId => $inbox->{id},
        role => undef
    }}}, "R1"]]);
    $self->assert_not_null($res->[0][1]{created}{1});
    my $id = $res->[0][1]{created}{1}{id};

    xlog "get mailbox $id";
    $res = $jmap->CallMethods([['Mailbox/get', { ids => [$id] }, "R1"]]);
    $self->assert_str_equals($want, $res->[0][1]{list}[0]->{name});
}


sub test_mailbox_set_role
    :min_version_3_1 :needs_component_jmap
{
    my ($self) = @_;

    my $jmap = $self->{jmap};
    my $imaptalk = $self->{store}->get_client();

    xlog "get inbox";
    my $res = $jmap->CallMethods([['Mailbox/get', { }, "R1"]]);
    my $inbox = $res->[0][1]{list}[0];
    $self->assert_str_equals($inbox->{name}, "Inbox");

    my $state = $res->[0][1]{state};

    xlog "try to create mailbox with inbox role";
    $res = $jmap->CallMethods([
            ['Mailbox/set', { create => { "1" => {
                            name => "foo",
                            parentId => $inbox->{id},
                            role => "inbox"
             }}}, "R1"]
    ]);
    $self->assert_str_equals($res->[0][0], 'Mailbox/set');
    $self->assert_str_equals($res->[0][2], 'R1');
    my $errType = $res->[0][1]{notCreated}{"1"}{type};
    my $errProp = $res->[0][1]{notCreated}{"1"}{properties};
    $self->assert_str_equals($errType, "invalidProperties");
    $self->assert_deep_equals($errProp, [ "role" ]);

    xlog "create mailbox with trash role";
    $res = $jmap->CallMethods([
            ['Mailbox/set', { create => { "1" => {
                            name => "foo",
                            parentId => undef,
                            role => "trash"
             }}}, "R1"]
    ]);
    $self->assert_str_equals($res->[0][0], 'Mailbox/set');
    $self->assert_str_equals($res->[0][2], 'R1');
    $self->assert_not_null($res->[0][1]{created});

    my $id = $res->[0][1]{created}{"1"}{id};

    xlog "get mailbox $id";
    $res = $jmap->CallMethods([['Mailbox/get', { ids => [$id] }, "R1"]]);

    $self->assert_str_equals($res->[0][1]{list}[0]->{role}, "trash");

    xlog "get mailbox $id via IMAP";
    my $data = $imaptalk->xlist("INBOX.foo", "%");
    my %annots = map { $_ => 1 } @{$data->[0]->[0]};
    $self->assert(exists $annots{"\\Trash"});

    xlog "try to create another mailbox with trash role";
    $res = $jmap->CallMethods([
            ['Mailbox/set', { create => { "1" => {
                            name => "bar",
                            parentId => $inbox->{id},
                            role => "trash"
             }}}, "R1"]
    ]);
    $errType = $res->[0][1]{notCreated}{"1"}{type};
    $errProp = $res->[0][1]{notCreated}{"1"}{properties};
    $self->assert_str_equals($errType, "invalidProperties");
    $self->assert_deep_equals($errProp, [ "role" ]);

    xlog "create mailbox with x-bam role";
    $res = $jmap->CallMethods([
            ['Mailbox/set', { create => { "1" => {
                            name => "baz",
                            parentId => undef,
                            role => "x-bam"
             }}}, "R1"]
    ]);
    $self->assert_not_null($res->[0][1]{created});
    $id = $res->[0][1]{created}{"1"}{id};

    xlog "get mailbox $id";
    $res = $jmap->CallMethods([['Mailbox/get', { ids => [$id] }, "R1"]]);
    $self->assert_str_equals($res->[0][1]{list}[0]->{role}, "x-bam");

    xlog "update of mailbox role";
    $res = $jmap->CallMethods([
            ['Mailbox/set', { update => { "$id" => {
                            role => "x-baz"
             }}}, "R1"]
    ]);
    $self->assert_not_null($res->[0][1]{updated});

    xlog "get mailbox $id";
    $res = $jmap->CallMethods([['Mailbox/get', { ids => [$id] }, "R1"]]);
    $self->assert_str_equals($res->[0][1]{list}[0]->{role}, "x-baz");

    xlog "try to create another mailbox with the x-baz role";
    $res = $jmap->CallMethods([
            ['Mailbox/set', { create => { "1" => {
                            name => "bar",
                            parentId => $inbox->{id},
                            role => "x-baz"
             }}}, "R1"]
    ]);
    $errType = $res->[0][1]{notCreated}{"1"}{type};
    $errProp = $res->[0][1]{notCreated}{"1"}{properties};
    $self->assert_str_equals($errType, "invalidProperties");
    $self->assert_deep_equals($errProp, [ "role" ]);

    xlog "try to create a mailbox with an unknown, non-x role";
    $res = $jmap->CallMethods([
            ['Mailbox/set', { create => { "1" => {
                            name => "bam",
                            parentId => $inbox->{id},
                            role => "unknown"
             }}}, "R1"]
    ]);
    $errType = $res->[0][1]{notCreated}{"1"}{type};
    $errProp = $res->[0][1]{notCreated}{"1"}{properties};
    $self->assert_str_equals($errType, "invalidProperties");
    $self->assert_deep_equals($errProp, [ "role" ]);

    xlog "create a specialuse Sent mailbox via IMAP";
    $imaptalk->create("INBOX.Sent", "(USE (\\Sent))") || die;

    xlog "create a specialuse Archive and Junk mailbox via IMAP";
    $imaptalk->create("INBOX.Multi", "(USE (\\Archive \\Junk))") || die;

    xlog "get mailboxes";
    $res = $jmap->CallMethods([['Mailbox/get', { }, "R1"]]);
    my %m = map { $_->{name} => $_ } @{$res->[0][1]{list}};
    my $sent = $m{"Sent"};
    my $multi = $m{"Multi"};
    $self->assert_str_equals($sent->{role}, "sent");
    $self->assert_str_equals($multi->{role}, "archive");

    xlog "remove a mailbox role";
    $res = $jmap->CallMethods([
        ['Mailbox/set', {
            update => { "$id" => {
                role => undef,
            }
        }}, "R1"],
        ['Mailbox/get', {
            ids => [$id], properties => ['role'],
        }, 'R2'],
    ]);
    $self->assert(exists $res->[0][1]{updated}{$id});
    $self->assert_null($res->[1][1]{list}[0]{role});
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
    xlog "create mailbox foo";
    my $res = $jmap->CallMethods([['Mailbox/set', {
        create => {
            "1" => {
                name => "foo",
                parentId => undef,
                role => undef }
        }
    }, "R1"]]);
    my $id1 = $res->[0][1]{created}{"1"}{id};
    xlog "create mailbox foo.bar";
    $res = $jmap->CallMethods([['Mailbox/set', {
        create => {
            "2" => {
                name => "bar",
                parentId => $id1,
                role => undef }
        }
    }, "R1"]]);
    my $id2 = $res->[0][1]{created}{"2"}{id};
    xlog "create mailbox foo.bar.baz";
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
    $self->assert_str_equals($res->[0][1]{list}[0]->{parentId}, $id1);
    $res = $jmap->CallMethods([['Mailbox/get', { ids => [$id3] }, "R1"]]);
    $self->assert_str_equals($res->[0][1]{list}[0]->{parentId}, $id2);

    xlog "move foo.bar to bar";
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

    xlog "move bar.baz to foo.baz";
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
    $self->assert_str_equals($res->[0][1]{list}[0]->{parentId}, $id1);

    xlog "move foo to bar.foo";
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
    $self->assert_str_equals($res->[0][1]{list}[0]->{parentId}, $id2);

    xlog "move foo to non-existent parent";
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
    $self->assert_str_equals($errType, "invalidProperties");
    $self->assert_deep_equals($errProp, [ "parentId" ]);
    $res = $jmap->CallMethods([['Mailbox/get', { ids => [$id1] }, "R1"]]);
    $self->assert_str_equals($res->[0][1]{list}[0]->{parentId}, $id2);

    xlog "attempt to destroy bar (which has child foo)";
    $res = $jmap->CallMethods([['Mailbox/set', {
        destroy => [$id2]
    }, "R1"]]);
    $errType = $res->[0][1]{notDestroyed}{$id2}{type};
    $self->assert_str_equals($errType, "mailboxHasChild");
    $res = $jmap->CallMethods([['Mailbox/get', { ids => [$id2] }, "R1"]]);
    $self->assert_null($res->[0][1]{list}[0]->{parentId});

    xlog "destroy all";
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

    xlog "get inbox";
    my $res = $jmap->CallMethods([['Mailbox/get', { }, "R1"]]);
    my $inbox = $res->[0][1]{list}[0];
    $self->assert_str_equals($inbox->{name}, "Inbox");

    xlog "get inbox ACL";
    my $parentacl = $admintalk->getacl("user.cassandane");

    xlog "create mailbox";
    $res = $jmap->CallMethods([
            ['Mailbox/set', { create => { "1" => {
                            name => "foo",
                            role => undef
             }}}, "R1"]
    ]);
    $self->assert_not_null($res->[0][1]{created});

    xlog "get new mailbox ACL";
    my $myacl = $admintalk->getacl("user.cassandane.foo");

    xlog "assert ACL matches parent ACL";
    $self->assert_deep_equals($parentacl, $myacl);
}

sub test_mailbox_set_destroy_empty
    :min_version_3_1 :needs_component_jmap
{
    my ($self) = @_;
    my $jmap = $self->{jmap};

    my $store = $self->{store};
    my $talk = $store->get_client();

    xlog "Generate a email in INBOX via IMAP";
    $self->make_message("Email A") || die;

    xlog "get email list";
    my $res = $jmap->CallMethods([['Email/query', {}, "R1"]]);
    $self->assert_num_equals(scalar @{$res->[0][1]->{ids}}, 1);
    my $msgid = $res->[0][1]->{ids}[0];

    xlog "get inbox";
    $res = $jmap->CallMethods([['Mailbox/get', { }, "R1"]]);
    my $inbox = $res->[0][1]{list}[0];
    $self->assert_str_equals($inbox->{name}, "Inbox");

    my $state = $res->[0][1]{state};

    xlog "create mailbox";
    $res = $jmap->CallMethods([
            ['Mailbox/set', { create => { "1" => {
                            name => "foo",
                            parentId => $inbox->{id},
                            role => undef
             }}}, "R1"]
    ]);
    $self->assert_str_equals($res->[0][0], 'Mailbox/set');
    $self->assert_str_equals($res->[0][2], 'R1');
    $self->assert_str_not_equals($res->[0][1]{newState}, $state);
    $self->assert_not_null($res->[0][1]{created});
    my $mboxid = $res->[0][1]{created}{"1"}{id};

    xlog "copy email to newly created mailbox";
    $res = $jmap->CallMethods([['Email/set', {
        update => { $msgid => { mailboxIds => {
            $inbox->{id} => JSON::true,
            $mboxid => JSON::true,
        }}},
    }, "R1"]]);
    $self->assert_not_null($res->[0][1]{updated});

    xlog "attempt to destroy mailbox with email";
    $res = $jmap->CallMethods([
            ['Mailbox/set', { destroy => [ $mboxid ] }, "R1"]
    ]);
    $self->assert_not_null($res->[0][1]{notDestroyed}{$mboxid});
    $self->assert_str_equals('mailboxHasEmail', $res->[0][1]{notDestroyed}{$mboxid}{type});

    xlog "remove email from mailbox";
    $res = $jmap->CallMethods([['Email/set', {
        update => { $msgid => { mailboxIds => {
            $inbox->{id} => JSON::true,
        }}},
    }, "R1"]]);
    $self->assert_not_null($res->[0][1]{updated});

    xlog "destroy empty mailbox";
    $res = $jmap->CallMethods([
            ['Mailbox/set', { destroy => [ $mboxid ] }, "R1"]
    ]);
    $self->assert_str_equals($res->[0][1]{destroyed}[0], $mboxid);
}

sub test_mailbox_set_destroy_removemsgs
    :min_version_3_1 :needs_component_jmap
{
    my ($self) = @_;
    my $jmap = $self->{jmap};

    my $store = $self->{store};
    my $talk = $store->get_client();

    xlog "Generate a email in INBOX via IMAP";
    $self->make_message("Email A") || die;

    xlog "get email list";
    my $res = $jmap->CallMethods([['Email/query', {}, "R1"]]);
    $self->assert_num_equals(scalar @{$res->[0][1]->{ids}}, 1);
    my $msgid = $res->[0][1]->{ids}[0];

    xlog "get inbox";
    $res = $jmap->CallMethods([['Mailbox/get', { }, "R1"]]);
    my $inbox = $res->[0][1]{list}[0];
    $self->assert_str_equals($inbox->{name}, "Inbox");

    my $state = $res->[0][1]{state};

    xlog "create mailbox";
    $res = $jmap->CallMethods([
            ['Mailbox/set', { create => { "1" => {
                            name => "foo",
                            parentId => $inbox->{id},
                            role => undef
             }}}, "R1"]
    ]);
    $self->assert_str_equals($res->[0][0], 'Mailbox/set');
    $self->assert_str_equals($res->[0][2], 'R1');
    $self->assert_str_not_equals($res->[0][1]{newState}, $state);
    $self->assert_not_null($res->[0][1]{created});
    my $mboxid = $res->[0][1]{created}{"1"}{id};

    xlog "copy email to newly created mailbox";
    $res = $jmap->CallMethods([['Email/set', {
        update => { $msgid => { mailboxIds => {
            $inbox->{id} => JSON::true,
            $mboxid => JSON::true,
        }}},
    }, "R1"]]);
    $self->assert_not_null($res->[0][1]{updated});

    xlog "destroy mailbox with email";
    $res = $jmap->CallMethods([[
        'Mailbox/set', {
            destroy => [ $mboxid ],
            onDestroyRemoveMessages => JSON::true,
        }, 'R1',
    ]]);
    $self->assert_str_equals($res->[0][1]{destroyed}[0], $mboxid);
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

    xlog "get mailboxes for foo account";
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

    xlog "update shared INBOX (should fail)";
    $res = $jmap->CallMethods([ $update ]);
    $self->assert(exists $res->[0][1]{notUpdated}{$inboxId});

    xlog "Add update ACL rights to shared INBOX";
    $admintalk->setacl("user.foo", "cassandane", "lrw") or die;

    xlog "update shared INBOX (should succeed)";
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

    xlog "create mailbox child (should fail)";
    $res = $jmap->CallMethods([ $create ]);
    $self->assert_not_null($res->[0][1]{notCreated}{1});

    xlog "Add update ACL rights to shared INBOX";
    $admintalk->setacl("user.foo", "cassandane", "lrwk") or die;

    xlog "create mailbox child (should succeed)";
    $res = $jmap->CallMethods([ $create ]);
    $self->assert_not_null($res->[0][1]{created}{1});
    my $childId = $res->[0][1]{created}{1}{id};

    my $destroy = ['Mailbox/set', {
        accountId => "foo",
        destroy => [ $childId ],
    }, 'R1' ];

    xlog "destroy shared mailbox child (should fail)";
    $res = $jmap->CallMethods([ $destroy ]);
    $self->assert(exists $res->[0][1]{notDestroyed}{$childId});

    xlog "Add delete ACL rights";
    $admintalk->setacl("user.foo.x", "cassandane", "lrwkx") or die;

    xlog "destroy shared mailbox child (should succeed)";
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

sub test_mailbox_set_isseenshared
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
                    isSeenShared => JSON::true,
                }
            }
        }, "R1"]
    ]);
    $self->assert_equals(JSON::false, $res->[0][1]{created}{A}{isSeenShared});
    $self->assert(not exists $res->[0][1]{created}{B}{isSeenShared});
    my $mboxIdA = $res->[0][1]{created}{A}{id};
    my $mboxIdB = $res->[0][1]{created}{B}{id};

    $res = $jmap->CallMethods([
        ['Mailbox/get', {
            ids => [$mboxIdA, $mboxIdB],
            properties => ['isSeenShared'],
        }, 'R1']
    ]);
    $self->assert_equals($mboxIdA, $res->[0][1]{list}[0]{id});
    $self->assert_equals(JSON::false, $res->[0][1]{list}[0]{isSeenShared});
    $self->assert_equals($mboxIdB, $res->[0][1]{list}[1]{id});
    $self->assert_equals(JSON::true, $res->[0][1]{list}[1]{isSeenShared});

    $res = $jmap->CallMethods([
        ['Mailbox/set', {
            update => {
                $mboxIdA => {
                    isSeenShared => JSON::true,
                },
                $mboxIdB => {
                    isSeenShared => JSON::false,
                },
            }
        }, "R1"]
    ]);
    $res = $jmap->CallMethods([
        ['Mailbox/get', {
            ids => [$mboxIdA, $mboxIdB],
            properties => ['isSeenShared'],
        }, 'R1']
    ]);
    $self->assert_equals($mboxIdA, $res->[0][1]{list}[0]{id});
    $self->assert_equals(JSON::true, $res->[0][1]{list}[0]{isSeenShared});
    $self->assert_equals($mboxIdB, $res->[0][1]{list}[1]{id});
    $self->assert_equals(JSON::false, $res->[0][1]{list}[1]{isSeenShared});
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

    xlog "get mailbox list";
    $res = $jmap->CallMethods([['Mailbox/get', {}, "R1"]]);
    $state = $res->[0][1]->{state};
    $self->assert_not_null($state);
    %m = map { $_->{name} => $_ } @{$res->[0][1]{list}};
    $inbox = $m{"Inbox"}->{id};
    $self->assert_not_null($inbox);

    xlog "get mailbox updates (expect error)";
    $res = $jmap->CallMethods([['Mailbox/changes', { sinceState => 0 }, "R1"]]);
    $self->assert_str_equals($res->[0][1]->{type}, "invalidArguments");
    $self->assert_str_equals($res->[0][1]->{arguments}[0], "sinceState");

    xlog "get mailbox updates (expect no changes)";
    $res = $jmap->CallMethods([['Mailbox/changes', { sinceState => $state }, "R1"]]);
    $self->assert_str_equals($state, $res->[0][1]->{oldState});
    $self->assert_str_equals($state, $res->[0][1]->{newState});
    $self->assert_equals(JSON::false, $res->[0][1]->{hasMoreChanges});
    $self->assert_deep_equals([], $res->[0][1]{created});
    $self->assert_deep_equals([], $res->[0][1]{updated});
    $self->assert_deep_equals([], $res->[0][1]{destroyed});
    $self->assert_null($res->[0][1]{updatedProperties});

    xlog "create mailbox via IMAP";
    $imaptalk->create("INBOX.foo")
        or die "Cannot create mailbox INBOX.foo: $@";

    xlog "get mailbox list";
    $res = $jmap->CallMethods([['Mailbox/get', {}, "R1"]]);
    %m = map { $_->{name} => $_ } @{$res->[0][1]{list}};
    $foo = $m{"foo"}->{id};
    $self->assert_not_null($foo);

    xlog "get mailbox updates";
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

    xlog "create drafts mailbox";
    $res = $jmap->CallMethods([
            ['Mailbox/set', { create => { "1" => {
                            name => "drafts",
                            parentId => undef,
                            role => "drafts"
             }}}, "R1"]
    ]);
    $drafts = $res->[0][1]{created}{"1"}{id};
    $self->assert_not_null($drafts);

    xlog "get mailbox updates";
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

    xlog "rename mailbox foo to bar";
    $res = $jmap->CallMethods([
            ['Mailbox/set', { update => { $foo => {
                            name => "bar",
                            sortOrder => 20
             }}}, "R1"]
    ]);
    $self->assert_num_equals(1, scalar keys %{$res->[0][1]{updated}});

    xlog "get mailbox updates";
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

    xlog "delete mailbox bar";
    $res = $jmap->CallMethods([
            ['Mailbox/set', {
                    destroy => [ $foo ],
             }, "R1"]
    ]);
    $self->assert_num_equals(1, scalar @{$res->[0][1]{destroyed}});

    xlog "rename mailbox drafts to stfard";
    $res = $jmap->CallMethods([
            ['Mailbox/set', {
                    update => { $drafts => { name => "stfard" } },
             }, "R1"]
    ]);
    $self->assert_num_equals(1, scalar keys %{$res->[0][1]{updated}});

    xlog "get mailbox updates, limit to 1";
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

    xlog "get mailbox updates, limit to 1";
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

    xlog "get mailbox updates (expect no changes)";
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

    xlog "create drafts mailbox";
    my $res = $jmap->CallMethods([
            ['Mailbox/set', { create => { "1" => {
                            name => "drafts",
                            parentId => undef,
                            role => "drafts"
             }}}, "R1"]
    ]);
    $self->assert_str_equals($res->[0][0], 'Mailbox/set');
    $self->assert_str_equals($res->[0][2], 'R1');
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
            '$Draft' => JSON::true,
        },
    };

    xlog "get mailbox updates";
    $res = $jmap->CallMethods([['Mailbox/changes', { sinceState => $state }, "R1"]]);
    $state = $res->[0][1]{newState};

    xlog "Create a draft";
    $res = $jmap->CallMethods([['Email/set', { create => { "1" => $draft }}, "R1"]]);
    my $msgid = $res->[0][1]{created}{"1"}{id};

    xlog "update email";
    $res = $jmap->CallMethods([['Email/set', {
            update => { $msgid => {
                    keywords => {
                        '$Draft' => JSON::true,
                        '$Seen' => JSON::true
                    }
                }
            }
    }, "R1"]]);
    $self->assert(exists $res->[0][1]->{updated}{$msgid});

    xlog "get mailbox updates";
    $res = $jmap->CallMethods([['Mailbox/changes', { sinceState => $state }, "R1"]]);
    $self->assert_str_not_equals($state, $res->[0][1]{newState});
    $self->assert_not_null($res->[0][1]{updatedProperties});
    $self->assert_deep_equals([], $res->[0][1]{created});
    $self->assert_num_not_equals(0, scalar @{$res->[0][1]{updated}});
    $self->assert_deep_equals([], $res->[0][1]{destroyed});
    $state = $res->[0][1]{newState};

    xlog "update mailbox";
    $res = $jmap->CallMethods([['Mailbox/set', { update => { $mboxid => { name => "bar" }}}, "R1"]]);

    xlog "get mailbox updates";
    $res = $jmap->CallMethods([['Mailbox/changes', { sinceState => $state }, "R1"]]);
    $self->assert_str_not_equals($state, $res->[0][1]{newState});
    $self->assert_null($res->[0][1]{updatedProperties});
    $self->assert_deep_equals([], $res->[0][1]{created});
    $self->assert_num_not_equals(0, scalar @{$res->[0][1]{updated}});
    $self->assert_deep_equals([], $res->[0][1]{destroyed});
    $state = $res->[0][1]{newState};

    xlog "update email";
    $res = $jmap->CallMethods([['Email/set', { update => { $msgid => { 'keywords/$flagged' => JSON::true }}
    }, "R1"]]);
    $self->assert(exists $res->[0][1]->{updated}{$msgid});

    xlog "get mailbox updates";
    $res = $jmap->CallMethods([['Mailbox/changes', { sinceState => $state }, "R1"]]);
    $self->assert_str_not_equals($state, $res->[0][1]{newState});
    $self->assert_not_null($res->[0][1]{updatedProperties});
    $self->assert_deep_equals([], $res->[0][1]{created});
    $self->assert_num_not_equals(0, scalar @{$res->[0][1]{updated}});
    $self->assert_deep_equals([], $res->[0][1]{destroyed});
    $state = $res->[0][1]{newState};

    xlog "update mailbox";
    $res = $jmap->CallMethods([['Mailbox/set', { update => { $mboxid => { name => "baz" }}}, "R1"]]);

    xlog "get mailbox updates";
    $res = $jmap->CallMethods([['Mailbox/changes', { sinceState => $state }, "R1"]]);
    $self->assert_str_not_equals($state, $res->[0][1]{newState});
    $self->assert_null($res->[0][1]{updatedProperties});
    $self->assert_deep_equals([], $res->[0][1]{created});
    $self->assert_num_not_equals(0, scalar @{$res->[0][1]{updated}});
    $self->assert_deep_equals([], $res->[0][1]{destroyed});
    $state = $res->[0][1]{newState};

    xlog "get mailbox updates (expect no changes)";
    $res = $jmap->CallMethods([['Mailbox/changes', { sinceState => $state }, "R1"]]);
    $self->assert_str_equals($state, $res->[0][1]{newState});
    $self->assert_null($res->[0][1]{updatedProperties});
    $self->assert_deep_equals([], $res->[0][1]{created});
    $self->assert_deep_equals([], $res->[0][1]{updated});
    $self->assert_deep_equals([], $res->[0][1]{destroyed});
    $state = $res->[0][1]{newState};

    $draft->{subject} = "memo2";

    xlog "Create another draft";
    $res = $jmap->CallMethods([['Email/set', { create => { "1" => $draft }}, "R1"]]);
    $msgid = $res->[0][1]{created}{"1"}{id};

    xlog "get mailbox updates";
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

    xlog "get mailbox list";
    my $res = $jmap->CallMethods([['Mailbox/get', { accountId => 'foo' }, "R1"]]);
    my $state = $res->[0][1]->{state};
    $self->assert_not_null($state);

    xlog "get mailbox updates (expect no changes)";
    $res = $jmap->CallMethods([['Mailbox/changes', { accountId => 'foo', sinceState => $state }, "R1"]]);
    $self->assert_str_equals($state, $res->[0][1]->{oldState});
    $self->assert_str_equals($state, $res->[0][1]->{newState});

    xlog "create mailbox box1 via IMAP";
    $admintalk->create("user.foo.box1") or die;
    $admintalk->setacl("user.foo.box1", "cassandane", "lrwkxd") or die;

    xlog "get mailbox updates";
    $res = $jmap->CallMethods([['Mailbox/changes', { accountId => 'foo', sinceState => $state }, "R1"]]);
    $self->assert_str_equals($state, $res->[0][1]->{oldState});
    $self->assert_str_not_equals($state, $res->[0][1]->{newState});
    $self->assert_num_equals(1, scalar @{$res->[0][1]->{created}});
    $self->assert_deep_equals([], $res->[0][1]{updated});
    $self->assert_deep_equals([], $res->[0][1]{destroyed});
    $state = $res->[0][1]->{newState};
    my $box1 = $res->[0][1]->{created}[0];

    xlog "destroy mailbox via JMAP";
    $res = $jmap->CallMethods([['Mailbox/set', { accountId => "foo", destroy => [ $box1 ] }, 'R1' ]]);
    $self->assert_str_equals($box1, $res->[0][1]{destroyed}[0]);

    xlog "get mailbox updates";
    $res = $jmap->CallMethods([['Mailbox/changes', { accountId => 'foo', sinceState => $state }, "R1"]]);
    $self->assert_str_equals($state, $res->[0][1]->{oldState});
    $self->assert_str_not_equals($state, $res->[0][1]->{newState});
    $self->assert_deep_equals([], $res->[0][1]{created});
    $self->assert_deep_equals([], $res->[0][1]{updated});
    $self->assert_num_equals(1, scalar @{$res->[0][1]->{destroyed}});
    $self->assert_str_equals($box1, $res->[0][1]->{destroyed}[0]);
    $state = $res->[0][1]->{newState};

    xlog "create mailbox box2 via IMAP";
    $admintalk->create("user.foo.box2") or die;
    $admintalk->setacl("user.foo.box2", "cassandane", "lrwkxd") or die;

    xlog "get mailbox updates";
    $res = $jmap->CallMethods([['Mailbox/changes', { accountId => 'foo', sinceState => $state }, "R1"]]);
    $self->assert_str_equals($state, $res->[0][1]->{oldState});
    $self->assert_str_not_equals($state, $res->[0][1]->{newState});
    $self->assert_num_equals(1, scalar @{$res->[0][1]->{created}});
    $self->assert_deep_equals([], $res->[0][1]{updated});
    $self->assert_deep_equals([], $res->[0][1]{destroyed});
    $state = $res->[0][1]->{newState};

    my $box2 = $res->[0][1]->{created}[0];

    xlog "Remove lookup rights on box2";
    $admintalk->setacl("user.foo.box2", "cassandane", "") or die;

    xlog "get mailbox updates";
    $res = $jmap->CallMethods([['Mailbox/changes', { accountId => 'foo', sinceState => $state }, "R1"]]);
    $self->assert_str_equals($state, $res->[0][1]->{oldState});
    $self->assert_str_not_equals($state, $res->[0][1]->{newState});
    $self->assert_deep_equals([], $res->[0][1]{created});
    $self->assert_deep_equals([], $res->[0][1]{updated});
    $self->assert_num_equals(1, scalar @{$res->[0][1]->{destroyed}});
    $self->assert_str_equals($box2, $res->[0][1]->{destroyed}[0]);
    $state = $res->[0][1]->{newState};
}

sub test_mailbox_set_issue2377
    :min_version_3_1 :needs_component_jmap
{
    my ($self) = @_;

    my $jmap = $self->{jmap};

    xlog "get inbox";
    my $res = $jmap->CallMethods([['Mailbox/get', { }, "R1"]]);
    my $inbox = $res->[0][1]{list}[0];
    $self->assert_str_equals($inbox->{name}, "Inbox");

    my $state = $res->[0][1]{state};

    xlog "create mailbox";
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
    :min_version_3_1 :needs_component_jmap
{
    my ($self) = @_;
    my $jmap = $self->{jmap};
    my $imap = $self->{store}->get_client();

    xlog "Fetch initial mailbox state";
    my $res = $jmap->CallMethods([['Mailbox/query', {
        sort => [{ property => "name" }],
    }, "R1"]]);
    $self->assert_num_equals(1, scalar @{$res->[0][1]{ids}});
    $self->assert_equals(JSON::true, $res->[0][1]->{canCalculateChanges});
    my $state = $res->[0][1]->{queryState};
    $self->assert_not_null($state);

    xlog "Create intermediate mailboxes via IMAP";
    $imap->create("INBOX.A.B.Z") or die;

    xlog "Fetch updated mailbox state";
    $res = $jmap->CallMethods([['Mailbox/queryChanges', {
        sinceQueryState => $state,
        sort => [{ property => "name" }],
    }, "R1"]]);
    $self->assert_str_not_equals($state, $res->[0][1]->{newQueryState});
    my @ids = map { $_->{id} } @{$res->[0][1]->{added}};
    $self->assert_num_equals(3, scalar @ids);

    xlog "Make sure intermediate mailboxes got reported";
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
    :min_version_3_1 :needs_component_jmap
{
    my ($self) = @_;
    my $jmap = $self->{jmap};
    my $imap = $self->{store}->get_client();

    xlog "Create intermediate mailboxes via IMAP";
    $imap->create("INBOX.A.B.Z") or die;

    xlog "Fetch initial mailbox state";
    my $res = $jmap->CallMethods([['Mailbox/query', {
        sort => [{ property => "name" }],
    }, "R1"]]);
    $self->assert_num_equals(4, scalar @{$res->[0][1]{ids}});
    $self->assert_equals(JSON::true, $res->[0][1]->{canCalculateChanges});
    my $state = $res->[0][1]->{queryState};
    $self->assert_not_null($state);

    xlog "Delete intermediate mailboxes via IMAP";
    $imap->delete("INBOX.A.B.Z") or die;

    xlog "Fetch updated mailbox state";
    $res = $jmap->CallMethods([['Mailbox/queryChanges', {
        sinceQueryState => $state,
        sort => [{ property => "name" }],
    }, "R1"]]);
    $self->assert_str_not_equals($state, $res->[0][1]->{newQueryState});
    $self->assert_num_equals(3, scalar @{$res->[0][1]->{removed}});
}

sub test_mailbox_get_intermediate
    :min_version_3_1 :needs_component_jmap
{
    my ($self) = @_;

    my $jmap = $self->{jmap};
    my $imap = $self->{store}->get_client();

    xlog "Create intermediate mailbox via IMAP";
    $imap->create("INBOX.A.Z") or die;

    xlog "Get mailboxes";
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
    $self->assert_num_equals($mboxA->{totalEmails}, 0);
    $self->assert_num_equals($mboxA->{unreadEmails}, 0);
    $self->assert_num_equals($mboxA->{totalThreads}, 0);
    $self->assert_num_equals($mboxA->{unreadThreads}, 0);
    $self->assert_num_equals($mboxA->{isSeenShared}, JSON::false);
}

sub test_mailbox_intermediary_imaprename_preservetree
    :min_version_3_1 :needs_component_jmap
{
    my ($self) = @_;

    my $jmap = $self->{jmap};
    my $imap = $self->{store}->get_client();

    xlog "Create mailboxes";
    $imap->create("INBOX.i1.i2.i3.foo") or die;
    $imap->create("INBOX.i1.i2.bar") or die;
    my $res = $jmap->CallMethods([['Mailbox/get', {
        properties => ['name', 'parentId'],
    }, "R1"]]);

    xlog "Assert mailbox tree";
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

    xlog "Rename mailbox";
    $imap->rename("INBOX.i1.i2.i3.foo", "INBOX.i1.i4.baz") or die;

    xlog "Assert mailbox tree";
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
    :min_version_3_1 :needs_component_jmap
{
    my ($self) = @_;

    my $jmap = $self->{jmap};
    my $imap = $self->{store}->get_client();

    xlog "Create mailboxes";
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

    xlog "Assert mailbox tree";
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
    :min_version_3_1 :needs_component_jmap
{
    my ($self) = @_;

    my $jmap = $self->{jmap};
    my $imap = $self->{store}->get_client();

    xlog "Create mailboxes";
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

    xlog "Rename intermediate";
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

    xlog "Assert mailbox tree";
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
    :min_version_3_1 :needs_component_jmap
{
    my ($self) = @_;

    my $jmap = $self->{jmap};
    my $imap = $self->{store}->get_client();

    xlog "Create mailboxes";
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

    xlog "Set annotation on intermediate";
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

    xlog "Assert mailbox tree";
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
    :min_version_3_1 :needs_component_jmap
{
    my ($self) = @_;

    my $jmap = $self->{jmap};
    my $imap = $self->{store}->get_client();

    xlog "Create mailboxes";
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

    xlog "Destroy child of intermediate";
    $res = $jmap->CallMethods([
        ['Mailbox/set', {
            destroy => [$mboxIdFoo],
        }, 'R1'],
    ]);
    $self->assert_str_equals($mboxIdFoo, $res->[0][1]{destroyed}[0]);
    $self->assert_str_not_equals($state, $res->[0][1]{newState});
    $state = $res->[0][1]{newState};

    xlog "Assert mailbox tree and changes";
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
    :min_version_3_1 :needs_component_jmap
{
    my ($self) = @_;

    my $jmap = $self->{jmap};
    my $imap = $self->{store}->get_client();

    xlog "Create mailboxes";
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

    xlog "Move child of intermediary to another intermediary";
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

    xlog "Assert mailbox tree and changes";
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
    :min_version_3_1 :needs_component_jmap
{
    my ($self) = @_;

    my $jmap = $self->{jmap};
    my $imap = $self->{store}->get_client();

    xlog "Create mailboxes";
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

    xlog "Destroy intermediate";
    $res = $jmap->CallMethods([
        ['Mailbox/set', {
            destroy => [$mboxId2, $mboxIdFoo],
        }, 'R1'],
    ]);
    $self->assert_num_equals(2, scalar @{$res->[0][1]{destroyed}});

    xlog "Assert mailbox tree and changes";
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
    :min_version_3_1 :needs_component_jmap
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
    :min_version_3_1 :needs_component_jmap
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
    :min_version_3_1 :needs_component_jmap
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


1;
