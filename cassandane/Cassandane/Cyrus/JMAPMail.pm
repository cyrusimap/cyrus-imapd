#!/usr/bin/perl
#
#  Copyright (c) 2011 Opera Software Australia Pty. Ltd.  All rights
#  reserved.
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
#  3. The name "Opera Software Australia" must not be used to
#     endorse or promote products derived from this software without
#     prior written permission. For permission or any legal
#     details, please contact
# 	Opera Software Australia Pty. Ltd.
# 	Level 50, 120 Collins St
# 	Melbourne 3000
# 	Victoria
# 	Australia
#
#  4. Redistributions of any form whatsoever must retain the following
#     acknowledgment:
#     "This product includes software developed by Opera Software
#     Australia Pty. Ltd."
#
#  OPERA SOFTWARE AUSTRALIA DISCLAIMS ALL WARRANTIES WITH REGARD TO
#  THIS SOFTWARE, INCLUDING ALL IMPLIED WARRANTIES OF MERCHANTABILITY
#  AND FITNESS, IN NO EVENT SHALL OPERA SOFTWARE AUSTRALIA BE LIABLE
#  FOR ANY SPECIAL, INDIRECT OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES
#  WHATSOEVER RESULTING FROM LOSS OF USE, DATA OR PROFITS, WHETHER IN
#  AN ACTION OF CONTRACT, NEGLIGENCE OR OTHER TORTIOUS ACTION, ARISING
#  OUT OF OR IN CONNECTION WITH THE USE OR PERFORMANCE OF THIS SOFTWARE.
#

package Cassandane::Cyrus::JMAPMail;
use strict;
use warnings;
use DateTime;
use JSON::XS;
use Net::CalDAVTalk 0.09;
use Net::CardDAVTalk 0.03;
use Mail::JMAPTalk;
use Data::Dumper;
use Storable 'dclone';

use lib '.';
use base qw(Cassandane::Cyrus::JMAP);
use Cassandane::Util::Log;

use charnames ':full';

sub uniq {
  my %seen;
  return grep { !$seen{$_}++ } @_;
}

sub getinbox
{
    my ($self) = @_;

    my $jmap = $self->{jmap};

    xlog "get existing mailboxes";
    my $res = $jmap->Request([['getMailboxes', {}, "R1"]]);
    $self->assert_not_null($res);

    my %m = map { $_->{name} => $_ } @{$res->[0][1]{list}};
    return $m{"Inbox"};
}

sub test_getmailboxes
    :min_version_3_0
{
    my ($self) = @_;

    my $jmap = $self->{jmap};
    my $imaptalk = $self->{store}->get_client();

    $imaptalk->create("INBOX.foo")
        or die "Cannot create mailbox INBOX.foo: $@";

    $imaptalk->create("INBOX.foo.bar")
        or die "Cannot create mailbox INBOX.foo.bar: $@";

    xlog "get existing mailboxes";
    my $res = $jmap->Request([['getMailboxes', {}, "R1"]]);
    $self->assert_not_null($res);
    $self->assert_str_equals($res->[0][0], 'mailboxes');
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
    $self->assert_equals($inbox->{mustBeOnlyMailbox}, JSON::false);
    $self->assert_equals($inbox->{mayReadItems}, JSON::true);
    $self->assert_equals($inbox->{mayAddItems}, JSON::true);
    $self->assert_equals($inbox->{mayRemoveItems}, JSON::true);
    $self->assert_equals($inbox->{mayCreateChild}, JSON::true);
    $self->assert_equals($inbox->{mayRename}, JSON::false);
    $self->assert_equals($inbox->{mayDelete}, JSON::false);
    $self->assert_num_equals($inbox->{totalMessages}, 0);
    $self->assert_num_equals($inbox->{unreadMessages}, 0);
    $self->assert_num_equals($inbox->{totalThreads}, 0);
    $self->assert_num_equals($inbox->{unreadThreads}, 0);

    # INBOX.foo
    $self->assert_str_equals($foo->{name}, "foo");
    $self->assert_null($foo->{parentId});
    $self->assert_null($foo->{role});
    $self->assert_num_equals($foo->{sortOrder}, 0);
    $self->assert_equals($foo->{mustBeOnlyMailbox}, JSON::false);
    $self->assert_equals($foo->{mayReadItems}, JSON::true);
    $self->assert_equals($foo->{mayAddItems}, JSON::true);
    $self->assert_equals($foo->{mayRemoveItems}, JSON::true);
    $self->assert_equals($foo->{mayCreateChild}, JSON::true);
    $self->assert_equals($foo->{mayRename}, JSON::true);
    $self->assert_equals($foo->{mayDelete}, JSON::true);
    $self->assert_num_equals($foo->{totalMessages}, 0);
    $self->assert_num_equals($foo->{unreadMessages}, 0);
    $self->assert_num_equals($foo->{totalThreads}, 0);
    $self->assert_num_equals($foo->{unreadThreads}, 0);

    # INBOX.foo.bar
    $self->assert_str_equals($bar->{name}, "bar");
    $self->assert_str_equals($bar->{parentId}, $foo->{id});
    $self->assert_null($bar->{role});
    $self->assert_num_equals($bar->{sortOrder}, 0);
    $self->assert_equals($bar->{mustBeOnlyMailbox}, JSON::false);
    $self->assert_equals($bar->{mayReadItems}, JSON::true);
    $self->assert_equals($bar->{mayAddItems}, JSON::true);
    $self->assert_equals($bar->{mayRemoveItems}, JSON::true);
    $self->assert_equals($bar->{mayCreateChild}, JSON::true);
    $self->assert_equals($bar->{mayRename}, JSON::true);
    $self->assert_equals($bar->{mayDelete}, JSON::true);
    $self->assert_num_equals($bar->{totalMessages}, 0);
    $self->assert_num_equals($bar->{unreadMessages}, 0);
    $self->assert_num_equals($bar->{totalThreads}, 0);
    $self->assert_num_equals($bar->{unreadThreads}, 0);
}

sub test_getmailboxes_specialuse
    :min_version_3_0
{
    my ($self) = @_;

    my $jmap = $self->{jmap};
    my $imaptalk = $self->{store}->get_client();

    $imaptalk->create("INBOX.Archive", "(USE (\\Archive))") || die;
    $imaptalk->create("INBOX.Drafts", "(USE (\\Drafts))") || die;
    $imaptalk->create("INBOX.Junk", "(USE (\\Junk))") || die;
    $imaptalk->create("INBOX.Sent", "(USE (\\Sent))") || die;
    $imaptalk->create("INBOX.Trash", "(USE (\\Trash))") || die;

    xlog "get mailboxes";
    my $res = $jmap->Request([['getMailboxes', {}, "R1"]]);
    $self->assert_not_null($res);
    $self->assert_str_equals($res->[0][0], 'mailboxes');
    $self->assert_str_equals($res->[0][2], 'R1');

    my %m = map { $_->{name} => $_ } @{$res->[0][1]{list}};
    my $inbox = $m{"Inbox"};
    my $archive = $m{"Archive"};
    my $drafts = $m{"Drafts"};
    my $junk = $m{"Junk"};
    my $sent = $m{"Sent"};
    my $trash = $m{"Trash"};

    $self->assert_str_equals($archive->{name}, "Archive");
    $self->assert_str_equals($archive->{role}, "archive");

    $self->assert_str_equals($drafts->{name}, "Drafts");
    $self->assert_null($drafts->{parentId});
    $self->assert_str_equals($drafts->{role}, "drafts");

    $self->assert_str_equals($junk->{name}, "Junk");
    $self->assert_null($junk->{parentId});
    $self->assert_str_equals($junk->{role}, "junk");

    $self->assert_str_equals($sent->{name}, "Sent");
    $self->assert_null($sent->{parentId});
    $self->assert_str_equals($sent->{role}, "sent");

    $self->assert_str_equals($trash->{name}, "Trash");
    $self->assert_null($trash->{parentId});
    $self->assert_str_equals($trash->{role}, "trash");
}

sub test_getmailboxes_properties
    :min_version_3_0
{
    my ($self) = @_;

    my $jmap = $self->{jmap};

    xlog "get mailboxes with name property";
    my $res = $jmap->Request([['getMailboxes', { properties => ["name"]}, "R1"]]);
    $self->assert_not_null($res);
    $self->assert_str_equals($res->[0][0], 'mailboxes');
    $self->assert_str_equals($res->[0][2], 'R1');

    my $inbox = $res->[0][1]{list}[0];
    $self->assert_str_equals($inbox->{name}, "Inbox");
    $self->assert_num_equals(scalar keys %{$inbox}, 2); # id and name

    xlog "get mailboxes with erroneous property";
    $res = $jmap->Request([['getMailboxes', { properties => ["name", 123]}, "R1"]]);
    $self->assert_not_null($res);
    $self->assert_str_equals($res->[0][0], 'error');
    $self->assert_str_equals($res->[0][2], 'R1');

    my $err = $res->[0][1];
    $self->assert_str_equals($err->{type}, "invalidArguments");
    $self->assert_str_equals($err->{arguments}[0], "properties");
}

sub test_getmailboxes_ids
    :min_version_3_0
{
    my ($self) = @_;

    my $jmap = $self->{jmap};
    my $imaptalk = $self->{store}->get_client();

    $imaptalk->create("INBOX.foo") || die;

    xlog "get all mailboxes";
    my $res = $jmap->Request([['getMailboxes', { }, "R1"]]);
    $self->assert_not_null($res);
    $self->assert_str_equals($res->[0][0], 'mailboxes');
    $self->assert_str_equals($res->[0][2], 'R1');

    my %m = map { $_->{name} => $_ } @{$res->[0][1]{list}};
    my $inbox = $m{"Inbox"};
    my $foo = $m{"foo"};
    $self->assert_not_null($inbox);
    $self->assert_not_null($foo);

    xlog "get foo and unknown mailbox";
    $res = $jmap->Request([['getMailboxes', { ids => [$foo->{id}, "nope"] }, "R1"]]);
    $self->assert_str_equals($res->[0][1]{list}[0]->{id}, $foo->{id});
    $self->assert_str_equals($res->[0][1]{notFound}[0], "nope");

    xlog "get mailbox with erroneous id";
    $res = $jmap->Request([['getMailboxes', { ids => [123]}, "R1"]]);
    $self->assert_not_null($res);
    $self->assert_str_equals($res->[0][0], 'error');
    $self->assert_str_equals($res->[0][2], 'R1');

    my $err = $res->[0][1];
    $self->assert_str_equals($err->{type}, "invalidArguments");
    $self->assert_str_equals($err->{arguments}[0], "ids");
}

sub test_getmailboxes_nocalendars
    :min_version_3_0
{
    my ($self) = @_;

    my $jmap = $self->{jmap};
    my $caldav = $self->{caldav};

    xlog "get existing mailboxes";
    my $res = $jmap->Request([['getMailboxes', {}, "R1"]]);
    $self->assert_not_null($res);
    $self->assert_str_equals($res->[0][0], 'mailboxes');
    $self->assert_str_equals($res->[0][2], 'R1');
    my $mboxes = $res->[0][1]{list};

    xlog "create calendar";
    $res = $jmap->Request([
            ['setCalendars', { create => { "#1" => {
                            name => "foo",
                            color => "coral",
                            sortOrder => 2,
                            isVisible => \1
             }}}, "R1"]
    ]);
    $self->assert_not_null($res->[0][1]{created});

    xlog "get updated mailboxes";
    $res = $jmap->Request([['getMailboxes', {}, "R1"]]);
    $self->assert_not_null($res);
    $self->assert_num_equals(scalar @{$res->[0][1]{list}}, scalar @{$mboxes});
}

sub test_setmailboxes
    :min_version_3_0
{
    my ($self) = @_;

    my $jmap = $self->{jmap};

    xlog "get inbox";
    my $res = $jmap->Request([['getMailboxes', { }, "R1"]]);
    my $inbox = $res->[0][1]{list}[0];
    $self->assert_str_equals($inbox->{name}, "Inbox");

    my $state = $res->[0][1]{state};

    xlog "create mailbox";
    $res = $jmap->Request([
            ['setMailboxes', { create => { "#1" => {
                            name => "foo",
                            parentId => $inbox->{id},
                            role => undef
             }}}, "R1"]
    ]);
    $self->assert_str_equals($res->[0][0], 'mailboxesSet');
    $self->assert_str_equals($res->[0][2], 'R1');
    $self->assert_str_not_equals($res->[0][1]{newState}, $state);
    $self->assert_not_null($res->[0][1]{created});
    my $id = $res->[0][1]{created}{"#1"}{id};

    xlog "get mailbox $id";
    $res = $jmap->Request([['getMailboxes', { ids => [$id] }, "R1"]]);
    $self->assert_str_equals($res->[0][1]{list}[0]->{id}, $id);

    my $mbox = $res->[0][1]{list}[0];
    $self->assert_str_equals($mbox->{name}, "foo");
    $self->assert_null($mbox->{parentId});
    $self->assert_null($mbox->{role});
    $self->assert_num_equals($mbox->{sortOrder}, 0);
    $self->assert_equals($mbox->{mustBeOnlyMailbox}, JSON::false);
    $self->assert_equals($mbox->{mayReadItems}, JSON::true);
    $self->assert_equals($mbox->{mayAddItems}, JSON::true);
    $self->assert_equals($mbox->{mayRemoveItems}, JSON::true);
    $self->assert_equals($mbox->{mayCreateChild}, JSON::true);
    $self->assert_equals($mbox->{mayRename}, JSON::true);
    $self->assert_equals($mbox->{mayDelete}, JSON::true);
    $self->assert_num_equals($mbox->{totalMessages}, 0);
    $self->assert_num_equals($mbox->{unreadMessages}, 0);
    $self->assert_num_equals($mbox->{totalThreads}, 0);
    $self->assert_num_equals($mbox->{unreadThreads}, 0);

    xlog "update mailbox";
    $res = $jmap->Request([
            ['setMailboxes', { update => { $id => {
                            name => "bar",
                            sortOrder => 10
             }}}, "R1"]
    ]);

    $self->assert_str_equals($res->[0][0], 'mailboxesSet');
    $self->assert_str_equals($res->[0][2], 'R1');
    $self->assert_str_not_equals($res->[0][1]{newState}, $state);
    $self->assert_str_equals($res->[0][1]{updated}[0], $id);

    xlog "get mailbox $id";
    $res = $jmap->Request([['getMailboxes', { ids => [$id] }, "R1"]]);
    $self->assert_str_equals($res->[0][1]{list}[0]->{id}, $id);
    $mbox = $res->[0][1]{list}[0];
    $self->assert_str_equals($mbox->{name}, "bar");
    $self->assert_num_equals($mbox->{sortOrder}, 10);

    xlog "destroy mailbox";
    $res = $jmap->Request([
            ['setMailboxes', { destroy => [ $id ] }, "R1"]
    ]);
    $self->assert_str_equals($res->[0][0], 'mailboxesSet');
    $self->assert_str_equals($res->[0][2], 'R1');
    $self->assert_str_not_equals($res->[0][1]{newState}, $state);
    $self->assert_str_equals($res->[0][1]{destroyed}[0], $id);

    xlog "get mailbox $id";
    $res = $jmap->Request([['getMailboxes', { ids => [$id] }, "R1"]]);
    $self->assert_str_equals($res->[0][1]{notFound}[0], $id);
}

sub test_setmailboxes_name_collision
    :min_version_3_0
{
    my ($self) = @_;

    my $jmap = $self->{jmap};

    xlog "get inbox";
    my $res = $jmap->Request([['getMailboxes', { }, "R1"]]);
    my $inbox = $res->[0][1]{list}[0];
    $self->assert_str_equals($inbox->{name}, "Inbox");

    my $state = $res->[0][1]{state};

    xlog "create three mailboxes named foo";
    $res = $jmap->Request([
            ['setMailboxes', { create =>
                    { "#1" => {
                            name => "foo",
                            parentId => $inbox->{id},
                            role => undef
                        },
                        "#2" => {
                            name => "foo",
                            parentId => $inbox->{id},
                            role => undef
                        },
                        "#3" => {
                            name => "foo",
                            parentId => $inbox->{id},
                            role => undef
                        }}}, "R1"]
    ]);
    $self->assert_not_null($res->[0][1]{created});

    my $id1 = $res->[0][1]{created}{"#1"}{id};
    my $id2 = $res->[0][1]{created}{"#2"}{id};
    my $id3 = $res->[0][1]{created}{"#3"}{id};

    xlog "get mailbox $id1";
    $res = $jmap->Request([['getMailboxes', { ids => [$id1] }, "R1"]]);
    $self->assert_str_equals($res->[0][1]{list}[0]->{name}, "foo");

    xlog "get mailbox $id2";
    $res = $jmap->Request([['getMailboxes', { ids => [$id2] }, "R1"]]);
    $self->assert_str_equals($res->[0][1]{list}[0]->{name}, "foo");

    xlog "get mailbox $id3";
    $res = $jmap->Request([['getMailboxes', { ids => [$id3] }, "R1"]]);
    $self->assert_str_equals($res->[0][1]{list}[0]->{name}, "foo");

    xlog "rename all three mailboxes to bar";
    $res = $jmap->Request([
            ['setMailboxes', { update =>
                    { $id1 => { name => "bar" },
                      $id2 => { name => "bar" },
                      $id3 => { name => "bar" }
                  }}, "R1"]
    ]);
    $self->assert_not_null($res->[0][1]{updated});

    xlog "get mailbox $id1";
    $res = $jmap->Request([['getMailboxes', { ids => [$id1] }, "R1"]]);
    $self->assert_str_equals($res->[0][1]{list}[0]->{name}, "bar");

    xlog "get mailbox $id2";
    $res = $jmap->Request([['getMailboxes', { ids => [$id2] }, "R1"]]);
    $self->assert_str_equals($res->[0][1]{list}[0]->{name}, "bar");

    xlog "get mailbox $id3";
    $res = $jmap->Request([['getMailboxes', { ids => [$id3] }, "R1"]]);
    $self->assert_str_equals($res->[0][1]{list}[0]->{name}, "bar");
}

sub test_setmailboxes_name_interop
    :min_version_3_0
{
    my ($self) = @_;

    my $jmap = $self->{jmap};
    my $imaptalk = $self->{store}->get_client();

    xlog "create mailbox via IMAP";
    $imaptalk->create("INBOX.foo")
        or die "Cannot create mailbox INBOX.foo: $@";

    xlog "get foo mailbox";
    my $res = $jmap->Request([['getMailboxes', {}, "R1"]]);
    my %m = map { $_->{name} => $_ } @{$res->[0][1]{list}};
    my $foo = $m{"foo"};
    my $id = $foo->{id};
    $self->assert_str_equals($foo->{name}, "foo");

    xlog "rename mailbox foo to oof via JMAP";
    $res = $jmap->Request([
            ['setMailboxes', { update => { $id => { name => "oof" }}}, "R1"]
    ]);
    $self->assert_not_null($res->[0][1]{updated});

    xlog "get mailbox via IMAP";
    my $data = $imaptalk->list("INBOX.oof", "%");
    $self->assert_num_equals(scalar @{$data}, 1);

    xlog "rename mailbox oof to bar via IMAP";
    $imaptalk->rename("INBOX.oof", "INBOX.bar")
        or die "Cannot rename mailbox: $@";

    xlog "get mailbox $id";
    $res = $jmap->Request([['getMailboxes', { ids => [$id] }, "R1"]]);
    $self->assert_str_equals($res->[0][1]{list}[0]->{name}, "bar");

    xlog "rename mailbox bar to baz via JMAP";
    $res = $jmap->Request([
            ['setMailboxes', { update => { $id => { name => "baz" }}}, "R1"]
    ]);
    $self->assert_not_null($res->[0][1]{updated});

    xlog "get mailbox via IMAP";
    $data = $imaptalk->list("INBOX.baz", "%");
    $self->assert_num_equals(scalar @{$data}, 1);

    xlog "rename mailbox baz to IFeel\N{WHITE SMILING FACE} via IMAP";
    $imaptalk->rename("INBOX.baz", "INBOX.IFeel\N{WHITE SMILING FACE}")
        or die "Cannot rename mailbox: $@";

    xlog "get mailbox $id";
    $res = $jmap->Request([['getMailboxes', { ids => [$id] }, "R1"]]);
    $self->assert_str_equals($res->[0][1]{list}[0]->{name}, "IFeel\N{WHITE SMILING FACE}");
}

sub test_setmailboxes_role
    :min_version_3_0
{
    my ($self) = @_;

    my $jmap = $self->{jmap};
    my $imaptalk = $self->{store}->get_client();

    xlog "get inbox";
    my $res = $jmap->Request([['getMailboxes', { }, "R1"]]);
    my $inbox = $res->[0][1]{list}[0];
    $self->assert_str_equals($inbox->{name}, "Inbox");

    my $state = $res->[0][1]{state};

    xlog "try to create mailbox with inbox role";
    $res = $jmap->Request([
            ['setMailboxes', { create => { "#1" => {
                            name => "foo",
                            parentId => $inbox->{id},
                            role => "inbox"
             }}}, "R1"]
    ]);
    $self->assert_str_equals($res->[0][0], 'mailboxesSet');
    $self->assert_str_equals($res->[0][2], 'R1');
    my $errType = $res->[0][1]{notCreated}{"#1"}{type};
    my $errProp = $res->[0][1]{notCreated}{"#1"}{properties};
    $self->assert_str_equals($errType, "invalidProperties");
    $self->assert_deep_equals($errProp, [ "role" ]);

    xlog "create mailbox with trash role";
    $res = $jmap->Request([
            ['setMailboxes', { create => { "#1" => {
                            name => "foo",
                            parentId => undef,
                            role => "trash"
             }}}, "R1"]
    ]);
    $self->assert_str_equals($res->[0][0], 'mailboxesSet');
    $self->assert_str_equals($res->[0][2], 'R1');
    $self->assert_not_null($res->[0][1]{created});

    my $id = $res->[0][1]{created}{"#1"}{id};

    xlog "get mailbox $id";
    $res = $jmap->Request([['getMailboxes', { ids => [$id] }, "R1"]]);

    $self->assert_str_equals($res->[0][1]{list}[0]->{role}, "trash");

    xlog "get mailbox $id via IMAP";
    my $data = $imaptalk->xlist("INBOX.foo", "%");
    my %annots = map { $_ => 1 } @{$data->[0]->[0]};
    $self->assert(exists $annots{"\\Trash"});

    xlog "try to create another mailbox with trash role";
    $res = $jmap->Request([
            ['setMailboxes', { create => { "#1" => {
                            name => "bar",
                            parentId => $inbox->{id},
                            role => "trash"
             }}}, "R1"]
    ]);
    $errType = $res->[0][1]{notCreated}{"#1"}{type};
    $errProp = $res->[0][1]{notCreated}{"#1"}{properties};
    $self->assert_str_equals($errType, "invalidProperties");
    $self->assert_deep_equals($errProp, [ "role" ]);

    xlog "create mailbox with x-bam role";
    $res = $jmap->Request([
            ['setMailboxes', { create => { "#1" => {
                            name => "baz",
                            parentId => undef,
                            role => "x-bam"
             }}}, "R1"]
    ]);
    $self->assert_not_null($res->[0][1]{created});
    $id = $res->[0][1]{created}{"#1"}{id};

    xlog "get mailbox $id";
    $res = $jmap->Request([['getMailboxes', { ids => [$id] }, "R1"]]);
    $self->assert_str_equals($res->[0][1]{list}[0]->{role}, "x-bam");

    xlog "update of a mailbox role is always an error";
    $res = $jmap->Request([
            ['setMailboxes', { update => { "$id" => {
                            role => "x-baz"
             }}}, "R1"]
    ]);
    $errType = $res->[0][1]{notUpdated}{$id}{type};
    $errProp = $res->[0][1]{notUpdated}{$id}{properties};
    $self->assert_str_equals($errType, "invalidProperties");
    $self->assert_deep_equals($errProp, [ "role" ]);

    xlog "try to create another mailbox with the x-bam role";
    $res = $jmap->Request([
            ['setMailboxes', { create => { "#1" => {
                            name => "bar",
                            parentId => $inbox->{id},
                            role => "x-bam"
             }}}, "R1"]
    ]);
    $errType = $res->[0][1]{notCreated}{"#1"}{type};
    $errProp = $res->[0][1]{notCreated}{"#1"}{properties};
    $self->assert_str_equals($errType, "invalidProperties");
    $self->assert_deep_equals($errProp, [ "role" ]);

    xlog "try to create a mailbox with an unknown, non-x role";
    $res = $jmap->Request([
            ['setMailboxes', { create => { "#1" => {
                            name => "bam",
                            parentId => $inbox->{id},
                            role => "unknown"
             }}}, "R1"]
    ]);
    $errType = $res->[0][1]{notCreated}{"#1"}{type};
    $errProp = $res->[0][1]{notCreated}{"#1"}{properties};
    $self->assert_str_equals($errType, "invalidProperties");
    $self->assert_deep_equals($errProp, [ "role" ]);

    xlog "create a specialuse Sent mailbox via IMAP";
    $imaptalk->create("INBOX.Sent", "(USE (\\Sent))") || die;

    xlog "create a specialuse Archive and Junk mailbox via IMAP";
    $imaptalk->create("INBOX.Multi", "(USE (\\Archive \\Junk))") || die;

    xlog "get mailboxes";
    $res = $jmap->Request([['getMailboxes', { }, "R1"]]);
    my %m = map { $_->{name} => $_ } @{$res->[0][1]{list}};
    my $sent = $m{"Sent"};
    my $multi = $m{"Multi"};
    $self->assert_str_equals($sent->{role}, "sent");
    $self->assert_str_equals($multi->{role}, "archive");
}

sub test_setmailboxes_parent
    :min_version_3_0
{
    my ($self) = @_;

    my $jmap = $self->{jmap};

    # Create mailboxes
    xlog "create mailbox foo";
    my $res = $jmap->Request([['setMailboxes', { create => {
                        "1" => { name => "foo", parentId => undef, role => undef }
                    }}, "R1"]]);
    my $id1 = $res->[0][1]{created}{"1"}{id};
    xlog "create mailbox foo.bar";
    $res = $jmap->Request([
            ['setMailboxes', { create => {
                        "2" => { name => "bar", parentId => $id1, role => undef }
                    }}, "R1"]
        ]);
    my $id2 = $res->[0][1]{created}{"2"}{id};
    xlog "create mailbox foo.bar.baz";
    $res = $jmap->Request([
            ['setMailboxes', { create => {
                        "3" => { name => "baz", parentId => $id2, role => undef }
                    }}, "R1"]
        ]);
    my $id3 = $res->[0][1]{created}{"3"}{id};

    # All set up?
    $res = $jmap->Request([['getMailboxes', { ids => [$id1] }, "R1"]]);
    $self->assert_null($res->[0][1]{list}[0]->{parentId});
    $res = $jmap->Request([['getMailboxes', { ids => [$id2] }, "R1"]]);
    $self->assert_str_equals($res->[0][1]{list}[0]->{parentId}, $id1);
    $res = $jmap->Request([['getMailboxes', { ids => [$id3] }, "R1"]]);
    $self->assert_str_equals($res->[0][1]{list}[0]->{parentId}, $id2);

    xlog "move foo.bar to bar";
    $res = $jmap->Request([
            ['setMailboxes', { update => {
                        $id2 => { name => "bar", parentId => undef, role => undef }
                    }}, "R1"]
        ]);
    $res = $jmap->Request([['getMailboxes', { ids => [$id2] }, "R1"]]);
    $self->assert_null($res->[0][1]{list}[0]->{parentId});

    xlog "move bar.baz to foo.baz";
    $res = $jmap->Request([
            ['setMailboxes', { update => {
                        $id3 => { name => "baz", parentId => $id1, role => undef }
                    }}, "R1"]
        ]);
    $res = $jmap->Request([['getMailboxes', { ids => [$id3] }, "R1"]]);
    $self->assert_str_equals($res->[0][1]{list}[0]->{parentId}, $id1);

    xlog "move foo to bar.foo";
    $res = $jmap->Request([
            ['setMailboxes', { update => {
                        $id1 => { name => "foo", parentId => $id2, role => undef }
                    }}, "R1"]
        ]);
    $res = $jmap->Request([['getMailboxes', { ids => [$id1] }, "R1"]]);
    $self->assert_str_equals($res->[0][1]{list}[0]->{parentId}, $id2);

    xlog "move foo to non-existent parent";
    $res = $jmap->Request([
            ['setMailboxes', { update => {
                        $id1 => { name => "foo", parentId => "nope", role => undef }
                    }}, "R1"]
        ]);
    my $errType = $res->[0][1]{notUpdated}{$id1}{type};
    my $errProp = $res->[0][1]{notUpdated}{$id1}{properties};
    $self->assert_str_equals($errType, "invalidProperties");
    $self->assert_deep_equals($errProp, [ "parentId" ]);
    $res = $jmap->Request([['getMailboxes', { ids => [$id1] }, "R1"]]);
    $self->assert_str_equals($res->[0][1]{list}[0]->{parentId}, $id2);

    xlog "attempt to destroy bar (which has child foo)";
    $res = $jmap->Request([
            ['setMailboxes', { destroy => [$id2] }, "R1"]
        ]);
    $errType = $res->[0][1]{notDestroyed}{$id2}{type};
    $self->assert_str_equals($errType, "mailboxHasChild");
    $res = $jmap->Request([['getMailboxes', { ids => [$id2] }, "R1"]]);
    $self->assert_null($res->[0][1]{list}[0]->{parentId});

    xlog "destroy all";
    $res = $jmap->Request([
            ['setMailboxes', { destroy => [$id3, $id1, $id2] }, "R1"]
        ]);
    $self->assert_str_equals($res->[0][1]{destroyed}[0], $id3);
    $self->assert_str_equals($res->[0][1]{destroyed}[1], $id1);
    $self->assert_str_equals($res->[0][1]{destroyed}[2], $id2);
}

sub test_getmessages
    :min_version_3_0
{
    my ($self) = @_;
    my $jmap = $self->{jmap};

    my $store = $self->{store};
    my $talk = $store->get_client();

    my $res = $jmap->Request([['getMailboxes', { }, "R1"]]);
    my $inboxid = $res->[0][1]{list}[0]{id};

    my $body = "";
    $body .= "Lorem ipsum dolor sit amet, consectetur adipiscing\r\n";
    $body .= "elit. Nunc in fermentum nibh. Vivamus enim metus.";

    my $maildate = DateTime->now();
    $maildate->add(DateTime::Duration->new(seconds => -10));

    xlog "Generate a message in INBOX via IMAP";
    my %exp_inbox;
    my %params = (
        date => $maildate,
        from => Cassandane::Address->new(
            name => "Sally Sender",
            localpart => "sally",
            domain => "local"
        ),
        to => Cassandane::Address->new(
            name => "Tom To",
            localpart => 'tom',
            domain => 'local'
        ),
        cc => Cassandane::Address->new(
            name => "Cindy CeeCee",
            localpart => 'cindy',
            domain => 'local'
        ),
        bcc => Cassandane::Address->new(
            name => "Benny CarbonCopy",
            localpart => 'benny',
            domain => 'local'
        ),
        messageid => 'fake.123456789@local',
        extra_headers => [
            ['X-Tra', "foo bar\r\n baz"],
            ['Sender', "Bla <blu\@local>"],
        ],
        body => $body
    );
    $self->make_message("Message A", %params) || die;

    xlog "get message list";
    $res = $jmap->Request([['getMessageList', {}, "R1"]]);
    $self->assert_num_equals(scalar @{$res->[0][1]->{messageIds}}, 1);

    xlog "get messages";
    # Could also have set fetchMessages in getMessageList, but let's call
    # getMessages explicitely.
    $res = $jmap->Request([['getMessages', { ids => $res->[0][1]->{messageIds} }, "R1"]]);
    my $msg = $res->[0][1]->{list}[0];

    $self->assert_str_equals($msg->{mailboxIds}[0], $inboxid);
    $self->assert_num_equals(scalar @{$msg->{mailboxIds}}, 1);
    $self->assert_equals($msg->{isUnread}, JSON::true);
    $self->assert_equals($msg->{isFlagged}, JSON::false);
    $self->assert_equals($msg->{isAnswered}, JSON::false);
    $self->assert_equals($msg->{isDraft}, JSON::false);

    my $hdrs = $msg->{headers};
    $self->assert_str_equals($hdrs->{'Message-ID'}, '<fake.123456789@local>');
    $self->assert_str_equals($hdrs->{'X-Tra'}, 'foo bar baz');
    $self->assert_deep_equals($msg->{from}[0], {
            name => "Sally Sender",
            email => "sally\@local"
    });
    $self->assert_deep_equals($msg->{to}[0], {
            name => "Tom To",
            email => "tom\@local"
    });
    $self->assert_num_equals(scalar @{$msg->{to}}, 1);
    $self->assert_deep_equals($msg->{cc}[0], {
            name => "Cindy CeeCee",
            email => "cindy\@local"
    });
    $self->assert_num_equals(scalar @{$msg->{cc}}, 1);
    $self->assert_deep_equals($msg->{bcc}[0], {
            name => "Benny CarbonCopy",
            email => "benny\@local"
    });
    $self->assert_num_equals(scalar @{$msg->{bcc}}, 1);
    $self->assert_null($msg->{replyTo});
    $self->assert_deep_equals($msg->{sender}, {
            name => "Bla",
            email => "blu\@local"
    });
    $self->assert_str_equals($msg->{subject}, "Message A");

    my $datestr = $maildate->strftime('%Y-%m-%dT%TZ');
    $self->assert_str_equals($datestr, $msg->{date});
    $self->assert_not_null($msg->{size});
}

sub test_getmessages_multimailboxes
    :min_version_3_0
{
    my ($self) = @_;
    my $jmap = $self->{jmap};

    my $store = $self->{store};
    my $talk = $store->get_client();

    my $now = DateTime->now();

    xlog "Generate a message in INBOX via IMAP";
    my $res = $self->make_message("foo") || die;
    my $uid = $res->{attrs}->{uid};
    my $msg;

    xlog "get message";
    $res = $jmap->Request([['getMessageList', {fetchMessages => JSON::true}, "R1"]]);
    $msg = $res->[1][1]{list}[0];
    $self->assert_num_equals(1, scalar @{$res->[0][1]{messageIds}});
    $self->assert_num_equals(1, scalar @{$msg->{mailboxIds}});

    xlog "Create target mailbox";
    $talk->create("INBOX.target");

    xlog "Copy message into INBOX.target";
    $talk->copy($uid, "INBOX.target");

    xlog "get message";
    $res = $jmap->Request([['getMessageList', {fetchMessages => JSON::true}, "R1"]]);
    $msg = $res->[1][1]{list}[0];
    $self->assert_num_equals(1, scalar @{$res->[0][1]{messageIds}});
    $self->assert_num_equals(2, scalar @{$msg->{mailboxIds}});
}


sub test_getmessages_body_both
    :min_version_3_0
{
    my ($self) = @_;
    my $jmap = $self->{jmap};

    my $store = $self->{store};
    my $talk = $store->get_client();
    my $inbox = 'INBOX';

    xlog "Generate a message in $inbox via IMAP";
    my %exp_sub;
    $store->set_folder($inbox);
    $store->_select();
    $self->{gen}->set_next_uid(1);

    my $htmlBody = "<html><body><p>This is the html part.</p></body></html>";
    my $textBody = "This is the plain text part.";

    my $body = "--047d7b33dd729737fe04d3bde348\r\n";
    $body .= "Content-Type: text/plain; charset=UTF-8\r\n";
    $body .= "\r\n";
    $body .= $textBody;
    $body .= "\r\n";
    $body .= "--047d7b33dd729737fe04d3bde348\r\n";
    $body .= "Content-Type: text/html;charset=\"UTF-8\"\r\n";
    $body .= "\r\n";
    $body .= $htmlBody;
    $body .= "\r\n";
    $body .= "--047d7b33dd729737fe04d3bde348--";
    $exp_sub{A} = $self->make_message("foo",
        mime_type => "multipart/alternative",
        mime_boundary => "047d7b33dd729737fe04d3bde348",
        body => $body
    );

    xlog "get message list";
    my $res = $jmap->Request([['getMessageList', {}, "R1"]]);
    my $ids = $res->[0][1]->{messageIds};

    xlog "get message";
    $res = $jmap->Request([['getMessages', { ids => $ids }, "R1"]]);
    my $msg = $res->[0][1]{list}[0];

    $self->assert_str_equals($textBody, $msg->{textBody});
    $self->assert_str_equals($htmlBody, $msg->{htmlBody});

    xlog "get message";
    $res = $jmap->Request([['getMessages', { ids => $ids, properties => ["body"] }, "R1"]]);
    $msg = $res->[0][1]{list}[0];

    $self->assert_str_equals($htmlBody, $msg->{body});
}

sub test_getmessages_body_plain
    :min_version_3_0
{
    my ($self) = @_;
    my $jmap = $self->{jmap};

    my $store = $self->{store};
    my $talk = $store->get_client();
    my $inbox = 'INBOX';

    xlog "Generate a message in $inbox via IMAP";
    my %exp_sub;
    $store->set_folder($inbox);
    $store->_select();
    $self->{gen}->set_next_uid(1);

    my $body = "A plain text message.";
    $exp_sub{A} = $self->make_message("foo",
        body => $body
    );

    xlog "get message list";
    my $res = $jmap->Request([['getMessageList', {}, "R1"]]);
    my $ids = $res->[0][1]->{messageIds};

    xlog "get messages";
    $res = $jmap->Request([['getMessages', { ids => $ids }, "R1"]]);
    my $msg = $res->[0][1]{list}[0];

    $self->assert_str_equals($body, $msg->{textBody});
    $self->assert_str_equals($body, $msg->{htmlBody});

    xlog "get messages";
    $res = $jmap->Request([['getMessages', { ids => $ids, properties => ["body"] }, "R1"]]);
    $msg = $res->[0][1]{list}[0];

    $self->assert_str_equals($body, $msg->{body});
}

sub test_getmessages_body_html
    :min_version_3_0
{
    my ($self) = @_;
    my $jmap = $self->{jmap};

    my $store = $self->{store};
    my $talk = $store->get_client();
    my $inbox = 'INBOX';

    xlog "Generate a message in $inbox via IMAP";
    my %exp_sub;
    $store->set_folder($inbox);
    $store->_select();
    $self->{gen}->set_next_uid(1);

    my $body = "<html><body> <p>A HTML message.</p> </body></html>";
    $exp_sub{A} = $self->make_message("foo",
        mime_type => "text/html",
        body => $body
    );

    xlog "get message list";
    my $res = $jmap->Request([['getMessageList', {}, "R1"]]);
    my $ids = $res->[0][1]->{messageIds};

    xlog "get message";
    $res = $jmap->Request([['getMessages', { ids => $ids }, "R1"]]);
    my $msg = $res->[0][1]{list}[0];

    $self->assert_str_equals('A HTML message.', $msg->{textBody});
    $self->assert_str_equals($body, $msg->{htmlBody});

    xlog "get message";
    $res = $jmap->Request([['getMessages', {
        ids => $ids, properties => ["body"],
    }, "R1"]]);
    $msg = $res->[0][1]{list}[0];
    $self->assert_str_equals($body, $msg->{body});
}

sub test_getmessages_body_multi
    :min_version_3_0
{
    my ($self) = @_;
    my $jmap = $self->{jmap};

    my $store = $self->{store};
    my $talk = $store->get_client();
    my $inbox = 'INBOX';

    xlog "Generate a message in $inbox via IMAP";
    my %exp_sub;
    $store->set_folder($inbox);
    $store->_select();
    $self->{gen}->set_next_uid(1);

    my $body = "".
    "--sub\r\n".
    "Content-Type: text/plain; charset=UTF-8\r\n".
    "Content-Disposition: inline\r\n".
    "\r\n".
    "Short text". # Exactly 10 byte long body
    "\r\n--sub\r\n".
    "Content-Type: multipart/mixed; boundary=subsub\r\n".
        "\r\n--subsub\r\n".
        "Content-Type: multipart/alternative; boundary=subsubsub\r\n".
            "\r\n--subsubsub\r\n".
            "Content-Type: multipart/mixed; boundary=subsubsubsub\r\n".
                "\r\n--subsubsubsub\r\n".
                "Content-Type: text/plain\r\n".
                "\r\n" .
                "Be that the best text that we'll find".
                "\r\n--subsubsubsub\r\n".
                "Content-Type: image/jpeg\r\n".
                "Content-Transfer-Encoding: base64\r\n".
                "\r\n" .
                "beefc0de==".
                "\r\n--subsubsubsub\r\n".
                "Content-Type: text/plain\r\n".
                "\r\n".
                "Don't expect this to be the text body, even if it's longer".
                "\r\n--subsubsubsub--\r\n".
            "\r\n--subsubsub\r\n".
            "Content-Type: multipart/related; boundary=subsubsubsub\r\n".
                "\r\n--subsubsubsub\r\n".
                "Content-Type: text/html\r\n".
                "\r\n" .
                "<html>Expect this to be the html body</html>".
                "\r\n--subsubsubsub\r\n".
                "Content-Type: image/png\r\n".
                "Content-Transfer-Encoding: base64\r\n".
                "\r\n" .
                "f00bae==".
                "\r\n--subsubsubsub--\r\n".
            "\r\n--subsubsub\r\n".
            "Content-Type: image/tiff\r\n".
            "Content-Transfer-Encoding: base64\r\n".
            "\r\n" .
            "beefc0de==".
            "\r\n--subsubsub\r\n".
            "Content-Type: application/x-excel\r\n".
            "Content-Transfer-Encoding: base64\r\n".
            "\r\n" .
            "012312312313==".
            "\r\n--subsubsub\r\n".
            "Content-Type: message/rfc822\r\n".
            "\r\n" .
            "Return-Path: <Ava.Nguyen\@local>\r\n".
            "Mime-Version: 1.0\r\n".
            "Content-Type: text/plain\r\n".
            "Content-Transfer-Encoding: 7bit\r\n".
            "Subject: bar\r\n".
            "From: Ava T. Nguyen <Ava.Nguyen\@local>\r\n".
            "Message-ID: <fake.1475639947.6507\@local>\r\n".
            "Date: Wed, 05 Oct 2016 14:59:07 +1100\r\n".
            "To: Test User <test\@local>\r\n".
            "\r\n".
            "Jeez....an embedded message".
            "\r\n--subsubsub--\r\n".
        "\r\n--subsub\r\n".
        "Content-Type: text/plain\r\n".
        "\r\n".
        "The Kenosha Kid".
        "\r\n--subsub--\r\n".
    "\r\n--sub--";

    $exp_sub{A} = $self->make_message("foo",
        mime_type => "multipart/mixed",
        mime_boundary => "sub",
        body => $body
    );

    xlog "get message list";
    my $res = $jmap->Request([['getMessageList', {}, "R1"]]);
    my $ids = $res->[0][1]->{messageIds};

    xlog "get message";
    $res = $jmap->Request([['getMessages', { ids => $ids }, "R1"]]);
    my $msg = $res->[0][1]{list}[0];

    $self->assert_str_equals("Be that the best text that we'll find", $msg->{textBody});

    $self->assert_equals(JSON::true, $msg->{hasAttachment});

    # Assert embedded message support
    $self->assert_num_equals(1, scalar keys %{$msg->{attachedMessages}});
    my $submsg = (values %{$msg->{attachedMessages}})[0];

    $self->assert_str_equals('<fake.1475639947.6507@local>', $submsg->{headers}->{'Message-ID'});
    $self->assert_deep_equals({
            name => "Ava T. Nguyen",
            email => "Ava.Nguyen\@local"
    }, $submsg->{from}[0]);
    $self->assert_deep_equals({
            name => "Test User",
            email => "test\@local"
    }, $submsg->{to}[0]);
    $self->assert_null($submsg->{cc});
    $self->assert_null($submsg->{bcc});
    $self->assert_null($submsg->{replyTo});
    $self->assert_str_equals("bar", $submsg->{subject});
    $self->assert_str_equals("2016-10-05T03:59:07Z", $submsg->{date});
    $self->assert_str_equals("Jeez....an embedded message", $submsg->{textBody});
    $self->assert_null($submsg->{mailboxIds});
    $self->assert_null($submsg->{isUnread});
    $self->assert_null($submsg->{isFlagged});
    $self->assert_null($submsg->{isAnswered});
    $self->assert_null($submsg->{isDraft});
    $self->assert_null($submsg->{size});

    # Assert attachments
    $self->assert_num_equals(4, scalar keys %{$msg->{attachments}});
}

sub test_getmessages_preview
    :min_version_3_0
{
    my ($self) = @_;
    my $jmap = $self->{jmap};

    my $store = $self->{store};
    my $talk = $store->get_client();
    my $inbox = 'INBOX';

    xlog "Generate a message in $inbox via IMAP";
    my %exp_sub;
    $store->set_folder($inbox);
    $store->_select();
    $self->{gen}->set_next_uid(1);

    my $body = "A   plain\r\ntext message.";
    $exp_sub{A} = $self->make_message("foo",
        body => $body
    );

    xlog "get message list";
    my $res = $jmap->Request([['getMessageList', {}, "R1"]]);

    xlog "get messages";
    $res = $jmap->Request([['getMessages', { ids => $res->[0][1]->{messageIds} }, "R1"]]);
    my $msg = $res->[0][1]{list}[0];

    $self->assert_str_equals($msg->{textBody}, "A   plain\r\ntext message.");
    $self->assert_str_equals($msg->{preview}, 'A plain text message.');
}

sub test_setmessages_draft
    :min_version_3_0
{
    my ($self) = @_;
    my $jmap = $self->{jmap};

    xlog "create drafts mailbox";
    my $res = $jmap->Request([
            ['setMailboxes', { create => { "#1" => {
                            name => "drafts",
                            parentId => undef,
                            role => "drafts"
             }}}, "R1"]
    ]);
    $self->assert_str_equals($res->[0][0], 'mailboxesSet');
    $self->assert_str_equals($res->[0][2], 'R1');
    $self->assert_not_null($res->[0][1]{created});
    my $draftsmbox = $res->[0][1]{created}{"#1"}{id};

    my $draft =  {
        mailboxIds => [$draftsmbox],
        from => [ { name => "Yosemite Sam", email => "sam\@acme.local" } ] ,
        sender => { name => "Marvin the Martian", email => "marvin\@acme.local" },
        to => [
            { name => "Bugs Bunny", email => "bugs\@acme.local" },
            { name => "Rainer M\N{LATIN SMALL LETTER U WITH DIAERESIS}ller", email => "rainer\@de.local" },
        ],
        cc => [
            { name => "Elmer Fudd", email => "elmer\@acme.local" },
            { name => "Porky Pig", email => "porky\@acme.local" },
        ],
        bcc => [
            { name => "Wile E. Coyote", email => "coyote\@acme.local" },
        ],
        replyTo => [ { name => "", email => "the.other.sam\@acme.local" } ],
        subject => "Memo",
        textBody => "I'm givin' ya one last chance ta surrenda!",
        htmlBody => "Oh!!! I <em>hate</em> that Rabbit.",
        headers => {
            "Foo" => "bar\nbaz\nbam",
        }
    };

    xlog "Create a draft";
    $res = $jmap->Request([['setMessages', { create => { "1" => $draft }}, "R1"]]);
    my $id = $res->[0][1]{created}{"1"}{id};

    xlog "Get draft $id";
    $res = $jmap->Request([['getMessages', { ids => [$id] }, "R1"]]);
    my $msg = $res->[0][1]->{list}[0];

    $self->assert_deep_equals($msg->{mailboxIds}, $draft->{mailboxIds});
    $self->assert_deep_equals($msg->{from}, $draft->{from});
    $self->assert_deep_equals($msg->{sender}, $draft->{sender});
    $self->assert_deep_equals($msg->{to}, $draft->{to});
    $self->assert_deep_equals($msg->{cc}, $draft->{cc});
    $self->assert_deep_equals($msg->{bcc}, $draft->{bcc});
    $self->assert_deep_equals($msg->{replyTo}, $draft->{replyTo});
    $self->assert_str_equals($msg->{subject}, $draft->{subject});
    $self->assert_str_equals($msg->{textBody}, $draft->{textBody});
    $self->assert_str_equals($msg->{htmlBody}, $draft->{htmlBody});
    $self->assert_str_equals($msg->{headers}->{Foo}, $draft->{headers}->{Foo});
    $self->assert_equals($msg->{isDraft}, JSON::true);
    $self->assert_equals($msg->{isFlagged}, JSON::false);
}

sub test_setmessages_inreplytoid
    :min_version_3_0
{
    my ($self) = @_;
    my $jmap = $self->{jmap};

    my $store = $self->{store};
    my $talk = $store->get_client();

    my $res = $jmap->Request([['getMailboxes', { }, "R1"]]);
    my $inboxid = $res->[0][1]{list}[0]{id};

    xlog "Create message to reply to";
    $self->make_message("foo") || die;
    $res = $jmap->Request([['getMessageList', {}, "R1"]]);
    $self->assert_num_equals(scalar @{$res->[0][1]->{messageIds}}, 1);
    my $msgid = $res->[0][1]->{messageIds}[0];

    xlog "create drafts mailbox";
    $res = $jmap->Request([
            ['setMailboxes', { create => { "#1" => {
                            name => "drafts",
                            parentId => undef,
                            role => "drafts"
             }}}, "R1"]
    ]);
    my $draftsmbox = $res->[0][1]{created}{"#1"}{id};

    my $draft =  {
        mailboxIds => [$draftsmbox],
        from => [ { name => "Yosemite Sam", email => "sam\@acme.local" } ] ,
        to => [
            { name => "Bugs Bunny", email => "bugs\@acme.local" },
        ],
        subject => "Memo",
        textBody => "I'm givin' ya one last chance ta surrenda!",
        inReplyToMessageId => $msgid,
    };

    $res = $jmap->Request([['setMessages', { create => { "1" => $draft }}, "R1"]]);
    my $id = $res->[0][1]{created}{"1"}{id};

    $res = $jmap->Request([['getMessages', { ids => [$id] }, "R1"]]);
    my $msg = $res->[0][1]->{list}[0];
    $self->assert_str_equals($msg->{inReplyToMessageId}, $msgid);
}

sub test_setmessages_attachedmessages
    :min_version_3_0
{
    my ($self) = @_;
    my $jmap = $self->{jmap};

    xlog "create drafts mailbox";
    my $res = $jmap->Request([
            ['setMailboxes', { create => { "#1" => {
                            name => "drafts",
                            parentId => undef,
                            role => "drafts"
             }}}, "R1"]
    ]);
    $self->assert_str_equals($res->[0][0], 'mailboxesSet');
    $self->assert_str_equals($res->[0][2], 'R1');
    $self->assert_not_null($res->[0][1]{created});
    my $draftsmbox = $res->[0][1]{created}{"#1"}{id};

    my $draft =  {
        mailboxIds => [$draftsmbox],
        from => [ { name => "Yosemite Sam", email => "sam\@acme.local" } ] ,
        to => [
            { name => "Bugs Bunny", email => "bugs\@acme.local" },
        ],
        subject => "Memo",
        textBody => "I'm givin' ya one last chance ta surrenda!",
        htmlBody => "<html>I'm givin' ya one last chance ta surrenda!</html>",
        attachedMessages => {
            "1" => {
                from => [ { name => "Bla", email => "bla\@acme.local" } ],
                to => [ { name => "Blu",   email => "blu\@acme.local" } ],
                subject  => "an embedded message",
                textBody => "Yo!",
            },
        },
    };

    xlog "Create a draft";
    $res = $jmap->Request([['setMessages', { create => { "1" => $draft }}, "R1"]]);
    my $id = $res->[0][1]{created}{"1"}{id};

    xlog "Get draft $id";
    $res = $jmap->Request([['getMessages', { ids => [$id] }, "R1"]]);
    my $msg = $res->[0][1]->{list}[0];

    $self->assert_deep_equals($msg->{mailboxIds}, $draft->{mailboxIds});
    $self->assert_deep_equals($msg->{from}, $draft->{from});
    $self->assert_deep_equals($msg->{to}, $draft->{to});
    $self->assert_str_equals($msg->{subject}, $draft->{subject});
    $self->assert_str_equals($msg->{textBody}, $draft->{textBody});

    my $got = (values %{$msg->{attachedMessages}})[0];
    my $want = $draft->{attachedMessages}->{1};
    $self->assert_deep_equals($got->{from}, $want->{from});
    $self->assert_deep_equals($got->{to}, $want->{to});
    $self->assert_str_equals($got->{textBody}, $want->{textBody});
    $self->assert_str_equals($got->{subject}, $want->{subject});
}

sub test_setmessages_flagged
    :min_version_3_0
{
    my ($self) = @_;
    my $jmap = $self->{jmap};

    xlog "create drafts mailbox";
    my $res = $jmap->Request([
            ['setMailboxes', { create => { "#1" => {
                            name => "drafts",
                            parentId => undef,
                            role => "drafts"
             }}}, "R1"]
    ]);
    $self->assert_str_equals($res->[0][0], 'mailboxesSet');
    $self->assert_str_equals($res->[0][2], 'R1');
    $self->assert_not_null($res->[0][1]{created});
    my $drafts = $res->[0][1]{created}{"#1"}{id};

    my $draft =  {
        mailboxIds => [$drafts],
        isFlagged => JSON::true,
        textBody => "a flagged draft"
    };

    xlog "Create a draft";
    $res = $jmap->Request([['setMessages', { create => { "1" => $draft }}, "R1"]]);
    my $id = $res->[0][1]{created}{"1"}{id};

    xlog "Get draft $id";
    $res = $jmap->Request([['getMessages', { ids => [$id] }, "R1"]]);
    my $msg = $res->[0][1]->{list}[0];

    $self->assert_deep_equals($msg->{mailboxIds}, $draft->{mailboxIds});
    $self->assert_equals($msg->{isFlagged}, JSON::true);
}

sub test_setmessages_invalid_mailaddr
    :min_version_3_0
{
    my ($self) = @_;
    my $jmap = $self->{jmap};

    # XXX Why do we have to do this? Shouldn't Cyrus provision the Outbox?
    xlog "create outbox";
    my $res = $jmap->Request([
            ['setMailboxes', { create => { "#1" => {
                            name => "drafts",
                            parentId => undef,
                            role => "outbox"
             }}}, "R1"]
    ]);
    $self->assert_str_equals($res->[0][0], 'mailboxesSet');
    $self->assert_str_equals($res->[0][2], 'R1');
    $self->assert_not_null($res->[0][1]{created});
    my $outbox = $res->[0][1]{created}{"#1"}{id};

    xlog "Send a message with invalid replyTo property";
    my $draft =  {
        mailboxIds => [$outbox],
        from => [ { name => "Yosemite Sam", email => "sam\@acme.local" } ],
        to => [ { name => "Bugs Bunny", email => "bugs\@acme.local" }, ],
        replyTo => [ { name => "", email => "a\@bad\@address\@acme.local" } ],
        subject => "Memo",
        textBody => "I'm givin' ya one last chance ta surrenda!",
    };
    $res = $jmap->Request([['setMessages', { create => { "1" => $draft }}, "R1"]]);
    $self->assert_str_equals($res->[0][1]{notCreated}{"1"}{type}, 'invalidProperties');
    $self->assert_str_equals($res->[0][1]{notCreated}{"1"}{properties}[0], 'replyTo[0].email');

    xlog "Send a message with invalid To header";
    $draft =  {
        mailboxIds => [$outbox],
        from => [ { name => "Yosemite Sam", email => "sam\@acme.local" } ],
        headers => { "To" => "bugs\@acme.local, a\@bad\@address\@acme.local" },
        subject => "Memo",
        textBody => "I'm givin' ya one last chance ta surrenda!",
    };
    $res = $jmap->Request([['setMessages', { create => { "1" => $draft }}, "R1"]]);
    $self->assert_str_equals($res->[0][1]{notCreated}{"1"}{type}, 'invalidProperties');
    $self->assert_str_equals($res->[0][1]{notCreated}{"1"}{properties}[0], 'header[To]');
}

sub test_setmessages_mailboxids
    :min_version_3_0
{
    my ($self) = @_;
    my $jmap = $self->{jmap};

    my $inboxid = $self->getinbox()->{id};
    $self->assert_not_null($inboxid);

    my $res = $jmap->Request([
        ['setMailboxes', { create => {
            "#1" => { name => "outbox", parentId => undef, role => "outbox" },
            "#2" => { name => "drafts", parentId => undef, role => "drafts" },
        }}, "R1"]
    ]);
    my $outboxid = $res->[0][1]{created}{"#1"}{id};
    my $draftsid = $res->[0][1]{created}{"#2"}{id};
    $self->assert_not_null($outboxid);
    $self->assert_not_null($draftsid);

    my $msg =  {
        from => [ { name => "Yosemite Sam", email => "sam\@acme.local" } ],
        to => [ { name => "Bugs Bunny", email => "bugs\@acme.local" }, ],
        subject => "Memo",
        textBody => "I'm givin' ya one last chance ta surrenda!",
    };

    # Not: OK at least one mailbox must be specified
    $res = $jmap->Request([['setMessages', { create => { "1" => $msg }}, "R1"]]);
    $self->assert_str_equals('invalidProperties', $res->[0][1]{notCreated}{"1"}{type});
    $self->assert_str_equals('mailboxIds', $res->[0][1]{notCreated}{"1"}{properties}[0]);
    $msg->{mailboxIds} = [];
    $res = $jmap->Request([['setMessages', { create => { "1" => $msg }}, "R1"]]);
    $self->assert_str_equals('invalidProperties', $res->[0][1]{notCreated}{"1"}{type});
    $self->assert_str_equals('mailboxIds', $res->[0][1]{notCreated}{"1"}{properties}[0]);

    # Not OK, either outbox or drafts must be in mailboxIds
    $msg->{mailboxIds} = [$inboxid];
    $res = $jmap->Request([['setMessages', { create => { "1" => $msg }}, "R1"]]);
    $self->assert_str_equals('invalidProperties', $res->[0][1]{notCreated}{"1"}{type});
    $self->assert_str_equals('mailboxIds', $res->[0][1]{notCreated}{"1"}{properties}[0]);

    # OK, save draft
    $msg->{mailboxIds} = [$outboxid];
    $res = $jmap->Request([['setMessages', { create => { "1" => $msg }}, "R1"]]);
    $self->assert_not_null($res->[0][1]{created}{"1"}{id});

    # OK, send immediately
    $msg->{mailboxIds} = [$outboxid];
    $res = $jmap->Request([['setMessages', { create => { "1" => $msg }}, "R1"]]);
    $self->assert_not_null($res->[0][1]{created}{"1"}{id});

    # Weird, but OK
    $msg->{mailboxIds} = [$inboxid, $outboxid];
    $res = $jmap->Request([['setMessages', { create => { "1" => $msg }}, "R1"]]);
    $self->assert_not_null($res->[0][1]{created}{"1"}{id});

    # Also weird, but OK
    $msg->{mailboxIds} = [$draftsid, $outboxid];
    $res = $jmap->Request([['setMessages', { create => { "1" => $msg }}, "R1"]]);
    $self->assert_not_null($res->[0][1]{created}{"1"}{id});
}

sub test_setmessages_move
    :min_version_3_0
{
    my ($self) = @_;
    my $jmap = $self->{jmap};

    my $store = $self->{store};
    my $talk = $store->get_client();
    my $inbox = 'INBOX';

    xlog "Create test mailboxes";
    my $res = $jmap->Request([
        ['setMailboxes', { create => {
            "#a" => { name => "a", parentId => undef },
            "#b" => { name => "b", parentId => undef },
            "#c" => { name => "c", parentId => undef },
            "#d" => { name => "d", parentId => undef },
        }}, "R1"]
    ]);
    $self->assert_num_equals( 4, scalar keys %{$res->[0][1]{created}} );
    my $a = $res->[0][1]{created}{"#a"}{id};
    my $b = $res->[0][1]{created}{"#b"}{id};
    my $c = $res->[0][1]{created}{"#c"}{id};
    my $d = $res->[0][1]{created}{"#d"}{id};

    xlog "Generate a message via IMAP";
    my %exp_sub;
    $exp_sub{A} = $self->make_message(
        "foo", body => "a message",
    );

    xlog "get message id";
    $res = $jmap->Request( [ [ 'getMessageList', {}, "R1" ] ] );
    my $id = $res->[0][1]->{messageIds}[0];

    xlog "get message";
    $res = $jmap->Request([['getMessages', { ids => [$id] }, "R1"]]);
    my $msg = $res->[0][1]->{list}[0];
    my @mboxids = $msg->{mailboxIds};
    $self->assert_num_equals(1, scalar @mboxids);

    local *assert_move = sub {
        my ($moveto) = (@_);

        xlog "move message to " . Dumper($moveto);
        $msg->{mailboxIds} = $moveto;
        $res = $jmap->Request(
            [ [ 'setMessages', { update => { $id => $msg } }, "R1" ] ] );
        $self->assert_str_equals( $res->[0][1]{updated}[0], $id );

        $res = $jmap->Request( [ [ 'getMessages', { ids => [$id] }, "R1" ] ] );
        $msg = $res->[0][1]->{list}[0];

        my @want = sort @$moveto;
        my @got  = sort @{ $msg->{mailboxIds} };
        $self->assert_deep_equals( \@want, \@got );
    };

    assert_move([$a, $b]);
    assert_move([$a, $b, $c]);
    assert_move([$d]);
}

sub test_setmessages_update
    :min_version_3_0
{
    my ($self) = @_;
    my $jmap = $self->{jmap};

    xlog "create drafts mailbox";
    my $res = $jmap->Request([
            ['setMailboxes', { create => { "#1" => {
                            name => "drafts",
                            parentId => undef,
                            role => "drafts"
             }}}, "R1"]
    ]);
    $self->assert_str_equals($res->[0][0], 'mailboxesSet');
    $self->assert_str_equals($res->[0][2], 'R1');
    $self->assert_not_null($res->[0][1]{created});
    my $drafts = $res->[0][1]{created}{"#1"}{id};

    my $draft =  {
        mailboxIds => [$drafts],
        from => [ { name => "Yosemite Sam", email => "sam\@acme.local" } ],
        to => [ { name => "Bugs Bunny", email => "bugs\@acme.local" } ],
        cc => [ { name => "Elmer Fudd", email => "elmer\@acme.local" } ],
        subject => "created",
        htmlBody => "Oh!!! I <em>hate</em> that Rabbit.",
    };

    xlog "Create a draft";
    $res = $jmap->Request([['setMessages', { create => { "1" => $draft }}, "R1"]]);
    my $id = $res->[0][1]{created}{"1"}{id};

    xlog "Get draft $id";
    $res = $jmap->Request([['getMessages', { ids => [$id] }, "R1"]]);
    my $msg = $res->[0][1]->{list}[0];

    xlog "Update draft $id";
    $draft->{isFlagged} = JSON::true;
    $draft->{isUnread} = JSON::false;
    $draft->{isAnswered} = JSON::false;
    $res = $jmap->Request([['setMessages', { update => { $id => $draft }}, "R1"]]);

    xlog "Get draft $id";
    $res = $jmap->Request([['getMessages', { ids => [$id] }, "R1"]]);
    $msg = $res->[0][1]->{list}[0];
    $self->assert_equals($msg->{isFlagged}, $draft->{isFlagged});
    $self->assert_equals($msg->{isUnread}, $draft->{isUnread});
    $self->assert_equals($msg->{isAnswered}, $draft->{isAnswered});
}

sub test_setmessages_destroy
  : min_version_3_0 {
    my ($self) = @_;
    my $jmap = $self->{jmap};

    xlog "create mailboxes";
    my $res = $jmap->Request(
        [
            [
                'setMailboxes',
                {
                    create => {
                        "#1" => {
                            name     => "drafts",
                            parentId => undef,
                            role     => "drafts"
                        },
                        "#2" => {
                            name     => "foo",
                            parentId => undef,
                        },
                        "#3" => {
                            name     => "bar",
                            parentId => undef,
                        },
                    }
                },
                "R1"
            ]
        ]
    );
    $self->assert_str_equals( $res->[0][0], 'mailboxesSet' );
    $self->assert_str_equals( $res->[0][2], 'R1' );
    $self->assert_not_null( $res->[0][1]{created} );
    my $mailboxids = [
        $res->[0][1]{created}{"#1"}{id},
        $res->[0][1]{created}{"#2"}{id},
        $res->[0][1]{created}{"#3"}{id},
    ];

    xlog "Create a draft";
    my $draft = {
        mailboxIds => $mailboxids,
        from       => [ { name => "Yosemite Sam", email => "sam\@acme.local" } ],
        to         => [ { name => "Bugs Bunny", email => "bugs\@acme.local" } ],
        subject    => "created",
        textBody   => "Oh!!! I *hate* that Rabbit.",
    };
    $res = $jmap->Request(
        [ [ 'setMessages', { create => { "1" => $draft } }, "R1" ] ],
    );
    my $id = $res->[0][1]{created}{"1"}{id};
    $self->assert_not_null($id);

    xlog "Get draft $id";
    $res = $jmap->Request( [ [ 'getMessages', { ids => [$id] }, "R1" ] ]);
    $self->assert_num_equals(3, scalar @{$res->[0][1]->{list}[0]{mailboxIds}});

    xlog "Destroy draft $id";
    $res = $jmap->Request(
        [ [ 'setMessages', { destroy => [ $id ] }, "R1" ] ],
    );
    $self->assert_str_equals( $res->[0][1]{destroyed}[0], $id );

    xlog "Get draft $id";
    $res = $jmap->Request( [ [ 'getMessages', { ids => [$id] }, "R1" ] ]);
    $self->assert_str_equals( $res->[0][1]->{notFound}[0], $id );

    xlog "Get messages";
    $res = $jmap->Request([['getMessageList', {}, "R1"]]);
    $self->assert_num_equals(0, scalar @{$res->[0][1]->{messageIds}});
}

sub test_getmessagelist
    :min_version_3_0
{
    my ($self) = @_;
    my $jmap = $self->{jmap};

    my $store = $self->{store};
    my $talk = $store->get_client();

    my $res = $jmap->Request([['getMailboxes', { }, "R1"]]);
    my $inboxid = $res->[0][1]{list}[0]{id};


    xlog "create mailboxes";
    $talk->create("INBOX.A") || die;
    $talk->create("INBOX.B") || die;
    $talk->create("INBOX.C") || die;
    $res = $jmap->Request([['getMailboxes', {}, "R1"]]);
    my %m = map { $_->{name} => $_ } @{$res->[0][1]{list}};
    my $mboxa = $m{"A"}->{id};
    my $mboxb = $m{"B"}->{id};
    my $mboxc = $m{"C"}->{id};
    $self->assert_not_null($mboxa);
    $self->assert_not_null($mboxb);
    $self->assert_not_null($mboxc);

    xlog "create messages";
    my %params;
    $store->set_folder("INBOX.A");
    my $dtfoo = DateTime->new(
        year       => 2016,
        month      => 11,
        day        => 1,
        hour       => 7,
        time_zone  => 'Etc/UTC',
    );
    my $bodyfoo = "A rather short message";
    %params = (
        date => $dtfoo,
        body => $bodyfoo,
    );
    $res = $self->make_message("foo", %params) || die;
    $talk->copy($res->{attrs}->{uid}, "INBOX.C");

    $store->set_folder("INBOX.B");
    my $dtbar = DateTime->new(
        year       => 2016,
        month      => 3,
        day        => 1,
        hour       => 19,
        time_zone  => 'Etc/UTC',
    );
    my $bodybar = ""
        . "In the context of electronic mail, messages are viewed as having an\r\n"
        . "envelope and contents.  The envelope contains whatever information is\r\n"
        . "needed to accomplish transmission and delivery.  (See [RFC5321] for a\r\n"
        . "discussion of the envelope.)  The contents comprise the object to be\r\n"
        . "delivered to the recipient.  This specification applies only to the\r\n"
        . "format and some of the semantics of message contents.  It contains no\r\n"
        . "specification of the information in the envelope.i\r\n"
        . "\r\n"
        . "However, some message systems may use information from the contents\r\n"
        . "to create the envelope.  It is intended that this specification\r\n"
        . "facilitate the acquisition of such information by programs.\r\n"
        . "\r\n"
        . "This specification is intended as a definition of what message\r\n"
        . "content format is to be passed between systems.  Though some message\r\n"
        . "systems locally store messages in this format (which eliminates the\r\n"
        . "need for translation between formats) and others use formats that\r\n"
        . "differ from the one specified in this specification, local storage is\r\n"
        . "outside of the scope of this specification.\r\n";

    %params = (
        date => $dtbar,
        body => $bodybar,
        extra_headers => [
            ['X-Tra', "baz"],
        ],
    );
    $self->make_message("bar", %params) || die;

    xlog "run squatter";
    $self->{instance}->run_command({cyrus => 1}, 'squatter');

    xlog "fetch messages without filter";
    $res = $jmap->Request([['getMessageList', { fetchMessages => JSON::true }, "R1"]]);
    $self->assert_num_equals(2, scalar @{$res->[0][1]->{messageIds}});
    $self->assert_num_equals(2, scalar @{$res->[1][1]->{list}});

    %m = map { $_->{subject} => $_ } @{$res->[1][1]{list}};
    my $foo = $m{"foo"}->{id};
    my $bar = $m{"bar"}->{id};
    $self->assert_not_null($foo);
    $self->assert_not_null($bar);

    xlog "filter text";
    $res = $jmap->Request([['getMessageList', {
        filter => {
            text => "foo",
        },
    }, "R1"]]);
    $self->assert_num_equals(1, scalar @{$res->[0][1]->{messageIds}});
    $self->assert_str_equals($foo, $res->[0][1]->{messageIds}[0]);

    xlog "filter NOT text";
    $res = $jmap->Request([['getMessageList', {
        filter => {
            operator => "NOT",
            conditions => [ {text => "foo"} ],
        },
    }, "R1"]]);
    $self->assert_num_equals(1, scalar @{$res->[0][1]->{messageIds}});
    $self->assert_str_equals($bar, $res->[0][1]->{messageIds}[0]);

    xlog "filter mailbox A";
    $res = $jmap->Request([['getMessageList', {
        filter => {
            inMailboxes => [ $mboxa ],
        },
    }, "R1"]]);
    $self->assert_num_equals(1, scalar @{$res->[0][1]->{messageIds}});
    $self->assert_str_equals($foo, $res->[0][1]->{messageIds}[0]);

    xlog "filter mailboxes";
    $res = $jmap->Request([['getMessageList', {
        filter => {
            inMailboxes => [ $mboxa, $mboxc ]
        },
    }, "R1"]]);
    $self->assert_num_equals(1, scalar @{$res->[0][1]->{messageIds}});
    $self->assert_str_equals($foo, $res->[0][1]->{messageIds}[0]);

    xlog "filter mailboxes";
    $res = $jmap->Request([['getMessageList', {
        filter => {
            inMailboxes => [ $mboxa, $mboxb, $mboxc ]
        },
    }, "R1"]]);
    $self->assert_num_equals(0, scalar @{$res->[0][1]->{messageIds}});

    xlog "filter not in mailbox A";
    $res = $jmap->Request([['getMessageList', {
        filter => {
            notInMailboxes => [ $mboxa ],
        },
    }, "R1"]]);
    $self->assert_num_equals(1, scalar @{$res->[0][1]->{messageIds}});
    $self->assert_str_equals($bar, $res->[0][1]->{messageIds}[0]);

    xlog "filter by before";
    my $dtbefore = $dtfoo->clone()->subtract(seconds => 1);
    $res = $jmap->Request([['getMessageList', {
        filter => {
            before => $dtbefore->strftime('%Y-%m-%dT%TZ'),
        },
    }, "R1"]]);
    $self->assert_num_equals(1, scalar @{$res->[0][1]->{messageIds}});
    $self->assert_str_equals($bar, $res->[0][1]->{messageIds}[0]);

    xlog "filter by after",
    my $dtafter = $dtbar->clone()->add(seconds => 1);
    $res = $jmap->Request([['getMessageList', {
        filter => {
            after => $dtafter->strftime('%Y-%m-%dT%TZ'),
        },
    }, "R1"]]);
    $self->assert_num_equals(1, scalar @{$res->[0][1]->{messageIds}});
    $self->assert_str_equals($foo, $res->[0][1]->{messageIds}[0]);

    xlog "filter by after and before",
    $res = $jmap->Request([['getMessageList', {
        filter => {
            after => $dtafter->strftime('%Y-%m-%dT%TZ'),
            before => $dtbefore->strftime('%Y-%m-%dT%TZ'),
        },
    }, "R1"]]);
    $self->assert_num_equals(0, scalar @{$res->[0][1]->{messageIds}});

    xlog "filter by minSize";
    $res = $jmap->Request([['getMessageList', {
        filter => {
            minSize => length($bodybar),
        },
    }, "R1"]]);
    $self->assert_num_equals(1, scalar @{$res->[0][1]->{messageIds}});
    $self->assert_str_equals($bar, $res->[0][1]->{messageIds}[0]);

    xlog "filter by maxSize";
    $res = $jmap->Request([['getMessageList', {
        filter => {
            maxSize => length($bodybar),
        },
    }, "R1"]]);
    $self->assert_num_equals(1, scalar @{$res->[0][1]->{messageIds}});
    $self->assert_str_equals($foo, $res->[0][1]->{messageIds}[0]);

    xlog "filter by header";
    $res = $jmap->Request([['getMessageList', {
        filter => {
            header => [ "X-Tra" ],
        },
    }, "R1"]]);
    $self->assert_num_equals(1, scalar @{$res->[0][1]->{messageIds}});
    $self->assert_str_equals($bar, $res->[0][1]->{messageIds}[0]);

    xlog "filter by header and value";
    $res = $jmap->Request([['getMessageList', {
        filter => {
            header => [ "X-Tra", "bam" ],
        },
    }, "R1"]]);
    $self->assert_num_equals(0, scalar @{$res->[0][1]->{messageIds}});

    xlog "sort by ascending date";
    $res = $jmap->Request([['getMessageList', {
        sort => [ "date asc" ],
    }, "R1"]]);
    $self->assert_num_equals(2, scalar @{$res->[0][1]->{messageIds}});
    $self->assert_str_equals($bar, $res->[0][1]->{messageIds}[0]);
    $self->assert_str_equals($foo, $res->[0][1]->{messageIds}[1]);

    xlog "sort by descending date";
    $res = $jmap->Request([['getMessageList', {
        sort => [ "date desc" ],
    }, "R1"]]);
    $self->assert_num_equals(2, scalar @{$res->[0][1]->{messageIds}});
    $self->assert_str_equals($foo, $res->[0][1]->{messageIds}[0]);
    $self->assert_str_equals($bar, $res->[0][1]->{messageIds}[1]);

    xlog "sort by ascending size";
    $res = $jmap->Request([['getMessageList', {
        sort => [ "size asc" ],
    }, "R1"]]);
    $self->assert_num_equals(2, scalar @{$res->[0][1]->{messageIds}});
    $self->assert_str_equals($foo, $res->[0][1]->{messageIds}[0]);
    $self->assert_str_equals($bar, $res->[0][1]->{messageIds}[1]);

    xlog "sort by descending size";
    $res = $jmap->Request([['getMessageList', {
        sort => [ "size desc" ],
    }, "R1"]]);
    $self->assert_num_equals(2, scalar @{$res->[0][1]->{messageIds}});
    $self->assert_str_equals($bar, $res->[0][1]->{messageIds}[0]);
    $self->assert_str_equals($foo, $res->[0][1]->{messageIds}[1]);

    xlog "sort by ascending id";
    $res = $jmap->Request([['getMessageList', {
        sort => [ "id asc" ],
    }, "R1"]]);
    my @ids = sort ($foo, $bar);
    $self->assert_deep_equals(\@ids, $res->[0][1]->{messageIds});

    xlog "sort by descending id";
    $res = $jmap->Request([['getMessageList', {
        sort => [ "id desc" ],
    }, "R1"]]);
    @ids = reverse sort ($foo, $bar);
    $self->assert_deep_equals(\@ids, $res->[0][1]->{messageIds});
}

sub test_getmessagelist_collapse
{
    my ($self) = @_;
    my %exp;
    my $jmap = $self->{jmap};
    my $res;

    my $imaptalk = $self->{store}->get_client();

    # check IMAP server has the XCONVERSATIONS capability
    $self->assert($self->{store}->get_client()->capability()->{xconversations});

    xlog "generating message A";
    $exp{A} = $self->make_message("Message A");
    $exp{A}->set_attributes(uid => 1, cid => $exp{A}->make_cid());

    xlog "generating message B";
    $exp{B} = $self->make_message("Message B");
    $exp{B}->set_attributes(uid => 2, cid => $exp{B}->make_cid());

    xlog "generating message C referencing A";
    $exp{C} = $self->make_message("Re: Message A", references => [ $exp{A} ]);
    $exp{C}->set_attributes(uid => 3, cid => $exp{A}->get_attribute('cid'));

    $imaptalk->select("INBOX");
    $imaptalk->fetch("1:*", "(CID UID FLAGS)");

    xlog "list uncollapsed threads";
    $res = $jmap->Request([['getMessageList', { }, "R1"]]);
    $self->assert_num_equals(3, scalar @{$res->[0][1]->{messageIds}});
    $self->assert_num_equals(3, scalar @{$res->[0][1]->{threadIds}});
    $self->assert_num_equals(2, scalar uniq @{$res->[0][1]->{threadIds}});

    $res = $jmap->Request([['getMessageList', { collapseThreads => JSON::true }, "R1"]]);
    $self->assert_num_equals(2, scalar @{$res->[0][1]->{messageIds}});
    $self->assert_num_equals(2, scalar @{$res->[0][1]->{threadIds}});
    $self->assert_num_equals(2, scalar uniq @{$res->[0][1]->{threadIds}});
}

1;
