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
use Mail::JMAPTalk 0.06;
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
    return $class->SUPER::new({}, @args);
}

sub set_up
{
    my ($self) = @_;
    $self->SUPER::set_up();

    xlog "Requesting JMAP access token";
    my $jmap = $self->{jmap};
    $jmap->Login($jmap->{user}, $jmap->{password}) || die;
}

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
    :JMAP :min_version_3_0
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
    $self->assert_num_equals($inbox->{sortOrder}, 1);
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
    $self->assert_num_equals($foo->{sortOrder}, 10);
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
    $self->assert_num_equals($bar->{sortOrder}, 10);
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
    :JMAP :min_version_3_0
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
    my $res = $jmap->Request([['getMailboxes', {}, "R1"]]);
    $self->assert_not_null($res);
    $self->assert_str_equals($res->[0][0], 'mailboxes');
    $self->assert_str_equals($res->[0][2], 'R1');

    my %m = map { $_->{name} => $_ } @{$res->[0][1]{list}};
    my $inbox = $m{"Inbox"};
    my $archive = $m{"Archive"};
    my $drafts = $m{"Drafts"};
    my $spam = $m{"Spam"};
    my $sent = $m{"Sent"};
    my $trash = $m{"Trash"};

    $self->assert_str_equals($archive->{name}, "Archive");
    $self->assert_str_equals($archive->{role}, "archive");

    $self->assert_str_equals($drafts->{name}, "Drafts");
    $self->assert_null($drafts->{parentId});
    $self->assert_str_equals($drafts->{role}, "drafts");

    $self->assert_str_equals($spam->{name}, "Spam");
    $self->assert_null($spam->{parentId});
    $self->assert_str_equals($spam->{role}, "spam");

    $self->assert_str_equals($sent->{name}, "Sent");
    $self->assert_null($sent->{parentId});
    $self->assert_str_equals($sent->{role}, "sent");

    $self->assert_str_equals($trash->{name}, "Trash");
    $self->assert_null($trash->{parentId});
    $self->assert_str_equals($trash->{role}, "trash");
}

sub test_getmailboxes_properties
    :JMAP :min_version_3_0
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
    :JMAP :min_version_3_0
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
    :JMAP :min_version_3_0
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
            ['setCalendars', { create => { "1" => {
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
    :JMAP :min_version_3_0
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
            ['setMailboxes', { create => { "1" => {
                            name => "foo",
                            parentId => $inbox->{id},
                            role => undef
             }}}, "R1"]
    ]);
    $self->assert_str_equals($res->[0][0], 'mailboxesSet');
    $self->assert_str_equals($res->[0][2], 'R1');
    $self->assert_str_not_equals($res->[0][1]{newState}, $state);
    $self->assert_not_null($res->[0][1]{created});
    my $id = $res->[0][1]{created}{"1"}{id};

    xlog "get mailbox $id";
    $res = $jmap->Request([['getMailboxes', { ids => [$id] }, "R1"]]);
    $self->assert_str_equals($res->[0][1]{list}[0]->{id}, $id);

    my $mbox = $res->[0][1]{list}[0];
    $self->assert_str_equals($mbox->{name}, "foo");
    $self->assert_null($mbox->{parentId});
    $self->assert_null($mbox->{role});
    $self->assert_num_equals($mbox->{sortOrder}, 10);
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
                            sortOrder => 20
             }}}, "R1"]
    ]);

    $self->assert_str_equals($res->[0][0], 'mailboxesSet');
    $self->assert_str_equals($res->[0][2], 'R1');
    $self->assert_str_not_equals($res->[0][1]{newState}, $state);
    $self->assert(exists $res->[0][1]{updated}{$id});

    xlog "get mailbox $id";
    $res = $jmap->Request([['getMailboxes', { ids => [$id] }, "R1"]]);
    $self->assert_str_equals($res->[0][1]{list}[0]->{id}, $id);
    $mbox = $res->[0][1]{list}[0];
    $self->assert_str_equals($mbox->{name}, "bar");
    $self->assert_num_equals($mbox->{sortOrder}, 20);

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
    :JMAP :min_version_3_0
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
                    { "1" => {
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
                        }}}, "R1"]
    ]);
    $self->assert_not_null($res->[0][1]{created});

    my $id1 = $res->[0][1]{created}{"1"}{id};
    my $id2 = $res->[0][1]{created}{"2"}{id};
    my $id3 = $res->[0][1]{created}{"3"}{id};

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
    :JMAP :min_version_3_0
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
    :JMAP :min_version_3_0
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
            ['setMailboxes', { create => { "1" => {
                            name => "foo",
                            parentId => $inbox->{id},
                            role => "inbox"
             }}}, "R1"]
    ]);
    $self->assert_str_equals($res->[0][0], 'mailboxesSet');
    $self->assert_str_equals($res->[0][2], 'R1');
    my $errType = $res->[0][1]{notCreated}{"1"}{type};
    my $errProp = $res->[0][1]{notCreated}{"1"}{properties};
    $self->assert_str_equals($errType, "invalidProperties");
    $self->assert_deep_equals($errProp, [ "role" ]);

    xlog "create mailbox with trash role";
    $res = $jmap->Request([
            ['setMailboxes', { create => { "1" => {
                            name => "foo",
                            parentId => undef,
                            role => "trash"
             }}}, "R1"]
    ]);
    $self->assert_str_equals($res->[0][0], 'mailboxesSet');
    $self->assert_str_equals($res->[0][2], 'R1');
    $self->assert_not_null($res->[0][1]{created});

    my $id = $res->[0][1]{created}{"1"}{id};

    xlog "get mailbox $id";
    $res = $jmap->Request([['getMailboxes', { ids => [$id] }, "R1"]]);

    $self->assert_str_equals($res->[0][1]{list}[0]->{role}, "trash");

    xlog "get mailbox $id via IMAP";
    my $data = $imaptalk->xlist("INBOX.foo", "%");
    my %annots = map { $_ => 1 } @{$data->[0]->[0]};
    $self->assert(exists $annots{"\\Trash"});

    xlog "try to create another mailbox with trash role";
    $res = $jmap->Request([
            ['setMailboxes', { create => { "1" => {
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
    $res = $jmap->Request([
            ['setMailboxes', { create => { "1" => {
                            name => "baz",
                            parentId => undef,
                            role => "x-bam"
             }}}, "R1"]
    ]);
    $self->assert_not_null($res->[0][1]{created});
    $id = $res->[0][1]{created}{"1"}{id};

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
            ['setMailboxes', { create => { "1" => {
                            name => "bar",
                            parentId => $inbox->{id},
                            role => "x-bam"
             }}}, "R1"]
    ]);
    $errType = $res->[0][1]{notCreated}{"1"}{type};
    $errProp = $res->[0][1]{notCreated}{"1"}{properties};
    $self->assert_str_equals($errType, "invalidProperties");
    $self->assert_deep_equals($errProp, [ "role" ]);

    xlog "try to create a mailbox with an unknown, non-x role";
    $res = $jmap->Request([
            ['setMailboxes', { create => { "1" => {
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
    $res = $jmap->Request([['getMailboxes', { }, "R1"]]);
    my %m = map { $_->{name} => $_ } @{$res->[0][1]{list}};
    my $sent = $m{"Sent"};
    my $multi = $m{"Multi"};
    $self->assert_str_equals($sent->{role}, "sent");
    $self->assert_str_equals($multi->{role}, "archive");
}

sub test_setmailboxes_parent
    :JMAP :min_version_3_0
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

sub test_getmailboxupdates
    :JMAP :min_version_3_0
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
    $res = $jmap->Request([['getMailboxes', {}, "R1"]]);
    $state = $res->[0][1]->{state};
    $self->assert_not_null($state);
    %m = map { $_->{name} => $_ } @{$res->[0][1]{list}};
    $inbox = $m{"Inbox"}->{id};
    $self->assert_not_null($inbox);

    xlog "get mailbox updates (expect error)";
    $res = $jmap->Request([['getMailboxUpdates', { sinceState => 0 }, "R1"]]);
    $self->assert_str_equals($res->[0][1]->{type}, "invalidArguments");
    $self->assert_str_equals($res->[0][1]->{arguments}[0], "sinceState");

    xlog "get mailbox updates (expect no changes)";
    $res = $jmap->Request([['getMailboxUpdates', { sinceState => $state }, "R1"]]);
    $self->assert_str_equals($state, $res->[0][1]->{oldState});
    $self->assert_str_equals($state, $res->[0][1]->{newState});
    $self->assert_equals(JSON::false, $res->[0][1]->{hasMoreUpdates});
    $self->assert_num_equals(0, scalar @{$res->[0][1]{changed}});
    $self->assert_num_equals(0, scalar @{$res->[0][1]{removed}});

    xlog "create mailbox via IMAP";
    $imaptalk->create("INBOX.foo")
        or die "Cannot create mailbox INBOX.foo: $@";

    xlog "get mailbox list";
    $res = $jmap->Request([['getMailboxes', {}, "R1"]]);
    %m = map { $_->{name} => $_ } @{$res->[0][1]{list}};
    $foo = $m{"foo"}->{id};
    $self->assert_not_null($foo);

    xlog "get mailbox updates";
    $res = $jmap->Request([['getMailboxUpdates', { sinceState => $state }, "R1"]]);
    $self->assert_str_equals($state, $res->[0][1]->{oldState});
    $self->assert_str_not_equals($state, $res->[0][1]->{newState});
    $self->assert_equals(JSON::false, $res->[0][1]->{hasMoreUpdates});
    $self->assert_num_equals(1, scalar @{$res->[0][1]{changed}});
    $self->assert_str_equals($foo, $res->[0][1]{changed}[0]);
    $self->assert_num_equals(0, scalar @{$res->[0][1]{removed}});
    $state = $res->[0][1]->{newState};

    xlog "create drafts mailbox";
    $res = $jmap->Request([
            ['setMailboxes', { create => { "1" => {
                            name => "drafts",
                            parentId => undef,
                            role => "drafts"
             }}}, "R1"]
    ]);
    $drafts = $res->[0][1]{created}{"1"}{id};
    $self->assert_not_null($drafts);

    xlog "get mailbox updates";
    $res = $jmap->Request([['getMailboxUpdates', { sinceState => $state }, "R1"]]);
    $self->assert_str_equals($state, $res->[0][1]->{oldState});
    $self->assert_str_not_equals($state, $res->[0][1]->{newState});
    $self->assert_equals(JSON::false, $res->[0][1]->{hasMoreUpdates});
    $self->assert_num_equals(1, scalar @{$res->[0][1]{changed}});
    $self->assert_str_equals($drafts, $res->[0][1]{changed}[0]);
    $self->assert_num_equals(0, scalar @{$res->[0][1]{removed}});
    $state = $res->[0][1]->{newState};

    xlog "rename mailbox foo to bar";
    $res = $jmap->Request([
            ['setMailboxes', { update => { $foo => {
                            name => "bar",
                            sortOrder => 20
             }}}, "R1"]
    ]);
    $self->assert_num_equals(1, scalar keys %{$res->[0][1]{updated}});

    xlog "get mailbox updates";
    $res = $jmap->Request([['getMailboxUpdates', { sinceState => $state }, "R1"]]);
    $self->assert_str_equals($state, $res->[0][1]->{oldState});
    $self->assert_str_not_equals($state, $res->[0][1]->{newState});
    $self->assert_equals(JSON::false, $res->[0][1]->{hasMoreUpdates});
    $self->assert_num_equals(1, scalar @{$res->[0][1]{changed}});
    $self->assert_str_equals($foo, $res->[0][1]{changed}[0]);
    $self->assert_num_equals(0, scalar @{$res->[0][1]{removed}});
    $state = $res->[0][1]->{newState};

    xlog "delete mailbox bar";
    $res = $jmap->Request([
            ['setMailboxes', {
                    destroy => [ $foo ],
             }, "R1"]
    ]);
    $self->assert_num_equals(1, scalar @{$res->[0][1]{destroyed}});

    xlog "rename mailbox drafts to stfard";
    $res = $jmap->Request([
            ['setMailboxes', {
                    update => { $drafts => { name => "stfard" } },
             }, "R1"]
    ]);
    $self->assert_num_equals(1, scalar keys %{$res->[0][1]{updated}});

    xlog "get mailbox updates, limit to 1";
    $res = $jmap->Request([['getMailboxUpdates', { sinceState => $state, maxChanges => 1 }, "R1"]]);
    $self->assert_str_equals($state, $res->[0][1]->{oldState});
    $self->assert_str_not_equals($state, $res->[0][1]->{newState});
    $self->assert_equals(JSON::true, $res->[0][1]->{hasMoreUpdates});
    $self->assert_num_equals(0, scalar @{$res->[0][1]{changed}});
    $self->assert_num_equals(1, scalar @{$res->[0][1]{removed}});
    $self->assert_str_equals($foo, $res->[0][1]{removed}[0]);
    $state = $res->[0][1]->{newState};

    xlog "get mailbox updates, limit to 1";
    $res = $jmap->Request([['getMailboxUpdates', { sinceState => $state, maxChanges => 1 }, "R1"]]);
    $self->assert_str_equals($state, $res->[0][1]->{oldState});
    $self->assert_str_not_equals($state, $res->[0][1]->{newState});
    $self->assert_equals(JSON::false, $res->[0][1]->{hasMoreUpdates});
    $self->assert_num_equals(1, scalar @{$res->[0][1]{changed}});
    $self->assert_str_equals($drafts, $res->[0][1]{changed}[0]);
    $self->assert_num_equals(0, scalar @{$res->[0][1]{removed}});
    $state = $res->[0][1]->{newState};

    xlog "get mailbox updates (expect no changes)";
    $res = $jmap->Request([['getMailboxUpdates', { sinceState => $state }, "R1"]]);
    $self->assert_str_equals($state, $res->[0][1]->{oldState});
    $self->assert_str_equals($state, $res->[0][1]->{newState});
    $self->assert_equals(JSON::false, $res->[0][1]->{hasMoreUpdates});
    $self->assert_num_equals(0, scalar @{$res->[0][1]{changed}});
    $self->assert_num_equals(0, scalar @{$res->[0][1]{removed}});
}

sub test_getmessages
    :JMAP :min_version_3_0
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
            ['x-tra', "foo bar\r\n baz"],
            ['sender', "Bla <blu\@local>"],
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
    my $ids = $res->[0][1]->{messageIds};
    $res = $jmap->Request([['getMessages', { ids => $ids }, "R1"]]);
    my $msg = $res->[0][1]->{list}[0];

    $self->assert_str_equals($msg->{mailboxIds}[0], $inboxid);
    $self->assert_num_equals(scalar @{$msg->{mailboxIds}}, 1);
    $self->assert_equals($msg->{isUnread}, JSON::true);
    $self->assert_equals($msg->{isFlagged}, JSON::false);
    $self->assert_equals($msg->{isAnswered}, JSON::false);
    $self->assert_equals($msg->{isDraft}, JSON::false);

    my $hdrs = $msg->{headers};
    $self->assert_str_equals($hdrs->{'message-id'}, '<fake.123456789@local>');
    $self->assert_str_equals($hdrs->{'x-tra'}, 'foo bar baz');
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

    xlog "fetch again but only some properties";
    $res = $jmap->Request([['getMessages', { ids => $ids, properties => ['sender', 'headers.x-tra', 'isUnread'] }, "R1"]]);
    $msg = $res->[0][1]->{list}[0];
    $hdrs = $msg->{headers};
    $self->assert_null($msg->{mailboxIds});
    $self->assert_equals($msg->{isUnread}, JSON::true);
    $self->assert_null($msg->{subject});
    $self->assert_deep_equals($msg->{sender}, {
            name => "Bla",
            email => "blu\@local"
    });
    $self->assert_null($hdrs->{'Message-ID'});
    $self->assert_str_equals($hdrs->{'x-tra'}, 'foo bar baz');
}

sub test_getmessages_mimeencode
    :JMAP :min_version_3_0
{
    my ($self) = @_;
    my $jmap = $self->{jmap};

    my $store = $self->{store};
    my $talk = $store->get_client();

    my $res = $jmap->Request([['getMailboxes', { }, "R1"]]);
    my $inboxid = $res->[0][1]{list}[0]{id};

    my $body = "a body";

    my $maildate = DateTime->now();
    $maildate->add(DateTime::Duration->new(seconds => -10));

     # Thanks to http://dogmamix.com/MimeHeadersDecoder/ for examples

    xlog "Generate a message in INBOX via IMAP";
    my %exp_inbox;
    my %params = (
        date => $maildate,
        from => Cassandane::Address->new(
            name => "=?ISO-8859-1?Q?Keld_J=F8rn_Simonsen?=",
            localpart => "keld",
            domain => "local"
        ),
        to => Cassandane::Address->new(
            name => "=?US-ASCII?Q?Tom To?=",
            localpart => 'tom',
            domain => 'local'
        ),
        messageid => 'fake.123456789@local',
        extra_headers => [
            ['x-tra', "foo bar\r\n baz"],
            ['sender', "Bla <blu\@local>"],
            ['x-mood', '=?UTF-8?Q?I feel =E2=98=BA?='],
        ],
        body => $body
    );

    $self->make_message(
          "=?ISO-8859-1?B?SWYgeW91IGNhbiByZWFkIHRoaXMgeW8=?= " .
          "=?ISO-8859-2?B?dSB1bmRlcnN0YW5kIHRoZSBleGFtcGxlLg==?=",
    %params ) || die;

    xlog "get message list";
    $res = $jmap->Request([['getMessageList', { fetchMessages => JSON::true }, "R1"]]);
    $self->assert_num_equals(scalar @{$res->[0][1]->{messageIds}}, 1);
    my $ids = $res->[1][1]->{messageIds};
    my $msg = $res->[1][1]->{list}[0];

    $self->assert_str_equals("If you can read this you understand the example.", $msg->{subject});
    $self->assert_str_equals("I feel \N{WHITE SMILING FACE}", $msg->{headers}{"x-mood"});
    $self->assert_str_equals("Keld J\N{LATIN SMALL LETTER O WITH STROKE}rn Simonsen", $msg->{from}[0]{name});
    $self->assert_str_equals("Tom To", $msg->{to}[0]{name});
}

sub test_getmessages_fetchmessages
    :JMAP :min_version_3_0
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
            ['x-tra', "foo bar\r\n baz"],
            ['sender', "Bla <blu\@local>"],
        ],
        body => $body
    );
    $self->make_message("Message A", %params) || die;

    xlog "get message list";
    $res = $jmap->Request([['getMessageList', { fetchMessages => $JSON::true }, "R1"]]);
    $self->assert_num_equals(scalar @{$res}, 2);
    $self->assert_str_equals($res->[0][0], "messageList");
    $self->assert_str_equals($res->[1][0], "messages");
    $self->assert_num_equals(scalar @{$res->[0][1]->{messageIds}}, 1);
    $self->assert_num_equals(scalar @{$res->[1][1]->{list}}, 1);

    my $msg = $res->[1][1]->{list}[0];

    $self->assert_str_equals($msg->{mailboxIds}[0], $inboxid);
    $self->assert_num_equals(scalar @{$msg->{mailboxIds}}, 1);
    $self->assert_equals($msg->{isUnread}, JSON::true);
    $self->assert_equals($msg->{isFlagged}, JSON::false);
    $self->assert_equals($msg->{isAnswered}, JSON::false);
    $self->assert_equals($msg->{isDraft}, JSON::false);

    my $hdrs = $msg->{headers};
    $self->assert_str_equals($hdrs->{'message-id'}, '<fake.123456789@local>');
    $self->assert_str_equals($hdrs->{'x-tra'}, 'foo bar baz');
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

    xlog "fetch again but only some properties";
    $res = $jmap->Request([['getMessageList', { fetchMessages => $JSON::true, fetchMessageProperties => ['sender', 'headers.x-tra', 'isUnread']  }, "R1"]]);
    $self->assert_num_equals(scalar @{$res}, 2);
    $self->assert_str_equals($res->[0][0], "messageList");
    $self->assert_str_equals($res->[1][0], "messages");
    $self->assert_num_equals(scalar @{$res->[0][1]->{messageIds}}, 1);
    $self->assert_num_equals(scalar @{$res->[1][1]->{list}}, 1);

    $msg = $res->[1][1]->{list}[0];
    $hdrs = $msg->{headers};
    $self->assert_null($msg->{mailboxIds});
    $self->assert_equals($msg->{isUnread}, JSON::true);
    $self->assert_null($msg->{subject});
    $self->assert_deep_equals($msg->{sender}, {
            name => "Bla",
            email => "blu\@local"
    });
    $self->assert_null($hdrs->{'Message-ID'});
    $self->assert_str_equals($hdrs->{'x-tra'}, 'foo bar baz');
}

sub test_getmessages_threads
    :JMAP :min_version_3_0
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
            ['x-tra', "foo bar\r\n baz"],
            ['sender', "Bla <blu\@local>"],
        ],
        body => $body
    );
    $self->make_message("Message A", %params) || die;

    xlog "get message list";
    $res = $jmap->Request([['getMessageList', { fetchThreads => $JSON::true, fetchMessages => $JSON::true }, "R1"]]);
    $self->assert_num_equals(scalar @{$res}, 3);
    $self->assert_str_equals($res->[0][0], "messageList");
    $self->assert_str_equals($res->[1][0], "threads");
    $self->assert_str_equals($res->[2][0], "messages");
    $self->assert_num_equals(scalar @{$res->[0][1]->{messageIds}}, 1);
    $self->assert_num_equals(scalar @{$res->[1][1]->{list}}, 1);
    $self->assert_num_equals(scalar @{$res->[2][1]->{list}}, 1);

    my $thread = $res->[1][1]->{list}[0];

    $self->assert_num_equals(scalar @{$thread->{messageIds}}, 1);

    my $msg = $res->[2][1]->{list}[0];

    $self->assert_str_equals($msg->{mailboxIds}[0], $inboxid);
    $self->assert_num_equals(scalar @{$msg->{mailboxIds}}, 1);
    $self->assert_equals($msg->{isUnread}, JSON::true);
    $self->assert_equals($msg->{isFlagged}, JSON::false);
    $self->assert_equals($msg->{isAnswered}, JSON::false);
    $self->assert_equals($msg->{isDraft}, JSON::false);

    my $hdrs = $msg->{headers};
    $self->assert_str_equals($hdrs->{'message-id'}, '<fake.123456789@local>');
    $self->assert_str_equals($hdrs->{'x-tra'}, 'foo bar baz');
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
    :JMAP :min_version_3_0
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
    :JMAP :min_version_3_0
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

    $self->assert_str_equals($htmlBody, $msg->{htmlBody});
    $self->assert(not exists $msg->{textBody});
}

sub test_getmessages_body_plain
    :JMAP :min_version_3_0
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
    $self->assert_null($msg->{htmlBody});

    xlog "get messages";
    $res = $jmap->Request([['getMessages', { ids => $ids, properties => ["body"] }, "R1"]]);
    $msg = $res->[0][1]{list}[0];

    $self->assert_str_equals($body, $msg->{textBody});
    $self->assert_null($msg->{htmlBody});
}

sub test_getmessages_body_html
    :JMAP :min_version_3_0
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
    $self->assert_str_equals($body, $msg->{htmlBody});
    $self->assert(not exists $msg->{textBody});
}

sub test_getmessages_body_multi
    :JMAP :min_version_3_0
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
                "beefc0de".
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
            "abc=".
            "\r\n--subsubsub\r\n".
            "Content-Type: application/x-excel\r\n".
            "Content-Transfer-Encoding: base64\r\n".
            "Content-Disposition: attachment; filename=\"f.xls\"\r\n".
            "\r\n" .
            "012312312313".
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
    $talk->store('1', '+flags', '($HasAttachment)');

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

    $self->assert_str_equals('<fake.1475639947.6507@local>', $submsg->{headers}->{'message-id'});
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
    $self->assert_num_equals(4, scalar @{$msg->{attachments}});
    my %m = map { $_->{type} => $_ } @{$msg->{attachments}};
    my $att;

    $att = $m{"image/jpeg"};
    $self->assert_num_equals(6, $att->{size});
    $self->assert_equals(JSON::false, $att->{isInline});
    $self->assert_null($att->{cid});

    $att = $m{"image/png"};
    $self->assert_num_equals(4, $att->{size});
    $self->assert_equals(JSON::false, $att->{isInline});
    $self->assert_null($att->{cid});

    $att = $m{"image/tiff"};
    $self->assert_num_equals(2, $att->{size});
    $self->assert_equals(JSON::false, $att->{isInline});
    $self->assert_null($att->{cid});

    $att = $m{"application/x-excel"};
    $self->assert_num_equals(9, $att->{size});
    $self->assert_equals(JSON::false, $att->{isInline});
    $self->assert_null($att->{cid});
}

sub test_getmessages_preview
    :JMAP :min_version_3_0
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
    :JMAP :min_version_3_0
{
    my ($self) = @_;
    my $jmap = $self->{jmap};

    xlog "create drafts mailbox";
    my $res = $jmap->Request([
            ['setMailboxes', { create => { "1" => {
                            name => "drafts",
                            parentId => undef,
                            role => "drafts"
             }}}, "R1"]
    ]);
    $self->assert_str_equals($res->[0][0], 'mailboxesSet');
    $self->assert_str_equals($res->[0][2], 'R1');
    $self->assert_not_null($res->[0][1]{created});
    my $draftsmbox = $res->[0][1]{created}{"1"}{id};

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
            "foo" => "bar\nbaz\nbam",
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
    $self->assert_str_equals($msg->{headers}->{foo}, $draft->{headers}->{foo});
    $self->assert_equals($msg->{isDraft}, JSON::true);
    $self->assert_equals($msg->{isFlagged}, JSON::false);
}

sub test_setmessages_inreplytoid
    :JMAP :min_version_3_0
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
            ['setMailboxes', { create => { "1" => {
                            name => "drafts",
                            parentId => undef,
                            role => "drafts"
             }}}, "R1"]
    ]);
    my $draftsmbox = $res->[0][1]{created}{"1"}{id};

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
    :JMAP :min_version_3_0
{
    my ($self) = @_;
    my $jmap = $self->{jmap};

    xlog "create drafts mailbox";
    my $res = $jmap->Request([
            ['setMailboxes', { create => { "1" => {
                            name => "drafts",
                            parentId => undef,
                            role => "drafts"
             }}}, "R1"]
    ]);
    $self->assert_str_equals($res->[0][0], 'mailboxesSet');
    $self->assert_str_equals($res->[0][2], 'R1');
    $self->assert_not_null($res->[0][1]{created});
    my $draftsmbox = $res->[0][1]{created}{"1"}{id};

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

sub test_uploadzero
    :JMAP :min_version_3_0
{
    my ($self) = @_;
    my $jmap = $self->{jmap};

    xlog "create drafts mailbox";
    my $res = $jmap->Request([
            ['setMailboxes', { create => { "1" => {
                            name => "drafts",
                            parentId => undef,
                            role => "drafts"
             }}}, "R1"]
    ]);
    $self->assert_str_equals($res->[0][0], 'mailboxesSet');
    $self->assert_str_equals($res->[0][2], 'R1');
    $self->assert_not_null($res->[0][1]{created});
    my $draftsmbox = $res->[0][1]{created}{"1"}{id};

    my $data = $jmap->Upload("", "text/plain");
    $self->assert_matches(qr/^Gda39a3ee5e6b4b0d3255bfef95601890/, $data->{blobId});
    $self->assert_num_equals(0, $data->{size});
    $self->assert_str_equals("text/plain", $data->{type});

    my $msgresp = $jmap->Request([
      ['setMessages', { create => { "2" => {
        mailboxIds => [$draftsmbox],
        from => [ { name => "Yosemite Sam", email => "sam\@acme.local" } ] ,
        to => [
            { name => "Bugs Bunny", email => "bugs\@acme.local" },
        ],
        subject => "Memo",
        textBody => "I'm givin' ya one last chance ta surrenda!",
        htmlBody => "<html>I'm givin' ya one last chance ta surrenda!</html>",
        attachments => [{
            blobId => $data->{blobId},
            name => "emptyfile.txt",
        }],
      } } }, 'R2'],
    ]);

    $self->assert_not_null($msgresp->[0][1]{created});
}

sub test_upload
    :JMAP :min_version_3_0
{
    my ($self) = @_;
    my $jmap = $self->{jmap};

    xlog "create drafts mailbox";
    my $res = $jmap->Request([
            ['setMailboxes', { create => { "1" => {
                            name => "drafts",
                            parentId => undef,
                            role => "drafts"
             }}}, "R1"]
    ]);
    $self->assert_str_equals($res->[0][0], 'mailboxesSet');
    $self->assert_str_equals($res->[0][2], 'R1');
    $self->assert_not_null($res->[0][1]{created});
    my $draftsmbox = $res->[0][1]{created}{"1"}{id};

    my $data = $jmap->Upload("a message with some text", "text/rubbish");
    $self->assert_matches(qr/^G44911b55c3b83ca05db9659d7a8e8b7b/, $data->{blobId});
    $self->assert_num_equals(24, $data->{size});
    $self->assert_str_equals("text/rubbish", $data->{type});

    my $msgresp = $jmap->Request([
      ['setMessages', { create => { "2" => {
        mailboxIds => [$draftsmbox],
        from => [ { name => "Yosemite Sam", email => "sam\@acme.local" } ] ,
        to => [
            { name => "Bugs Bunny", email => "bugs\@acme.local" },
        ],
        subject => "Memo",
        textBody => "I'm givin' ya one last chance ta surrenda!",
        htmlBody => "<html>I'm givin' ya one last chance ta surrenda!</html>",
        attachments => [{
            blobId => $data->{blobId},
            name => "test.txt",
        }],
      } } }, 'R2'],
    ]);

    $self->assert_not_null($msgresp->[0][1]{created});
}

sub test_uploadcharset
    :JMAP :min_version_3_0
{
    my ($self) = @_;
    my $jmap = $self->{jmap};

    xlog "create drafts mailbox";
    my $res = $jmap->Request([
            ['setMailboxes', { create => { "1" => {
                            name => "drafts",
                            parentId => undef,
                            role => "drafts"
             }}}, "R1"]
    ]);
    $self->assert_str_equals($res->[0][0], 'mailboxesSet');
    $self->assert_str_equals($res->[0][2], 'R1');
    $self->assert_not_null($res->[0][1]{created});
    my $draftsmbox = $res->[0][1]{created}{"1"}{id};

    my $data = $jmap->Upload("some test with utf8", "text/plain; charset=utf-8");

    my $resp = $jmap->Download('cassandane', $data->{blobId});

    $self->assert_str_equals('text/plain; charset=utf-8', $resp->{headers}{'content-type'});

    # XXX - fetch back the parts
}

sub test_uploadbin
    :JMAP :min_version_3_0
{
    my ($self) = @_;
    my $jmap = $self->{jmap};

    xlog "create drafts mailbox";
    my $res = $jmap->Request([
            ['setMailboxes', { create => { "1" => {
                            name => "drafts",
                            parentId => undef,
                            role => "drafts"
             }}}, "R1"]
    ]);
    $self->assert_str_equals($res->[0][0], 'mailboxesSet');
    $self->assert_str_equals($res->[0][2], 'R1');
    $self->assert_not_null($res->[0][1]{created});
    my $draftsmbox = $res->[0][1]{created}{"1"}{id};

    my $logofile = abs_path('data/logo.gif');
    open(FH, "<$logofile");
    local $/ = undef;
    my $binary = <FH>;
    close(FH);
    my $data = $jmap->Upload($binary, "image/gif");

    my $msgresp = $jmap->Request([
      ['setMessages', { create => { "2" => {
        mailboxIds => [$draftsmbox],
        from => [ { name => "Yosemite Sam", email => "sam\@acme.local" } ] ,
        to => [
            { name => "Bugs Bunny", email => "bugs\@acme.local" },
        ],
        subject => "Memo",
        textBody => "I'm givin' ya one last chance ta surrenda!",
        htmlBody => "<html>I'm givin' ya one last chance ta surrenda!</html>",
        attachments => [{
            blobId => $data->{blobId},
            name => "logo.gif",
        }],
      } } }, 'R2'],
    ]);

    $self->assert_not_null($msgresp->[0][1]{created});

    # XXX - fetch back the parts
}

sub test_download
    :JMAP :min_version_3_0
{
    my ($self) = @_;
    my $jmap = $self->{jmap};

    my $store = $self->{store};
    my $talk = $store->get_client();
    my $inbox = 'INBOX';

    # Generate a message to have some blob ids
    xlog "Generate a message in $inbox via IMAP";
    $self->make_message("foo",
        mime_type => "multipart/mixed",
        mime_boundary => "sub",
        body => ""
          . "--sub\r\n"
          . "Content-Type: text/plain; charset=UTF-8\r\n"
          . "Content-Disposition: inline\r\n" . "\r\n"
          . "some text"
          . "\r\n--sub\r\n"
          . "Content-Type: image/jpeg\r\n"
          . "Content-Transfer-Encoding: base64\r\n" . "\r\n"
          . "beefc0de"
          . "\r\n--sub\r\n"
          . "Content-Type: image/png\r\n"
          . "Content-Transfer-Encoding: base64\r\n"
          . "\r\n"
          . "f00bae=="
          . "\r\n--sub--",
    );

    xlog "get message list";
    my $res = $jmap->Request([['getMessageList', {}, "R1"]]);
    my $ids = $res->[0][1]->{messageIds};

    xlog "get message";
    $res = $jmap->Request([['getMessages', { ids => $ids }, "R1"]]);
    my $msg = $res->[0][1]{list}[0];

    my %m = map { $_->{type} => $_ } @{$res->[0][1]{list}[0]->{attachments}};
    my $blobid1 = $m{"image/jpeg"}->{blobId};
    my $blobid2 = $m{"image/png"}->{blobId};
    $self->assert_not_null($blobid1);
    $self->assert_not_null($blobid2);

    $res = $jmap->Download('cassandane', $blobid1);
    $self->assert_str_equals(encode_base64($res->{content}, ''), "beefc0de");
}

sub test_setmessages_attachments
    :JMAP :min_version_3_0
{
    my ($self) = @_;
    my $jmap = $self->{jmap};

    my $store = $self->{store};
    my $talk = $store->get_client();
    my $inbox = 'INBOX';

    # Generate a message to have some blob ids
    xlog "Generate a message in $inbox via IMAP";
    $self->make_message("foo",
        mime_type => "multipart/mixed",
        mime_boundary => "sub",
        body => ""
          . "--sub\r\n"
          . "Content-Type: text/plain; charset=UTF-8\r\n"
          . "Content-Disposition: inline\r\n" . "\r\n"
          . "some text"
          . "\r\n--sub\r\n"
          . "Content-Type: image/jpeg\r\n"
          . "Content-Transfer-Encoding: base64\r\n" . "\r\n"
          . "beefc0de"
          . "\r\n--sub\r\n"
          . "Content-Type: image/png\r\n"
          . "Content-Transfer-Encoding: base64\r\n"
          . "\r\n"
          . "f00bae=="
          . "\r\n--sub--",
    );

    xlog "get message list";
    my $res = $jmap->Request([['getMessageList', {}, "R1"]]);
    my $ids = $res->[0][1]->{messageIds};

    xlog "get message";
    $res = $jmap->Request([['getMessages', { ids => $ids }, "R1"]]);
    my $msg = $res->[0][1]{list}[0];

    my %m = map { $_->{type} => $_ } @{$res->[0][1]{list}[0]->{attachments}};
    my $blobid1 = $m{"image/jpeg"}->{blobId};
    my $blobid2 = $m{"image/png"}->{blobId};
    $self->assert_not_null($blobid1);
    $self->assert_not_null($blobid2);

    xlog "create drafts mailbox";
    $res = $jmap->Request([
            ['setMailboxes', { create => { "1" => {
                            name => "drafts",
                            parentId => undef,
                            role => "drafts"
             }}}, "R1"]
    ]);
    $self->assert_str_equals($res->[0][0], 'mailboxesSet');
    $self->assert_str_equals($res->[0][2], 'R1');
    $self->assert_not_null($res->[0][1]{created});
    my $draftsmbox = $res->[0][1]{created}{"1"}{id};

    my $draft =  {
        mailboxIds => [$draftsmbox],
        from => [ { name => "Yosemite Sam", email => "sam\@acme.local" } ] ,
        to => [ { name => "Bugs Bunny", email => "bugs\@acme.local" }, ],
        subject => "Memo",
        htmlBody => "<html>I'm givin' ya one last chance ta surrenda! ".
                    "<img src=\"cid:foo\@local\"></html>",
        attachments => [{
            blobId => $blobid1,
            name => "test.jpg",
        }, {
            blobId => $blobid2,
            cid => "<foo\@local>",
            isInline => JSON::true,
        }],
    };

    xlog "Create a draft";
    $res = $jmap->Request([['setMessages', { create => { "1" => $draft }}, "R1"]]);
    my $id = $res->[0][1]{created}{"1"}{id};

    xlog "Get draft $id";
    $res = $jmap->Request([['getMessages', { ids => [$id] }, "R1"]]);
    $msg = $res->[0][1]->{list}[0];

    %m = map { $_->{type} => $_ } @{$res->[0][1]{list}[0]->{attachments}};
    my $att1 = $m{"image/jpeg"};
    my $att2 = $m{"image/png"};
    $self->assert_not_null($att1);
    $self->assert_not_null($att2);

    $self->assert_str_equals($att1->{type}, "image/jpeg");
    $self->assert_str_equals($att1->{name}, "test.jpg");
    $self->assert_num_equals($att1->{size}, 6);
    $self->assert_null($att1->{cid});
    $self->assert_equals(JSON::false, $att1->{isInline});
    $self->assert_null($att1->{width});
    $self->assert_null($att1->{height});

    $self->assert_str_equals($att2->{type}, "image/png");
    $self->assert_num_equals($att2->{size}, 4);
    $self->assert_str_equals("<foo\@local>", $att2->{cid});
    # FIXME this test is too brittle to setup. We'd need to:
    # - add our custom annotation to both the annotations
    #   definition file and in cassandane.ini's cyrus config
    # - run an annotator daemon or set the annotation via IMAP
    #$self->assert_equals(JSON::true, $att2->{isInline});
    $self->assert_null($att2->{width});
    $self->assert_null($att2->{height});
}

sub test_setmessages_flagged
    :JMAP :min_version_3_0
{
    my ($self) = @_;
    my $jmap = $self->{jmap};

    xlog "create drafts mailbox";
    my $res = $jmap->Request([
            ['setMailboxes', { create => { "1" => {
                            name => "drafts",
                            parentId => undef,
                            role => "drafts"
             }}}, "R1"]
    ]);
    $self->assert_str_equals($res->[0][0], 'mailboxesSet');
    $self->assert_str_equals($res->[0][2], 'R1');
    $self->assert_not_null($res->[0][1]{created});
    my $drafts = $res->[0][1]{created}{"1"}{id};

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
    :JMAP :min_version_3_0
{
    my ($self) = @_;
    my $jmap = $self->{jmap};

    # XXX Why do we have to do this? Shouldn't Cyrus provision the Outbox?
    xlog "create outbox";
    my $res = $jmap->Request([
            ['setMailboxes', { create => { "1" => {
                            name => "drafts",
                            parentId => undef,
                            role => "outbox"
             }}}, "R1"]
    ]);
    $self->assert_str_equals($res->[0][0], 'mailboxesSet');
    $self->assert_str_equals($res->[0][2], 'R1');
    $self->assert_not_null($res->[0][1]{created});
    my $outbox = $res->[0][1]{created}{"1"}{id};

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
    :JMAP :min_version_3_0
{
    my ($self) = @_;
    my $jmap = $self->{jmap};

    my $inboxid = $self->getinbox()->{id};
    $self->assert_not_null($inboxid);

    my $res = $jmap->Request([
        ['setMailboxes', { create => {
            "1" => { name => "outbox", parentId => undef, role => "outbox" },
            "2" => { name => "drafts", parentId => undef, role => "drafts" },
        }}, "R1"]
    ]);
    my $outboxid = $res->[0][1]{created}{"1"}{id};
    my $draftsid = $res->[0][1]{created}{"2"}{id};
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
    :JMAP :min_version_3_0
{
    my ($self) = @_;
    my $jmap = $self->{jmap};

    my $store = $self->{store};
    my $talk = $store->get_client();
    my $inbox = 'INBOX';

    xlog "Create test mailboxes";
    my $res = $jmap->Request([
        ['setMailboxes', { create => {
            "a" => { name => "a", parentId => undef },
            "b" => { name => "b", parentId => undef },
            "c" => { name => "c", parentId => undef },
            "d" => { name => "d", parentId => undef },
        }}, "R1"]
    ]);
    $self->assert_num_equals( 4, scalar keys %{$res->[0][1]{created}} );
    my $a = $res->[0][1]{created}{"a"}{id};
    my $b = $res->[0][1]{created}{"b"}{id};
    my $c = $res->[0][1]{created}{"c"}{id};
    my $d = $res->[0][1]{created}{"d"}{id};

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
        $self->assert(exists $res->[0][1]{updated}{$id});

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
    :JMAP :min_version_3_0
{
    my ($self) = @_;
    my $jmap = $self->{jmap};

    xlog "create drafts mailbox";
    my $res = $jmap->Request([
            ['setMailboxes', { create => { "1" => {
                            name => "drafts",
                            parentId => undef,
                            role => "drafts"
             }}}, "R1"]
    ]);
    $self->assert_str_equals($res->[0][0], 'mailboxesSet');
    $self->assert_str_equals($res->[0][2], 'R1');
    $self->assert_not_null($res->[0][1]{created});
    my $drafts = $res->[0][1]{created}{"1"}{id};

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
    :JMAP :min_version_3_0
{
    my ($self) = @_;
    my $jmap = $self->{jmap};

    xlog "create mailboxes";
    my $res = $jmap->Request(
        [
            [
                'setMailboxes',
                {
                    create => {
                        "1" => {
                            name     => "drafts",
                            parentId => undef,
                            role     => "drafts"
                        },
                        "2" => {
                            name     => "foo",
                            parentId => undef,
                        },
                        "3" => {
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
        $res->[0][1]{created}{"1"}{id},
        $res->[0][1]{created}{"2"}{id},
        $res->[0][1]{created}{"3"}{id},
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

sub test_acl
    :JMAP :min_version_3_0
{
    my ($self) = @_;
    my $jmap = $self->{jmap};
    my $res;
    my $msgid;
    my $mboxid;

    my $admintalk = $self->{adminstore}->get_client();
    my $imaptalk = $self->{store}->get_client();

    my $entry = '/shared/vendor/cmu/cyrus-imapd/uniqueid';

    # Create another user and give cassandane to its mailboxes
    $self->{instance}->create_user("foo");
    $admintalk->create("user.foo.Drafts", "(USE (\\Drafts))") || die;
    $admintalk->setacl("user.foo", "cassandane", "lrswp");
    $admintalk->setacl("user.foo.Drafts", "cassandane", "lrswp");

    $self->{adminstore}->set_folder('user.foo.Drafts');
    $msgid = $self->make_message( "Message A", store => $self->{adminstore})->get_guid();
    $self->assert_not_null($msgid);
    $self->{adminstore}->_select();

    $res = $admintalk->getmetadata('user.foo.Drafts', $entry);
    $self->assert_str_equals('ok', $imaptalk->get_last_completion_response());
    $self->assert_not_null($res);
    $mboxid = $res->{'user.foo.Drafts'}{$entry};
    $self->assert_not_null(1);

    # For now, JMAP methods may not operate on other accounts.
    $res = $jmap->Request([['getMessages', { ids => [ $msgid ] }, "R1"]]);
    $self->assert_num_equals(0, scalar @{$res->[0][1]->{list}});
    $self->assert_num_equals(1, scalar @{$res->[0][1]->{notFound}});
    $self->assert_str_equals($msgid, $res->[0][1]->{notFound}[0]);

    $res = $jmap->Request([['getMessages', { accountId => "foo", ids => [ $msgid ] }, "R1"]]);
    $self->assert_num_equals(0, scalar @{$res->[0][1]->{list}});
    $self->assert_num_equals(1, scalar @{$res->[0][1]->{notFound}});
    $self->assert_str_equals($msgid, $res->[0][1]->{notFound}[0]);

    $res = $jmap->Request([['getMailboxes', { ids => [ $mboxid ] }, "R1"]]);
    $self->assert_num_equals(0, scalar @{$res->[0][1]->{list}});
    $self->assert_num_equals(1, scalar @{$res->[0][1]->{notFound}});
    $self->assert_str_equals($mboxid, $res->[0][1]->{notFound}[0]);

    $res = $jmap->Request([['getMailboxes', { accountId => "foo", ids => [ $mboxid ] }, "R1"]]);
    $self->assert_num_equals(0, scalar @{$res->[0][1]->{list}});
    $self->assert_num_equals(1, scalar @{$res->[0][1]->{notFound}});
    $self->assert_str_equals($mboxid, $res->[0][1]->{notFound}[0]);

    $res = $jmap->Request([['setMessages', { create => { "1" => {
        mailboxIds => [$mboxid],
        from => [ { name => "Yosemite Sam", email => "sam\@acme.local" } ] ,
        to => [
            { name => "Bugs Bunny", email => "bugs\@acme.local" },
        ],
        subject => "Memo",
        textBody => "I'm givin' ya one last chance ta surrenda!",
        inReplyToMessageId => $msgid,
    } }}, "R1"]]);
    $self->assert_str_equals("invalidProperties", $res->[0][1]->{notCreated}{"1"}{type});
    $self->assert_str_equals("mailboxIds[0]", $res->[0][1]->{notCreated}{"1"}{properties}[0]);

    $res = $jmap->Request([['setMessages', { accountId => "foo", create => { "1" => {
        mailboxIds => [$mboxid],
        from => [ { name => "Yosemite Sam", email => "sam\@acme.local" } ] ,
        to => [
            { name => "Bugs Bunny", email => "bugs\@acme.local" },
        ],
        subject => "Memo",
        textBody => "I'm givin' ya one last chance ta surrenda!",
        inReplyToMessageId => $msgid,
    } }}, "R1"]]);
    $self->assert_str_equals("invalidProperties", $res->[0][1]->{notCreated}{"1"}{type});
    $self->assert_str_equals("mailboxIds[0]", $res->[0][1]->{notCreated}{"1"}{properties}[0]);

    $res = $jmap->Request([[ 'setMailboxes', { update => {
            $mboxid => { sortOrder => 20 }
    }}, "R1" ]]);
    $self->assert_str_equals("notFound", $res->[0][1]->{notUpdated}{$mboxid}{type});

    $res = $jmap->Request([[ 'setMailboxes', { accountId => "foo", update => {
            $mboxid => { sortOrder => 20 }
    }}, "R1" ]]);
    $self->assert_str_equals("notFound", $res->[0][1]->{notUpdated}{$mboxid}{type});
}

sub test_getmessagelist
    :JMAP :min_version_3_0
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
            ['x-tra', "baz"],
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
            inMailbox => $mboxa,
        },
    }, "R1"]]);
    $self->assert_num_equals(1, scalar @{$res->[0][1]->{messageIds}});
    $self->assert_str_equals($foo, $res->[0][1]->{messageIds}[0]);

    xlog "filter mailboxes";
    $res = $jmap->Request([['getMessageList', {
        filter => {
            operator => 'OR',
            conditions => [
                {
                    inMailbox => $mboxa,
                },
                {
                    inMailbox => $mboxc,
                },
            ],
        },
    }, "R1"]]);
    $self->assert_num_equals(1, scalar @{$res->[0][1]->{messageIds}});
    $self->assert_str_equals($foo, $res->[0][1]->{messageIds}[0]);

    xlog "filter mailboxes with not in";
    $res = $jmap->Request([['getMessageList', {
        filter => {
            inMailboxOtherThan => $mboxb,
        },
    }, "R1"]]);
    $self->assert_num_equals(1, scalar @{$res->[0][1]->{messageIds}});
    $self->assert_str_equals($foo, $res->[0][1]->{messageIds}[0]);

    xlog "filter mailboxes";
    $res = $jmap->Request([['getMessageList', {
        filter => {
            operator => 'AND',
            conditions => [
                {
                    inMailbox => $mboxa,
                },
                {
                    inMailbox => $mboxb,
                },
                {
                    inMailbox => $mboxc,
                },
            ],
        },
    }, "R1"]]);
    $self->assert_num_equals(0, scalar @{$res->[0][1]->{messageIds}});

    xlog "filter not in mailbox A";
    $res = $jmap->Request([['getMessageList', {
        filter => {
            operator => 'NOT',
            conditions => [
                {
                    inMailbox => $mboxa,
                },
            ],
        },
    }, "R1"]]);
    $self->assert_num_equals(2, scalar @{$res->[0][1]->{messageIds}});

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
            header => [ "x-tra" ],
        },
    }, "R1"]]);
    $self->assert_num_equals(1, scalar @{$res->[0][1]->{messageIds}});
    $self->assert_str_equals($bar, $res->[0][1]->{messageIds}[0]);

    xlog "filter by header and value";
    $res = $jmap->Request([['getMessageList', {
        filter => {
            header => [ "x-tra", "bam" ],
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
    :JMAP :min_version_3_0
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

sub test_getmessagelist_window
    :JMAP :min_version_3_0
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

    xlog "generating message D";
    $exp{D} = $self->make_message("Message D");
    $exp{D}->set_attributes(uid => 2, cid => $exp{B}->make_cid());

    xlog "list all messages";
    $res = $jmap->Request([['getMessageList', { }, "R1"]]);
    $self->assert_num_equals(4, scalar @{$res->[0][1]->{messageIds}});
    $self->assert_num_equals(4, $res->[0][1]->{total});

    my $ids = $res->[0][1]->{messageIds};
    my @subids;

    xlog "list messages from position 1";
    $res = $jmap->Request([['getMessageList', { position => 1 }, "R1"]]);
    @subids = @{$ids}[1..3];
    $self->assert_deep_equals(\@subids, $res->[0][1]->{messageIds});
    $self->assert_num_equals(4, $res->[0][1]->{total});

    xlog "list messages from position 4";
    $res = $jmap->Request([['getMessageList', { position => 4 }, "R1"]]);
    $self->assert_num_equals(0, scalar @{$res->[0][1]->{messageIds}});
    $self->assert_num_equals(4, $res->[0][1]->{total});

    xlog "limit messages from position 1 to one message";
    $res = $jmap->Request([['getMessageList', { position => 1, limit => 1 }, "R1"]]);
    @subids = @{$ids}[1..1];
    $self->assert_deep_equals(\@subids, $res->[0][1]->{messageIds});
    $self->assert_num_equals(4, $res->[0][1]->{total});

    xlog "anchor at 2nd message";
    $res = $jmap->Request([['getMessageList', { anchor => @{$ids}[1] }, "R1"]]);
    @subids = @{$ids}[1..3];
    $self->assert_deep_equals(\@subids, $res->[0][1]->{messageIds});
    $self->assert_num_equals(4, $res->[0][1]->{total});

    xlog "anchor at 2nd message and offset -1";
    $res = $jmap->Request([['getMessageList', {
        anchor => @{$ids}[1], anchorOffset => -1,
    }, "R1"]]);
    @subids = @{$ids}[2..3];
    $self->assert_deep_equals(\@subids, $res->[0][1]->{messageIds});
    $self->assert_num_equals(4, $res->[0][1]->{total});

    xlog "anchor at 3rd message and offset 1";
    $res = $jmap->Request([['getMessageList', {
        anchor => @{$ids}[2], anchorOffset => 1,
    }, "R1"]]);
    @subids = @{$ids}[1..3];
    $self->assert_deep_equals(\@subids, $res->[0][1]->{messageIds});
    $self->assert_num_equals(4, $res->[0][1]->{total});

    xlog "anchor at 1st message offset -1 and limit 2";
    $res = $jmap->Request([['getMessageList', {
        anchor => @{$ids}[0], anchorOffset => -1, limit => 2
    }, "R1"]]);
    @subids = @{$ids}[1..2];
    $self->assert_deep_equals(\@subids, $res->[0][1]->{messageIds});
    $self->assert_num_equals(4, $res->[0][1]->{total});
}

sub test_getsearchsnippets
    :JMAP :min_version_3_0
{
    my ($self) = @_;
    my $jmap = $self->{jmap};

    my $store = $self->{store};
    my $talk = $store->get_client();

    my $res = $jmap->Request([['getMailboxes', { }, "R1"]]);
    my $inboxid = $res->[0][1]{list}[0]{id};

    xlog "create messages";
    my %params = (
        body => "A simple message",
    );
    $res = $self->make_message("Message foo", %params) || die;

    %params = (
        body => ""
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
        . "outside of the scope of this specification.\r\n"
        . "\r\n"
        . "This paragraph is not part of the specification, it has been added to\r\n"
        . "contain the most mentions of the word message. Messages are processed\r\n"
        . "by messaging systems, which is the message of this paragraph.\r\n"
        . "Don't interpret too much into this message.\r\n",
    );
    $self->make_message("Message bar", %params) || die;
    %params = (
        body => "This body doesn't contain any of the search terms.\r\n",
    );
    $self->make_message("A subject without any matching search term", %params) || die;

    $self->make_message("Message baz", %params) || die;
    %params = (
        body => "This body doesn't contain any of the search terms.\r\n",
    );
    $self->make_message("A subject with message", %params) || die;

    xlog "run squatter";
    $self->{instance}->run_command({cyrus => 1}, 'squatter');

    xlog "fetch message ids";
    $res = $jmap->Request([['getMessageList', { fetchMessages => JSON::true }, "R1"]]);

    my %m = map { $_->{subject} => $_ } @{$res->[1][1]{list}};
    my $foo = $m{"Message foo"}->{id};
    my $bar = $m{"Message bar"}->{id};
    my $baz = $m{"Message baz"}->{id};
    $self->assert_not_null($foo);
    $self->assert_not_null($bar);
    $self->assert_not_null($baz);

    xlog "fetch snippets";
    $res = $jmap->Request([['getSearchSnippets', {
            messageIds => [ $foo, $bar ],
            filter => { text => "message" },
    }, "R1"]]);
    $self->assert_num_equals(2, scalar @{$res->[0][1]->{list}});
    $self->assert_null($res->[0][1]->{notFound});
    %m = map { $_->{messageId} => $_ } @{$res->[0][1]{list}};
    $self->assert_not_null($m{$foo});
    $self->assert_not_null($m{$bar});

    %m = map { $_->{messageId} => $_ } @{$res->[0][1]{list}};
    $self->assert_num_not_equals(-1, index($m{$foo}->{subject}, "<mark>Message</mark> foo"));
    $self->assert_num_not_equals(-1, index($m{$foo}->{preview}, "A simple <mark>message</mark>"));
    $self->assert_num_not_equals(-1, index($m{$bar}->{subject}, "<mark>Message</mark> bar"));
    $self->assert_num_not_equals(-1, index($m{$bar}->{preview}, ""
        . "<mark>Messages</mark> are processed by <mark>messaging</mark> systems,"
    ));

    xlog "fetch snippets with one unknown id";
    $res = $jmap->Request([['getSearchSnippets', {
            messageIds => [ $foo, "bam" ],
            filter => { text => "message" },
    }, "R1"]]);
    $self->assert_num_equals(1, scalar @{$res->[0][1]->{list}});
    $self->assert_num_equals(1, scalar @{$res->[0][1]->{notFound}});

    xlog "fetch snippets with only a matching subject";
    $res = $jmap->Request([['getSearchSnippets', {
            messageIds => [ $baz ],
            filter => { text => "message" },
    }, "R1"]]);
    $self->assert_not_null($res->[0][1]->{list}[0]->{subject});
    $self->assert(exists $res->[0][1]->{list}[0]->{preview});
    $self->assert_null($res->[0][1]->{list}[0]->{preview});
}

sub test_getmessagelist_snippets
    :JMAP :min_version_3_0
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

    xlog "run squatter";
    $self->{instance}->run_command({cyrus => 1}, 'squatter');

    xlog "fetch message and snippet";
    $res = $jmap->Request([['getMessageList', {
        filter => { text => "message" },
        fetchSearchSnippets => JSON::true,
    }, "R1"]]);

    my $snippet = $res->[1][1]{list}[0];
    $self->assert_not_null($snippet);
    $self->assert_num_not_equals(-1, index($snippet->{subject}, "<mark>Message</mark> A"));

    xlog "fetch message and snippet with no filter";
    $res = $jmap->Request([['getMessageList', {
        fetchSearchSnippets => JSON::true,
    }, "R1"]]);

    $snippet = $res->[1][1]{list}[0];
    $self->assert_not_null($snippet);
    $self->assert_null($snippet->{subject});
    $self->assert_null($snippet->{preview});

    xlog "fetch message and snippet with no text filter";
    $res = $jmap->Request([['getMessageList', {
        filter => {
            operator => "OR",
            conditions => [{isUnread => JSON::true}, {isUnread => JSON::false}]
        },
        fetchSearchSnippets => JSON::true,
    }, "R1"]]);

    $snippet = $res->[1][1]{list}[0];
    $self->assert_not_null($snippet);
    $self->assert_null($snippet->{subject});
    $self->assert_null($snippet->{preview});
}

sub test_getthreads
    :JMAP :min_version_3_0
{
    my ($self) = @_;
    my %exp;
    my $jmap = $self->{jmap};
    my $res;
    my %params;
    my $dt;

    my $imaptalk = $self->{store}->get_client();

    xlog "create drafts mailbox";
    $res = $jmap->Request([
            ['setMailboxes', { create => { "1" => {
                            name => "drafts",
                            parentId => undef,
                            role => "drafts"
             }}}, "R1"]
    ]);
    my $drafts = $res->[0][1]{created}{"1"}{id};
    $self->assert_not_null($drafts);

    xlog "generating message A";
    $dt = DateTime->now();
    $dt->add(DateTime::Duration->new(hours => -3));
    $exp{A} = $self->make_message("Message A", date => $dt, body => "a");
    $exp{A}->set_attributes(uid => 1, cid => $exp{A}->make_cid());

    xlog "generating message B";
    $exp{B} = $self->make_message("Message B", body => "b");
    $exp{B}->set_attributes(uid => 2, cid => $exp{B}->make_cid());

    xlog "generating message C referencing A";
    $dt = DateTime->now();
    $dt->add(DateTime::Duration->new(hours => -2));
    $exp{C} = $self->make_message("Re: Message A", references => [ $exp{A} ], date => $dt, body => "c");
    $exp{C}->set_attributes(uid => 3, cid => $exp{A}->get_attribute('cid'));

    xlog "generating message D referencing A";
    $dt = DateTime->now();
    $dt->add(DateTime::Duration->new(hours => -1));
    $exp{D} = $self->make_message("Re: Message A", references => [ $exp{A} ], date => $dt, body => "d");
    $exp{D}->set_attributes(uid => 4, cid => $exp{A}->get_attribute('cid'));

    xlog "fetch messages"; $res = $jmap->Request([['getMessageList', { fetchMessages => JSON::true }, "R1"]]);

    my %m = map { $_->{textBody} => $_ } @{$res->[1][1]{list}};
    my $msgA = $m{"a"};
    my $msgB = $m{"b"};
    my $msgC = $m{"c"};
    my $msgD = $m{"d"};
    $self->assert_not_null($msgA);
    $self->assert_not_null($msgB);
    $self->assert_not_null($msgC);
    $self->assert_not_null($msgD);

    %m = map { $_->{threadId} => 1 } @{$res->[1][1]{list}};
    my @threadids = keys %m;

    xlog "create draft replying to message A";
    $res = $jmap->Request(
        [[ 'setMessages', { create => { "1" => {
            mailboxIds           => [$drafts],
            inReplyToMessageId   => $msgA->{id},
            from                 => [ { name => "", email => "sam\@acme.local" } ],
            to                   => [ { name => "", email => "bugs\@acme.local" } ],
            subject              => "Re: Message A",
            textBody             => "I'm givin' ya one last chance ta surrenda!",
        }}}, "R1" ]]);
    my $draftid = $res->[0][1]{created}{"1"}{id};
    $self->assert_not_null($draftid);

    xlog "get threads";
    $res = $jmap->Request([['getThreads', { ids => \@threadids }, "R1"]]);
    $self->assert_num_equals(2, scalar @{$res->[0][1]->{list}});
    $self->assert_null($res->[0][1]->{notFound});

    %m = map { $_->{id} => $_ } @{$res->[0][1]{list}};
    my $threadA = $m{$msgA->{threadId}};
    my $threadB = $m{$msgB->{threadId}};

    # Assert all messages are listed
    $self->assert_num_equals(4, scalar @{$threadA->{messageIds}});
    $self->assert_num_equals(1, scalar @{$threadB->{messageIds}});

    # Assert sort order by date
    $self->assert_str_equals($msgA->{id}, $threadA->{messageIds}[0]);
    $self->assert_str_equals($draftid, $threadA->{messageIds}[1]);
    $self->assert_str_equals($msgC->{id}, $threadA->{messageIds}[2]);
    $self->assert_str_equals($msgD->{id}, $threadA->{messageIds}[3]);
}

sub test_getidentities
    :JMAP :min_version_3_0
{
    my ($self) = @_;
    my $jmap = $self->{jmap};
    my $id;
    my $res;

    xlog "get identities";
    $res = $jmap->Request([['getIdentities', { }, "R1"]]);

    $self->assert_num_equals(1, scalar @{$res->[0][1]->{list}});
    $self->assert_num_equals(0, scalar @{$res->[0][1]->{notFound}});

    $id = $res->[0][1]->{list}[0];
    $self->assert_not_null($id->{id});
    $self->assert_not_null($id->{email});

    xlog "get unknown identities";
    $res = $jmap->Request([['getIdentities', { ids => ["foo"] }, "R1"]]);
    $self->assert_num_equals(0, scalar @{$res->[0][1]->{list}});
    $self->assert_num_equals(1, scalar @{$res->[0][1]->{notFound}});
}

sub test_emptyids
    :JMAP :min_version_3_0
{
    my ($self) = @_;

    my $jmap = $self->{jmap};
    my $imaptalk = $self->{store}->get_client();
    my $res;

    $imaptalk->create("INBOX.foo") || die;

    $res = $jmap->Request([['getMailboxes', { ids => [] }, "R1"]]);
    $self->assert_num_equals(0, scalar @{$res->[0][1]{list}});

    $res = $jmap->Request([['getThreads', { ids => [] }, "R1"]]);
    $self->assert_num_equals(0, scalar @{$res->[0][1]{list}});

    $res = $jmap->Request([['getMessages', { ids => [] }, "R1"]]);
    $self->assert_num_equals(0, scalar @{$res->[0][1]{list}});

    $res = $jmap->Request([['getIdentities', { ids => [] }, "R1"]]);
    $self->assert_num_equals(0, scalar @{$res->[0][1]{list}});

    $res = $jmap->Request([['getSearchSnippets', { messageIds => [], filter => { text => "foo" } }, "R1"]]);
    $self->assert_num_equals(0, scalar @{$res->[0][1]{list}});
}

sub test_getmessageupdates
    :JMAP :min_version_3_0
{
    my ($self) = @_;
    my $jmap = $self->{jmap};
    my $res;
    my $state;

    my $store = $self->{store};
    my $talk = $store->get_client();
    my $draftsmbox;

    # FIXME mailbox changes also bump the state of messages
    xlog "create drafts mailbox";
    $res = $jmap->Request([
            ['setMailboxes', { create => { "1" => {
                            name => "drafts",
                            parentId => undef,
                            role => "drafts"
             }}}, "R1"]
    ]);
    $draftsmbox = $res->[0][1]{created}{"1"}{id};

    xlog "get message updates (expect error)";
    $res = $jmap->Request([['getMessageUpdates', { sinceState => 0 }, "R1"]]);
    $self->assert_str_equals($res->[0][1]->{type}, "invalidArguments");
    $self->assert_str_equals($res->[0][1]->{arguments}[0], "sinceState");

    xlog "get message list";
    $res = $jmap->Request([['getMessageList', {}, "R1"]]);
    $state = $res->[0][1]->{state};
    $self->assert_not_null($state);


    xlog "get message updates";
    $res = $jmap->Request([['getMessageUpdates', { sinceState => $state }, "R1"]]);
    $self->assert_str_equals($state, $res->[0][1]->{oldState});
    $self->assert_str_equals($state, $res->[0][1]->{newState});
    $self->assert_equals(JSON::false, $res->[0][1]->{hasMoreUpdates});
    $self->assert_num_equals(0, scalar @{$res->[0][1]{changed}});
    $self->assert_num_equals(0, scalar @{$res->[0][1]{removed}});

    xlog "Generate a message in INBOX via IMAP";
    $self->make_message("Message A") || die;

    xlog "Get message id";
    $res = $jmap->Request([['getMessageList', {}, "R1"]]);
    my $ida = $res->[0][1]->{messageIds}[0];
    $self->assert_not_null($ida);

    xlog "get message updates";
    $res = $jmap->Request([['getMessageUpdates', { sinceState => $state }, "R1"]]);
    $self->assert_str_equals($state, $res->[0][1]->{oldState});
    $self->assert_str_not_equals($state, $res->[0][1]->{newState});
    $self->assert_equals(JSON::false, $res->[0][1]->{hasMoreUpdates});
    $self->assert_num_equals(1, scalar @{$res->[0][1]{changed}});
    $self->assert_str_equals($ida, $res->[0][1]{changed}[0]);
    $self->assert_num_equals(0, scalar @{$res->[0][1]{removed}});
    $state = $res->[0][1]->{newState};

    xlog "get message updates (expect no changes)";
    $res = $jmap->Request([['getMessageUpdates', { sinceState => $state }, "R1"]]);
    $self->assert_str_equals($state, $res->[0][1]->{oldState});
    $self->assert_str_equals($state, $res->[0][1]->{newState});
    $self->assert_equals(JSON::false, $res->[0][1]->{hasMoreUpdates});
    $self->assert_num_equals(0, scalar @{$res->[0][1]{changed}});
    $self->assert_num_equals(0, scalar @{$res->[0][1]{removed}});

    xlog "update message $ida";
    $res = $jmap->Request([['setMessages', {
        update => { $ida => { isUnread => JSON::false }}
    }, "R1"]]);
    $self->assert(exists $res->[0][1]->{updated}{$ida});

    xlog "get message updates";
    $res = $jmap->Request([['getMessageUpdates', { sinceState => $state }, "R1"]]);
    $self->assert_str_equals($state, $res->[0][1]->{oldState});
    $self->assert_str_not_equals($state, $res->[0][1]->{newState});
    $self->assert_equals(JSON::false, $res->[0][1]->{hasMoreUpdates});
    $self->assert_num_equals(1, scalar @{$res->[0][1]{changed}});
    $self->assert_str_equals($ida, $res->[0][1]{changed}[0]);
    $self->assert_num_equals(0, scalar @{$res->[0][1]{removed}});
    $state = $res->[0][1]->{newState};

    xlog "delete message $ida";
    $res = $jmap->Request([['setMessages', {destroy => [ $ida ] }, "R1"]]);
    $self->assert_str_equals($ida, $res->[0][1]->{destroyed}[0]);

    xlog "get message updates";
    $res = $jmap->Request([['getMessageUpdates', { sinceState => $state }, "R1"]]);
    $self->assert_str_equals($state, $res->[0][1]->{oldState});
    $self->assert_str_not_equals($state, $res->[0][1]->{newState});
    $self->assert_equals(JSON::false, $res->[0][1]->{hasMoreUpdates});
    $self->assert_num_equals(0, scalar @{$res->[0][1]{changed}});
    $self->assert_num_equals(1, scalar @{$res->[0][1]{removed}});
    $self->assert_str_equals($ida, $res->[0][1]{removed}[0]);
    $state = $res->[0][1]->{newState};

    xlog "get message updates (expect no changes)";
    $res = $jmap->Request([['getMessageUpdates', { sinceState => $state }, "R1"]]);
    $self->assert_str_equals($state, $res->[0][1]->{oldState});
    $self->assert_str_equals($state, $res->[0][1]->{newState});
    $self->assert_equals(JSON::false, $res->[0][1]->{hasMoreUpdates});
    $self->assert_num_equals(0, scalar @{$res->[0][1]{changed}});
    $self->assert_num_equals(0, scalar @{$res->[0][1]{removed}});

    xlog "create message B";
    $res = $jmap->Request(
        [[ 'setMessages', { create => { "1" => {
            mailboxIds           => [$draftsmbox],
            from                 => [ { name => "", email => "sam\@acme.local" } ],
            to                   => [ { name => "", email => "bugs\@acme.local" } ],
            subject              => "Message B",
            textBody             => "I'm givin' ya one last chance ta surrenda!",
        }}}, "R1" ]]);
    my $idb = $res->[0][1]{created}{"1"}{id};
    $self->assert_not_null($idb);

    xlog "create message C";
    $res = $jmap->Request(
        [[ 'setMessages', { create => { "1" => {
            mailboxIds           => [$draftsmbox],
            from                 => [ { name => "", email => "sam\@acme.local" } ],
            to                   => [ { name => "", email => "bugs\@acme.local" } ],
            subject              => "Message C",
            textBody             => "I *hate* that rabbit!",
        }}}, "R1" ]]);
    my $idc = $res->[0][1]{created}{"1"}{id};
    $self->assert_not_null($idc);

    xlog "get max 1 message updates";
    $res = $jmap->Request([['getMessageUpdates', { sinceState => $state, maxChanges => 1 }, "R1"]]);
    $self->assert_str_equals($state, $res->[0][1]->{oldState});
    $self->assert_str_not_equals($state, $res->[0][1]->{newState});
    $self->assert_equals(JSON::true, $res->[0][1]->{hasMoreUpdates});
    $self->assert_num_equals(1, scalar @{$res->[0][1]{changed}});
    $self->assert_str_equals($idb, $res->[0][1]{changed}[0]);
    $self->assert_num_equals(0, scalar @{$res->[0][1]{removed}});
    $state = $res->[0][1]->{newState};

    xlog "get max 1 message updates";
    $res = $jmap->Request([['getMessageUpdates', { sinceState => $state, maxChanges => 1 }, "R1"]]);
    $self->assert_str_equals($state, $res->[0][1]->{oldState});
    $self->assert_str_not_equals($state, $res->[0][1]->{newState});
    $self->assert_equals(JSON::false, $res->[0][1]->{hasMoreUpdates});
    $self->assert_num_equals(1, scalar @{$res->[0][1]{changed}});
    $self->assert_str_equals($idc, $res->[0][1]{changed}[0]);
    $self->assert_num_equals(0, scalar @{$res->[0][1]{removed}});
    $state = $res->[0][1]->{newState};

    xlog "get message updates (expect no changes)";
    $res = $jmap->Request([['getMessageUpdates', { sinceState => $state }, "R1"]]);
    $self->assert_str_equals($state, $res->[0][1]->{oldState});
    $self->assert_str_equals($state, $res->[0][1]->{newState});
    $self->assert_equals(JSON::false, $res->[0][1]->{hasMoreUpdates});
    $self->assert_num_equals(0, scalar @{$res->[0][1]{changed}});
    $self->assert_num_equals(0, scalar @{$res->[0][1]{removed}});
}

sub test_uploaddownload822
    :JMAP :min_version_3_0
{
    my ($self) = @_;
    my $jmap = $self->{jmap};

    my $message = <<'EOF';
From: "Some Example Sender" <example@example.com>
To: baseball@vitaead.com
Subject: test message
Date: Wed, 7 Dec 2016 00:21:50 -0500
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Content-Transfer-Encoding: quoted-printable

This is a test message.
EOF
    $message =~ s/\r?\n/\r\n/gs;
    my $data = $jmap->Upload($message, "message/rfc822");
    my $blobid = $data->{blobId};

    my $download = $jmap->Download('cassandane', $blobid);

    $self->assert_str_equals($download->{content}, $message);
}

sub test_uploadsametype
    :JMAP :min_version_3_0
{
    my ($self) = @_;
    my $jmap = $self->{jmap};

    my $lazy = "the quick brown fox jumped over the lazy dog";

    my $data = $jmap->Upload($lazy, "text/plain; charset=us-ascii");
    my $blobid = $data->{blobId};

    $data = $jmap->Upload($lazy, "TEXT/PLAIN; charset=US-Ascii");
    my $blobid2 = $data->{blobId};

    $self->assert_str_equals($blobid, $blobid2);
}

sub test_uploaddownloadtypes
    :JMAP :min_version_3_0
{
    my ($self) = @_;
    my $jmap = $self->{jmap};

    my $lazy = "the quick brown fox jumped over the lazy dog";

    my $data = $jmap->Upload($lazy, "text/plain");
    my $blobid = $data->{blobId};

    $data = $jmap->Upload($lazy, "text/html");
    my $blobid2 = $data->{blobId};

    $self->assert_str_not_equals($blobid, $blobid2);

    my $download = $jmap->Download('cassandane', $blobid);

    $self->assert_str_equals($download->{content}, $lazy);
    $self->assert_str_equals($download->{headers}{'content-type'}, "text/plain");

    $download = $jmap->Download('cassandane', $blobid2);

    $self->assert_str_equals($download->{content}, $lazy);
    $self->assert_str_equals($download->{headers}{'content-type'}, "text/html");
}

sub test_uploaddownloadcharsets
    :JMAP :min_version_3_0
{
    my ($self) = @_;
    my $jmap = $self->{jmap};

    my $lazy = "the quick brown fox jumped over the lazy dog";

    my $data = $jmap->Upload($lazy, "text/plain; charset=us-ascii");
    my $blobid = $data->{blobId};

    $data = $jmap->Upload($lazy, "text/plain; charset=utf-8");
    my $blobid2 = $data->{blobId};

    $self->assert_str_not_equals($blobid, $blobid2);

    my $download = $jmap->Download('cassandane', $blobid);

    $self->assert_str_equals($download->{content}, $lazy);
    $self->assert_matches(qr/text\/plain/, $download->{headers}{'content-type'});

    $download = $jmap->Download('cassandane', $blobid2);

    $self->assert_str_equals($download->{content}, $lazy);
    $self->assert_matches(qr/text\/plain/, $download->{headers}{'content-type'});
}

sub test_brokenrfc822_badendline
    :JMAP :min_version_3_0
{
    my ($self) = @_;
    my $jmap = $self->{jmap};

    my $message = <<'EOF';
From: "Some Example Sender" <example@example.com>
To: baseball@vitaead.com
Subject: test message
Date: Wed, 7 Dec 2016 00:21:50 -0500
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Content-Transfer-Encoding: quoted-printable

This is a test message.
EOF
    $message =~ s/\r//gs;
    my $data = $jmap->Upload($message, "message/rfc822");
    my $blobid = $data->{blobId};

    xlog "create drafts mailbox";
    my $res = $jmap->Request([
            ['setMailboxes', { create => { "1" => {
                            name => "drafts",
                            parentId => undef,
                            role => "drafts"
             }}}, "R1"]
    ]);
    my $draftsmbox = $res->[0][1]{created}{"1"}{id};
    $self->assert_not_null($draftsmbox);

    xlog "import message from blob $blobid";
    eval {
        $jmap->Request([['importMessages', {
            messages => {
                "1" => {
                    blobId => $blobid,
                    mailboxIds => [ $draftsmbox ],
                    isUnread => JSON::true,
                    isFlagged => JSON::false,
                    isAnswered => JSON::false,
                    isDraft => JSON::true,
                },
            },
        }, "R1"]]);
    };
    my $error = $@;
    $self->assert_matches(qr/Message contains bare newlines/, $error);
}

sub test_import_setdate
    :JMAP :min_version_3_0
{
    my ($self) = @_;
    my $jmap = $self->{jmap};

    my $message = <<'EOF';
From: "Some Example Sender" <example@example.com>
To: baseball@vitaead.com
Subject: test message
Date: Wed, 7 Dec 2016 22:11:11 +1100
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Content-Transfer-Encoding: quoted-printable

This is a test message.
EOF
    $message =~ s/\r?\n/\r\n/gs;
    my $data = $jmap->Upload($message, "message/rfc822");
    my $blobid = $data->{blobId};

    xlog "create drafts mailbox";
    my $res = $jmap->Request([
            ['setMailboxes', { create => { "1" => {
                            name => "drafts",
                            parentId => undef,
                            role => "drafts"
             }}}, "R1"]
    ]);
    my $draftsmbox = $res->[0][1]{created}{"1"}{id};
    $self->assert_not_null($draftsmbox);

    my $date = '2016-12-07T11:11:12Z';
    xlog "import message from blob $blobid";
    $res = eval {
        $jmap->Request([['importMessages', {
            messages => {
                "1" => {
                    blobId => $blobid,
                    mailboxIds => [ $draftsmbox ],
                    isUnread => JSON::true,
                    isFlagged => JSON::false,
                    isAnswered => JSON::false,
                    isDraft => JSON::true,
                    date => $date,
                },
            },
        }, "R1"], ['getMessages', {ids => ["#1"]}, "R2"]]);
    };

    $self->assert_str_equals("messagesImported", $res->[0][0]);
    my $msg = $res->[0][1]->{created}{"1"};
    $self->assert_not_null($msg);

    $self->assert_str_equals("messages", $res->[1][0]);
    $self->assert_str_equals($msg->{id}, $res->[1][1]{list}[0]->{id});
    $self->assert_str_equals($date, $res->[1][1]{list}[0]->{date});
}

sub test_getthreadonemsg
    :JMAP :min_version_3_0
{
    my ($self) = @_;
    my %exp;
    my $jmap = $self->{jmap};
    my $res;
    my $draftsmbox;
    my $state;
    my $threadA;
    my $threadB;

    my $imaptalk = $self->{store}->get_client();

    xlog "create drafts mailbox";
    $res = $jmap->Request([
            ['setMailboxes', { create => { "1" => {
                            name => "drafts",
                            parentId => undef,
                            role => "drafts"
             }}}, "R1"]
    ]);
    $draftsmbox = $res->[0][1]{created}{"1"}{id};
    $self->assert_not_null($draftsmbox);

    xlog "get thread state";
    $res = $jmap->Request([['getThreads', { ids => [ 'no' ] }, "R1"]]);
    $state = $res->[0][1]->{state};
    $self->assert_not_null($state);

    my $message = <<'EOF';
Return-Path: <Hannah.Smith@gmail.com>
Received: from gateway (gateway.vmtom.com [10.0.0.1])
    by ahost (ahost.vmtom.com[10.0.0.2]); Wed, 07 Dec 2016 11:43:25 +1100
Received: from mail.gmail.com (mail.gmail.com [192.168.0.1])
    by gateway.vmtom.com (gateway.vmtom.com [10.0.0.1]); Wed, 07 Dec 2016 11:43:25 +1100
Mime-Version: 1.0
Content-Type: text/plain; charset="us-ascii"
Content-Transfer-Encoding: 7bit
Subject: Message A
From: Hannah V. Smith <Hannah.Smith@gmail.com>
Message-ID: <fake.1481071405.58492@gmail.com>
Date: Wed, 07 Dec 2016 11:43:25 +1100
To: Test User <test@vmtom.com>
X-Cassandane-Unique: 294f71c341218d36d4bda75aad56599b7be3d15b

a
EOF
    $message =~ s/\r?\n/\r\n/gs;
    my $data = $jmap->Upload($message, "message/rfc822");
    my $blobid = $data->{blobId};
    xlog "import message from blob $blobid";
    $res = $jmap->Request([['importMessages', {
        messages => {
            "1" => {
                blobId => $blobid,
                mailboxIds => [ $draftsmbox ],
                isUnread => JSON::true,
                isFlagged => JSON::false,
                isAnswered => JSON::false,
                isDraft => JSON::true,
            },
        },
    }, "R1"]]);

    xlog "get thread updates";
    $res = $jmap->Request([['getThreadUpdates', { sinceState => $state, fetchRecords => $JSON::true }, "R1"]]);
    $self->assert_equals(JSON::false, $res->[0][1]->{hasMoreUpdates});
}

sub test_getthreadupdates
    :JMAP :min_version_3_0
{
    my ($self) = @_;
    my %exp;
    my $jmap = $self->{jmap};
    my $res;
    my %params;
    my $dt;
    my $draftsmbox;
    my $state;
    my $threadA;
    my $threadB;

    my $imaptalk = $self->{store}->get_client();

    xlog "create drafts mailbox";
    $res = $jmap->Request([
            ['setMailboxes', { create => { "1" => {
                            name => "drafts",
                            parentId => undef,
                            role => "drafts"
             }}}, "R1"]
    ]);
    $draftsmbox = $res->[0][1]{created}{"1"}{id};
    $self->assert_not_null($draftsmbox);

    xlog "get thread state";
    $res = $jmap->Request([['getMessageList', {}, "R1"]]);
    $state = $res->[0][1]->{state};
    $self->assert_not_null($state);

    xlog "get thread updates";
    $res = $jmap->Request([['getThreadUpdates', { sinceState => $state }, "R1"]]);
    $self->assert_str_equals($state, $res->[0][1]->{oldState});
    $self->assert_str_equals($state, $res->[0][1]->{newState});
    $self->assert_equals(JSON::false, $res->[0][1]->{hasMoreUpdates});
    $self->assert_num_equals(0, scalar @{$res->[0][1]{changed}});
    $self->assert_num_equals(0, scalar @{$res->[0][1]{removed}});

    xlog "generating message A";
    $dt = DateTime->now();
    $dt->add(DateTime::Duration->new(hours => -3));
    $exp{A} = $self->make_message("Message A", date => $dt, body => "a");
    $exp{A}->set_attributes(uid => 1, cid => $exp{A}->make_cid());

    xlog "get thread updates";
    $res = $jmap->Request([['getThreadUpdates', { sinceState => $state }, "R1"]]);
    $self->assert_str_equals($state, $res->[0][1]->{oldState});
    $self->assert_str_not_equals($state, $res->[0][1]->{newState});
    $self->assert_equals(JSON::false, $res->[0][1]->{hasMoreUpdates});
    $self->assert_num_equals(1, scalar @{$res->[0][1]{changed}});
    $self->assert_num_equals(0, scalar @{$res->[0][1]{removed}});
    $state = $res->[0][1]->{newState};
    $threadA = $res->[0][1]{changed}[0];

    xlog "generating message C referencing A";
    $dt = DateTime->now();
    $dt->add(DateTime::Duration->new(hours => -2));
    $exp{C} = $self->make_message("Re: Message A", references => [ $exp{A} ], date => $dt, body => "c");
    $exp{C}->set_attributes(uid => 3, cid => $exp{A}->get_attribute('cid'));

    xlog "get thread updates";
    $res = $jmap->Request([['getThreadUpdates', { sinceState => $state }, "R1"]]);
    $self->assert_str_equals($state, $res->[0][1]->{oldState});
    $self->assert_str_not_equals($state, $res->[0][1]->{newState});
    $self->assert_equals(JSON::false, $res->[0][1]->{hasMoreUpdates});
    $self->assert_num_equals(1, scalar @{$res->[0][1]{changed}});
    $self->assert_str_equals($threadA, $res->[0][1]{changed}[0]);
    $self->assert_num_equals(0, scalar @{$res->[0][1]{removed}});
    $state = $res->[0][1]->{newState};

    xlog "get thread updates (expect no changes)";
    $res = $jmap->Request([['getThreadUpdates', { sinceState => $state }, "R1"]]);
    $self->assert_str_equals($state, $res->[0][1]->{oldState});
    $self->assert_str_equals($state, $res->[0][1]->{newState});
    $self->assert_equals(JSON::false, $res->[0][1]->{hasMoreUpdates});
    $self->assert_num_equals(0, scalar @{$res->[0][1]{changed}});
    $self->assert_num_equals(0, scalar @{$res->[0][1]{removed}});

    xlog "generating message B";
    $exp{B} = $self->make_message("Message B", body => "b");
    $exp{B}->set_attributes(uid => 2, cid => $exp{B}->make_cid());

    xlog "generating message D referencing A";
    $dt = DateTime->now();
    $dt->add(DateTime::Duration->new(hours => -1));
    $exp{D} = $self->make_message("Re: Message A", references => [ $exp{A} ], date => $dt, body => "d");
    $exp{D}->set_attributes(uid => 4, cid => $exp{A}->get_attribute('cid'));

    xlog "generating message E referencing A";
    $dt = DateTime->now();
    $dt->add(DateTime::Duration->new(minutes => -30));
    $exp{E} = $self->make_message("Re: Message A", references => [ $exp{A} ], date => $dt, body => "e");
    $exp{E}->set_attributes(uid => 5, cid => $exp{A}->get_attribute('cid'));

    xlog "get max 1 thread updates";
    $res = $jmap->Request([['getThreadUpdates', { sinceState => $state, maxChanges => 1 }, "R1"]]);
    $self->assert_str_equals($state, $res->[0][1]->{oldState});
    $self->assert_str_not_equals($state, $res->[0][1]->{newState});
    $self->assert_equals(JSON::true, $res->[0][1]->{hasMoreUpdates});
    $self->assert_num_equals(1, scalar @{$res->[0][1]{changed}});
    $self->assert_str_not_equals($threadA, $res->[0][1]{changed}[0]);
    $self->assert_num_equals(0, scalar @{$res->[0][1]{removed}});
    $state = $res->[0][1]->{newState};
    $threadB = $res->[0][1]{changed}[0];

    xlog "get max 2 thread updates";
    $res = $jmap->Request([['getThreadUpdates', { sinceState => $state, maxChanges => 2 }, "R1"]]);
    $self->assert_str_equals($state, $res->[0][1]->{oldState});
    $self->assert_str_not_equals($state, $res->[0][1]->{newState});
    $self->assert_equals(JSON::false, $res->[0][1]->{hasMoreUpdates});
    $self->assert_num_equals(1, scalar @{$res->[0][1]{changed}});
    $self->assert_str_equals($threadA, $res->[0][1]{changed}[0]);
    $self->assert_num_equals(0, scalar @{$res->[0][1]{removed}});
    $state = $res->[0][1]->{newState};

    xlog "fetch messages"; $res = $jmap->Request([['getMessageList', {
        fetchMessages => JSON::true,
    }, "R1"]]);

    my %m = map { $_->{textBody} => $_ } @{$res->[1][1]{list}};
    my $msgA = $m{"a"};
    my $msgB = $m{"b"};
    my $msgC = $m{"c"};
    my $msgD = $m{"d"};
    my $msgE = $m{"e"};
    $self->assert_not_null($msgA);
    $self->assert_not_null($msgB);
    $self->assert_not_null($msgC);
    $self->assert_not_null($msgD);
    $self->assert_not_null($msgE);

    xlog "destroy message b, update message d";
    $res = $jmap->Request([['setMessages', {
        destroy => [ $msgB->{id} ],
        update =>  { $msgD->{id} => { isUnread => JSON::false }},
    }, "R1"]]);
    $self->assert_str_equals($res->[0][1]{destroyed}[0], $msgB->{id});
    $self->assert(exists $res->[0][1]->{updated}{$msgD->{id}});

    xlog "get thread updates";
    $res = $jmap->Request([['getThreadUpdates', { sinceState => $state }, "R1"]]);
    $self->assert_str_equals($state, $res->[0][1]->{oldState});
    $self->assert_str_not_equals($state, $res->[0][1]->{newState});
    $self->assert_equals(JSON::false, $res->[0][1]->{hasMoreUpdates});
    $self->assert_num_equals(1, scalar @{$res->[0][1]{changed}});
    $self->assert_str_equals($threadA, $res->[0][1]{changed}[0]);
    $self->assert_num_equals(1, scalar @{$res->[0][1]{removed}});
    $self->assert_str_equals($threadB, $res->[0][1]{removed}[0]);
    $state = $res->[0][1]->{newState};

    xlog "destroy messages c and e";
    $res = $jmap->Request([['setMessages', {
        destroy => [ $msgC->{id}, $msgE->{id} ],
    }, "R1"]]);
    $self->assert_num_equals(2, scalar @{$res->[0][1]{destroyed}});

    xlog "get thread updates, fetch threads";
    $res = $jmap->Request([['getThreadUpdates', {
            sinceState => $state,
            fetchRecords => JSON::true
    }, "R1"]]);
    $self->assert_str_equals($state, $res->[0][1]->{oldState});
    $self->assert_str_not_equals($state, $res->[0][1]->{newState});
    $self->assert_equals(JSON::false, $res->[0][1]->{hasMoreUpdates});
    $self->assert_num_equals(1, scalar @{$res->[0][1]{changed}});
    $self->assert_str_equals($threadA, $res->[0][1]{changed}[0]);
    $self->assert_num_equals(0, scalar @{$res->[0][1]{removed}});
    $state = $res->[0][1]->{newState};

    $self->assert_str_equals("threads", $res->[1][0]);
    $self->assert_num_equals(1, scalar @{$res->[1][1]{list}});
    $self->assert_str_equals($threadA, $res->[1][1]{list}[0]->{id});

    xlog "destroy messages a and d";
    $res = $jmap->Request([['setMessages', {
        destroy => [ $msgA->{id}, $msgD->{id} ],
    }, "R1"]]);
    $self->assert_num_equals(2, scalar @{$res->[0][1]{destroyed}});

    xlog "get thread updates";
    $res = $jmap->Request([['getThreadUpdates', { sinceState => $state }, "R1"]]);
    $self->assert_str_equals($state, $res->[0][1]->{oldState});
    $self->assert_str_not_equals($state, $res->[0][1]->{newState});
    $self->assert_equals(JSON::false, $res->[0][1]->{hasMoreUpdates});
    $self->assert_num_equals(0, scalar @{$res->[0][1]{changed}});
    $self->assert_num_equals(1, scalar @{$res->[0][1]{removed}});
    $self->assert_str_equals($threadA, $res->[0][1]{removed}[0]);
    $state = $res->[0][1]->{newState};

    xlog "get thread updates (expect no changes)";
    $res = $jmap->Request([['getThreadUpdates', { sinceState => $state }, "R1"]]);
    $self->assert_str_equals($state, $res->[0][1]->{oldState});
    $self->assert_str_equals($state, $res->[0][1]->{newState});
    $self->assert_equals(JSON::false, $res->[0][1]->{hasMoreUpdates});
    $self->assert_num_equals(0, scalar @{$res->[0][1]{changed}});
    $self->assert_num_equals(0, scalar @{$res->[0][1]{removed}});
}

sub test_importmessages
    :JMAP :min_version_3_0
{
    my ($self) = @_;
    my $jmap = $self->{jmap};

    my $store = $self->{store};
    my $talk = $store->get_client();

    my $res;
    my $blobid;
    my $drafts;
    my $inbox;
    my $msg;

    # Generate an embedded message to get a blob id
    xlog "Generate a message in INBOX via IMAP";
    $self->make_message("foo",
        mime_type => "multipart/mixed",
        mime_boundary => "sub",
        body => ""
          . "--sub\r\n"
          . "Content-Type: text/plain; charset=UTF-8\r\n"
          . "Content-Disposition: inline\r\n" . "\r\n"
          . "some text"
          . "\r\n--sub\r\n"
          . "Content-Type: message/rfc822\r\n"
          . "\r\n"
          . "Return-Path: <Ava.Nguyen\@local>\r\n"
          . "Mime-Version: 1.0\r\n"
          . "Content-Type: text/plain\r\n"
          . "Content-Transfer-Encoding: 7bit\r\n"
          . "Subject: bar\r\n"
          . "From: Ava T. Nguyen <Ava.Nguyen\@local>\r\n"
          . "Message-ID: <fake.1475639947.6507\@local>\r\n"
          . "Date: Wed, 05 Oct 2016 14:59:07 +1100\r\n"
          . "To: Test User <test\@local>\r\n"
          . "\r\n"
          . "An embedded message"
          . "\r\n--sub--",
    ) || die;

    xlog "get blobId";
    $res = $jmap->Request([['getMessageList', {
        fetchMessages => JSON::true,
        fetchMessageProperties => ["attachedMessages"],
    }, "R1"]]);
    $blobid = (keys %{$res->[1][1]->{list}[0]->{attachedMessages}})[0];
    $self->assert_not_null($blobid);

    xlog "create drafts mailbox";
    $res = $jmap->Request([
            ['setMailboxes', { create => { "1" => {
                            name => "drafts",
                            parentId => undef,
                            role => "drafts"
             }}}, "R1"]
    ]);
    $drafts = $res->[0][1]{created}{"1"}{id};
    $self->assert_not_null($drafts);

    $inbox = $self->getinbox()->{id};
    $self->assert_not_null($inbox);

    xlog "import and get message from blob $blobid";
    $res = $jmap->Request([['importMessages', {
        messages => {
            "1" => {
                blobId => $blobid,
                mailboxIds => [ $drafts ],
                isUnread => JSON::true,
                isFlagged => JSON::false,
                isAnswered => JSON::false,
                isDraft => JSON::true,
            },
        },
    }, "R1"], ["getMessages", { ids => ["#1"] }, "R2" ]]);

    $self->assert_str_equals("messagesImported", $res->[0][0]);
    $msg = $res->[0][1]->{created}{"1"};
    $self->assert_not_null($msg);

    $self->assert_str_equals("messages", $res->[1][0]);
    $self->assert_str_equals($msg->{id}, $res->[1][1]{list}[0]->{id});

    xlog "load message";
    $res = $jmap->Request([['getMessages', { ids => [$msg->{id}] }, "R1"]]);
    $self->assert_num_equals(1, scalar @{$res->[0][1]{list}[0]->{mailboxIds}});
    $self->assert_str_equals($drafts, $res->[0][1]{list}[0]->{mailboxIds}[0]);

    xlog "import existing message (expect message exists error)";
    $res = $jmap->Request([['importMessages', {
        messages => {
            "1" => {
                blobId => $blobid,
                mailboxIds => [ $drafts ],
                isUnread => JSON::true,
                isFlagged => JSON::false,
                isAnswered => JSON::false,
                isDraft => JSON::true,
            },
        },
    }, "R1"]]);
    $self->assert_str_equals("messagesImported", $res->[0][0]);
    $self->assert_str_equals("messageExists", $res->[0][1]->{notCreated}{"1"}{type});

    xlog "import existing message into new mailbox";
    $res = $jmap->Request([['importMessages', {
        messages => {
            "1" => {
                blobId => $blobid,
                mailboxIds => [ $drafts, $inbox ],
                isUnread => JSON::true,
                isFlagged => JSON::false,
                isAnswered => JSON::false,
                isDraft => JSON::true,
            },
        },
    }, "R1"]]);
    $self->assert_str_equals("messagesImported", $res->[0][0]);
    $msg = $res->[0][1]->{created}{"1"};
    $self->assert_not_null($msg);

    xlog "load message";
    $res = $jmap->Request([['getMessages', { ids => [$msg->{id}] }, "R1"]]);
    $self->assert_num_equals(2, scalar @{$res->[0][1]{list}[0]->{mailboxIds}});
}

sub test_creationids
:JMAP :min_version_3_0
{
    my ($self) = @_;

    my $jmap = $self->{jmap};

    xlog "create and get mailbox and message";
    my $res = $jmap->Request([
        ['setMailboxes', { create => { "1" => {
            name => "foo",
            parentId => undef,
            role => "drafts",
        }}}, 'R1'],
        ['setMessages', { create => { "1" => {
            mailboxIds => ['#1'],
            from => [ { name => "Yosemite Sam", email => "sam\@acme.local" } ] ,
            to => [ { name => "Bugs Bunny", email => "bugs\@acme.local" } ],
            subject => "Memo",
            textBody => "I'm givin' ya one last chance ta surrenda!",
        }}}, 'R2'],
        ['getMessages', {ids => ["#1"]}, "R3"],
        ['getMailboxes', {ids => ["#1"]}, "R4"],
    ]);
    my $msg = $res->[2][1]{list}[0];
    $self->assert_str_equals("Memo", $msg->{subject});

    my $mbox = $res->[3][1]{list}[0];
    $self->assert_str_equals("foo", $mbox->{name});

    $self->assert_str_equals($mbox->{id}, $msg->{mailboxIds}[0]);
}



1;
