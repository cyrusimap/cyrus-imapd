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

package Cassandane::Cyrus::JMAPMail;
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
		 httpmodules => 'carddav caldav jmap',
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
}

sub uniq {
  my %seen;
  return grep { !$seen{$_}++ } @_;
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

    xlog "filter mailboxes by hasRole == true";
    $res = $jmap->CallMethods([['Mailbox/query', {filter => {hasRole => JSON::true}}, "R1"]]);
    $self->assert_num_equals(1, scalar @{$res->[0][1]->{ids}});
    $self->assert_str_equals($mboxids{'Inbox'}, $res->[0][1]{ids}[0]);

    xlog "filter mailboxes by hasRole == false";
    $res = $jmap->CallMethods([['Mailbox/query', {
        filter => {hasRole => JSON::false},
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

    xlog "list mailboxes filtered by parentId OR role";
    $res = $jmap->CallMethods([['Mailbox/query', {
        filter => {
            operator => "OR",
            conditions => [{
                parentId => $mboxids{'Ham'},
            }, {
                hasRole => JSON::true,
            }],
        },
        sort => [{ property => "name" }],
    }, "R1"]]);
    $self->assert_num_equals(3, scalar @{$res->[0][1]->{ids}});
    $self->assert_str_equals($mboxids{'Bonk'}, $res->[0][1]{ids}[0]);
    $self->assert_str_equals($mboxids{'Spam'}, $res->[0][1]{ids}[1]);
    $self->assert_str_equals($mboxids{'Zonk'}, $res->[0][1]{ids}[2]);

    xlog "list mailboxes filtered by parentId AND hasRole false";
    $res = $jmap->CallMethods([['Mailbox/query', {
        filter => {
            operator => "AND",
            conditions => [{
                parentId => $mboxids{'Inbox'},
            }, {
                hasRole => JSON::false,
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
                    hasRole => JSON::true,
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

sub test_mailbox_querychanges
    :min_version_3_1 :needs_component_jmap
{
    my ($self) = @_;
    my $jmap = $self->{jmap};

    # This just tests that Mailbox/queryChanges isn't supported.

    xlog "get current mailbox state";
    my $res = $jmap->CallMethods([['Mailbox/query', { }, "R1"]]);
    my $state = $res->[0][1]->{queryState};
    $self->assert_not_null($state);
    $self->assert_equals(JSON::false, $res->[0][1]->{canCalculateChanges});

    xlog "get mailbox list updates";
    $res = $jmap->CallMethods([['Mailbox/queryChanges', {
        filter => {},
        sinceQueryState => $state,
    }, "R1"]]);
    $self->assert_str_equals("error", $res->[0][0]);
    $self->assert_str_equals("cannotCalculateChanges", $res->[0][1]{type});
    $self->assert_str_equals("R1", $res->[0][2]);
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
    my $res = $jmap->CallMethods([['Mailbox/get', {}, "R1"]]);
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

    $res = $jmap->CallMethods([['Mailbox/get', {}, "R1"]]);
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
    $self->assert_num_equals(5, scalar @{$res->[0][1]{list}});

    # Assert rights
    my %m = map { lc($_->{name}) => $_ } @{$res->[0][1]{list}};
    $self->assert_equals(JSON::false, $m{inbox}->{myRights}->{mayReadItems});
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
    $self->assert_null($res->[0][1]{changedProperties});

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
    $self->assert_null($res->[0][1]{changedProperties});
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
    $self->assert_null($res->[0][1]{changedProperties});
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
    $self->assert_null($res->[0][1]{changedProperties});
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
    $self->assert_null($res->[0][1]{changedProperties});
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
    $self->assert_null($res->[0][1]{changedProperties});
    $state = $res->[0][1]->{newState};

    xlog "get mailbox updates (expect no changes)";
    $res = $jmap->CallMethods([['Mailbox/changes', { sinceState => $state }, "R1"]]);
    $self->assert_str_equals($state, $res->[0][1]->{oldState});
    $self->assert_str_equals($state, $res->[0][1]->{newState});
    $self->assert_equals(JSON::false, $res->[0][1]->{hasMoreChanges});
    $self->assert_deep_equals([], $res->[0][1]{created});
    $self->assert_deep_equals([], $res->[0][1]{updated});
    $self->assert_deep_equals([], $res->[0][1]{destroyed});
    $self->assert_null($res->[0][1]{changedProperties});
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
    $self->assert_not_null($res->[0][1]{changedProperties});
    $self->assert_deep_equals([], $res->[0][1]{created});
    $self->assert_num_not_equals(0, scalar @{$res->[0][1]{updated}});
    $self->assert_deep_equals([], $res->[0][1]{destroyed});
    $state = $res->[0][1]{newState};

    xlog "update mailbox";
    $res = $jmap->CallMethods([['Mailbox/set', { update => { $mboxid => { name => "bar" }}}, "R1"]]);

    xlog "get mailbox updates";
    $res = $jmap->CallMethods([['Mailbox/changes', { sinceState => $state }, "R1"]]);
    $self->assert_str_not_equals($state, $res->[0][1]{newState});
    $self->assert_null($res->[0][1]{changedProperties});
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
    $self->assert_not_null($res->[0][1]{changedProperties});
    $self->assert_deep_equals([], $res->[0][1]{created});
    $self->assert_num_not_equals(0, scalar @{$res->[0][1]{updated}});
    $self->assert_deep_equals([], $res->[0][1]{destroyed});
    $state = $res->[0][1]{newState};

    xlog "update mailbox";
    $res = $jmap->CallMethods([['Mailbox/set', { update => { $mboxid => { name => "baz" }}}, "R1"]]);

    xlog "get mailbox updates";
    $res = $jmap->CallMethods([['Mailbox/changes', { sinceState => $state }, "R1"]]);
    $self->assert_str_not_equals($state, $res->[0][1]{newState});
    $self->assert_null($res->[0][1]{changedProperties});
    $self->assert_deep_equals([], $res->[0][1]{created});
    $self->assert_num_not_equals(0, scalar @{$res->[0][1]{updated}});
    $self->assert_deep_equals([], $res->[0][1]{destroyed});
    $state = $res->[0][1]{newState};

    xlog "get mailbox updates (expect no changes)";
    $res = $jmap->CallMethods([['Mailbox/changes', { sinceState => $state }, "R1"]]);
    $self->assert_str_equals($state, $res->[0][1]{newState});
    $self->assert_null($res->[0][1]{changedProperties});
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
    $self->assert_not_null($res->[0][1]{changedProperties});
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

sub defaultprops_for_email_get
{
    return ( "id", "blobId", "threadId", "mailboxIds", "keywords", "size", "receivedAt", "messageId", "inReplyTo", "references", "sender", "from", "to", "cc", "bcc", "replyTo", "subject", "sentAt", "hasAttachment", "preview", "bodyValues", "textBody", "htmlBody", "attachedFiles", "attachedEmails" );
}

sub test_email_get
    :min_version_3_1 :needs_component_jmap
{
    my ($self) = @_;
    my $jmap = $self->{jmap};

    my $store = $self->{store};
    my $talk = $store->get_client();

    my $res = $jmap->CallMethods([['Mailbox/get', { }, "R1"]]);
    my $inboxid = $res->[0][1]{list}[0]{id};

    my $body = "";
    $body .= "Lorem ipsum dolor sit amet, consectetur adipiscing\r\n";
    $body .= "elit. Nunc in fermentum nibh. Vivamus enim metus.";

    my $maildate = DateTime->now();
    $maildate->add(DateTime::Duration->new(seconds => -10));

    xlog "Generate a email in INBOX via IMAP";
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
    $self->make_message("Email A", %params) || die;

    xlog "get email list";
    $res = $jmap->CallMethods([['Email/query', {}, "R1"]]);
    $self->assert_num_equals(scalar @{$res->[0][1]->{ids}}, 1);

    my @props = $self->defaultprops_for_email_get();

    push @props, "header:x-tra";

    xlog "get emails";
    my $ids = $res->[0][1]->{ids};
    $res = $jmap->CallMethods([['Email/get', { ids => $ids, properties => \@props }, "R1"]]);
    my $msg = $res->[0][1]->{list}[0];

    $self->assert_not_null($msg->{mailboxIds}{$inboxid});
    $self->assert_num_equals(1, scalar keys %{$msg->{mailboxIds}});
    $self->assert_num_equals(0, scalar keys %{$msg->{keywords}});

    $self->assert_str_equals('fake.123456789@local', $msg->{messageId}[0]);
    $self->assert_str_equals(" foo bar\r\n baz", $msg->{'header:x-tra'});
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
    $self->assert_deep_equals($msg->{sender}, [{
            name => "Bla",
            email => "blu\@local"
    }]);
    $self->assert_str_equals($msg->{subject}, "Email A");

    my $datestr = $maildate->strftime('%Y-%m-%dT%TZ');
    $self->assert_str_equals($datestr, $msg->{receivedAt});
    $self->assert_not_null($msg->{size});
}

sub test_email_get_mimeencode
    :min_version_3_1 :needs_component_jmap
{
    my ($self) = @_;
    my $jmap = $self->{jmap};

    my $store = $self->{store};
    my $talk = $store->get_client();

    my $res = $jmap->CallMethods([['Mailbox/get', { }, "R1"]]);
    my $inboxid = $res->[0][1]{list}[0]{id};

    my $body = "a body";

    my $maildate = DateTime->now();
    $maildate->add(DateTime::Duration->new(seconds => -10));

     # Thanks to http://dogmamix.com/MimeHeadersDecoder/ for examples

    xlog "Generate a email in INBOX via IMAP";
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

    xlog "get email list";
    $res = $jmap->CallMethods([
        ['Email/query', { }, 'R1'],
        ['Email/get', {
            '#ids' => {
                resultOf => 'R1',
                name => 'Email/query',
                path => '/ids'
            },
            properties => [ 'subject', 'header:x-mood:asText', 'from', 'to' ],
        }, 'R2'],
    ]);
    $self->assert_num_equals(scalar @{$res->[0][1]->{ids}}, 1);
    my $msg = $res->[1][1]->{list}[0];

    $self->assert_str_equals("If you can read this you understand the example.", $msg->{subject});
    $self->assert_str_equals("I feel \N{WHITE SMILING FACE}", $msg->{'header:x-mood:asText'});
    $self->assert_str_equals("Keld J\N{LATIN SMALL LETTER O WITH STROKE}rn Simonsen", $msg->{from}[0]{name});
    $self->assert_str_equals("Tom To", $msg->{to}[0]{name});
}

sub test_email_get_multimailboxes
    :min_version_3_1 :needs_component_jmap
{
    my ($self) = @_;
    my $jmap = $self->{jmap};

    my $store = $self->{store};
    my $talk = $store->get_client();

    my $now = DateTime->now();

    xlog "Generate a email in INBOX via IMAP";
    my $res = $self->make_message("foo") || die;
    my $uid = $res->{attrs}->{uid};
    my $msg;

    xlog "get email";
    $res = $jmap->CallMethods([
        ['Email/query', {}, "R1"],
        ['Email/get', { '#ids' => { resultOf => 'R1', name => 'Email/query', path => '/ids' } }, 'R2'],
    ]);
    $msg = $res->[1][1]{list}[0];
    $self->assert_num_equals(1, scalar @{$res->[0][1]{ids}});
    $self->assert_num_equals(1, scalar keys %{$msg->{mailboxIds}});

    xlog "Create target mailbox";
    $talk->create("INBOX.target");

    xlog "Copy email into INBOX.target";
    $talk->copy($uid, "INBOX.target");

    xlog "get email";
    $res = $jmap->CallMethods([
        ['Email/query', {}, "R1"],
        ['Email/get', { '#ids' => { resultOf => 'R1', name => 'Email/query', path => '/ids' } }, 'R2'],
    ]);
    $msg = $res->[1][1]{list}[0];
    $self->assert_num_equals(1, scalar @{$res->[0][1]{ids}});
    $self->assert_num_equals(2, scalar keys %{$msg->{mailboxIds}});
}

sub test_email_get_body_both
    :min_version_3_1 :needs_component_jmap
{
    my ($self) = @_;
    my $jmap = $self->{jmap};

    my $store = $self->{store};
    my $talk = $store->get_client();
    my $inbox = 'INBOX';

    xlog "Generate a email in $inbox via IMAP";
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
    $body .= "--047d7b33dd729737fe04d3bde348--\r\n";
    $exp_sub{A} = $self->make_message("foo",
        mime_type => "multipart/alternative",
        mime_boundary => "047d7b33dd729737fe04d3bde348",
        body => $body
    );

    xlog "get email list";
    my $res = $jmap->CallMethods([['Email/query', {}, "R1"]]);
    my $ids = $res->[0][1]->{ids};

    xlog "get email";
    $res = $jmap->CallMethods([['Email/get', { ids => $ids, fetchAllBodyValues => JSON::true }, "R1"]]);
    my $msg = $res->[0][1]{list}[0];

    my $partId = $msg->{textBody}[0]{partId};
    $self->assert_str_equals($textBody, $msg->{bodyValues}{$partId}{value});
    $partId = $msg->{htmlBody}[0]{partId};
    $self->assert_str_equals($htmlBody, $msg->{bodyValues}{$partId}{value});
}

sub test_email_get_body_plain
    :min_version_3_1 :needs_component_jmap
{
    my ($self) = @_;
    my $jmap = $self->{jmap};

    my $store = $self->{store};
    my $talk = $store->get_client();
    my $inbox = 'INBOX';

    xlog "Generate a email in $inbox via IMAP";
    my %exp_sub;
    $store->set_folder($inbox);
    $store->_select();
    $self->{gen}->set_next_uid(1);

    my $body = "A plain text email.";
    $exp_sub{A} = $self->make_message("foo",
        body => $body
    );

    xlog "get email list";
    my $res = $jmap->CallMethods([['Email/query', {}, "R1"]]);
    my $ids = $res->[0][1]->{ids};

    xlog "get emails";
    $res = $jmap->CallMethods([['Email/get', { ids => $ids, fetchAllBodyValues => JSON::true,  }, "R1"]]);
    my $msg = $res->[0][1]{list}[0];

    my $partId = $msg->{textBody}[0]{partId};
    $self->assert_str_equals($body, $msg->{bodyValues}{$partId}{value});
    $self->assert_str_equals($msg->{textBody}[0]{partId}, $msg->{htmlBody}[0]{partId});
}

sub test_email_get_body_html
    :min_version_3_1 :needs_component_jmap
{
    my ($self) = @_;
    my $jmap = $self->{jmap};

    my $store = $self->{store};
    my $talk = $store->get_client();
    my $inbox = 'INBOX';

    xlog "Generate a email in $inbox via IMAP";
    my %exp_sub;
    $store->set_folder($inbox);
    $store->_select();
    $self->{gen}->set_next_uid(1);

    my $body = "<html><body> <p>A HTML email.</p> </body></html>";
    $exp_sub{A} = $self->make_message("foo",
        mime_type => "text/html",
        body => $body
    );

    xlog "get email list";
    my $res = $jmap->CallMethods([['Email/query', {}, "R1"]]);
    my $ids = $res->[0][1]->{ids};

    xlog "get email";
    $res = $jmap->CallMethods([['Email/get', { ids => $ids, fetchAllBodyValues => JSON::true }, "R1"]]);
    my $msg = $res->[0][1]{list}[0];

    my $partId = $msg->{htmlBody}[0]{partId};
    $self->assert_str_equals($body, $msg->{bodyValues}{$partId}{value});
}

sub test_email_get_attachment_name
    :min_version_3_1 :needs_component_jmap
{
    my ($self) = @_;
    my $jmap = $self->{jmap};

    my $store = $self->{store};
    my $talk = $store->get_client();
    my $inbox = 'INBOX';

    xlog "Generate a email in $inbox via IMAP";
    my %exp_sub;
    $store->set_folder($inbox);
    $store->_select();
    $self->{gen}->set_next_uid(1);

    my $body = "".
    "--sub\r\n".
    "Content-Type: image/jpeg\r\n".
    "Content-Disposition: attachment; filename\r\n\t=\"image1.jpg\"\r\n".
    "Content-Transfer-Encoding: base64\r\n".
    "\r\n" .
    "beefc0de".
    "\r\n--sub\r\n".
    "Content-Type: image/tiff\r\n".
    "Content-Transfer-Encoding: base64\r\n".
    "\r\n" .
    "abc=".
    "\r\n--sub\r\n".
    "Content-Type: application/x-excel\r\n".
    "Content-Transfer-Encoding: base64\r\n".
    "Content-Disposition: attachment; filename\r\n\t=\"f.xls\"\r\n".
    "\r\n" .
    "012312312313".
    "\r\n--sub\r\n".
    "Content-Type: application/foo;name=y.dat\r\n".
    "Content-Disposition: attachment; filename=z.dat\r\n".
    "\r\n" .
    "foo".
    "\r\n--sub\r\n".
    "Content-Type: application/bar;name*0=looo;name*1=ooong;name*2=.name\r\n".
    "\r\n" .
    "bar".
    "\r\n--sub\r\n".
    "Content-Type: application/baz\r\n".
    "Content-Disposition: attachment; filename*0=cont;\r\n filename*1=inue\r\n".
    "\r\n" .
    "baz".
    "\r\n--sub\r\n".
    "Content-Type: application/bam; name=\"=?utf-8?Q?=F0=9F=98=80=2Etxt?=\"\r\n".
    "\r\n" .
    "bam".
    "\r\n--sub\r\n".
    "Content-Type: application/tux\r\n".
    "Content-Disposition: attachment; filename*0*=utf-8''%F0%9F%98%80;\r\n filename*1=\".txt\"\r\n".
    "\r\n" .
    "baz".
    "\r\n--sub--\r\n";

    $exp_sub{A} = $self->make_message("foo",
        mime_type => "multipart/mixed",
        mime_boundary => "sub",
        body => $body
    );
    $talk->store('1', '+flags', '($HasAttachment)');

    xlog "get email list";
    my $res = $jmap->CallMethods([['Email/query', {}, "R1"]]);
    my $ids = $res->[0][1]->{ids};

    xlog "get email";
    $res = $jmap->CallMethods([['Email/get', { ids => $ids }, "R1"]]);
    my $msg = $res->[0][1]{list}[0];

    $self->assert_equals(JSON::true, $msg->{hasAttachment});

    # Assert embedded email support
    my %m = map { $_->{type} => $_ } @{$msg->{attachments}};
    my $att;

    $att = $m{"image/tiff"};
    $self->assert_null($att->{name});

    $att = $m{"application/x-excel"};
    $self->assert_str_equals("f.xls", $att->{name});

    $att = $m{"image/jpeg"};
    $self->assert_str_equals("image1.jpg", $att->{name});

    $att = $m{"application/foo"};
    $self->assert_str_equals("z.dat", $att->{name});

    $att = $m{"application/bar"};
    $self->assert_str_equals("loooooong.name", $att->{name});

    $att = $m{"application/baz"};
    $self->assert_str_equals("continue", $att->{name});

    $att = $m{"application/bam"};
    $self->assert_str_equals("\N{GRINNING FACE}.txt", $att->{name});

    $att = $m{"application/tux"};
    $self->assert_str_equals("\N{GRINNING FACE}.txt", $att->{name});
}

sub test_email_get_body_notext
    :min_version_3_1 :needs_component_jmap
{
    my ($self) = @_;
    my $jmap = $self->{jmap};

    my $store = $self->{store};
    my $talk = $store->get_client();
    my $inbox = 'INBOX';

    # Generate a email to have some blob ids
    xlog "Generate a email in $inbox via IMAP";
    $self->make_message("foo",
        mime_type => "application/zip",
        body => "boguszip",
    );

    xlog "get email list";
    my $res = $jmap->CallMethods([
        ['Email/query', { }, "R1"],
        ['Email/get', { '#ids' => { resultOf => 'R1', name => 'Email/query', path => '/ids' } }, 'R2'],
    ]);
    my $msg = $res->[1][1]->{list}[0];

    $self->assert_deep_equals([], $msg->{textBody});
    $self->assert_deep_equals([], $msg->{htmlBody});
}


sub test_email_get_preview
    :min_version_3_1 :needs_component_jmap
{
    my ($self) = @_;
    my $jmap = $self->{jmap};

    my $store = $self->{store};
    my $talk = $store->get_client();
    my $inbox = 'INBOX';

    xlog "Generate a email in $inbox via IMAP";
    my %exp_sub;
    $store->set_folder($inbox);
    $store->_select();
    $self->{gen}->set_next_uid(1);

    my $body = "A   plain\r\ntext email.";
    $exp_sub{A} = $self->make_message("foo",
        body => $body
    );

    xlog "get email list";
    my $res = $jmap->CallMethods([['Email/query', {}, "R1"]]);

    xlog "get emails";
    $res = $jmap->CallMethods([['Email/get', { ids => $res->[0][1]->{ids} }, "R1"]]);
    my $msg = $res->[0][1]{list}[0];

    $self->assert_str_equals('A plain text email.', $msg->{preview});
}

sub test_email_get_imagesize
    :min_version_3_1 :needs_component_jmap
{
    # This is a FastMail-extension

    my ($self) = @_;
    my $jmap = $self->{jmap};

    my $store = $self->{store};
    my $talk = $store->get_client();
    $store->set_folder('INBOX');

    # Part 1 has no imagesize defined, part 2 defines no EXIF
    # orientation, part 3 defines all image size properties.
    my $imageSize = {
        '2' => [1,2],
        '3' => [1,2,3],
    };

    # Generate an email with image MIME parts.
    xlog "Generate an email via IMAP";
    my $msg = $self->make_message("foo",
        mime_type => "multipart/mixed",
        mime_boundary => "sub",
        body => ""
          . "--sub\r\n"
          . "Content-Type: text/plain; charset=UTF-8\r\n"
          . "some text"
          . "\r\n--sub\r\n"
          . "Content-Type: image/png\r\n"
          . "Content-Transfer-Encoding: base64\r\n"
          . "\r\n"
          . "iVBORw0KGgoAAAANSUhEUgAAAAEAAAABCAQAAAC1HAwCAAAAC0lEQVQYV2NgYAAAAAMAAWgmWQ0AAAAASUVORK5CYII="
          . "\r\n--sub\r\n"
          . "Content-Type: image/png\r\n"
          . "Content-Transfer-Encoding: base64\r\n"
          . "\r\n"
          . "iVBORw0KGgoAAAANSUhEUgAAAAEAAAABCAQAAAC1HAwCAAAAC0lEQVQYV2NgYAAAAAMAAWgmWQ0AAAAASUVORK5CYII="
          . "\r\n--sub\r\n"
          . "Content-Type: image/png\r\n"
          . "Content-Transfer-Encoding: base64\r\n"
          . "\r\n"
          . "iVBORw0KGgoAAAANSUhEUgAAAAEAAAABCAQAAAC1HAwCAAAAC0lEQVQYV2NgYAAAAAMAAWgmWQ0AAAAASUVORK5CYII="
          . "\r\n--sub--\r\n",
    );
    xlog "set imagesize annotation";
    my $annot = '/vendor/messagingengine.com/imagesize';
    my $ret = $talk->store('1', 'annotation', [
        $annot, ['value.shared', { Quote => encode_json($imageSize) }]
    ]);
    if (not $ret) {
        xlog "Could not set $annot annotation. Aborting.";
        return;
    }

    xlog "get email list";
    my $res = $jmap->CallMethods([['Email/query', {}, "R1"]]);
    my $ids = $res->[0][1]->{ids};

    xlog "get email";
    $res = $jmap->CallMethods([['Email/get', {
        ids => $ids,
        properties => ['bodyStructure'],
        bodyProperties => ['partId', 'imageSize' ],
    }, "R1"]]);
    my $email = $res->[0][1]{list}[0];

    my $part = $email->{bodyStructure}{subParts}[0];
    $self->assert_str_equals('1', $part->{partId});
    $self->assert_null($part->{imageSize});

    $part = $email->{bodyStructure}{subParts}[1];
    $self->assert_str_equals('2', $part->{partId});
    $self->assert_deep_equals($imageSize->{2}, $part->{imageSize});

    $part = $email->{bodyStructure}{subParts}[2];
    $self->assert_str_equals('3', $part->{partId});
    $self->assert_deep_equals($imageSize->{3}, $part->{imageSize});
}

sub test_email_get_isdeleted
    :min_version_3_1 :needs_component_jmap
{
    # This is a FastMail-extension

    my ($self) = @_;
    my $jmap = $self->{jmap};

    my $store = $self->{store};
    my $talk = $store->get_client();
    $store->set_folder('INBOX');

    my $msg = $self->make_message("foo",
        mime_type => "multipart/mixed",
        mime_boundary => "sub",
        body => ""
          . "--sub\r\n"
          . "Content-Type: text/plain; charset=UTF-8\r\n"
          . "some text"
          . "\r\n--sub\r\n"
          . "Content-Type: text/x-me-removed-file\r\n"
          . "\r\n"
          . "deleted"
          . "\r\n--sub--\r\n",
    );

    xlog "get email list";
    my $res = $jmap->CallMethods([['Email/query', {}, "R1"]]);
    my $ids = $res->[0][1]->{ids};

    xlog "get email";
    $res = $jmap->CallMethods([['Email/get', {
        ids => $ids,
        properties => ['bodyStructure'],
        bodyProperties => ['partId', 'isDeleted' ],
    }, "R1"]]);
    my $email = $res->[0][1]{list}[0];

    my $part = $email->{bodyStructure}{subParts}[0];
    $self->assert_str_equals('1', $part->{partId});
    $self->assert_equals(JSON::false, $part->{isDeleted});

    $part = $email->{bodyStructure}{subParts}[1];
    $self->assert_str_equals('2', $part->{partId});
    $self->assert_equals(JSON::true, $part->{isDeleted});
}

sub test_email_get_trustedsender
    :min_version_3_1 :needs_component_jmap
{
    # This is a FastMail-extension

    my ($self) = @_;
    my $jmap = $self->{jmap};

    my $store = $self->{store};
    my $talk = $store->get_client();
    $store->set_folder('INBOX');

    my $msg = $self->make_message("foo");

    xlog "Assert trustedSender isn't set";
    my $res = $jmap->CallMethods([
        ['Email/query', { }, "R1"],
        ['Email/get', {
            '#ids' => { resultOf => 'R1', name => 'Email/query', path => '/ids' },
            properties => [ 'id', 'trustedSender', 'keywords' ],
        }, 'R2'],
    ]);
    my $emailId = $res->[0][1]{ids}[0];
    my $email = $res->[1][1]{list}[0];
    $self->assert_null($email->{trustedSender});

    xlog "Set IsTrusted flag";
    $talk->store('1', '+flags', '($IsTrusted)');

    xlog "Assert trustedSender isn't set";
    $res = $jmap->CallMethods([['Email/get', {
        ids => [$emailId], properties => [ 'id', 'trustedSender', 'keywords' ],
    }, 'R1']]);
    $email = $res->[0][1]{list}[0];
    $self->assert_null($email->{trustedSender});

    xlog "Set zero-length trusted annotation";
    my $annot = '/vendor/messagingengine.com/trusted';
    my $ret = $talk->store('1', 'annotation', [
        $annot, ['value.shared', { Quote => '' }]
    ]);
    if (not $ret) {
        xlog "Could not set $annot annotation. Aborting.";
        return;
    }

    xlog "Assert trustedSender isn't set";
    $res = $jmap->CallMethods([['Email/get', {
        ids => [$emailId], properties => [ 'id', 'trustedSender', 'keywords' ],
    }, 'R1']]);
    $email = $res->[0][1]{list}[0];
    $self->assert_null($email->{trustedSender});

    xlog "Set trusted annotation";
    $ret = $talk->store('1', 'annotation', [
        $annot, ['value.shared', { Quote => 'bar' }]
    ]);
    if (not $ret) {
        xlog "Could not set $annot annotation. Aborting.";
        return;
    }

    xlog "Assert trustedSender is set";
    $res = $jmap->CallMethods([['Email/get', {
        ids => [$emailId], properties => [ 'id', 'trustedSender', 'keywords' ],
    }, 'R1']]);
    $email = $res->[0][1]{list}[0];
    $self->assert_str_equals('bar', $email->{trustedSender});

    xlog "Remove IsTrusted flag";
    $talk->store('1', '-flags', '($IsTrusted)');

    xlog "Assert trustedSender isn't set";
    $res = $jmap->CallMethods([['Email/get', {
        ids => [$emailId], properties => [ 'id', 'trustedSender', 'keywords' ],
    }, 'R1']]);
    $email = $res->[0][1]{list}[0];
    $self->assert_null($email->{trustedSender});
}

sub test_email_get_shared
    :min_version_3_1 :needs_component_jmap
{
    my ($self) = @_;
    my $jmap = $self->{jmap};

    my $store = $self->{store};
    my $talk = $store->get_client();

    my $admintalk = $self->{adminstore}->get_client();

    # Create user and share mailbox
    xlog "Create shared mailbox";
    $self->{instance}->create_user("foo");
    $admintalk->setacl("user.foo", "cassandane", "lr") or die;
    $admintalk->create("user.foo.box1") or die;
    $admintalk->setacl("user.foo.box1", "cassandane", "lr") or die;

    xlog "Create email in shared account";
    $self->{adminstore}->set_folder('user.foo.box1');
    $self->make_message("Email foo", store => $self->{adminstore}) or die;

    xlog "get email list in shared account";
    my $res = $jmap->CallMethods([['Email/query', { accountId => 'foo' }, "R1"]]);
    $self->assert_num_equals(1, scalar @{$res->[0][1]->{ids}});
    my $id = $res->[0][1]->{ids}[0];

    xlog "get email from shared account";
    $res = $jmap->CallMethods([['Email/get', { accountId => 'foo', ids => [$id]}, "R1"]]);
    my $msg = $res->[0][1]{list}[0];
    $self->assert_not_null($msg);
    $self->assert_str_equals("Email foo", $msg->{subject});

    xlog "Unshare mailbox";
    $admintalk->setacl("user.foo.box1", "cassandane", "") or die;

    xlog "refetch email from unshared mailbox (should fail)";
    $res = $jmap->CallMethods([['Email/get', { accountId => 'foo', ids => [$id]}, "R1"]]);
    $self->assert_str_equals($id, $res->[0][1]{notFound}[0]);
}

sub test_email_set_draft
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
    my $draftsmbox = $res->[0][1]{created}{"1"}{id};

    my $draft =  {
        mailboxIds => { $draftsmbox => JSON::true },
        from => [ { name => "Yosemite Sam", email => "sam\@acme.local" } ] ,
        sender => [{ name => "Marvin the Martian", email => "marvin\@acme.local" }],
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
        replyTo => [ { name => undef, email => "the.other.sam\@acme.local" } ],
        subject => "Memo",
        textBody => [{ partId => '1' }],
        htmlBody => [{ partId => '2' }],
        bodyValues => {
            '1' => { value => "I'm givin' ya one last chance ta surrenda!" },
            '2' => { value => "Oh!!! I <em>hate</em> that Rabbit." },
        },
        keywords => { '$Draft' => JSON::true },
    };

    xlog "Create a draft";
    $res = $jmap->CallMethods([['Email/set', { create => { "1" => $draft }}, "R1"]]);
    my $id = $res->[0][1]{created}{"1"}{id};

    xlog "Get draft $id";
    $res = $jmap->CallMethods([['Email/get', { ids => [$id] }, "R1"]]);
    my $msg = $res->[0][1]->{list}[0];

    $self->assert_deep_equals($msg->{mailboxIds}, $draft->{mailboxIds});
    $self->assert_deep_equals($msg->{from}, $draft->{from});
    $self->assert_deep_equals($msg->{sender}, $draft->{sender});
    $self->assert_deep_equals($msg->{to}, $draft->{to});
    $self->assert_deep_equals($msg->{cc}, $draft->{cc});
    $self->assert_deep_equals($msg->{bcc}, $draft->{bcc});
    $self->assert_deep_equals($msg->{replyTo}, $draft->{replyTo});
    $self->assert_str_equals($msg->{subject}, $draft->{subject});
    $self->assert_equals(JSON::true, $msg->{keywords}->{'$draft'});
    $self->assert_num_equals(1, scalar keys %{$msg->{keywords}});

    # Now change the draft keyword, which is allowed since approx ~Q1/2018.
    xlog "Update a draft";
    $res = $jmap->CallMethods([
        ['Email/set', {
            update => { $id => { 'keywords/$draft' => undef } },
        }, "R1"]
    ]);
    $self->assert(exists $res->[0][1]{updated}{$id});
}

sub test_email_set_issue2293
    :min_version_3_1 :needs_component_jmap
{
    my ($self) = @_;
    my $jmap = $self->{jmap};

    my $inboxid = $self->getinbox()->{id};

    my $email =  {
        mailboxIds => { $inboxid => JSON::true },
        from => [ { email => q{test1@robmtest.vm}, name => q{} } ],
        to => [ {
            email => q{foo@bar.com},
            name => "asd \x{529b}\x{9928}\x{5fc5}  asd \x{30ec}\x{30f1}\x{30b9}"
        } ],
    };

    xlog "create and get email";
    my $res = $jmap->CallMethods([
        ['Email/set', { create => { "1" => $email }}, "R1"],
        ['Email/get', { ids => [ "#1" ] }, "R2" ],
    ]);
    my $ret = $res->[1][1]->{list}[0];
    $self->assert_str_equals($email->{to}[0]{email}, $ret->{to}[0]{email});
    $self->assert_str_equals($email->{to}[0]{name}, $ret->{to}[0]{name});


    xlog "create and get email";
    $email->{to}[0]{name} = "asd \x{529b}\x{9928}\x{5fc5}  asd \x{30ec}\x{30f1}\x{30b9} asd  \x{3b1}\x{3bc}\x{3b5}\x{3c4}";

    $res = $jmap->CallMethods([
        ['Email/set', { create => { "1" => $email }}, "R1"],
        ['Email/get', { ids => [ "#1" ] }, "R2" ],
    ]);
    $ret = $res->[1][1]->{list}[0];
    $self->assert_str_equals($email->{to}[0]{email}, $ret->{to}[0]{email});
    $self->assert_str_equals($email->{to}[0]{name}, $ret->{to}[0]{name});

    xlog "create and get email";
    my $to = [{
        name => "abcdefghijklmnopqrstuvwxyz1",
        email => q{abcdefghijklmnopqrstuvwxyz1@local},
    }, {
        name => "abcdefghijklmnopqrstuvwxyz2",
        email => q{abcdefghijklmnopqrstuvwxyz2@local},
    }, {
        name => "abcdefghijklmnopqrstuvwxyz3",
        email => q{abcdefghijklmnopqrstuvwxyz3@local},
    }, {
        name => "abcdefghijklmnopqrstuvwxyz4",
        email => q{abcdefghijklmnopqrstuvwxyz4@local},
    }, {
        name => "abcdefghijklmnopqrstuvwxyz5",
        email => q{abcdefghijklmnopqrstuvwxyz5@local},
    }, {
        name => "abcdefghijklmnopqrstuvwxyz6",
        email => q{abcdefghijklmnopqrstuvwxyz6@local},
    }, {
        name => "abcdefghijklmnopqrstuvwxyz7",
        email => q{abcdefghijklmnopqrstuvwxyz7@local},
    }, {
        name => "abcdefghijklmnopqrstuvwxyz8",
        email => q{abcdefghijklmnopqrstuvwxyz8@local},
    }, {
        name => "abcdefghijklmnopqrstuvwxyz9",
        email => q{abcdefghijklmnopqrstuvwxyz9@local},
    }];
    $email->{to} = $to;

    $res = $jmap->CallMethods([
        ['Email/set', { create => { "1" => $email }}, "R1"],
        ['Email/get', { ids => [ "#1" ] }, "R2" ],
    ]);
    $ret = $res->[1][1]->{list}[0];
    $self->assert_deep_equals($email->{to}, $ret->{to});
}

sub test_email_set_inreplyto
    :min_version_3_1 :needs_component_jmap
{
    my ($self) = @_;
    my $jmap = $self->{jmap};

    my $store = $self->{store};
    my $talk = $store->get_client();

    my $res = $jmap->CallMethods([['Mailbox/get', { }, "R1"]]);
    my $origid = $res->[0][1]{list}[0]{id};

    xlog "Create email to reply to";
    $self->make_message("foo") || die;
    $res = $jmap->CallMethods([
        ['Email/query', { }, "R1"],
        ['Email/get', {
            '#ids' => { resultOf => 'R1', name => 'Email/query', path => '/ids' },
            properties => [ 'id', 'messageId' ],
        }, 'R2'],
    ]);
    $self->assert_num_equals(1, scalar @{$res->[0][1]->{ids}});

    my $orig_msg = $res->[1][1]->{list}[0];
    my $orig_id = $orig_msg->{id};
    my $orig_msgid = $orig_msg->{messageId}[0];
    $self->assert(not exists $orig_msg->{keywords}->{'$answered'});

    xlog "create drafts mailbox";
    $res = $jmap->CallMethods([
            ['Mailbox/set', { create => { "1" => {
                            name => "drafts",
                            parentId => undef,
                            role => "drafts"
             }}}, "R1"]
    ]);
    my $draftsmbox = $res->[0][1]{created}{"1"}{id};

    my $draft =  {
        mailboxIds =>  { $draftsmbox => JSON::true },
        from => [ { name => "Yosemite Sam", email => "sam\@acme.local" } ] ,
        to => [
            { name => "Bugs Bunny", email => "bugs\@acme.local" },
        ],
        subject => "Memo",
        textBody => [{ partId => '1' }],
        bodyValues => { '1' => { value => "I'm givin' ya one last chance ta surrenda!" }},
        inReplyTo => [ $orig_msgid ],
        keywords => { '$Draft' => JSON::true },
    };

    $res = $jmap->CallMethods([['Email/set', { create => { "1" => $draft }}, "R1"]]);
    my $id = $res->[0][1]{created}{"1"}{id};

    $res = $jmap->CallMethods([['Email/get', { ids => [$id] }, "R1"]]);
    my $msg = $res->[0][1]->{list}[0];
    $self->assert_str_equals($orig_msgid, $msg->{inReplyTo}[0]);

    $res = $jmap->CallMethods([['Email/get', { ids => [$orig_id] }, "R1"]]);
    $orig_msg = $res->[0][1]->{list}[0];
    $self->assert_equals(JSON::true, $orig_msg->{keywords}->{'$answered'});
}

sub test_email_set_bodystructure
    :min_version_3_1 :needs_component_jmap
{
    my ($self) = @_;
    my $jmap = $self->{jmap};

    my $store = $self->{store};
    my $talk = $store->get_client();

    xlog "Generate a email in INBOX via IMAP";
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
          . "An embedded email"
          . "\r\n--sub--\r\n",
    ) || die;
    my $res = $jmap->CallMethods([
        ['Email/query', { }, "R1"],
        ['Email/get', {
            '#ids' => { resultOf => 'R1', name => 'Email/query', path => '/ids' },
            properties => ['attachments', 'blobId'],
        }, 'R2' ],
    ]);
    my $emailBlobId = $res->[1][1]->{list}[0]->{blobId};
    my $embeddedEmailBlobId = $res->[1][1]->{list}[0]->{attachments}[0]{blobId};

    xlog "Upload a data blob";
    my $binary = pack "H*", "beefcode";
    my $data = $jmap->Upload($binary, "image/gif");
    my $dataBlobId = $data->{blobId};

    $self->assert_not_null($emailBlobId);
    $self->assert_not_null($embeddedEmailBlobId);
    $self->assert_not_null($dataBlobId);

    my $bodyStructure = {
        type => "multipart/alternative",
        subParts => [{
                type => 'text/plain',
                partId => '1',
            }, {
                type => 'message/rfc822',
                blobId => $embeddedEmailBlobId,
            }, {
                type => 'image/gif',
                blobId => $dataBlobId,
            }, {
                # No type set
                blobId => $dataBlobId,
            }, {
                type => 'message/rfc822',
                blobId => $emailBlobId,
        }],
    };

    xlog "Create email with body structure";
    my $inboxid = $self->getinbox()->{id};
    my $email = {
        mailboxIds => { $inboxid => JSON::true },
        from => [{ name => "Test", email => q{foo@bar} }],
        subject => "test",
        bodyStructure => $bodyStructure,
        bodyValues => {
            "1" => {
                value => "A text body",
            },
        },
    };
    $res = $jmap->CallMethods([
        ['Email/set', { create => { '1' => $email } }, 'R1'],
        ['Email/get', {
            ids => [ '#1' ],
            properties => [ 'bodyStructure' ],
            bodyProperties => [ 'partId', 'blobId', 'type' ],
            fetchAllBodyValues => JSON::true,
        }, 'R2' ],
    ]);

    # Normalize server-set properties
    my $gotBodyStructure = $res->[1][1]{list}[0]{bodyStructure};
    $self->assert_str_equals('multipart/alternative', $gotBodyStructure->{type});
    $self->assert_null($gotBodyStructure->{blobId});
    $self->assert_str_equals('text/plain', $gotBodyStructure->{subParts}[0]{type});
    $self->assert_not_null($gotBodyStructure->{subParts}[0]{blobId});
    $self->assert_str_equals('message/rfc822', $gotBodyStructure->{subParts}[1]{type});
    $self->assert_str_equals($embeddedEmailBlobId, $gotBodyStructure->{subParts}[1]{blobId});
    $self->assert_str_equals('image/gif', $gotBodyStructure->{subParts}[2]{type});
    $self->assert_str_equals($dataBlobId, $gotBodyStructure->{subParts}[2]{blobId});
    # Default type is text/plain if no Content-Type header is set
    $self->assert_str_equals('text/plain', $gotBodyStructure->{subParts}[3]{type});
    $self->assert_str_equals($dataBlobId, $gotBodyStructure->{subParts}[3]{blobId});
    $self->assert_str_equals('message/rfc822', $gotBodyStructure->{subParts}[4]{type});
    $self->assert_str_equals($emailBlobId, $gotBodyStructure->{subParts}[4]{blobId});
}

sub test_email_set_shared
    :min_version_3_1 :needs_component_jmap
{
    my ($self) = @_;

    my $jmap = $self->{jmap};
    my $imaptalk = $self->{store}->get_client();
    my $admintalk = $self->{adminstore}->get_client();

    xlog "Create user and share mailbox";
    $self->{instance}->create_user("foo");
    $admintalk->setacl("user.foo", "cassandane", "lrswntex") or die;

    xlog "Create email in shared account via IMAP";
    $self->{adminstore}->set_folder('user.foo');
    $self->make_message("Email foo", store => $self->{adminstore}) or die;

    xlog "get email";
    my $res = $jmap->CallMethods([
        ['Email/query', { accountId => 'foo' }, "R1"],
    ]);
    my $id = $res->[0][1]->{ids}[0];

    xlog "toggle Seen flag on email";
    $res = $jmap->CallMethods([['Email/set', {
        accountId => 'foo',
        update => { $id => { keywords => { '$Seen' => JSON::true } } },
    }, "R1"]]);
    $self->assert(exists $res->[0][1]{updated}{$id});

    xlog "Remove right to write annotations";
    $admintalk->setacl("user.foo", "cassandane", "lrtex") or die;

    xlog 'Toggle \\Seen flag on email (should fail)';
    $res = $jmap->CallMethods([['Email/set', {
        accountId => 'foo',
        update => { $id => { keywords => { } } },
    }, "R1"]]);
    $self->assert(exists $res->[0][1]{notUpdated}{$id});

    xlog "Remove right to delete email";
    $admintalk->setacl("user.foo", "cassandane", "lr") or die;

    xlog 'Delete email (should fail)';
    $res = $jmap->CallMethods([['Email/set', {
        accountId => 'foo',
        destroy => [ $id ],
    }, "R1"]]);
    $self->assert(exists $res->[0][1]{notDestroyed}{$id});

    xlog "Add right to delete email";
    $admintalk->setacl("user.foo", "cassandane", "lrtex") or die;

    xlog 'Delete email';
    $res = $jmap->CallMethods([['Email/set', {
            accountId => 'foo',
            destroy => [ $id ],
    }, "R1"]]);
    $self->assert_str_equals($id, $res->[0][1]{destroyed}[0]);
}

sub test_email_set_userkeywords
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
    my $draftsmbox = $res->[0][1]{created}{"1"}{id};

    my $draft =  {
        mailboxIds =>  { $draftsmbox => JSON::true },
        from => [ { name => "Yosemite Sam", email => "sam\@acme.local" } ] ,
        to => [
            { name => "Bugs Bunny", email => "bugs\@acme.local" },
        ],
        subject => "Memo",
        textBody => [{ partId => '1' }],
        bodyValues => {
            '1' => {
                value => "I'm givin' ya one last chance ta surrenda!"
            }
        },
        keywords => {
            '$Draft' => JSON::true,
            'foo' => JSON::true
        },
    };

    xlog "Create a draft";
    $res = $jmap->CallMethods([['Email/set', { create => { "1" => $draft }}, "R1"]]);
    my $id = $res->[0][1]{created}{"1"}{id};

    xlog "Get draft $id";
    $res = $jmap->CallMethods([['Email/get', { ids => [$id] }, "R1"]]);
    my $msg = $res->[0][1]->{list}[0];

    $self->assert_equals(JSON::true, $msg->{keywords}->{'$draft'});
    $self->assert_equals(JSON::true, $msg->{keywords}->{'foo'});
    $self->assert_num_equals(2, scalar keys %{$msg->{keywords}});

    xlog "Update draft";
    $res = $jmap->CallMethods([['Email/set', {
        update => {
            $id => {
                "keywords" => {
                    '$Draft' => JSON::true,
                    'foo' => JSON::true,
                    'bar' => JSON::true
                }
            }
        }
    }, "R1"]]);

    xlog "Get draft $id";
    $res = $jmap->CallMethods([['Email/get', { ids => [$id] }, "R1"]]);
    $msg = $res->[0][1]->{list}[0];
    $self->assert_equals(JSON::true, JSON::true, $msg->{keywords}->{'$draft'}); # case-insensitive!
    $self->assert_equals(JSON::true, $msg->{keywords}->{'foo'});
    $self->assert_equals(JSON::true, $msg->{keywords}->{'bar'});
    $self->assert_num_equals(3, scalar keys %{$msg->{keywords}});
}

sub test_email_set_keywords_bogus_values
{
    my ($self) = @_;
    my $jmap = $self->{jmap};

    # See https://github.com/cyrusimap/cyrus-imapd/issues/2439

    $self->make_message("foo") || die;
    my $res = $jmap->CallMethods([['Email/query', { }, "R1"]]);
    my $emailId = $res->[0][1]{ids}[0];
    $self->assert_not_null($res);

    $res = $jmap->CallMethods([['Email/set', {
        'update' => { $emailId => {
            keywords => {
                'foo' => JSON::false,
            },
        }},
    }, 'R1' ]]);
    $self->assert_not_null($res->[0][1]{notUpdated}{$emailId});

    $res = $jmap->CallMethods([['Email/set', {
        'update' => { $emailId => {
            'keywords/foo' => JSON::false,
            },
        },
    }, 'R1' ]]);
    $self->assert_not_null($res->[0][1]{notUpdated}{$emailId});

    $res = $jmap->CallMethods([['Email/set', {
        'update' => { $emailId => {
            keywords => {
                'foo' => 1,
            },
        }},
    }, 'R1' ]]);
    $self->assert_not_null($res->[0][1]{notUpdated}{$emailId});

    $res = $jmap->CallMethods([['Email/set', {
        'update' => { $emailId => {
            'keywords/foo' => 1,
            },
        },
    }, 'R1' ]]);
    $self->assert_not_null($res->[0][1]{notUpdated}{$emailId});

    $res = $jmap->CallMethods([['Email/set', {
        'update' => { $emailId => {
            keywords => {
                'foo' => 'true',
            },
        }},
    }, 'R1' ]]);
    $self->assert_not_null($res->[0][1]{notUpdated}{$emailId});

    $res = $jmap->CallMethods([['Email/set', {
        'update' => { $emailId => {
            'keywords/foo' => 'true',
            },
        },
    }, 'R1' ]]);
    $self->assert_not_null($res->[0][1]{notUpdated}{$emailId});

    $res = $jmap->CallMethods([['Email/set', {
        'update' => { $emailId => {
            keywords => {
                'foo' => JSON::true,
            },
        }},
    }, 'R1' ]]);
    $self->assert(exists $res->[0][1]{updated}{$emailId});
}

sub test_misc_upload_zero
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
    my $draftsmbox = $res->[0][1]{created}{"1"}{id};

    my $data = $jmap->Upload("", "text/plain");
    $self->assert_matches(qr/^Gda39a3ee5e6b4b0d3255bfef95601890/, $data->{blobId});
    $self->assert_num_equals(0, $data->{size});
    $self->assert_str_equals("text/plain", $data->{type});

    my $msgresp = $jmap->CallMethods([
      ['Email/set', { create => { "2" => {
        mailboxIds =>  { $draftsmbox => JSON::true },
        from => [ { name => "Yosemite Sam", email => "sam\@acme.local" } ] ,
        to => [
            { name => "Bugs Bunny", email => "bugs\@acme.local" },
        ],
        subject => "Memo",
        textBody => [{ partId => '1' }],
        bodyValues => {
            '1' => {
                value => "I'm givin' ya one last chance ta surrenda!"
            }
        },
        attachedFiles => [{
            blobId => $data->{blobId},
            name => "emptyfile.txt",
        }],
        keywords => { '$Draft' => JSON::true },
      } } }, 'R2'],
    ]);

    $self->assert_not_null($msgresp->[0][1]{created});
}

sub test_misc_upload
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
    my $draftsmbox = $res->[0][1]{created}{"1"}{id};

    my $data = $jmap->Upload("a message with some text", "text/rubbish");
    $self->assert_matches(qr/^G44911b55c3b83ca05db9659d7a8e8b7b/, $data->{blobId});
    $self->assert_num_equals(24, $data->{size});
    $self->assert_str_equals("text/rubbish", $data->{type});

    my $msgresp = $jmap->CallMethods([
      ['Email/set', { create => { "2" => {
        mailboxIds =>  { $draftsmbox => JSON::true },
        from => [ { name => "Yosemite Sam", email => "sam\@acme.local" } ] ,
        to => [
            { name => "Bugs Bunny", email => "bugs\@acme.local" },
        ],
        subject => "Memo",
        textBody => [{partId => '1'}],
        htmlBody => [{partId => '2'}],
        bodyValues => {
            1 => {
                value => "I'm givin' ya one last chance ta surrenda!"
            },
            2 => {
                value => "<html>I'm givin' ya one last chance ta surrenda!</html>"
            },
        },
        attachedFiles => [{
            blobId => $data->{blobId},
            name => "test.txt",
        }],
        keywords => { '$Draft' => JSON::true },
      } } }, 'R2'],
    ]);

    $self->assert_not_null($msgresp->[0][1]{created});
}

sub test_misc_upload_multiaccount
    :min_version_3_1 :needs_component_jmap
{
    my ($self) = @_;
    my $jmap = $self->{jmap};

    my $imaptalk = $self->{store}->get_client();
    my $admintalk = $self->{adminstore}->get_client();

    # Create user and share mailbox
    $self->{instance}->create_user("foo");
    $admintalk->setacl("user.foo", "cassandane", "lrwkxd") or die;

    # Create user but don't share mailbox
    $self->{instance}->create_user("bar");

    my @res = $jmap->Upload("a email with some text", "text/rubbish", "foo");
    $self->assert_str_equals($res[0]->{status}, '201');

    @res = $jmap->Upload("a email with some text", "text/rubbish", "bar");
    $self->assert_str_equals($res[0]->{status}, '404');
}

sub test_misc_upload_bin
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
    my $draftsmbox = $res->[0][1]{created}{"1"}{id};

    my $logofile = abs_path('data/logo.gif');
    open(FH, "<$logofile");
    local $/ = undef;
    my $binary = <FH>;
    close(FH);
    my $data = $jmap->Upload($binary, "image/gif");

    my $msgresp = $jmap->CallMethods([
      ['Email/set', { create => { "2" => {
        mailboxIds =>  { $draftsmbox => JSON::true },
        from => [ { name => "Yosemite Sam", email => "sam\@acme.local" } ] ,
        to => [
            { name => "Bugs Bunny", email => "bugs\@acme.local" },
        ],
        subject => "Memo",
        textBody => [{ partId => '1' }],
        bodyValues => { 1 => { value => "I'm givin' ya one last chance ta surrenda!" }},
        attachedFiles => [{
            blobId => $data->{blobId},
            name => "logo.gif",
        }],
        keywords => { '$Draft' => JSON::true },
      } } }, 'R2'],
    ]);

    $self->assert_not_null($msgresp->[0][1]{created});

    # XXX - fetch back the parts
}

sub test_misc_download
    :min_version_3_1 :needs_component_jmap
{
    my ($self) = @_;
    my $jmap = $self->{jmap};

    my $store = $self->{store};
    my $talk = $store->get_client();
    my $inbox = 'INBOX';

    # Generate a email to have some blob ids
    xlog "Generate a email in $inbox via IMAP";
    $self->make_message("foo",
        mime_type => "multipart/mixed",
        mime_boundary => "sub",
        body => ""
          . "--sub\r\n"
          . "Content-Type: text/plain; charset=UTF-8\r\n"
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
          . "\r\n--sub--\r\n",
    );

    xlog "get email list";
    my $res = $jmap->CallMethods([['Email/query', {}, "R1"]]);
    my $ids = $res->[0][1]->{ids};

    xlog "get email";
    $res = $jmap->CallMethods([['Email/get', {
        ids => $ids,
        properties => ['bodyStructure'],
    }, "R1"]]);
    my $msg = $res->[0][1]{list}[0];

    my $blobid1 = $msg->{bodyStructure}{subParts}[1]{blobId};
    my $blobid2 = $msg->{bodyStructure}{subParts}[2]{blobId};
    $self->assert_not_null($blobid1);
    $self->assert_not_null($blobid2);

    $res = $jmap->Download('cassandane', $blobid1);
    $self->assert_str_equals(encode_base64($res->{content}, ''), "beefc0de");
}

sub test_base64_forward
    :min_version_3_1 :needs_component_jmap
{
    my ($self) = @_;
    my $jmap = $self->{jmap};

    my $store = $self->{store};
    my $talk = $store->get_client();
    my $inbox = 'INBOX';

    # Generate a email to have some blob ids
    xlog "Generate a email in $inbox via IMAP";
    $self->make_message("foo",
        mime_type => "multipart/mixed",
        mime_boundary => "sub",
        body => ""
          . "--sub\r\n"
          . "Content-Type: text/plain; charset=UTF-8\r\n"
          . "some text"
          . "\r\n--sub\r\n"
          . "Content-Type: image/jpeg\r\n"
          . "Content-Transfer-Encoding: base64\r\n" . "\r\n"
          . "beefc0de"
          . "\r\n--sub--\r\n",
    );

    xlog "get email list";
    my $res = $jmap->CallMethods([['Email/query', {}, "R1"]]);
    my $ids = $res->[0][1]->{ids};

    xlog "get email";
    $res = $jmap->CallMethods([['Email/get', {
        ids => $ids,
        properties => ['bodyStructure', 'mailboxIds'],
    }, "R1"]]);
    my $msg = $res->[0][1]{list}[0];

    my $blobid = $msg->{bodyStructure}{subParts}[1]{blobId};
    $self->assert_not_null($blobid);
    my $size = $msg->{bodyStructure}{subParts}[1]{size};
    $self->assert_num_equals(6, $size);

    $res = $jmap->Download('cassandane', $blobid);
    $self->assert_str_equals("beefc0de", encode_base64($res->{content}, ''));

    # now create a new message referencing this blobId:

    $res = $jmap->CallMethods([['Email/set', {
        create => {
            k1 => {
                bcc => undef,
                bodyStructure => {
                    subParts => [{
                        partId => 'text',
                        type => 'text/plain',
                    },{
                        blobId => $blobid,
                        cid => undef,
                        disposition => 'attachment',
                        height => undef,
                        name => 'foobar.jpg',
                        size => $size,
                        type => 'image/jpeg',
                        width => undef,
                    }],
                    type => 'multipart/mixed',
                },
                bodyValues => {
                    text => {
                        isTruncated => $JSON::false,
                        value => "Hello world",
                    },
                },
                cc => undef,
                inReplyTo => undef,
                mailboxIds => $msg->{mailboxIds},
                from => [ {email => 'foo@example.com', name => 'foo' } ],
                keywords => { '$draft' => $JSON::true, '$seen' => $JSON::true },
                receivedAt => '2018-06-26T03:10:07Z',
                references => undef,
                replyTo => undef,
                sentAt => '2018-06-26T03:10:07Z',
                subject => 'test email',
                to => [ {email => 'foo@example.com', name => 'foo' } ],
            },
        },
    }, "R1"]]);

    my $id = $res->[0][1]{created}{k1}{id};
    $self->assert_not_null($id);

    $res = $jmap->CallMethods([['Email/get', {
        ids => [$id],
        properties => ['bodyStructure'],
    }, "R1"]]);
    $msg = $res->[0][1]{list}[0];

    my $newpart = $msg->{bodyStructure}{subParts}[1];
    $self->assert_str_equals("foobar.jpg", $newpart->{name});
    $self->assert_str_equals("image/jpeg", $newpart->{type});
    $self->assert_num_equals(6, $newpart->{size});

    # XXX - in theory, this IS allowed to change
    if ($newpart->{blobId} ne $blobid) {
        $res = $jmap->Download('cassandane', $blobid);
        # but this isn't!
        $self->assert_str_equals("beefc0de", encode_base64($res->{content}, ''));
    }
}

sub download
{
    my ($self, $accountid, $blobid) = @_;
    my $jmap = $self->{jmap};

    my $uri = $jmap->downloaduri($accountid, $blobid);
    my %Headers;
    $Headers{'Authorization'} = $jmap->auth_header();
    my %getopts = (headers => \%Headers);
    my $res = $jmap->ua->get($uri, \%getopts);
    xlog "JMAP DOWNLOAD @_ " . Dumper($res);
    return $res;
}

sub test_blob_copy
    :min_version_3_1 :needs_component_jmap
{
    my ($self) = @_;
    my $jmap = $self->{jmap};

    my $imaptalk = $self->{store}->get_client();
    my $admintalk = $self->{adminstore}->get_client();

    # FIXME how to share just #jmap folder?
    xlog "create user foo and share inbox";
    $self->{instance}->create_user("foo");
    $admintalk->setacl("user.foo", "cassandane", "lrkintex") or die;

    xlog "upload blob in main account";
    my $data = $jmap->Upload('somedata', "text/plain");
    $self->assert_not_null($data);

    xlog "attempt to download from shared account (should fail)";
    my $res = $self->download('foo', $data->{blobId});
    $self->assert_str_equals('404', $res->{status});

    xlog "copy blob to shared account";
    $res = $jmap->CallMethods([['Blob/copy', {
        fromAccountId => 'cassandane',
        toAccountId => 'foo',
        blobIds => [ $data->{blobId} ],
    }, 'R1']]);

    xlog "download from shared account";
    $res = $self->download('foo', $data->{blobId});
    $self->assert_str_equals('200', $res->{status});

    xlog "generate an email in INBOX via IMAP";
    $self->make_message("Email A") || die;

    xlog "get email blob id";
    $res = $jmap->CallMethods([
        ['Email/query', {}, "R1"],
        ['Email/get', {
            '#ids' => {
                resultOf => 'R1',
                name => 'Email/query',
                path => '/ids'
            },
            properties => [ 'blobId' ],
        }, 'R2']
    ]);
    my $msgblobId = $res->[1][1]->{list}[0]{blobId};

    xlog "copy Email blob to shared account";
    $res = $jmap->CallMethods([['Blob/copy', {
        fromAccountId => 'cassandane',
        toAccountId => 'foo',
        blobIds => [ $msgblobId ],
    }, 'R1']]);

    xlog "download Email blob from shared account";
    $res = $self->download('foo', $msgblobId);
    $self->assert_str_equals('200', $res->{status});
}

sub test_email_set_attachments
    :min_version_3_1 :needs_component_jmap
{
    my ($self) = @_;
    my $jmap = $self->{jmap};

    my $store = $self->{store};
    my $talk = $store->get_client();
    my $inbox = 'INBOX';

    # Generate a email to have some blob ids
    xlog "Generate a email in $inbox via IMAP";
    $self->make_message("foo",
        mime_type => "multipart/mixed",
        mime_boundary => "sub",
        body => ""
          . "--sub\r\n"
          . "Content-Type: text/plain; charset=UTF-8\r\n"
          . "Content-Disposition: inline\r\n" . "\r\n"
          . "some text"
          . "\r\n--sub\r\n"
          . "Content-Type: image/jpeg;foo=bar\r\n"
          . "Content-Disposition: attachment\r\n"
          . "Content-Transfer-Encoding: base64\r\n" . "\r\n"
          . "beefc0de"
          . "\r\n--sub\r\n"
          . "Content-Type: image/png\r\n"
          . "Content-Disposition: attachment\r\n"
          . "Content-Transfer-Encoding: base64\r\n"
          . "\r\n"
          . "f00bae=="
          . "\r\n--sub--\r\n",
    );

    xlog "get email list";
    my $res = $jmap->CallMethods([['Email/query', {}, "R1"]]);
    my $ids = $res->[0][1]->{ids};

    xlog "get email";
    $res = $jmap->CallMethods([['Email/get', { ids => $ids }, "R1"]]);
    my $msg = $res->[0][1]{list}[0];

    my %m = map { $_->{type} => $_ } @{$res->[0][1]{list}[0]->{attachments}};
    my $blobJpeg = $m{"image/jpeg"}->{blobId};
    my $blobPng = $m{"image/png"}->{blobId};
    $self->assert_not_null($blobJpeg);
    $self->assert_not_null($blobPng);

    xlog "create drafts mailbox";
    $res = $jmap->CallMethods([
            ['Mailbox/set', { create => { "1" => {
                            name => "drafts",
                            parentId => undef,
                            role => "drafts"
             }}}, "R1"]
    ]);
    $self->assert_str_equals($res->[0][0], 'Mailbox/set');
    $self->assert_str_equals($res->[0][2], 'R1');
    $self->assert_not_null($res->[0][1]{created});
    my $draftsmbox = $res->[0][1]{created}{"1"}{id};
    my $shortfname = "test\N{GRINNING FACE}.jpg";
    my $longfname = "a_very_long_filename_thats_looking_quite_bogus_but_in_fact_is_absolutely_valid\N{GRINNING FACE}!.bin";

    my $draft =  {
        mailboxIds =>  { $draftsmbox => JSON::true },
        from => [ { name => "Yosemite Sam", email => "sam\@acme.local" } ] ,
        to => [ { name => "Bugs Bunny", email => "bugs\@acme.local" }, ],
        subject => "Memo",
        htmlBody => [{ partId => '1' }],
        bodyValues => {
            '1' => {
                value => "<html>I'm givin' ya one last chance ta surrenda! ".
                         "<img src=\"cid:foo\@local\"></html>",
            },
        },
        attachments => [{
            blobId => $blobJpeg,
            name => $shortfname,
            type => 'image/jpeg',
        }, {
            blobId => $blobPng,
            cid => "foo\@local",
            type => 'image/png',
            disposition => 'inline',
        }, {
            blobId => $blobJpeg,
            type => "application/test",
            name => $longfname,
        }, {
            blobId => $blobPng,
            type => "application/test2",
            name => "simple",
        }],
        keywords => { '$Draft' => JSON::true },
    };

    my $wantBodyStructure = {
        type => 'multipart/mixed',
        name => undef,
        cid => undef,
        disposition => undef,
        subParts => [{
            type => 'multipart/related',
            name => undef,
            cid => undef,
            disposition => undef,
            subParts => [{
                type => 'text/html',
                name => undef,
                cid => undef,
                disposition => undef,
                subParts => [],
            },{
                type => 'image/png',
                cid => "foo\@local",
                disposition => 'inline',
                name => undef,
                subParts => [],
            }],
        },{
            type => 'image/jpeg',
            name => $shortfname,
            cid => undef,
            disposition => 'attachment',
            subParts => [],
        },{
            type => 'application/test',
            name => $longfname,
            cid => undef,
            disposition => 'attachment',
            subParts => [],
        },{
            type => 'application/test2',
            name => 'simple',
            cid => undef,
            disposition => 'attachment',
            subParts => [],
        }]
    };

    xlog "Create a draft";
    $res = $jmap->CallMethods([['Email/set', { create => { "1" => $draft }}, "R1"]]);
    my $id = $res->[0][1]{created}{"1"}{id};

    xlog "Get draft $id";
    $res = $jmap->CallMethods([['Email/get', {
            ids => [$id],
            properties => ['bodyStructure'],
            bodyProperties => ['type', 'name', 'cid','disposition', 'subParts'],
    }, "R1"]]);
    $msg = $res->[0][1]->{list}[0];

    $self->assert_deep_equals($wantBodyStructure, $msg->{bodyStructure});
}

sub test_email_set_flagged
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
    my $drafts = $res->[0][1]{created}{"1"}{id};

    my $draft =  {
        mailboxIds =>  { $drafts => JSON::true },
        keywords => { '$Draft' => JSON::true, '$Flagged' => JSON::true },
        textBody => [{ partId => '1' }],
        bodyValues => { '1' => { value => "a flagged draft" }},
    };

    xlog "Create a draft";
    $res = $jmap->CallMethods([['Email/set', { create => { "1" => $draft }}, "R1"]]);
    my $id = $res->[0][1]{created}{"1"}{id};

    xlog "Get draft $id";
    $res = $jmap->CallMethods([['Email/get', { ids => [$id] }, "R1"]]);
    my $msg = $res->[0][1]->{list}[0];

    $self->assert_deep_equals($msg->{mailboxIds}, $draft->{mailboxIds});
    $self->assert_equals(JSON::true, $msg->{keywords}->{'$flagged'});
}

sub test_email_set_mailboxids
    :min_version_3_1 :needs_component_jmap
{
    my ($self) = @_;
    my $jmap = $self->{jmap};

    my $inboxid = $self->getinbox()->{id};
    $self->assert_not_null($inboxid);

    my $res = $jmap->CallMethods([
        ['Mailbox/set', { create => {
            "1" => { name => "drafts", parentId => undef, role => "drafts" },
        }}, "R1"]
    ]);
    my $draftsid = $res->[0][1]{created}{"1"}{id};
    $self->assert_not_null($draftsid);

    my $msg =  {
        from => [ { name => "Yosemite Sam", email => "sam\@acme.local" } ],
        to => [ { name => "Bugs Bunny", email => "bugs\@acme.local" }, ],
        subject => "Memo",
        textBody => [{ partId => '1' }],
        bodyValues => { '1' => { value => "I'm givin' ya one last chance ta surrenda!" }},
        keywords => { '$Draft' => JSON::true },
    };

    # Not OK: at least one mailbox must be specified
    $res = $jmap->CallMethods([['Email/set', { create => { "1" => $msg }}, "R1"]]);
    $self->assert_str_equals('invalidProperties', $res->[0][1]{notCreated}{"1"}{type});
    $self->assert_str_equals('mailboxIds', $res->[0][1]{notCreated}{"1"}{properties}[0]);
    $msg->{mailboxIds} = {};
    $res = $jmap->CallMethods([['Email/set', { create => { "1" => $msg }}, "R1"]]);
    $self->assert_str_equals('invalidProperties', $res->[0][1]{notCreated}{"1"}{type});
    $self->assert_str_equals('mailboxIds', $res->[0][1]{notCreated}{"1"}{properties}[0]);

    # OK: drafts mailbox isn't required (anymore)
    $msg->{mailboxIds} = { $inboxid => JSON::true },
    $msg->{subject} = "Email 1";
    $res = $jmap->CallMethods([['Email/set', { create => { "1" => $msg }}, "R1"]]);
    $self->assert(exists $res->[0][1]{created}{"1"});

    # OK: drafts mailbox is OK to create in
    $msg->{mailboxIds} = { $draftsid => JSON::true },
    $msg->{subject} = "Email 2";
    $res = $jmap->CallMethods([['Email/set', { create => { "1" => $msg }}, "R1"]]);
    $self->assert(exists $res->[0][1]{created}{"1"});

    # OK: drafts mailbox is OK to create in, as is for multiple mailboxes
    $msg->{mailboxIds} = { $draftsid => JSON::true, $inboxid => JSON::true },
    $msg->{subject} = "Email 3";
    $res = $jmap->CallMethods([['Email/set', { create => { "1" => $msg }}, "R1"]]);
    $self->assert(exists $res->[0][1]{created}{"1"});
}

sub test_email_get_keywords
    :min_version_3_1 :needs_component_jmap
{
    my ($self) = @_;
    my $jmap = $self->{jmap};

    my $store = $self->{store};
    my $talk = $store->get_client();

    xlog "Create IMAP mailbox and message A";
    $talk->create('INBOX.A') || die;
    $store->set_folder('INBOX.A');
    $self->make_message('A') || die;

    xlog "Create IMAP mailbox B and copy message A to B";
    $talk->create('INBOX.B') || die;
    $talk->copy('1:*', 'INBOX.B');
    $self->assert_str_equals('ok', $talk->get_last_completion_response());

    my $res = $jmap->CallMethods([
        ['Email/query', { }, 'R1'],
        ['Email/get', {
            '#ids' => { resultOf => 'R1', name => 'Email/query', path => '/ids'}
        }, 'R2' ]
    ]);
    $self->assert_num_equals(1, scalar @{$res->[1][1]{list}});
    my $jmapmsg = $res->[1][1]{list}[0];
    $self->assert_not_null($jmapmsg);

    # Keywords are empty by default
    my $keywords = {};
    $self->assert_deep_equals($keywords, $jmapmsg->{keywords});

    xlog "Set \\Seen on message A";
    $store->set_folder('INBOX.A');
    $talk->store('1', '+flags', '(\\Seen)');

    # Seen must only be set if ALL messages are seen.
    $res = $jmap->CallMethods([
        ['Email/get', { 'ids' => [ $jmapmsg->{id} ] }, 'R2' ]
    ]);
    $jmapmsg = $res->[0][1]{list}[0];
    $keywords = {};
    $self->assert_deep_equals($keywords, $jmapmsg->{keywords});

    xlog "Set \\Seen on message B";
    $store->set_folder('INBOX.B');
    $store->_select();
    $talk->store('1', '+flags', '(\\Seen)');

    # Seen must only be set if ALL messages are seen.
    $res = $jmap->CallMethods([
        ['Email/get', { 'ids' => [ $jmapmsg->{id} ] }, 'R2' ]
    ]);
    $jmapmsg = $res->[0][1]{list}[0];
    $keywords = {
        '$seen' => JSON::true,
    };
    $self->assert_deep_equals($keywords, $jmapmsg->{keywords});

    xlog "Set \\Flagged on message B";
    $store->set_folder('INBOX.B');
    $store->_select();
    $talk->store('1', '+flags', '(\\Flagged)');

    # Any other keyword is set if set on any IMAP message of this email.
    $res = $jmap->CallMethods([
        ['Email/get', { 'ids' => [ $jmapmsg->{id} ] }, 'R2' ]
    ]);
    $jmapmsg = $res->[0][1]{list}[0];
    $keywords = {
        '$seen' => JSON::true,
        '$flagged' => JSON::true,
    };
    $self->assert_deep_equals($keywords, $jmapmsg->{keywords});
}

sub test_email_get_keywords_case_insensitive
    :min_version_3_1 :needs_component_jmap
{
    my ($self) = @_;
    my $jmap = $self->{jmap};

    my $store = $self->{store};
    my $talk = $store->get_client();

    xlog "Create IMAP mailbox and message A";
    $talk->create('INBOX.A') || die;
    $store->set_folder('INBOX.A');
    $self->make_message('A') || die;

    xlog "Set flag Foo and Flagged on message A";
    $store->set_folder('INBOX.A');
    $talk->store('1', '+flags', '(Foo \\Flagged)');

    my $res = $jmap->CallMethods([
        ['Email/query', { }, 'R1'],
        ['Email/get', {
            '#ids' => { resultOf => 'R1', name => 'Email/query', path => '/ids'}
        }, 'R2' ]
    ]);
    $self->assert_num_equals(1, scalar @{$res->[1][1]{list}});
    my $jmapmsg = $res->[1][1]{list}[0];
    my $keywords = {
        'foo' => JSON::true,
        '$flagged' => JSON::true,
    };
    $self->assert_deep_equals($keywords, $jmapmsg->{keywords});
}

sub test_email_set_keywords
    :min_version_3_1 :needs_component_jmap
{
    my ($self) = @_;
    my $jmap = $self->{jmap};

    my $store = $self->{store};
    my $talk = $store->get_client();
    $self->{store}->set_fetch_attributes(qw(uid flags));

    xlog "Create IMAP mailboxes";
    $talk->create('INBOX.A') || die;
    $talk->create('INBOX.B') || die;
    $talk->create('INBOX.C') || die;

    xlog "Get JMAP mailboxes";
    my $res = $jmap->CallMethods([['Mailbox/get', { properties => [ 'name' ]}, "R1"]]);
    my %jmailboxes = map { $_->{name} => $_ } @{$res->[0][1]{list}};
    $self->assert_num_equals(scalar keys %jmailboxes, 4);
    my $jmailboxA = $jmailboxes{A};
    my $jmailboxB = $jmailboxes{B};
    my $jmailboxC = $jmailboxes{C};

    my %mailboxA;
    my %mailboxB;
    my %mailboxC;

    xlog "Create message in mailbox A";
    $store->set_folder('INBOX.A');
    $mailboxA{1} = $self->make_message('Message');
    $mailboxA{1}->set_attributes(id => 1, uid => 1, flags => []);

    xlog "Copy message from A to B";
    $talk->copy('1:*', 'INBOX.B');
    $self->assert_str_equals('ok', $talk->get_last_completion_response());

    xlog "Set IMAP flag foo on message A";
    $store->set_folder('INBOX.A');
    $store->_select();
    $talk->store('1', '+flags', '(foo)');

    xlog "Get JMAP keywords";
    $res = $jmap->CallMethods([
        ['Email/query', { }, 'R1'],
        ['Email/get', {
            '#ids' => {
                resultOf => 'R1',
                name => 'Email/query',
                path => '/ids'
            },
            properties => [ 'keywords']
        }, 'R2' ]
    ]);
    my $jmapmsg = $res->[1][1]{list}[0];
    my $keywords = {
        foo => JSON::true
    };
    $self->assert_deep_equals($keywords, $jmapmsg->{keywords});

    xlog "Update JMAP email keywords";
    $keywords = {
        bar => JSON::true,
        baz => JSON::true,
    };
    $res = $jmap->CallMethods([
        ['Email/set', {
            update => {
                $jmapmsg->{id} => {
                    keywords => $keywords
                }
            }
        }, 'R1'],
        ['Email/get', {
            ids => [ $jmapmsg->{id} ],
            properties => ['keywords']
        }, 'R2' ]
    ]);
    $jmapmsg = $res->[1][1]{list}[0];
    $self->assert_deep_equals($keywords, $jmapmsg->{keywords});

    xlog "Set \\Seen on message in mailbox B";
    $store->set_folder('INBOX.B');
    $store->_select();
    $talk->store('1', '+flags', '(\\Seen)');

    xlog "Patch JMAP email keywords and update mailboxIds";
    $res = $jmap->CallMethods([
        ['Email/set', {
            update => {
                $jmapmsg->{id} => {
                    'keywords/bar' => undef,
                    'keywords/qux' => JSON::true,
                    mailboxIds => {
                        $jmailboxB->{id} => JSON::true,
                        $jmailboxC->{id} => JSON::true,
                    }
                }
            }
        }, 'R1'],
        ['Email/get', {
            ids => [ $jmapmsg->{id} ],
            properties => ['keywords', 'mailboxIds']
        }, 'R2' ]
    ]);
    $jmapmsg = $res->[1][1]{list}[0];
    $keywords = {
        baz => JSON::true,
        qux => JSON::true,
    };
    $self->assert_deep_equals($keywords, $jmapmsg->{keywords});

    $self->assert_str_not_equals($res->[0][1]{oldState}, $res->[0][1]{newState});

    xlog "Set \\Seen on message in mailbox C";
    $store->set_folder('INBOX.C');
    $store->_select();
    $talk->store('1', '+flags', '(\\Seen)');

    xlog "Get JMAP keywords";
    $res = $jmap->CallMethods([
        ['Email/get', {
            ids => [ $jmapmsg->{id} ],
            properties => [ 'keywords']
        }, 'R2' ]
    ]);
    $jmapmsg = $res->[0][1]{list}[0];
    $keywords = {
        baz => JSON::true,
        qux => JSON::true,
        '$seen' => JSON::true
    };
    $self->assert_deep_equals($keywords, $jmapmsg->{keywords});
}

sub test_emailsubmission_set
    :min_version_3_1 :needs_component_jmap
{
    my ($self) = @_;
    my $jmap = $self->{jmap};

    my $res = $jmap->CallMethods( [ [ 'Identity/get', {}, "R1" ] ] );
    my $identityid = $res->[0][1]->{list}[0]->{id};
    $self->assert_not_null($identityid);

    xlog "Generate a email via IMAP";
    $self->make_message("foo", body => "a email") or die;

    xlog "get email id";
    $res = $jmap->CallMethods( [ [ 'Email/query', {}, "R1" ] ] );
    my $emailid = $res->[0][1]->{ids}[0];

    xlog "create email submission";
    $res = $jmap->CallMethods( [ [ 'EmailSubmission/set', {
        create => {
            '1' => {
                identityId => $identityid,
                emailId  => $emailid,
            }
       }
    }, "R1" ] ] );
    my $msgsubid = $res->[0][1]->{created}{1}{id};
    $self->assert_not_null($msgsubid);

    xlog "get email submission";
    $res = $jmap->CallMethods( [ [ 'EmailSubmission/get', {
        ids => [ $msgsubid ],
    }, "R1" ] ] );
    $self->assert_str_equals($msgsubid, $res->[0][1]->{notFound}[0]);

    xlog "update email submission";
    $res = $jmap->CallMethods( [ [ 'EmailSubmission/set', {
        update => {
            $msgsubid => {
                undoStatus => 'canceled',
            }
       }
    }, "R1" ] ] );
    $self->assert_str_equals('notFound', $res->[0][1]->{notUpdated}{$msgsubid}{type});

    xlog "destroy email submission";
    $res = $jmap->CallMethods( [ [ 'EmailSubmission/set', {
        destroy => [ $msgsubid ],
    }, "R1" ] ] );
    $self->assert_str_equals("notFound", $res->[0][1]->{notDestroyed}{$msgsubid}{type});
}

sub test_emailsubmission_set_with_envelope
    :min_version_3_1 :needs_component_jmap
{
    my ($self) = @_;
    my $jmap = $self->{jmap};

    my $res = $jmap->CallMethods( [ [ 'Identity/get', {}, "R1" ] ] );
    my $identityid = $res->[0][1]->{list}[0]->{id};
    $self->assert_not_null($identityid);

    xlog "Generate a email via IMAP";
    $self->make_message("foo", body => "a email\r\nwithCRLF\r\n") or die;

    xlog "get email id";
    $res = $jmap->CallMethods( [ [ 'Email/query', {}, "R1" ] ] );
    my $emailid = $res->[0][1]->{ids}[0];

    xlog "create email submission";
    $res = $jmap->CallMethods( [ [ 'EmailSubmission/set', {
        create => {
            '1' => {
                identityId => $identityid,
                emailId  => $emailid,
                envelope => {
                    mailFrom => {
                        email => 'from@localhost',
                    },
                    rcptTo => [{
                        email => 'rcpt1@localhost',
                    }, {
                        email => 'rcpt2@localhost',
                    }],
                },
            }
       }
    }, "R1" ] ] );
    my $msgsubid = $res->[0][1]->{created}{1}{id};
    $self->assert_not_null($msgsubid);
}

sub test_emailsubmission_set_issue2285
    :min_version_3_1 :needs_component_jmap
{
    my ($self) = @_;
    my $jmap = $self->{jmap};

    my $res = $jmap->CallMethods( [ [ 'Identity/get', {}, "R1" ] ] );
    my $identityid = $res->[0][1]->{list}[0]->{id};
    my $inboxid = $self->getinbox()->{id};

    xlog "Create email";
    $res = $jmap->CallMethods([
    [ 'Email/set', {
        create => {
            'k40' => {
                'bcc' => undef,
                'cc' => undef,
                'attachments' => undef,
                'subject' => 'zlskdjgh',
                'identityId' => 'test1@robmtest.vm',
                'keywords' => {
                    '$Seen' => JSON::true,
                    '$Draft' => JSON::true
                },
                textBody => [{partId => '1'}],
                bodyValues => { '1' => { value => 'lsdkgjh' }},
                'to' => [
                    {
                        'email' => 'foo@bar.com',
                        'name' => ''
                    }
                ],
                'from' => [
                    {
                        'email' => 'fooalias1@robmtest.vm',
                        'name' => 'some name'
                    }
                ],
                'receivedAt' => '2018-03-06T03:49:04Z',
                'mailboxIds' => {
                    $inboxid => JSON::true,
                },
            }
        }
    }, "R1" ],
    [ 'EmailSubmission/set', {
        create => {
            'k41' => {
                identityId => $identityid,
                emailId  => '#k40',
                envelope => undef,
            },
        },
        onSuccessDestroyEmail => [ '#k41' ],
    }, "R2" ] ] );
    $self->assert_str_equals('EmailSubmission/set', $res->[1][0]);
    $self->assert_not_null($res->[1][1]->{created}{'k41'}{id});
    $self->assert_str_equals('R2', $res->[1][2]);
    $self->assert_str_equals('Email/set', $res->[2][0]);
    $self->assert_not_null($res->[2][1]->{destroyed}[0]);
    $self->assert_str_equals('R2', $res->[2][2]);
}

sub test_emailsubmission_changes
    :min_version_3_1 :needs_component_jmap
{
    my ($self) = @_;
    my $jmap = $self->{jmap};

    my $res = $jmap->CallMethods( [ [ 'Identity/get', {}, "R1" ] ] );
    my $identityid = $res->[0][1]->{list}[0]->{id};
    $self->assert_not_null($identityid);

    xlog "get current email submission state";
    $res = $jmap->CallMethods([['EmailSubmission/get', { }, "R1"]]);
    my $state = $res->[0][1]->{state};
    $self->assert_not_null($state);

    xlog "get email submission updates";
    $res = $jmap->CallMethods( [ [ 'EmailSubmission/changes', {
        sinceState => $state,
    }, "R1" ] ] );
    $self->assert_deep_equals([], $res->[0][1]->{created});
    $self->assert_deep_equals([], $res->[0][1]->{updated});
    $self->assert_deep_equals([], $res->[0][1]->{destroyed});

    xlog "Generate a email via IMAP";
    $self->make_message("foo", body => "a email") or die;

    xlog "get email id";
    $res = $jmap->CallMethods( [ [ 'Email/query', {}, "R1" ] ] );
    my $emailid = $res->[0][1]->{ids}[0];

    xlog "create email submission but don't update state";
    $res = $jmap->CallMethods( [ [ 'EmailSubmission/set', {
        create => {
            '1' => {
                identityId => $identityid,
                emailId  => $emailid,
            }
       }
    }, "R1" ] ] );

    xlog "get email submission updates";
    $res = $jmap->CallMethods( [ [ 'EmailSubmission/changes', {
        sinceState => $state,
    }, "R1" ] ] );
    $self->assert_deep_equals([], $res->[0][1]->{created});
    $self->assert_deep_equals([], $res->[0][1]->{updated});
    $self->assert_deep_equals([], $res->[0][1]->{destroyed});
}

sub test_emailsubmission_query
    :min_version_3_1 :needs_component_jmap
{
    my ($self) = @_;
    my $jmap = $self->{jmap};

    xlog "get email submission list (no arguments)";
    my $res = $jmap->CallMethods([['EmailSubmission/query', { }, "R1"]]);
    $self->assert_null($res->[0][1]{filter});
    $self->assert_null($res->[0][1]{sort});
    $self->assert_not_null($res->[0][1]{queryState});
    $self->assert_equals(JSON::false, $res->[0][1]{canCalculateChanges});
    $self->assert_num_equals(0, $res->[0][1]{position});
    $self->assert_num_equals(0, $res->[0][1]{total});
    $self->assert_not_null($res->[0][1]{ids});

    xlog "get email submission list (error arguments)";
    $res = $jmap->CallMethods([['EmailSubmission/query', { filter => 1 }, "R1"]]);
    $self->assert_str_equals('invalidArguments', $res->[0][1]{type});
}

sub test_emailsubmission_querychanges
    :min_version_3_1 :needs_component_jmap
{
    my ($self) = @_;
    my $jmap = $self->{jmap};

    xlog "get current email submission state";
    my $res = $jmap->CallMethods([['EmailSubmission/query', { }, "R1"]]);
    my $state = $res->[0][1]->{queryState};
    $self->assert_not_null($state);

    xlog "get email submission list updates (empty filter)";
    $res = $jmap->CallMethods([['EmailSubmission/queryChanges', {
        filter => {},
        sinceQueryState => $state,
    }, "R1"]]);
    $self->assert_str_equals("error", $res->[0][0]);
    $self->assert_str_equals("cannotCalculateChanges", $res->[0][1]{type});
    $self->assert_str_equals("R1", $res->[0][2]);
}

sub test_email_set_move
    :min_version_3_1 :needs_component_jmap
{
    my ($self) = @_;
    my $jmap = $self->{jmap};

    my $store = $self->{store};
    my $talk = $store->get_client();
    my $inbox = 'INBOX';

    xlog "Create test mailboxes";
    my $res = $jmap->CallMethods([
        ['Mailbox/set', { create => {
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

    xlog "Generate a email via IMAP";
    my %exp_sub;
    $exp_sub{A} = $self->make_message(
        "foo", body => "a email",
    );

    xlog "get email id";
    $res = $jmap->CallMethods( [ [ 'Email/query', {}, "R1" ] ] );
    my $id = $res->[0][1]->{ids}[0];

    xlog "get email";
    $res = $jmap->CallMethods([['Email/get', { ids => [$id] }, "R1"]]);
    my $msg = $res->[0][1]->{list}[0];
    $self->assert_num_equals(1, scalar keys %{$msg->{mailboxIds}});

    local *assert_move = sub {
        my ($moveto) = (@_);

        xlog "move email to " . Dumper($moveto);
        $msg->{mailboxIds} = $moveto;
        $res = $jmap->CallMethods(
            [ [ 'Email/set', { update => { $id => $msg } }, "R1" ] ] );
        $self->assert(exists $res->[0][1]{updated}{$id});

        $res = $jmap->CallMethods( [ [ 'Email/get', { ids => [$id] }, "R1" ] ] );
        $msg = $res->[0][1]->{list}[0];

        $self->assert_deep_equals($moveto, $msg->{mailboxIds});
    };

    assert_move({$a => JSON::true, $b => JSON::true});
    assert_move({$a => JSON::true, $b => JSON::true, $c => JSON::true});
    assert_move({$d => JSON::true});
}

sub test_email_set_move_keywords
    :min_version_3_1 :needs_component_jmap
{
    my ($self) = @_;
    my $jmap = $self->{jmap};

    my $store = $self->{store};
    my $talk = $store->get_client();
    my $inbox = 'INBOX';

    xlog "Generate an email via IMAP";
    my %exp_sub;
    $exp_sub{A} = $self->make_message(
        "foo", body => "a email",
    );
    xlog "Set flags on message";
    $store->set_folder('INBOX');
    $talk->store('1', '+flags', '($foo \\Flagged)');

    xlog "get email";
    my $res = $jmap->CallMethods([
        ['Email/query', {}, 'R1'],
        ['Email/get', {
            '#ids' => { resultOf => 'R1', name => 'Email/query', path => '/ids'},
            properties => [ 'keywords', 'mailboxIds' ],
        }, 'R2' ]
    ]);
    my $msg = $res->[1][1]->{list}[0];
    $self->assert_num_equals(1, scalar keys %{$msg->{mailboxIds}});
    my $msgId = $msg->{id};
    my $inboxId = (keys %{$msg->{mailboxIds}})[0];
    $self->assert_not_null($inboxId);
    my $keywords = $msg->{keywords};

    xlog "create Archive mailbox";
    $res = $jmap->CallMethods([ ['Mailbox/get', {}, 'R1'], ]);
    my $mboxState = $res->[0][1]{state};
    $talk->create("INBOX.Archive", "(USE (\\Archive))") || die;
    $res = $jmap->CallMethods([
        ['Mailbox/changes', {sinceState => $mboxState }, 'R1'],
    ]);
    my $archiveId = $res->[0][1]{created}[0];
    $self->assert_not_null($archiveId);
    $self->assert_deep_equals([], $res->[0][1]->{updated});
    $self->assert_deep_equals([], $res->[0][1]->{destroyed});

    xlog "move email to Archive";
    xlog "update email";
    $res = $jmap->CallMethods([
        ['Email/set', { update => {
            $msgId => {
                mailboxIds => { $archiveId => JSON::true }
            },
        }}, "R1"],
        ['Email/get', { ids => [ $msgId ], properties => ['keywords'] }, 'R2'],
    ]);
    $self->assert(exists $res->[0][1]{updated}{$msgId});
    $self->assert_deep_equals($keywords, $res->[1][1]{list}[0]{keywords});
}

sub test_email_set_update
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
    my $drafts = $res->[0][1]{created}{"1"}{id};

    my $draft =  {
        mailboxIds => {$drafts => JSON::true},
        from => [ { name => "Yosemite Sam", email => "sam\@acme.local" } ],
        to => [ { name => "Bugs Bunny", email => "bugs\@acme.local" } ],
        cc => [ { name => "Elmer Fudd", email => "elmer\@acme.local" } ],
        subject => "created",
        htmlBody => [ {partId => '1'} ],
        bodyValues => { 1 => { value => "Oh!!! I <em>hate</em> that Rabbit." }},
        keywords => {
            '$Draft' => JSON::true,
        }
    };

    xlog "Create a draft";
    $res = $jmap->CallMethods([['Email/set', { create => { "1" => $draft }}, "R1"]]);
    my $id = $res->[0][1]{created}{"1"}{id};

    xlog "Get draft $id";
    $res = $jmap->CallMethods([['Email/get', { ids => [$id] }, "R1"]]);
    my $msg = $res->[0][1]->{list}[0];

    xlog "Update draft $id";
    $draft->{keywords} = {
        '$draft' => JSON::true,
        '$flagged' => JSON::true,
        '$seen' => JSON::true,
        '$answered' => JSON::true,
    };
    $res = $jmap->CallMethods([['Email/set', { update => { $id => $draft }}, "R1"]]);

    xlog "Get draft $id";
    $res = $jmap->CallMethods([['Email/get', { ids => [$id] }, "R1"]]);
    $msg = $res->[0][1]->{list}[0];
    $self->assert_deep_equals($draft->{keywords}, $msg->{keywords});
}

sub test_email_set_seen
    :min_version_3_1 :needs_component_jmap
{
    my ($self) = @_;
    my $jmap = $self->{jmap};

    # See https://github.com/cyrusimap/cyrus-imapd/issues/2270

    my $talk = $self->{store}->get_client();
    $self->{store}->_select();
    $self->{store}->set_fetch_attributes(qw(uid flags));

    xlog "Add message";
    $self->make_message('Message A');

    xlog "Query email";
    my $inbox = $self->getinbox();
    my $res = $jmap->CallMethods([
        ['Email/query', {
            filter => { inMailbox => $inbox->{id} }
        }, 'R1'],
        ['Email/get', {
            '#ids' => { resultOf => 'R1', name => 'Email/query', path => '/ids'}
        }, 'R2' ]
    ]);

    my $keywords = { };
    my $msg = $res->[1][1]->{list}[0];
    $self->assert_deep_equals($keywords, $msg->{keywords});

    $keywords->{'$seen'} = JSON::true;
    $res = $jmap->CallMethods([
        ['Email/set', { update => { $msg->{id} => { 'keywords/$seen' => JSON::true } } }, 'R1'],
        ['Email/get', { ids => [ $msg->{id} ] }, 'R2'],
    ]);
    $msg = $res->[1][1]->{list}[0];
    $self->assert_deep_equals($keywords, $msg->{keywords});
}

sub test_email_set_destroy
    :min_version_3_1 :needs_component_jmap
{
    my ($self) = @_;
    my $jmap = $self->{jmap};

    xlog "create mailboxes";
    my $res = $jmap->CallMethods(
        [
            [
                'Mailbox/set',
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
    $self->assert_str_equals( $res->[0][0], 'Mailbox/set' );
    $self->assert_str_equals( $res->[0][2], 'R1' );
    $self->assert_not_null( $res->[0][1]{created} );
    my $mailboxids = {
        $res->[0][1]{created}{"1"}{id} => JSON::true,
        $res->[0][1]{created}{"2"}{id} => JSON::true,
        $res->[0][1]{created}{"3"}{id} => JSON::true,
    };

    xlog "Create a draft";
    my $draft = {
        mailboxIds => $mailboxids,
        from       => [ { name => "Yosemite Sam", email => "sam\@acme.local" } ],
        to         => [ { name => "Bugs Bunny", email => "bugs\@acme.local" } ],
        subject    => "created",
        textBody   => [{ partId => '1' }],
        bodyValues => { '1' => { value => "Oh!!! I *hate* that Rabbit." }},
        keywords => { '$Draft' => JSON::true },
    };
    $res = $jmap->CallMethods(
        [ [ 'Email/set', { create => { "1" => $draft } }, "R1" ] ],
    );
    my $id = $res->[0][1]{created}{"1"}{id};
    $self->assert_not_null($id);

    xlog "Get draft $id";
    $res = $jmap->CallMethods( [ [ 'Email/get', { ids => [$id] }, "R1" ] ]);
    $self->assert_num_equals(3, scalar keys %{$res->[0][1]->{list}[0]{mailboxIds}});

    xlog "Destroy draft $id";
    $res = $jmap->CallMethods(
        [ [ 'Email/set', { destroy => [ $id ] }, "R1" ] ],
    );
    $self->assert_str_equals( $res->[0][1]{destroyed}[0], $id );

    xlog "Get draft $id";
    $res = $jmap->CallMethods( [ [ 'Email/get', { ids => [$id] }, "R1" ] ]);
    $self->assert_str_equals( $res->[0][1]->{notFound}[0], $id );

    xlog "Get emails";
    $res = $jmap->CallMethods([['Email/query', {}, "R1"]]);
    $self->assert_num_equals(0, scalar @{$res->[0][1]->{ids}});
}

sub test_email_query
    :min_version_3_1 :needs_component_jmap
{
    my ($self) = @_;
    my $jmap = $self->{jmap};

    my $account = undef;
    my $store = $self->{store};
    my $mboxprefix = "INBOX";
    my $talk = $store->get_client();

    my $res = $jmap->CallMethods([['Mailbox/get', { accountId => $account }, "R1"]]);
    my $inboxid = $res->[0][1]{list}[0]{id};

    xlog "create mailboxes";
    $talk->create("$mboxprefix.A") || die;
    $talk->create("$mboxprefix.B") || die;
    $talk->create("$mboxprefix.C") || die;

    $res = $jmap->CallMethods([['Mailbox/get', { accountId => $account }, "R1"]]);
    my %m = map { $_->{name} => $_ } @{$res->[0][1]{list}};
    my $mboxa = $m{"A"}->{id};
    my $mboxb = $m{"B"}->{id};
    my $mboxc = $m{"C"}->{id};
    $self->assert_not_null($mboxa);
    $self->assert_not_null($mboxb);
    $self->assert_not_null($mboxc);

    xlog "create emails";
    my %params;
    $store->set_folder("$mboxprefix.A");
    my $dtfoo = DateTime->new(
        year       => 2016,
        month      => 11,
        day        => 1,
        hour       => 7,
        time_zone  => 'Etc/UTC',
    );
    my $bodyfoo = "A rather short email";
    %params = (
        date => $dtfoo,
        body => $bodyfoo,
        store => $store,
    );
    $res = $self->make_message("foo", %params) || die;
    $talk->copy(1, "$mboxprefix.C") || die;

    $store->set_folder("$mboxprefix.B");
    my $dtbar = DateTime->new(
        year       => 2016,
        month      => 3,
        day        => 1,
        hour       => 19,
        time_zone  => 'Etc/UTC',
    );
    my $bodybar = ""
    . "In the context of electronic mail, emails are viewed as having an\r\n"
    . "envelope and contents.  The envelope contains whatever information is\r\n"
    . "needed to accomplish transmission and delivery.  (See [RFC5321] for a\r\n"
    . "discussion of the envelope.)  The contents comprise the object to be\r\n"
    . "delivered to the recipient.  This specification applies only to the\r\n"
    . "format and some of the semantics of email contents.  It contains no\r\n"
    . "specification of the information in the envelope.i\r\n"
    . "\r\n"
    . "However, some email systems may use information from the contents\r\n"
    . "to create the envelope.  It is intended that this specification\r\n"
    . "facilitate the acquisition of such information by programs.\r\n"
    . "\r\n"
    . "This specification is intended as a definition of what email\r\n"
    . "content format is to be passed between systems.  Though some email\r\n"
    . "systems locally store emails in this format (which eliminates the\r\n"
    . "need for translation between formats) and others use formats that\r\n"
    . "differ from the one specified in this specification, local storage is\r\n"
    . "outside of the scope of this specification.\r\n";

    %params = (
        date => $dtbar,
        body => $bodybar,
        extra_headers => [
            ['x-tra', "baz"],
        ],
        store => $store,
    );
    $self->make_message("bar", %params) || die;

    xlog "run squatter";
    $self->{instance}->run_command({cyrus => 1}, 'squatter');

    xlog "fetch emails without filter";
    $res = $jmap->CallMethods([
        ['Email/query', { accountId => $account }, 'R1'],
        ['Email/get', {
            accountId => $account,
            '#ids' => { resultOf => 'R1', name => 'Email/query', path => '/ids' }
        }, 'R2'],
    ]);
    $self->assert_num_equals(2, scalar @{$res->[0][1]->{ids}});
    $self->assert_num_equals(2, scalar @{$res->[1][1]->{list}});

    %m = map { $_->{subject} => $_ } @{$res->[1][1]{list}};
    my $foo = $m{"foo"}->{id};
    my $bar = $m{"bar"}->{id};
    $self->assert_not_null($foo);
    $self->assert_not_null($bar);

    xlog "filter text";
    $res = $jmap->CallMethods([['Email/query', {
                    accountId => $account,
                    filter => {
                        text => "foo",
                    },
                }, "R1"]]);
    $self->assert_num_equals(1, scalar @{$res->[0][1]->{ids}});
    $self->assert_str_equals($foo, $res->[0][1]->{ids}[0]);

    xlog "filter NOT text";
    $res = $jmap->CallMethods([['Email/query', {
                    accountId => $account,
                    filter => {
                        operator => "NOT",
                        conditions => [ {text => "foo"} ],
                    },
                }, "R1"]]);
    $self->assert_num_equals(1, scalar @{$res->[0][1]->{ids}});
    $self->assert_str_equals($bar, $res->[0][1]->{ids}[0]);

    xlog "filter mailbox A";
    $res = $jmap->CallMethods([['Email/query', {
                    accountId => $account,
                    filter => {
                        inMailbox => $mboxa,
                    },
                }, "R1"]]);
    $self->assert_num_equals(1, scalar @{$res->[0][1]->{ids}});
    $self->assert_str_equals($foo, $res->[0][1]->{ids}[0]);

    xlog "filter mailboxes";
    $res = $jmap->CallMethods([['Email/query', {
                    accountId => $account,
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
    $self->assert_num_equals(1, scalar @{$res->[0][1]->{ids}});
    $self->assert_str_equals($foo, $res->[0][1]->{ids}[0]);

    xlog "filter mailboxes with not in";
    $res = $jmap->CallMethods([['Email/query', {
                    accountId => $account,
                    filter => {
                        inMailboxOtherThan => [$mboxb],
                    },
                }, "R1"]]);
    $self->assert_num_equals(1, scalar @{$res->[0][1]->{ids}});
    $self->assert_str_equals($foo, $res->[0][1]->{ids}[0]);

    xlog "filter mailboxes";
    $res = $jmap->CallMethods([['Email/query', {
                    accountId => $account,
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
    $self->assert_num_equals(0, scalar @{$res->[0][1]->{ids}});

    xlog "filter not in mailbox A";
    $res = $jmap->CallMethods([['Email/query', {
                    accountId => $account,
                    filter => {
                        operator => 'NOT',
                        conditions => [
                            {
                                inMailbox => $mboxa,
                            },
                        ],
                    },
                }, "R1"]]);
    $self->assert_num_equals(2, scalar @{$res->[0][1]->{ids}});

    xlog "filter by before";
    my $dtbefore = $dtfoo->clone()->subtract(seconds => 1);
    $res = $jmap->CallMethods([['Email/query', {
                    accountId => $account,
                    filter => {
                        before => $dtbefore->strftime('%Y-%m-%dT%TZ'),
                    },
                }, "R1"]]);
    $self->assert_num_equals(1, scalar @{$res->[0][1]->{ids}});
    $self->assert_str_equals($bar, $res->[0][1]->{ids}[0]);

    xlog "filter by after",
    my $dtafter = $dtbar->clone()->add(seconds => 1);
    $res = $jmap->CallMethods([['Email/query', {
                    accountId => $account,
                    filter => {
                        after => $dtafter->strftime('%Y-%m-%dT%TZ'),
                    },
                }, "R1"]]);
    $self->assert_num_equals(1, scalar @{$res->[0][1]->{ids}});
    $self->assert_str_equals($foo, $res->[0][1]->{ids}[0]);

    xlog "filter by after and before",
    $res = $jmap->CallMethods([['Email/query', {
                    accountId => $account,
                    filter => {
                        after => $dtafter->strftime('%Y-%m-%dT%TZ'),
                        before => $dtbefore->strftime('%Y-%m-%dT%TZ'),
                    },
                }, "R1"]]);
    $self->assert_num_equals(0, scalar @{$res->[0][1]->{ids}});

    xlog "filter by minSize";
    $res = $jmap->CallMethods([['Email/query', {
                    accountId => $account,
                    filter => {
                        minSize => length($bodybar),
                    },
                }, "R1"]]);
    $self->assert_num_equals(1, scalar @{$res->[0][1]->{ids}});
    $self->assert_str_equals($bar, $res->[0][1]->{ids}[0]);

    xlog "filter by maxSize";
    $res = $jmap->CallMethods([['Email/query', {
                    accountId => $account,
                    filter => {
                        maxSize => length($bodybar),
                    },
                }, "R1"]]);
    $self->assert_num_equals(1, scalar @{$res->[0][1]->{ids}});
    $self->assert_str_equals($foo, $res->[0][1]->{ids}[0]);

    xlog "filter by header";
    $res = $jmap->CallMethods([['Email/query', {
                    accountId => $account,
                    filter => {
                        header => [ "x-tra" ],
                    },
                }, "R1"]]);
    $self->assert_num_equals(1, scalar @{$res->[0][1]->{ids}});
    $self->assert_str_equals($bar, $res->[0][1]->{ids}[0]);

    xlog "filter by header and value";
    $res = $jmap->CallMethods([['Email/query', {
                    accountId => $account,
                    filter => {
                        header => [ "x-tra", "bam" ],
                    },
                }, "R1"]]);
    $self->assert_num_equals(0, scalar @{$res->[0][1]->{ids}});

    xlog "sort by ascending receivedAt";
    $res = $jmap->CallMethods([['Email/query', {
                    accountId => $account,
                    sort => [{ property => "receivedAt" }],
                }, "R1"]]);
    $self->assert_num_equals(2, scalar @{$res->[0][1]->{ids}});
    $self->assert_str_equals($bar, $res->[0][1]->{ids}[0]);
    $self->assert_str_equals($foo, $res->[0][1]->{ids}[1]);

    xlog "sort by descending receivedAt";
    $res = $jmap->CallMethods([['Email/query', {
                    accountId => $account,
                    sort => [{ property => "receivedAt", isAscending => JSON::false }],
                }, "R1"]]);
    $self->assert_num_equals(2, scalar @{$res->[0][1]->{ids}});
    $self->assert_str_equals($foo, $res->[0][1]->{ids}[0]);
    $self->assert_str_equals($bar, $res->[0][1]->{ids}[1]);

    xlog "sort by ascending size";
    $res = $jmap->CallMethods([['Email/query', {
                    accountId => $account,
                    sort => [{ property =>  "size" }],
                }, "R1"]]);
    $self->assert_num_equals(2, scalar @{$res->[0][1]->{ids}});
    $self->assert_str_equals($foo, $res->[0][1]->{ids}[0]);
    $self->assert_str_equals($bar, $res->[0][1]->{ids}[1]);

    xlog "sort by descending size";
    $res = $jmap->CallMethods([['Email/query', {
                    accountId => $account,
                    sort => [{ property => "size", isAscending => JSON::false }],
                }, "R1"]]);
    $self->assert_num_equals(2, scalar @{$res->[0][1]->{ids}});
    $self->assert_str_equals($bar, $res->[0][1]->{ids}[0]);
    $self->assert_str_equals($foo, $res->[0][1]->{ids}[1]);

    xlog "sort by ascending id";
    $res = $jmap->CallMethods([['Email/query', {
                    accountId => $account,
                    sort => [{ property => "id" }],
                }, "R1"]]);
    my @ids = sort ($foo, $bar);
    $self->assert_deep_equals(\@ids, $res->[0][1]->{ids});

    xlog "sort by descending id";
    $res = $jmap->CallMethods([['Email/query', {
                    accountId => $account,
                    sort => [{ property => "id", isAscending => JSON::false }],
                }, "R1"]]);
    @ids = reverse sort ($foo, $bar);
    $self->assert_deep_equals(\@ids, $res->[0][1]->{ids});

    xlog "delete mailboxes";
    $talk->delete("$mboxprefix.A") or die;
    $talk->delete("$mboxprefix.B") or die;
    $talk->delete("$mboxprefix.C") or die;
}

sub test_email_query_shared
    :min_version_3_1 :needs_component_jmap
{
    my ($self) = @_;
    my $jmap = $self->{jmap};

    my $admintalk = $self->{adminstore}->get_client();
    $self->{instance}->create_user("test");
    $admintalk->setacl("user.test", "cassandane", "lrwkx") or die;

    # run tests for both the main and "test" account
    foreach (undef, "test") {
        my $account = $_;
        my $store = defined $account ? $self->{adminstore} : $self->{store};
        my $mboxprefix = defined $account ? "user.$account" : "INBOX";
        my $talk = $store->get_client();

        my $res = $jmap->CallMethods([['Mailbox/get', { accountId => $account }, "R1"]]);
        my $inboxid = $res->[0][1]{list}[0]{id};

        xlog "create mailboxes";
        $talk->create("$mboxprefix.A") || die;
        $talk->create("$mboxprefix.B") || die;
        $talk->create("$mboxprefix.C") || die;

        $res = $jmap->CallMethods([['Mailbox/get', { accountId => $account }, "R1"]]);
        my %m = map { $_->{name} => $_ } @{$res->[0][1]{list}};
        my $mboxa = $m{"A"}->{id};
        my $mboxb = $m{"B"}->{id};
        my $mboxc = $m{"C"}->{id};
        $self->assert_not_null($mboxa);
        $self->assert_not_null($mboxb);
        $self->assert_not_null($mboxc);

        xlog "create emails";
        my %params;
        $store->set_folder("$mboxprefix.A");
        my $dtfoo = DateTime->new(
            year       => 2016,
            month      => 11,
            day        => 1,
            hour       => 7,
            time_zone  => 'Etc/UTC',
        );
        my $bodyfoo = "A rather short email";
        %params = (
            date => $dtfoo,
            body => $bodyfoo,
            store => $store,
        );
        $res = $self->make_message("foo", %params) || die;
        $talk->copy(1, "$mboxprefix.C") || die;

        $store->set_folder("$mboxprefix.B");
        my $dtbar = DateTime->new(
            year       => 2016,
            month      => 3,
            day        => 1,
            hour       => 19,
            time_zone  => 'Etc/UTC',
        );
        my $bodybar = ""
        . "In the context of electronic mail, emails are viewed as having an\r\n"
        . "envelope and contents.  The envelope contains whatever information is\r\n"
        . "needed to accomplish transmission and delivery.  (See [RFC5321] for a\r\n"
        . "discussion of the envelope.)  The contents comprise the object to be\r\n"
        . "delivered to the recipient.  This specification applies only to the\r\n"
        . "format and some of the semantics of email contents.  It contains no\r\n"
        . "specification of the information in the envelope.i\r\n"
        . "\r\n"
        . "However, some email systems may use information from the contents\r\n"
        . "to create the envelope.  It is intended that this specification\r\n"
        . "facilitate the acquisition of such information by programs.\r\n"
        . "\r\n"
        . "This specification is intended as a definition of what email\r\n"
        . "content format is to be passed between systems.  Though some email\r\n"
        . "systems locally store emails in this format (which eliminates the\r\n"
        . "need for translation between formats) and others use formats that\r\n"
        . "differ from the one specified in this specification, local storage is\r\n"
        . "outside of the scope of this specification.\r\n";

        %params = (
            date => $dtbar,
            body => $bodybar,
            extra_headers => [
                ['x-tra', "baz"],
            ],
            store => $store,
        );
        $self->make_message("bar", %params) || die;

        xlog "run squatter";
        $self->{instance}->run_command({cyrus => 1}, 'squatter');

        xlog "fetch emails without filter";
        $res = $jmap->CallMethods([
                ['Email/query', { accountId => $account }, 'R1'],
                ['Email/get', {
                        accountId => $account,
                        '#ids' => { resultOf => 'R1', name => 'Email/query', path => '/ids' }
                    }, 'R2'],
            ]);
        $self->assert_num_equals(2, scalar @{$res->[0][1]->{ids}});
        $self->assert_num_equals(2, scalar @{$res->[1][1]->{list}});

        %m = map { $_->{subject} => $_ } @{$res->[1][1]{list}};
        my $foo = $m{"foo"}->{id};
        my $bar = $m{"bar"}->{id};
        $self->assert_not_null($foo);
        $self->assert_not_null($bar);

        xlog "filter text";
        $res = $jmap->CallMethods([['Email/query', {
                        accountId => $account,
                        filter => {
                            text => "foo",
                        },
                    }, "R1"]]);
        $self->assert_num_equals(1, scalar @{$res->[0][1]->{ids}});
        $self->assert_str_equals($foo, $res->[0][1]->{ids}[0]);

        xlog "filter NOT text";
        $res = $jmap->CallMethods([['Email/query', {
                        accountId => $account,
                        filter => {
                            operator => "NOT",
                            conditions => [ {text => "foo"} ],
                        },
                    }, "R1"]]);
        $self->assert_num_equals(1, scalar @{$res->[0][1]->{ids}});
        $self->assert_str_equals($bar, $res->[0][1]->{ids}[0]);

        xlog "filter mailbox A";
        $res = $jmap->CallMethods([['Email/query', {
                        accountId => $account,
                        filter => {
                            inMailbox => $mboxa,
                        },
                    }, "R1"]]);
        $self->assert_num_equals(1, scalar @{$res->[0][1]->{ids}});
        $self->assert_str_equals($foo, $res->[0][1]->{ids}[0]);

        xlog "filter mailboxes";
        $res = $jmap->CallMethods([['Email/query', {
                        accountId => $account,
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
        $self->assert_num_equals(1, scalar @{$res->[0][1]->{ids}});
        $self->assert_str_equals($foo, $res->[0][1]->{ids}[0]);

        xlog "filter mailboxes with not in";
        $res = $jmap->CallMethods([['Email/query', {
                        accountId => $account,
                        filter => {
                            inMailboxOtherThan => [$mboxb],
                        },
                    }, "R1"]]);
        $self->assert_num_equals(1, scalar @{$res->[0][1]->{ids}});
        $self->assert_str_equals($foo, $res->[0][1]->{ids}[0]);

        xlog "filter mailboxes with not in";
        $res = $jmap->CallMethods([['Email/query', {
                        accountId => $account,
                        filter => {
                            inMailboxOtherThan => [$mboxa],
                        },
                    }, "R1"]]);
        $self->assert_num_equals(2, scalar @{$res->[0][1]->{ids}});

        xlog "filter mailboxes with not in";
        $res = $jmap->CallMethods([['Email/query', {
                        accountId => $account,
                        filter => {
                            inMailboxOtherThan => [$mboxa, $mboxc],
                        },
                    }, "R1"]]);
        $self->assert_num_equals(1, scalar @{$res->[0][1]->{ids}});
        $self->assert_str_equals($bar, $res->[0][1]->{ids}[0]);

        xlog "filter mailboxes";
        $res = $jmap->CallMethods([['Email/query', {
                        accountId => $account,
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
        $self->assert_num_equals(0, scalar @{$res->[0][1]->{ids}});

        xlog "filter not in mailbox A";
        $res = $jmap->CallMethods([['Email/query', {
                        accountId => $account,
                        filter => {
                            operator => 'NOT',
                            conditions => [
                                {
                                    inMailbox => $mboxa,
                                },
                            ],
                        },
                    }, "R1"]]);
        $self->assert_num_equals(2, scalar @{$res->[0][1]->{ids}});

        xlog "filter by before";
        my $dtbefore = $dtfoo->clone()->subtract(seconds => 1);
        $res = $jmap->CallMethods([['Email/query', {
                        accountId => $account,
                        filter => {
                            before => $dtbefore->strftime('%Y-%m-%dT%TZ'),
                        },
                    }, "R1"]]);
        $self->assert_num_equals(1, scalar @{$res->[0][1]->{ids}});
        $self->assert_str_equals($bar, $res->[0][1]->{ids}[0]);

        xlog "filter by after",
        my $dtafter = $dtbar->clone()->add(seconds => 1);
        $res = $jmap->CallMethods([['Email/query', {
                        accountId => $account,
                        filter => {
                            after => $dtafter->strftime('%Y-%m-%dT%TZ'),
                        },
                    }, "R1"]]);
        $self->assert_num_equals(1, scalar @{$res->[0][1]->{ids}});
        $self->assert_str_equals($foo, $res->[0][1]->{ids}[0]);

        xlog "filter by after and before",
        $res = $jmap->CallMethods([['Email/query', {
                        accountId => $account,
                        filter => {
                            after => $dtafter->strftime('%Y-%m-%dT%TZ'),
                            before => $dtbefore->strftime('%Y-%m-%dT%TZ'),
                        },
                    }, "R1"]]);
        $self->assert_num_equals(0, scalar @{$res->[0][1]->{ids}});

        xlog "filter by minSize";
        $res = $jmap->CallMethods([['Email/query', {
                        accountId => $account,
                        filter => {
                            minSize => length($bodybar),
                        },
                    }, "R1"]]);
        $self->assert_num_equals(1, scalar @{$res->[0][1]->{ids}});
        $self->assert_str_equals($bar, $res->[0][1]->{ids}[0]);

        xlog "filter by maxSize";
        $res = $jmap->CallMethods([['Email/query', {
                        accountId => $account,
                        filter => {
                            maxSize => length($bodybar),
                        },
                    }, "R1"]]);
        $self->assert_num_equals(1, scalar @{$res->[0][1]->{ids}});
        $self->assert_str_equals($foo, $res->[0][1]->{ids}[0]);

        xlog "filter by header";
        $res = $jmap->CallMethods([['Email/query', {
                        accountId => $account,
                        filter => {
                            header => [ "x-tra" ],
                        },
                    }, "R1"]]);
        $self->assert_num_equals(1, scalar @{$res->[0][1]->{ids}});
        $self->assert_str_equals($bar, $res->[0][1]->{ids}[0]);

        xlog "filter by header and value";
        $res = $jmap->CallMethods([['Email/query', {
                        accountId => $account,
                        filter => {
                            header => [ "x-tra", "bam" ],
                        },
                    }, "R1"]]);
        $self->assert_num_equals(0, scalar @{$res->[0][1]->{ids}});

        xlog "sort by ascending receivedAt";
        $res = $jmap->CallMethods([['Email/query', {
                        accountId => $account,
                        sort => [{ property => "receivedAt" }],
                    }, "R1"]]);
        $self->assert_num_equals(2, scalar @{$res->[0][1]->{ids}});
        $self->assert_str_equals($bar, $res->[0][1]->{ids}[0]);
        $self->assert_str_equals($foo, $res->[0][1]->{ids}[1]);

        xlog "sort by descending receivedAt";
        $res = $jmap->CallMethods([['Email/query', {
                        accountId => $account,
                        sort => [{ property => "receivedAt", isAscending => JSON::false, }],
                    }, "R1"]]);
        $self->assert_num_equals(2, scalar @{$res->[0][1]->{ids}});
        $self->assert_str_equals($foo, $res->[0][1]->{ids}[0]);
        $self->assert_str_equals($bar, $res->[0][1]->{ids}[1]);

        xlog "sort by ascending size";
        $res = $jmap->CallMethods([['Email/query', {
                        accountId => $account,
                        sort => [{ property => "size" }],
                    }, "R1"]]);
        $self->assert_num_equals(2, scalar @{$res->[0][1]->{ids}});
        $self->assert_str_equals($foo, $res->[0][1]->{ids}[0]);
        $self->assert_str_equals($bar, $res->[0][1]->{ids}[1]);

        xlog "sort by descending size";
        $res = $jmap->CallMethods([['Email/query', {
                        accountId => $account,
                        sort => [{ property => "size", isAscending => JSON::false }],
                    }, "R1"]]);
        $self->assert_num_equals(2, scalar @{$res->[0][1]->{ids}});
        $self->assert_str_equals($bar, $res->[0][1]->{ids}[0]);
        $self->assert_str_equals($foo, $res->[0][1]->{ids}[1]);

        xlog "sort by ascending id";
        $res = $jmap->CallMethods([['Email/query', {
                        accountId => $account,
                        sort => [{ property => "id" }],
                    }, "R1"]]);
        my @ids = sort ($foo, $bar);
        $self->assert_deep_equals(\@ids, $res->[0][1]->{ids});

        xlog "sort by descending id";
        $res = $jmap->CallMethods([['Email/query', {
                        accountId => $account,
                        sort => [{ property => "id", isAscending => JSON::false }],
                    }, "R1"]]);
        @ids = reverse sort ($foo, $bar);
        $self->assert_deep_equals(\@ids, $res->[0][1]->{ids});

        xlog "delete mailboxes";
        $talk->delete("$mboxprefix.A") or die;
        $talk->delete("$mboxprefix.B") or die;
        $talk->delete("$mboxprefix.C") or die;
    }
}

sub test_email_query_keywords
    :min_version_3_1 :needs_component_jmap
{
    my ($self) = @_;
    my $jmap = $self->{jmap};

    my $store = $self->{store};
    my $talk = $store->get_client();

    my $res = $jmap->CallMethods([['Mailbox/get', { }, "R1"]]);
    my $inboxid = $res->[0][1]{list}[0]{id};

    xlog "create email";
    $res = $self->make_message("foo") || die;

    xlog "run squatter";
    $self->{instance}->run_command({cyrus => 1}, 'squatter');

    xlog "fetch emails without filter";
    $res = $jmap->CallMethods([
        ['Email/query', { }, 'R1'],
    ]);
    $self->assert_num_equals(1, scalar @{$res->[0][1]->{ids}});
    $self->assert_num_equals(1, scalar @{$res->[0][1]->{ids}});
    my $fooid = $res->[0][1]->{ids}[0];

    xlog "fetch emails with \$Seen flag";
    $res = $jmap->CallMethods([['Email/query', {
        filter => {
            hasKeyword => '$Seen',
        }
    }, "R1"]]);
    $self->assert_num_equals(0, scalar @{$res->[0][1]->{ids}});

    xlog "fetch emails without \$Seen flag";
    $res = $jmap->CallMethods([['Email/query', {
        filter => {
            notKeyword => '$Seen',
        }
    }, "R1"]]);
    $self->assert_num_equals(1, scalar @{$res->[0][1]->{ids}});

    xlog 'set $Seen flag on email';
    $res = $jmap->CallMethods([['Email/set', {
        update => {
            $fooid => {
                keywords => { '$Seen' => JSON::true },
            },
        }
    }, "R1"]]);
    $self->assert(exists $res->[0][1]->{updated}{$fooid});

    xlog "fetch emails with \$Seen flag";
    $res = $jmap->CallMethods([['Email/query', {
        filter => {
            hasKeyword => '$Seen',
        }
    }, "R1"]]);
    $self->assert_num_equals(1, scalar @{$res->[0][1]->{ids}});

    xlog "fetch emails without \$Seen flag";
    $res = $jmap->CallMethods([['Email/query', {
        filter => {
            notKeyword => '$Seen',
        }
    }, "R1"]]);
    $self->assert_num_equals(0, scalar @{$res->[0][1]->{ids}});

    xlog "create email";
    $res = $self->make_message("bar") || die;

    xlog "fetch emails without \$Seen flag";
    $res = $jmap->CallMethods([['Email/query', {
        filter => {
            notKeyword => '$Seen',
        }
    }, "R1"]]);
    $self->assert_num_equals(1, scalar @{$res->[0][1]->{ids}});
    my $barid = $res->[0][1]->{ids}[0];
    $self->assert_str_not_equals($barid, $fooid);

    xlog "fetch emails sorted ascending by \$Seen flag";
    $res = $jmap->CallMethods([['Email/query', {
        sort => [{ property => 'hasKeyword', keyword => '$Seen' }],
    }, "R1"]]);
    $self->assert_num_equals(2, scalar @{$res->[0][1]->{ids}});
    $self->assert_str_equals($barid, $res->[0][1]->{ids}[0]);
    $self->assert_str_equals($fooid, $res->[0][1]->{ids}[1]);

    xlog "fetch emails sorted descending by \$Seen flag";
    $res = $jmap->CallMethods([['Email/query', {
        sort => [{ property => 'hasKeyword', keyword => '$Seen', isAscending => JSON::false }],
    }, "R1"]]);
    $self->assert_num_equals(2, scalar @{$res->[0][1]->{ids}});
    $self->assert_str_equals($fooid, $res->[0][1]->{ids}[0]);
    $self->assert_str_equals($barid, $res->[0][1]->{ids}[1]);
}

sub test_email_query_userkeywords
    :min_version_3_1 :needs_component_jmap
{
    my ($self) = @_;
    my $jmap = $self->{jmap};

    my $store = $self->{store};
    my $talk = $store->get_client();

    xlog "create email foo";
    my $res = $self->make_message("foo") || die;

    xlog "fetch foo's id";
    $res = $jmap->CallMethods([['Email/query', { }, "R1"]]);
    my $fooid = $res->[0][1]->{ids}[0];
    $self->assert_not_null($fooid);

    xlog 'set foo flag on email foo';
    $res = $jmap->CallMethods([['Email/set', {
        update => {
            $fooid => {
                keywords => { 'foo' => JSON::true },
            },
        }
    }, "R1"]]);
    $self->assert(exists $res->[0][1]->{updated}{$fooid});

    xlog "run squatter";
    $self->{instance}->run_command({cyrus => 1}, 'squatter');

    xlog "fetch emails with foo flag";
    $res = $jmap->CallMethods([['Email/query', {
        filter => {
            hasKeyword => 'foo',
        }
    }, "R1"]]);
    $self->assert_num_equals(1, scalar @{$res->[0][1]->{ids}});
    $self->assert_str_equals($fooid, $res->[0][1]->{ids}[0]);

    xlog "create email bar";
    $res = $self->make_message("bar") || die;

    xlog "fetch emails without foo flag";
    $res = $jmap->CallMethods([['Email/query', {
        filter => {
            notKeyword => 'foo',
        }
    }, "R1"]]);
    $self->assert_num_equals(1, scalar @{$res->[0][1]->{ids}});
    my $barid = $res->[0][1]->{ids}[0];
    $self->assert_str_not_equals($barid, $fooid);

    xlog "fetch emails sorted ascending by foo flag";
    $res = $jmap->CallMethods([['Email/query', {
        sort => [{ property => 'hasKeyword', keyword => 'foo' }],
    }, "R1"]]);
    $self->assert_num_equals(2, scalar @{$res->[0][1]->{ids}});
    $self->assert_str_equals($barid, $res->[0][1]->{ids}[0]);
    $self->assert_str_equals($fooid, $res->[0][1]->{ids}[1]);

    xlog "fetch emails sorted descending by foo flag";
    $res = $jmap->CallMethods([['Email/query', {
        sort => [{ property => 'hasKeyword', keyword => 'foo', isAscending => JSON::false }],
    }, "R1"]]);
    $self->assert_num_equals(2, scalar @{$res->[0][1]->{ids}});
    $self->assert_str_equals($fooid, $res->[0][1]->{ids}[0]);
    $self->assert_str_equals($barid, $res->[0][1]->{ids}[1]);
}

sub test_email_query_threadkeywords
    :min_version_3_1 :needs_component_jmap
{
    my ($self) = @_;
    my %exp;
    my $jmap = $self->{jmap};
    my $res;

    my $imaptalk = $self->{store}->get_client();

    # check IMAP server has the XCONVERSATIONS capability
    $self->assert($self->{store}->get_client()->capability()->{xconversations});

    my $convflags = $self->{instance}->{config}->get('conversations_counted_flags');
    if (not defined $convflags) {
        xlog "conversations_counted_flags not configured. Skipping test";
        return;
    }

    my $store = $self->{store};
    my $talk = $store->get_client();

    my %params = (store => $store);
    $store->set_folder("INBOX");

    xlog "generating email A";
    $exp{A} = $self->make_message("Email A", %params);
    $exp{A}->set_attributes(uid => 1, cid => $exp{A}->make_cid());

    xlog "generating email B";
    $exp{B} = $self->make_message("Email B", %params);
    $exp{B}->set_attributes(uid => 2, cid => $exp{B}->make_cid());

    xlog "generating email C referencing A";
    %params = (
        references => [ $exp{A} ],
        store => $store,
    );
    $exp{C} = $self->make_message("Re: Email A", %params);
    $exp{C}->set_attributes(uid => 3, cid => $exp{A}->get_attribute('cid'));

    xlog "run squatter";
    $self->{instance}->run_command({cyrus => 1}, 'squatter');

    xlog "fetch email ids";
    $res = $jmap->CallMethods([
        ['Email/query', { }, "R1"],
        ['Email/get', { '#ids' => { resultOf => 'R1', name => 'Email/query', path => '/ids' } }, 'R2' ],
    ]);
    my %m = map { $_->{subject} => $_ } @{$res->[1][1]{list}};
    my $msga = $m{"Email A"};
    my $msgb = $m{"Email B"};
    my $msgc = $m{"Re: Email A"};
    $self->assert_not_null($msga);
    $self->assert_not_null($msgb);
    $self->assert_not_null($msgc);

    my @flags = split ' ', $convflags;
    foreach (@flags) {
        my $flag = $_;

        xlog "Testing for counted conversation flag $flag";
        $flag =~ s+^\\+\$+ ;

        xlog "fetch collapsed threads with some $flag flag";
        $res = $jmap->CallMethods([['Email/query', {
            filter => {
                someInThreadHaveKeyword => $flag,
            },
            collapseThreads => JSON::true,
        }, "R1"]]);
        $self->assert_num_equals(0, scalar @{$res->[0][1]->{ids}});

        xlog "set $flag flag on email email A";
        $res = $jmap->CallMethods([['Email/set', {
            update => {
                $msga->{id} => {
                    keywords => { $flag => JSON::true },
                },
            }
        }, "R1"]]);

        xlog "fetch collapsed threads with some $flag flag";
        $res = $jmap->CallMethods([
            ['Email/query', {
                filter => {
                    someInThreadHaveKeyword => $flag,
                },
                collapseThreads => JSON::true,
            }, "R1"],
        ]);
        $self->assert_num_equals(1, scalar @{$res->[0][1]->{ids}});
        $self->assert(
            ($msga->{id} eq $res->[0][1]->{ids}[0]) or
            ($msgc->{id} eq $res->[0][1]->{ids}[0])
        );

        xlog "fetch collapsed threads with no $flag flag";
        $res = $jmap->CallMethods([['Email/query', {
            filter => {
                noneInThreadHaveKeyword => $flag,
            },
            collapseThreads => JSON::true,
        }, "R1"]]);
        $self->assert_num_equals(1, scalar @{$res->[0][1]->{ids}});
        $self->assert_str_equals($msgb->{id}, $res->[0][1]->{ids}[0]);

        xlog "fetch collapsed threads sorted ascending by $flag";
        $res = $jmap->CallMethods([['Email/query', {
            sort => [{ property => "someInThreadHaveKeyword:$flag" }],
            collapseThreads => JSON::true,
        }, "R1"]]);
        $self->assert_num_equals(2, scalar @{$res->[0][1]->{ids}});
        $self->assert_str_equals($msgb->{id}, $res->[0][1]->{ids}[0]);
        $self->assert(
            ($msga->{id} eq $res->[0][1]->{ids}[1]) or
            ($msgc->{id} eq $res->[0][1]->{ids}[1])
        );

        xlog "fetch collapsed threads sorted descending by $flag";
        $res = $jmap->CallMethods([['Email/query', {
            sort => [{ property => "someInThreadHaveKeyword:$flag", isAscending => JSON::false }],
            collapseThreads => JSON::true,
        }, "R1"]]);
        $self->assert_num_equals(2, scalar @{$res->[0][1]->{ids}});
        $self->assert(
            ($msga->{id} eq $res->[0][1]->{ids}[0]) or
            ($msgc->{id} eq $res->[0][1]->{ids}[0])
        );
        $self->assert_str_equals($msgb->{id}, $res->[0][1]->{ids}[1]);

        xlog 'reset keywords on email email A';
        $res = $jmap->CallMethods([['Email/set', {
            update => {
                $msga->{id} => {
                    keywords => { },
                },
            }
        }, "R1"]]);
    }

    # Regression #1: test that 'allInThreadHaveKeyword' filters fail
    # with an 'cannotDoFilter' error for counted conversation flags.
    # Cyrus IMAP should support this filter but doesn't currently.
    my $flag = $flags[0];
    $flag =~ s+^\\+\$+ ;
    xlog "fetch collapsed threads with all having $flag flag";
    $res = $jmap->CallMethods([['Email/query', {
                    filter => {
                        allInThreadHaveKeyword => $flag,
                    },
                    collapseThreads => JSON::true,
                }, "R1"]]);
    $self->assert_str_equals('error', $res->[0][0]);
    $self->assert_str_equals('unsupportedFilter', $res->[0][1]->{type});

    # Regression #2: test that 'allInThreadHaveKeyword' sorts fail with
    # an 'unsupportedSort' error even for supported conversation flags
    $flag =~ s+^\\+\$+ ;
    xlog "fetch collapsed threads sorted by all having $flag flag";
    $res = $jmap->CallMethods([['Email/query', {
                    sort => [{ property => "allInThreadHaveKeyword:$flag" }],
                    collapseThreads => JSON::true,
                }, "R1"]]);
    $self->assert_str_equals('error', $res->[0][0]);
    $self->assert_str_equals('unsupportedSort', $res->[0][1]->{type});

    # Regression #3: test that 'someInThreadHaveKeyword' filter fail
    # with an 'cannotDoFilter' error for flags that are not defined
    # in the conversations_counted_flags config option
    xlog "fetch collapsed threads with unsupported flag";
    $res = $jmap->CallMethods([['Email/query', {
        filter => {
            someInThreadHaveKeyword => 'notcountedflag',
        },
        collapseThreads => JSON::true,
    }, "R1"]]);
    $self->assert_str_equals('error', $res->[0][0]);
    $self->assert_str_equals('unsupportedFilter', $res->[0][1]->{type});
}

sub test_email_query_empty
    :min_version_3_1 :needs_component_jmap
{
    my ($self) = @_;
    my $jmap = $self->{jmap};

    # See
    # https://github.com/cyrusimap/cyrus-imapd/issues/2266
    # and
    # https://github.com/cyrusimap/cyrus-imapd/issues/2287

    my $res = $jmap->CallMethods([['Email/query', { }, "R1"]]);
    $self->assert(ref($res->[0][1]->{ids}) eq 'ARRAY');
    $self->assert_num_equals(0, scalar @{$res->[0][1]->{ids}});

    $res = $jmap->CallMethods([['Email/query', { limit => 0 }, "R1"]]);
    $self->assert(ref($res->[0][1]->{ids}) eq 'ARRAY');
    $self->assert_num_equals(0, scalar @{$res->[0][1]->{ids}});
}

sub test_email_query_collapse
    :min_version_3_1 :needs_component_jmap
{
    my ($self) = @_;
    my %exp;
    my $jmap = $self->{jmap};
    my $res;

    my $imaptalk = $self->{store}->get_client();

    # check IMAP server has the XCONVERSATIONS capability
    $self->assert($self->{store}->get_client()->capability()->{xconversations});

    my $admintalk = $self->{adminstore}->get_client();
    $self->{instance}->create_user("test");
    $admintalk->setacl("user.test", "cassandane", "lrwkx") or die;

    # run tests for both the main and "test" account
    foreach (undef, "test") {
        my $account = $_;
        my $store = defined $account ? $self->{adminstore} : $self->{store};
        my $mboxprefix = defined $account ? "user.$account" : "INBOX";
        my $talk = $store->get_client();

        my %params = (store => $store);
        $store->set_folder($mboxprefix);

        xlog "generating email A";
        $exp{A} = $self->make_message("Email A", %params);
        $exp{A}->set_attributes(uid => 1, cid => $exp{A}->make_cid());

        xlog "generating email B";
        $exp{B} = $self->make_message("Email B", %params);
        $exp{B}->set_attributes(uid => 2, cid => $exp{B}->make_cid());

        xlog "generating email C referencing A";
        %params = (
            references => [ $exp{A} ],
            store => $store,
        );
        $exp{C} = $self->make_message("Re: Email A", %params);
        $exp{C}->set_attributes(uid => 3, cid => $exp{A}->get_attribute('cid'));

        xlog "list uncollapsed threads";
        $res = $jmap->CallMethods([['Email/query', { accountId => $account }, "R1"]]);
        $self->assert_num_equals(3, scalar @{$res->[0][1]->{ids}});

        $res = $jmap->CallMethods([['Email/query', { accountId => $account, collapseThreads => JSON::true }, "R1"]]);
        $self->assert_num_equals(2, scalar @{$res->[0][1]->{ids}});
    }
}

sub test_email_query_inmailbox_null
    :min_version_3_1 :needs_component_jmap
{
    my ($self) = @_;
    my $jmap = $self->{jmap};
    my $imaptalk = $self->{store}->get_client();

    # check IMAP server has the XCONVERSATIONS capability
    $self->assert($self->{store}->get_client()->capability()->{xconversations});

    xlog "generating email A";
    $self->make_message("Email A") or die;

    xlog "call Email/query with null inMailbox";
    my $res = $jmap->CallMethods([['Email/query', { filter => { inMailbox => undef } }, "R1"]]);
    $self->assert_str_equals("invalidArguments", $res->[0][1]{type});
}

sub test_misc_collapsethreads_issue2024
    :min_version_3_1 :needs_component_jmap
{
    my ($self) = @_;
    my %exp;
    my $jmap = $self->{jmap};
    my $res;

    my $imaptalk = $self->{store}->get_client();

    # test that the collapseThreads property is echoed back verbatim
    # see https://github.com/cyrusimap/cyrus-imapd/issues/2024

    # check IMAP server has the XCONVERSATIONS capability
    $self->assert($self->{store}->get_client()->capability()->{xconversations});

    xlog "generating email A";
    $exp{A} = $self->make_message("Email A");
    $exp{A}->set_attributes(uid => 1, cid => $exp{A}->make_cid());

    xlog "generating email B";
    $exp{B} = $self->make_message("Email B");
    $exp{B}->set_attributes(uid => 2, cid => $exp{B}->make_cid());

    xlog "generating email C referencing A";
    $exp{C} = $self->make_message("Re: Email A", references => [ $exp{A} ]);
    $exp{C}->set_attributes(uid => 3, cid => $exp{A}->get_attribute('cid'));

    $res = $jmap->CallMethods([['Email/query', { collapseThreads => JSON::true }, "R1"]]);
    $self->assert_equals(JSON::true, $res->[0][1]->{collapseThreads});

    $res = $jmap->CallMethods([['Email/query', { collapseThreads => JSON::false }, "R1"]]);
    $self->assert_equals(JSON::false, $res->[0][1]->{collapseThreads});

    $res = $jmap->CallMethods([['Email/query', { collapseThreads => undef }, "R1"]]);
    $self->assert_null($res->[0][1]->{collapseThreads});

    $res = $jmap->CallMethods([['Email/query', { }, "R1"]]);
    $self->assert_null($res->[0][1]->{collapseThreads});
}

sub test_email_query_window
    :min_version_3_1 :needs_component_jmap
{
    my ($self) = @_;
    my %exp;
    my $jmap = $self->{jmap};
    my $res;

    my $imaptalk = $self->{store}->get_client();

    # check IMAP server has the XCONVERSATIONS capability
    $self->assert($self->{store}->get_client()->capability()->{xconversations});

    xlog "generating email A";
    $exp{A} = $self->make_message("Email A");
    $exp{A}->set_attributes(uid => 1, cid => $exp{A}->make_cid());

    xlog "generating email B";
    $exp{B} = $self->make_message("Email B");
    $exp{B}->set_attributes(uid => 2, cid => $exp{B}->make_cid());

    xlog "generating email C referencing A";
    $exp{C} = $self->make_message("Re: Email A", references => [ $exp{A} ]);
    $exp{C}->set_attributes(uid => 3, cid => $exp{A}->get_attribute('cid'));

    xlog "generating email D";
    $exp{D} = $self->make_message("Email D");
    $exp{D}->set_attributes(uid => 2, cid => $exp{B}->make_cid());

    xlog "list all emails";
    $res = $jmap->CallMethods([['Email/query', { }, "R1"]]);
    $self->assert_num_equals(4, scalar @{$res->[0][1]->{ids}});
    $self->assert_num_equals(4, $res->[0][1]->{total});

    my $ids = $res->[0][1]->{ids};
    my @subids;

    xlog "list emails from position 1";
    $res = $jmap->CallMethods([['Email/query', { position => 1 }, "R1"]]);
    @subids = @{$ids}[1..3];
    $self->assert_deep_equals(\@subids, $res->[0][1]->{ids});
    $self->assert_num_equals(4, $res->[0][1]->{total});

    xlog "list emails from position 4";
    $res = $jmap->CallMethods([['Email/query', { position => 4 }, "R1"]]);
    $self->assert_num_equals(0, scalar @{$res->[0][1]->{ids}});
    $self->assert_num_equals(4, $res->[0][1]->{total});

    xlog "limit emails from position 1 to one email";
    $res = $jmap->CallMethods([['Email/query', { position => 1, limit => 1 }, "R1"]]);
    @subids = @{$ids}[1..1];
    $self->assert_deep_equals(\@subids, $res->[0][1]->{ids});
    $self->assert_num_equals(4, $res->[0][1]->{total});
    $self->assert_num_equals(1, $res->[0][1]->{position});

    xlog "anchor at 2nd email";
    $res = $jmap->CallMethods([['Email/query', { anchor => @{$ids}[1] }, "R1"]]);
    @subids = @{$ids}[1..3];
    $self->assert_deep_equals(\@subids, $res->[0][1]->{ids});
    $self->assert_num_equals(4, $res->[0][1]->{total});
    $self->assert_num_equals(1, $res->[0][1]->{position});

    xlog "anchor at 2nd email and offset -1";
    $res = $jmap->CallMethods([['Email/query', {
        anchor => @{$ids}[1], anchorOffset => -1,
    }, "R1"]]);
    @subids = @{$ids}[2..3];
    $self->assert_deep_equals(\@subids, $res->[0][1]->{ids});
    $self->assert_num_equals(4, $res->[0][1]->{total});
    $self->assert_num_equals(2, $res->[0][1]->{position});

    xlog "anchor at 3rd email and offset 1";
    $res = $jmap->CallMethods([['Email/query', {
        anchor => @{$ids}[2], anchorOffset => 1,
    }, "R1"]]);
    @subids = @{$ids}[1..3];
    $self->assert_deep_equals(\@subids, $res->[0][1]->{ids});
    $self->assert_num_equals(4, $res->[0][1]->{total});
    $self->assert_num_equals(1, $res->[0][1]->{position});

    xlog "anchor at 1st email offset -1 and limit 2";
    $res = $jmap->CallMethods([['Email/query', {
        anchor => @{$ids}[0], anchorOffset => -1, limit => 2
    }, "R1"]]);
    @subids = @{$ids}[1..2];
    $self->assert_deep_equals(\@subids, $res->[0][1]->{ids});
    $self->assert_num_equals(4, $res->[0][1]->{total});
    $self->assert_num_equals(1, $res->[0][1]->{position});
}

sub test_email_query_long
    :min_version_3_1 :needs_component_jmap
{
    my ($self) = @_;
    my %exp;
    my $jmap = $self->{jmap};
    my $res;

    my $imaptalk = $self->{store}->get_client();

    # check IMAP server has the XCONVERSATIONS capability
    $self->assert($self->{store}->get_client()->capability()->{xconversations});

    for (1..100) {
        $self->make_message("Email $_");
    }

    xlog "list first 60 emails";
    $res = $jmap->CallMethods([['Email/query', {
        limit => 60,
        offset => 0,
        collapseThreads => JSON::true,
        sort => [{ property => "id" }],
    }, "R1"]]);
    $self->assert_num_equals(60, scalar @{$res->[0][1]->{ids}});
    $self->assert_num_equals(100, $res->[0][1]->{total});
    $self->assert_num_equals(0, $res->[0][1]->{position});

    xlog "list 5 emails from offset 55 by anchor";
    $res = $jmap->CallMethods([['Email/query', {
        limit => 5,
        anchorOffset => 1,
        anchor => $res->[0][1]->{ids}[55],
        collapseThreads => JSON::true,
        sort => [{ property => "id" }],
    }, "R1"]]);
    $self->assert_num_equals(5, scalar @{$res->[0][1]->{ids}});
    $self->assert_num_equals(100, $res->[0][1]->{total});
    $self->assert_num_equals(54, $res->[0][1]->{position});

    my $ids = $res->[0][1]->{ids};
    my @subids;
}

sub test_email_query_acl
    :min_version_3_1 :needs_component_jmap
{
    my ($self) = @_;
    my $jmap = $self->{jmap};

    my $store = $self->{store};
    my $talk = $store->get_client();

    my $admintalk = $self->{adminstore}->get_client();

    # Create user and share mailbox
    $self->{instance}->create_user("foo");
    $admintalk->setacl("user.foo", "cassandane", "lr") or die;

    xlog "get email list";
    my $res = $jmap->CallMethods([['Email/query', { accountId => 'foo' }, "R1"]]);
    $self->assert_num_equals(0, scalar @{$res->[0][1]->{ids}});

    xlog "Create email in shared account";
    $self->{adminstore}->set_folder('user.foo');
    $self->make_message("Email foo", store => $self->{adminstore}) or die;

    xlog "get email list in main account";
    $res = $jmap->CallMethods([['Email/query', { }, "R1"]]);
    $self->assert_num_equals(0, scalar @{$res->[0][1]->{ids}});

    xlog "get email list in shared account";
    $res = $jmap->CallMethods([['Email/query', { accountId => 'foo' }, "R1"]]);
    $self->assert_num_equals(1, scalar @{$res->[0][1]->{ids}});
    my $id = $res->[0][1]->{ids}[0];

    xlog "Create email in main account";
    $self->make_message("Email cassandane") or die;

    xlog "get email list in main account";
    $res = $jmap->CallMethods([['Email/query', { }, "R1"]]);
    $self->assert_num_equals(1, scalar @{$res->[0][1]->{ids}});
    $self->assert_str_not_equals($id, $res->[0][1]->{ids}[0]);

    xlog "get email list in shared account";
    $res = $jmap->CallMethods([['Email/query', { accountId => 'foo' }, "R1"]]);
    $self->assert_num_equals(1, scalar @{$res->[0][1]->{ids}});
    $self->assert_str_equals($id, $res->[0][1]->{ids}[0]);

    xlog "create but do not share mailbox";
    $admintalk->create("user.foo.box1") or die;
    $admintalk->setacl("user.foo.box1", "cassandane", "") or die;

    xlog "create email in private mailbox";
    $self->{adminstore}->set_folder('user.foo.box1');
    $self->make_message("Email private foo", store => $self->{adminstore}) or die;

    xlog "get email list in shared account";
    $res = $jmap->CallMethods([['Email/query', { accountId => 'foo' }, "R1"]]);
    $self->assert_num_equals(1, scalar @{$res->[0][1]->{ids}});
    $self->assert_str_equals($id, $res->[0][1]->{ids}[0]);
}

sub test_email_query_unknown_mailbox
    :min_version_3_1 :needs_component_jmap
{
    my ($self) = @_;
    my %exp;
    my $jmap = $self->{jmap};
    my $res;

    my $imaptalk = $self->{store}->get_client();

    xlog "filter inMailbox with unknown mailbox";
    $res = $jmap->CallMethods([['Email/query', { filter => { inMailbox => "foo" } }, "R1"]]);
    $self->assert_str_equals('error', $res->[0][0]);
    $self->assert_str_equals('invalidArguments', $res->[0][1]{type});
    $self->assert_str_equals('filter/inMailbox', $res->[0][1]{arguments}[0]);

    xlog "filter inMailboxOtherThan with unknown mailbox";
    $res = $jmap->CallMethods([['Email/query', { filter => { inMailboxOtherThan => ["foo"] } }, "R1"]]);
    $self->assert_str_equals('error', $res->[0][0]);
    $self->assert_str_equals('invalidArguments', $res->[0][1]{type});
    $self->assert_str_equals('filter/inMailboxOtherThan[0]', $res->[0][1]{arguments}[0]);
}


sub test_searchsnippet_get
    :min_version_3_1 :needs_component_jmap
{
    my ($self) = @_;
    my $jmap = $self->{jmap};

    my $store = $self->{store};
    my $talk = $store->get_client();

    my $res = $jmap->CallMethods([['Mailbox/get', { }, "R1"]]);
    my $inboxid = $res->[0][1]{list}[0]{id};

    xlog "create emails";
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

    xlog "fetch email ids";
    $res = $jmap->CallMethods([
        ['Email/query', { }, "R1"],
        ['Email/get', { '#ids' => { resultOf => 'R1', name => 'Email/query', path => '/ids' } }, 'R2' ],
    ]);

    my %m = map { $_->{subject} => $_ } @{$res->[1][1]{list}};
    my $foo = $m{"Message foo"}->{id};
    my $bar = $m{"Message bar"}->{id};
    my $baz = $m{"Message baz"}->{id};
    $self->assert_not_null($foo);
    $self->assert_not_null($bar);
    $self->assert_not_null($baz);

    xlog "fetch snippets";
    $res = $jmap->CallMethods([['SearchSnippet/get', {
            emailIds => [ $foo, $bar ],
            filter => { text => "message" },
    }, "R1"]]);
    $self->assert_num_equals(2, scalar @{$res->[0][1]->{list}});
    $self->assert_null($res->[0][1]->{notFound});
    %m = map { $_->{emailId} => $_ } @{$res->[0][1]{list}};
    $self->assert_not_null($m{$foo});
    $self->assert_not_null($m{$bar});

    %m = map { $_->{emailId} => $_ } @{$res->[0][1]{list}};
    $self->assert_num_not_equals(-1, index($m{$foo}->{subject}, "<mark>Message</mark> foo"));
    $self->assert_num_not_equals(-1, index($m{$foo}->{preview}, "A simple <mark>message</mark>"));
    $self->assert_num_not_equals(-1, index($m{$bar}->{subject}, "<mark>Message</mark> bar"));
    $self->assert_num_not_equals(-1, index($m{$bar}->{preview}, ""
        . "<mark>Messages</mark> are processed by <mark>messaging</mark> systems,"
    ));

    xlog "fetch snippets with one unknown id";
    $res = $jmap->CallMethods([['SearchSnippet/get', {
            emailIds => [ $foo, "bam" ],
            filter => { text => "message" },
    }, "R1"]]);
    $self->assert_num_equals(1, scalar @{$res->[0][1]->{list}});
    $self->assert_num_equals(1, scalar @{$res->[0][1]->{notFound}});

    xlog "fetch snippets with only a matching subject";
    $res = $jmap->CallMethods([['SearchSnippet/get', {
            emailIds => [ $baz ],
            filter => { text => "message" },
    }, "R1"]]);
    $self->assert_not_null($res->[0][1]->{list}[0]->{subject});
    $self->assert(exists $res->[0][1]->{list}[0]->{preview});
}

sub test_searchsnippet_get_shared
    :min_version_3_1 :needs_component_jmap
{
    my ($self) = @_;
    my $jmap = $self->{jmap};

    my $store = $self->{store};
    my $talk = $store->get_client();

    my $admintalk = $self->{adminstore}->get_client();

    xlog "create user and share mailboxes";
    $self->{instance}->create_user("foo");
    $admintalk->setacl("user.foo", "cassandane", "lr") or die;
    $admintalk->create("user.foo.box1") or die;
    $admintalk->setacl("user.foo.box1", "cassandane", "lr") or die;

    my $res = $jmap->CallMethods([['Mailbox/get', { accountId => 'foo' }, "R1"]]);
    my $inboxid = $res->[0][1]{list}[0]{id};

    xlog "create emails in shared account";
    $self->{adminstore}->set_folder('user.foo');
    my %params = (
        body => "A simple email",
    );
    $res = $self->make_message("Email foo", %params, store => $self->{adminstore}) || die;
    $self->{adminstore}->set_folder('user.foo.box1');
    %params = (
        body => "Another simple email",
    );
    $res = $self->make_message("Email bar", %params, store => $self->{adminstore}) || die;

    xlog "run squatter";
    $self->{instance}->run_command({cyrus => 1}, 'squatter');

    xlog "fetch email ids";
    $res = $jmap->CallMethods([
        ['Email/query', { accountId => 'foo' }, "R1"],
        ['Email/get', {
            accountId => 'foo',
            '#ids' => { resultOf => 'R1', name => 'Email/query', path => '/ids' }
        }, 'R2' ],
    ]);

    my %m = map { $_->{subject} => $_ } @{$res->[1][1]{list}};
    my $foo = $m{"Email foo"}->{id};
    my $bar = $m{"Email bar"}->{id};
    $self->assert_not_null($foo);
    $self->assert_not_null($bar);

    xlog "remove read rights for mailbox containing email $bar";
    $admintalk->setacl("user.foo.box1", "cassandane", "") or die;

    xlog "fetch snippets";
    $res = $jmap->CallMethods([['SearchSnippet/get', {
            accountId => 'foo',
            emailIds => [ $foo, $bar ],
            filter => { text => "simple" },
    }, "R1"]]);
    $self->assert_str_equals($foo, $res->[0][1]->{list}[0]{emailId});
    $self->assert_str_equals($bar, $res->[0][1]->{notFound}[0]);
}

sub test_email_query_snippets
    :min_version_3_1 :needs_component_jmap
{
    my ($self) = @_;
    my %exp;
    my $jmap = $self->{jmap};
    my $res;

    my $imaptalk = $self->{store}->get_client();

    # check IMAP server has the XCONVERSATIONS capability
    $self->assert($self->{store}->get_client()->capability()->{xconversations});

    xlog "generating email A";
    $exp{A} = $self->make_message("Email A");
    $exp{A}->set_attributes(uid => 1, cid => $exp{A}->make_cid());

    xlog "run squatter";
    $self->{instance}->run_command({cyrus => 1}, 'squatter');

    xlog "fetch email and snippet";
    $res = $jmap->CallMethods([
        ['Email/query', { filter => { text => "email" }}, "R1"],
        ['SearchSnippet/get', {
            '#emailIds' => {
                resultOf => 'R1',
                name => 'Email/query',
                path => '/ids',
            },
            '#filter' => {
                resultOf => 'R1',
                name => 'Email/query', 
                path => '/filter',
            },
        }, 'R2'],
    ]);

    my $snippet = $res->[1][1]{list}[0];
    $self->assert_not_null($snippet);
    $self->assert_num_not_equals(-1, index($snippet->{subject}, "<mark>Email</mark> A"));

    xlog "fetch email and snippet with no filter";
    $res = $jmap->CallMethods([
        ['Email/query', { }, "R1"],
        ['SearchSnippet/get', {
            '#emailIds' => {
                resultOf => 'R1',
                name => 'Email/query', 
                path => '/ids',
            },
        }, 'R2'],
    ]);
    $snippet = $res->[1][1]{list}[0];
    $self->assert_not_null($snippet);
    $self->assert_null($snippet->{subject});
    $self->assert_null($snippet->{preview});

    xlog "fetch email and snippet with no text filter";
    $res = $jmap->CallMethods([
        ['Email/query', {
            filter => {
                operator => "OR",
                conditions => [{minSize => 1}, {maxSize => 1}]
            },
        }, "R1"],
        ['SearchSnippet/get', {
            '#emailIds' => {
                resultOf => 'R1',
                name => 'Email/query',
                path => '/ids',
            },
            '#filter' => {
                resultOf => 'R1',
                name => 'Email/query',
                path => '/filter',
            },
        }, 'R2'],
    ]);

    $snippet = $res->[1][1]{list}[0];
    $self->assert_not_null($snippet);
    $self->assert_null($snippet->{subject});
    $self->assert_null($snippet->{preview});
}

sub test_email_query_attachments
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
    my $draftsmbox = $res->[0][1]{created}{"1"}{id};

    # create a email with an attachment
    my $logofile = abs_path('data/logo.gif');
    open(FH, "<$logofile");
    local $/ = undef;
    my $binary = <FH>;
    close(FH);
    my $data = $jmap->Upload($binary, "image/gif");

    $res = $jmap->CallMethods([
      ['Email/set', { create => {
                  "1" => {
                      mailboxIds => {$draftsmbox =>  JSON::true},
                      from => [ { name => "Yosemite Sam", email => "sam\@acme.local" } ] ,
                      to => [
                          { name => "Bugs Bunny", email => "bugs\@acme.local" },
                      ],
                      subject => "Memo",
                      textBody => [{ partId => '1' }],
                      bodyValues => {'1' => { value => "I'm givin' ya one last chance ta surrenda!" }},
                      attachments => [{
                              blobId => $data->{blobId},
                              name => "logo.gif",
                      }],
                      keywords => { '$Draft' => JSON::true },
                  },
                  "2" => {
                      mailboxIds => {$draftsmbox =>  JSON::true},
                      from => [ { name => "Yosemite Sam", email => "sam\@acme.local" } ] ,
                      to => [
                          { name => "Bugs Bunny", email => "bugs\@acme.local" },
                      ],
                      subject => "Memo 2",
                      textBody => [{ partId => '1' }],
                      bodyValues => {'1' => { value => "I'm givin' ya *one* last chance ta surrenda!" }},
                      attachments => [{
                              blobId => $data->{blobId},
                              name => "somethingelse.gif",
                      }],
                      keywords => { '$Draft' => JSON::true },
                  },
  } }, 'R2'],
    ]);
    my $id1 = $res->[0][1]{created}{"1"}{id};
    my $id2 = $res->[0][1]{created}{"2"}{id};

    xlog "run squatter";
    $self->{instance}->run_command({cyrus => 1}, 'squatter');

    xlog "filter attachmentName";
    $res = $jmap->CallMethods([['Email/query', {
        filter => {
            attachmentName => "logo",
        },
    }, "R1"]]);
    $self->assert_num_equals(1, scalar @{$res->[0][1]->{ids}});
    $self->assert_str_equals($id1, $res->[0][1]->{ids}[0]);

    xlog "filter attachmentName";
    $res = $jmap->CallMethods([['Email/query', {
        filter => {
            attachmentName => "somethingelse.gif",
        },
    }, "R1"]]);
    $self->assert_num_equals(1, scalar @{$res->[0][1]->{ids}});
    $self->assert_str_equals($id2, $res->[0][1]->{ids}[0]);

    xlog "filter attachmentName";
    $res = $jmap->CallMethods([['Email/query', {
        filter => {
            attachmentName => "gif",
        },
    }, "R1"]]);
    $self->assert_num_equals(2, scalar @{$res->[0][1]->{ids}});

    xlog "filter text";
    $res = $jmap->CallMethods([['Email/query', {
        filter => {
            text => "logo",
        },
    }, "R1"]]);
    $self->assert_num_equals(1, scalar @{$res->[0][1]->{ids}});
    $self->assert_str_equals($id1, $res->[0][1]->{ids}[0]);
}

sub test_email_query_attachmentname
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
    my $draftsmbox = $res->[0][1]{created}{"1"}{id};

    # create a email with an attachment
    my $logofile = abs_path('data/logo.gif');
    open(FH, "<$logofile");
    local $/ = undef;
    my $binary = <FH>;
    close(FH);
    my $data = $jmap->Upload($binary, "image/gif");

    $res = $jmap->CallMethods([
      ['Email/set', { create => {
                  "1" => {
                      mailboxIds => {$draftsmbox =>  JSON::true},
                      from => [ { name => "", email => "sam\@acme.local" } ] ,
                      to => [ { name => "", email => "bugs\@acme.local" } ],
                      subject => "msg1",
                      textBody => [{ partId => '1' }],
                      bodyValues => { '1' => { value => "foo" } },
                      attachments => [{
                              blobId => $data->{blobId},
                              name => "R\N{LATIN SMALL LETTER U WITH DIAERESIS}bezahl.txt",
                      }],
                      keywords => { '$Draft' => JSON::true },
                  },
              }}, 'R2'],
    ]);
    my $id1 = $res->[0][1]{created}{"1"}{id};

    xlog "run squatter";
    $self->{instance}->run_command({cyrus => 1}, 'squatter');

    xlog "filter attachmentName";
    $res = $jmap->CallMethods([['Email/query', {
        filter => {
            attachmentName => "r\N{LATIN SMALL LETTER U WITH DIAERESIS}bezahl",
        },
    }, "R1"]]);
    $self->assert_num_equals(1, scalar @{$res->[0][1]->{ids}});
    $self->assert_str_equals($id1, $res->[0][1]->{ids}[0]);
}

sub test_email_query_attachmenttype
    :min_version_3_1 :needs_component_jmap
{
    my ($self) = @_;
    my $jmap = $self->{jmap};

    my $blobId = $jmap->Upload('some_data', "application/octet")->{blobId};

    my $inboxid = $self->getinbox()->{id};

    my $res = $jmap->CallMethods([
      ['Email/set', { create => {
        "1" => {
          mailboxIds => {$inboxid => JSON::true},
          from => [ { name => "", email => "sam\@acme.local" } ] ,
          to => [ { name => "", email => "bugs\@acme.local" } ],
          subject => "foo",
          textBody => [{ partId => '1' }],
          bodyValues => { '1' => { value => "foo" } },
          attachments => [{
            blobId => $blobId,
            type => 'image/gif',
          }],
      },
      "2" => {
          mailboxIds => {$inboxid => JSON::true},
          from => [ { name => "", email => "tweety\@acme.local" } ] ,
          to => [ { name => "", email => "duffy\@acme.local" } ],
          subject => "bar",
          textBody => [{ partId => '1' }],
          bodyValues => { '1' => { value => "bar" } },
      },
      "3" => {
          mailboxIds => {$inboxid => JSON::true},
          from => [ { name => "", email => "elmer\@acme.local" } ] ,
          to => [ { name => "", email => "porky\@acme.local" } ],
          subject => "baz",
          textBody => [{ partId => '1' }],
          bodyValues => { '1' => { value => "baz" } },
          attachments => [{
            blobId => $blobId,
            type => 'application/msword',
          }],
      }
      }}, 'R1']
    ]);
    my $idGif = $res->[0][1]{created}{"1"}{id};
    my $idTxt = $res->[0][1]{created}{"2"}{id};
    my $idDoc = $res->[0][1]{created}{"3"}{id};
    $self->assert_not_null($idGif);
    $self->assert_not_null($idTxt);
    $self->assert_not_null($idDoc);

    xlog "run squatter";
    $self->{instance}->run_command({cyrus => 1}, 'squatter');

    my @testCases = ({
        filter => {
            attachmentType => 'image/gif',
        },
        wantIds => [$idGif],
    }, {
        filter => {
            attachmentType => 'image',
        },
        wantIds => [$idGif],
    }, {
        filter => {
            attachmentType => 'application/msword',
        },
        wantIds => [$idDoc],
    }, {
        filter => {
            attachmentType => 'document',
        },
        wantIds => [$idDoc],
    }, {
        filter => {
            operator => 'NOT',
            conditions => [{
                attachmentType => 'image',
            }, {
                attachmentType => 'document',
            }],
        },
        wantIds => [$idTxt],
    });

    foreach (@testCases) {
        my $filter = $_->{filter};
        my $wantIds = $_->{wantIds};
        $res = $jmap->CallMethods([['Email/query', {
            filter => $filter,
        }, "R1"]]);
        my @wantIds = sort @{$wantIds};
        my @gotIds = sort @{$res->[0][1]->{ids}};
        $self->assert_deep_equals(\@wantIds, \@gotIds);
    }
}

sub test_thread_get
    :min_version_3_1 :needs_component_jmap
{
    my ($self) = @_;
    my %exp;
    my $jmap = $self->{jmap};
    my $res;
    my %params;
    my $dt;

    my $imaptalk = $self->{store}->get_client();

    xlog "create drafts mailbox";
    $res = $jmap->CallMethods([
            ['Mailbox/set', { create => { "1" => {
                            name => "drafts",
                            parentId => undef,
                            role => "drafts"
             }}}, "R1"]
    ]);
    my $drafts = $res->[0][1]{created}{"1"}{id};
    $self->assert_not_null($drafts);

    xlog "generating email A";
    $dt = DateTime->now();
    $dt->add(DateTime::Duration->new(hours => -3));
    $exp{A} = $self->make_message("Email A", date => $dt, body => "a");
    $exp{A}->set_attributes(uid => 1, cid => $exp{A}->make_cid());

    xlog "generating email B";
    $exp{B} = $self->make_message("Email B", body => "b");
    $exp{B}->set_attributes(uid => 2, cid => $exp{B}->make_cid());

    xlog "generating email C referencing A";
    $dt = DateTime->now();
    $dt->add(DateTime::Duration->new(hours => -2));
    $exp{C} = $self->make_message("Re: Email A", references => [ $exp{A} ], date => $dt, body => "c");
    $exp{C}->set_attributes(uid => 3, cid => $exp{A}->get_attribute('cid'));

    xlog "generating email D referencing A";
    $dt = DateTime->now();
    $dt->add(DateTime::Duration->new(hours => -1));
    $exp{D} = $self->make_message("Re: Email A", references => [ $exp{A} ], date => $dt, body => "d");
    $exp{D}->set_attributes(uid => 4, cid => $exp{A}->get_attribute('cid'));

    xlog "fetch emails";
    $res = $jmap->CallMethods([
        ['Email/query', { }, "R1"],
        ['Email/get', {
            '#ids' => {
                resultOf => 'R1',
                name => 'Email/query',
                path => '/ids'
            },
            fetchAllBodyValues => JSON::true,
        }, 'R2' ],
    ]);

    # Map messages by body contents
    my %m = map { $_->{bodyValues}{$_->{textBody}[0]{partId}}{value} => $_ } @{$res->[1][1]{list}};
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

    xlog "create draft replying to email A";
    $res = $jmap->CallMethods(
        [[ 'Email/set', { create => { "1" => {
            mailboxIds           => {$drafts =>  JSON::true},
            inReplyTo            => $msgA->{messageId},
            from                 => [ { name => "", email => "sam\@acme.local" } ],
            to                   => [ { name => "", email => "bugs\@acme.local" } ],
            subject              => "Re: Email A",
            textBody             => [{ partId => '1' }],
            bodyValues           => { 1 => { value => "I'm givin' ya one last chance ta surrenda!" }},
            keywords             => { '$Draft' => JSON::true },
        }}}, "R1" ]]);
    my $draftid = $res->[0][1]{created}{"1"}{id};
    $self->assert_not_null($draftid);

    xlog "get threads";
    $res = $jmap->CallMethods([['Thread/get', { ids => \@threadids }, "R1"]]);
    $self->assert_num_equals(2, scalar @{$res->[0][1]->{list}});
    $self->assert_deep_equals([], $res->[0][1]->{notFound});

    %m = map { $_->{id} => $_ } @{$res->[0][1]{list}};
    my $threadA = $m{$msgA->{threadId}};
    my $threadB = $m{$msgB->{threadId}};

    # Assert all emails are listed
    $self->assert_num_equals(4, scalar @{$threadA->{emailIds}});
    $self->assert_num_equals(1, scalar @{$threadB->{emailIds}});

    # Assert sort order by date
    $self->assert_str_equals($msgA->{id}, $threadA->{emailIds}[0]);
    $self->assert_str_equals($draftid, $threadA->{emailIds}[1]);
    $self->assert_str_equals($msgC->{id}, $threadA->{emailIds}[2]);
    $self->assert_str_equals($msgD->{id}, $threadA->{emailIds}[3]);
}

sub test_identity_get
    :min_version_3_1 :needs_component_jmap
{
    my ($self) = @_;
    my $jmap = $self->{jmap};
    my $id;
    my $res;

    xlog "get identities";
    $res = $jmap->CallMethods([['Identity/get', { }, "R1"]]);

    $self->assert_num_equals(1, scalar @{$res->[0][1]->{list}});
    $self->assert_num_equals(0, scalar @{$res->[0][1]->{notFound}});

    $id = $res->[0][1]->{list}[0];
    $self->assert_not_null($id->{id});
    $self->assert_not_null($id->{email});

    xlog "get unknown identities";
    $res = $jmap->CallMethods([['Identity/get', { ids => ["foo"] }, "R1"]]);
    $self->assert_num_equals(0, scalar @{$res->[0][1]->{list}});
    $self->assert_num_equals(1, scalar @{$res->[0][1]->{notFound}});
}

sub test_misc_emptyids
    :min_version_3_1 :needs_component_jmap
{
    my ($self) = @_;

    my $jmap = $self->{jmap};
    my $imaptalk = $self->{store}->get_client();
    my $res;

    $imaptalk->create("INBOX.foo") || die;

    $res = $jmap->CallMethods([['Mailbox/get', { ids => [] }, "R1"]]);
    $self->assert_num_equals(0, scalar @{$res->[0][1]{list}});

    $res = $jmap->CallMethods([['Thread/get', { ids => [] }, "R1"]]);
    $self->assert_num_equals(0, scalar @{$res->[0][1]{list}});

    $res = $jmap->CallMethods([['Email/get', { ids => [] }, "R1"]]);
    $self->assert_num_equals(0, scalar @{$res->[0][1]{list}});

    $res = $jmap->CallMethods([['Identity/get', { ids => [] }, "R1"]]);
    $self->assert_num_equals(0, scalar @{$res->[0][1]{list}});

    $res = $jmap->CallMethods([['SearchSnippet/get', { emailIds => [], filter => { text => "foo" } }, "R1"]]);
    $self->assert_num_equals(0, scalar @{$res->[0][1]{list}});
}

sub test_email_querychanges_basic
    :min_version_3_1 :needs_component_jmap
{
    my ($self) = @_;
    my $jmap = $self->{jmap};
    my $res;
    my $state;

    my $store = $self->{store};
    my $talk = $store->get_client();
    my $draftsmbox;

    xlog "Generate some email in INBOX via IMAP";
    $self->make_message("Email A") || die;
    $self->make_message("Email B") || die;
    $self->make_message("Email C") || die;
    $self->make_message("Email D") || die;

    $res = $jmap->CallMethods([['Email/query', {
        sort => [
         {
           property =>  "subject",
           isAscending => $JSON::true,
         }
        ],
    }, 'R1']]);

    $talk->select("INBOX");
    $talk->store("3", "+flags", "(\\Flagged)");

    my $old = $res->[0][1];

    $res = $jmap->CallMethods([['Email/queryChanges', {
        sort => [
         {
           property =>  "subject",
           isAscending => $JSON::true,
         }
        ],
        sinceQueryState => $old->{queryState},
    }, 'R2']]);

    my $new = $res->[0][1];
    $self->assert_str_equals($old->{queryState}, $new->{oldQueryState});
    $self->assert_str_not_equals($old->{queryState}, $new->{newQueryState});
    $self->assert_num_equals(1, scalar @{$new->{added}});
    $self->assert_num_equals(1, scalar @{$new->{removed}});
    $self->assert_str_equals($new->{removed}[0], $new->{added}[0]{id});
    $self->assert_str_equals($new->{removed}[0], $old->{ids}[$new->{added}[0]{index}]);
}

sub test_email_querychanges_basic_collapse
    :min_version_3_1 :needs_component_jmap
{
    my ($self) = @_;
    my $jmap = $self->{jmap};
    my $res;
    my $state;

    my $store = $self->{store};
    my $talk = $store->get_client();
    my $draftsmbox;

    xlog "Generate some email in INBOX via IMAP";
    $self->make_message("Email A") || die;
    $self->make_message("Email B") || die;
    $self->make_message("Email C") || die;
    $self->make_message("Email D") || die;

    $res = $jmap->CallMethods([['Email/query', {
        sort => [
         {
           property =>  "subject",
           isAscending => $JSON::true,
         }
        ],
        collapseThreads => $JSON::true,
    }, 'R1']]);

    $talk->select("INBOX");
    $talk->store("3", "+flags", "(\\Flagged)");

    my $old = $res->[0][1];

    $res = $jmap->CallMethods([['Email/queryChanges', {
        sort => [
         {
           property =>  "subject",
           isAscending => $JSON::true,
         }
        ],
        collapseThreads => $JSON::true,
        sinceQueryState => $old->{queryState},
    }, 'R2']]);

    my $new = $res->[0][1];
    $self->assert_str_equals($old->{queryState}, $new->{oldQueryState});
    $self->assert_str_not_equals($old->{queryState}, $new->{newQueryState});
    $self->assert_num_equals(1, scalar @{$new->{added}});
    $self->assert_num_equals(1, scalar @{$new->{removed}});
    $self->assert_str_equals($new->{removed}[0], $new->{added}[0]{id});
    $self->assert_str_equals($new->{removed}[0], $old->{ids}[$new->{added}[0]{index}]);
}

sub test_email_querychanges_basic_mb
    :min_version_3_1 :needs_component_jmap
{
    my ($self) = @_;
    my $jmap = $self->{jmap};
    my $res;
    my $state;

    my $store = $self->{store};
    my $talk = $store->get_client();
    my $inboxid = $self->getinbox()->{id};

    xlog "Generate some email in INBOX via IMAP";
    $self->make_message("Email A") || die;
    $self->make_message("Email B") || die;
    $self->make_message("Email C") || die;
    $self->make_message("Email D") || die;

    $res = $jmap->CallMethods([['Email/query', {
        sort => [
         {
           property =>  "subject",
           isAscending => $JSON::true,
         }
        ],
        filter => { inMailbox => $inboxid },
    }, 'R1']]);

    $talk->select("INBOX");
    $talk->store("3", "+flags", "(\\Flagged)");

    my $old = $res->[0][1];

    $res = $jmap->CallMethods([['Email/queryChanges', {
        sort => [
         {
           property =>  "subject",
           isAscending => $JSON::true,
         }
        ],
        filter => { inMailbox => $inboxid },
        sinceQueryState => $old->{queryState},
    }, 'R2']]);

    my $new = $res->[0][1];
    $self->assert_str_equals($old->{queryState}, $new->{oldQueryState});
    $self->assert_str_not_equals($old->{queryState}, $new->{newQueryState});
    $self->assert_num_equals(1, scalar @{$new->{added}});
    $self->assert_num_equals(1, scalar @{$new->{removed}});
    $self->assert_str_equals($new->{removed}[0], $new->{added}[0]{id});
    $self->assert_str_equals($new->{removed}[0], $old->{ids}[$new->{added}[0]{index}]);
}

sub test_email_querychanges_basic_mb_collapse
    :min_version_3_1 :needs_component_jmap
{
    my ($self) = @_;
    my $jmap = $self->{jmap};
    my $res;
    my $state;

    my $store = $self->{store};
    my $talk = $store->get_client();
    my $inboxid = $self->getinbox()->{id};

    xlog "Generate some email in INBOX via IMAP";
    $self->make_message("Email A") || die;
    $self->make_message("Email B") || die;
    $self->make_message("Email C") || die;
    $self->make_message("Email D") || die;

    $res = $jmap->CallMethods([['Email/query', {
        sort => [
         {
           property =>  "subject",
           isAscending => $JSON::true,
         }
        ],
        filter => { inMailbox => $inboxid },
        collapseThreads => $JSON::true,
    }, 'R1']]);

    $talk->select("INBOX");
    $talk->store("3", "+flags", "(\\Flagged)");

    my $old = $res->[0][1];

    $res = $jmap->CallMethods([['Email/queryChanges', {
        sort => [
         {
           property =>  "subject",
           isAscending => $JSON::true,
         }
        ],
        filter => { inMailbox => $inboxid },
        collapseThreads => $JSON::true,
        sinceQueryState => $old->{queryState},
        ##upToId => $old->{ids}[3],
    }, 'R2']]);

    my $new = $res->[0][1];
    $self->assert_str_equals($old->{queryState}, $new->{oldQueryState});
    $self->assert_str_not_equals($old->{queryState}, $new->{newQueryState});
    # with collased threads we have to check
    $self->assert_num_equals(1, scalar @{$new->{added}});
    $self->assert_num_equals(1, scalar @{$new->{removed}});
    $self->assert_str_equals($new->{removed}[0], $new->{added}[0]{id});
    $self->assert_str_equals($new->{removed}[0], $old->{ids}[$new->{added}[0]{index}]);

    xlog "now with upto past";
    $res = $jmap->CallMethods([['Email/queryChanges', {
        sort => [
         {
           property =>  "subject",
           isAscending => $JSON::true,
         }
        ],
        filter => { inMailbox => $inboxid },
        collapseThreads => $JSON::true,
        sinceQueryState => $old->{queryState},
        upToId => $old->{ids}[3],
    }, 'R2']]);

    $new = $res->[0][1];
    $self->assert_str_equals($old->{queryState}, $new->{oldQueryState});
    $self->assert_str_not_equals($old->{queryState}, $new->{newQueryState});
    $self->assert_num_equals(1, scalar @{$new->{added}});
    $self->assert_num_equals(1, scalar @{$new->{removed}});
    $self->assert_str_equals($new->{removed}[0], $new->{added}[0]{id});
    $self->assert_str_equals($new->{removed}[0], $old->{ids}[$new->{added}[0]{index}]);

    xlog "now with upto equal";
    $res = $jmap->CallMethods([['Email/queryChanges', {
        sort => [
         {
           property =>  "subject",
           isAscending => $JSON::true,
         }
        ],
        filter => { inMailbox => $inboxid },
        collapseThreads => $JSON::true,
        sinceQueryState => $old->{queryState},
        upToId => $old->{ids}[2],
    }, 'R2']]);

    $new = $res->[0][1];
    $self->assert_str_equals($old->{queryState}, $new->{oldQueryState});
    $self->assert_str_not_equals($old->{queryState}, $new->{newQueryState});
    $self->assert_num_equals(1, scalar @{$new->{added}});
    $self->assert_num_equals(1, scalar @{$new->{removed}});
    $self->assert_str_equals($new->{removed}[0], $new->{added}[0]{id});
    $self->assert_str_equals($new->{removed}[0], $old->{ids}[$new->{added}[0]{index}]);

    xlog "now with upto early";
    $res = $jmap->CallMethods([['Email/queryChanges', {
        sort => [
         {
           property =>  "subject",
           isAscending => $JSON::true,
         }
        ],
        filter => { inMailbox => $inboxid },
        collapseThreads => $JSON::true,
        sinceQueryState => $old->{queryState},
        upToId => $old->{ids}[1],
    }, 'R2']]);

    $new = $res->[0][1];
    $self->assert_str_equals($old->{queryState}, $new->{oldQueryState});
    $self->assert_str_not_equals($old->{queryState}, $new->{newQueryState});
    $self->assert_num_equals(0, scalar @{$new->{added}});
    $self->assert_num_equals(0, scalar @{$new->{removed}});
}

sub test_email_querychanges_skipdeleted
    :min_version_3_1 :needs_component_jmap
{
    my ($self) = @_;
    my $jmap = $self->{jmap};
    my $res;
    my $state;

    my $store = $self->{store};
    my $talk = $store->get_client();
    my $inboxid = $self->getinbox()->{id};

    xlog "Generate some email in INBOX via IMAP";
    $self->make_message("Email A") || die;
    $self->make_message("Email B") || die;
    $self->make_message("Email C") || die;
    $self->make_message("Email D") || die;

    $talk->create("INBOX.foo");
    $talk->select("INBOX");
    $talk->move("1:2", "INBOX.foo");
    $talk->select("INBOX.foo");
    $talk->move("1:2", "INBOX");

    $res = $jmap->CallMethods([['Email/query', {
        sort => [
         {
           property =>  "subject",
           isAscending => $JSON::true,
         }
        ],
        filter => { inMailbox => $inboxid },
        collapseThreads => $JSON::true,
    }, 'R1']]);

    my $old = $res->[0][1];

    $talk->select("INBOX");
    $talk->store("1", "+flags", "(\\Flagged)");

    $res = $jmap->CallMethods([['Email/queryChanges', {
        sort => [
         {
           property =>  "subject",
           isAscending => $JSON::true,
         }
        ],
        filter => { inMailbox => $inboxid },
        collapseThreads => $JSON::true,
        sinceQueryState => $old->{queryState},
    }, 'R2']]);

    my $new = $res->[0][1];
    $self->assert_str_equals($old->{queryState}, $new->{oldQueryState});
    $self->assert_str_not_equals($old->{queryState}, $new->{newQueryState});
    # with collased threads we have to check
    $self->assert_num_equals(1, scalar @{$new->{added}});
    $self->assert_num_equals(1, scalar @{$new->{removed}});
    $self->assert_str_equals($new->{removed}[0], $new->{added}[0]{id});
    $self->assert_str_equals($new->{removed}[0], $old->{ids}[$new->{added}[0]{index}]);
}

sub test_email_querychanges_deletedcopy
    :min_version_3_1 :needs_component_jmap
{
    my ($self) = @_;
    my $jmap = $self->{jmap};
    my $res;
    my $state;

    my $store = $self->{store};
    my $talk = $store->get_client();
    my $inboxid = $self->getinbox()->{id};

    xlog "Generate some email in INBOX via IMAP";
    $self->make_message("Email A") || die;
    $self->make_message("Email B") || die;
    $self->make_message("Email C") || die;
    $self->make_message("Email D") || die;

    $res = $jmap->CallMethods([['Email/query', {
        sort => [
         {
           property =>  "subject",
           isAscending => $JSON::true,
         }
        ],
        filter => { inMailbox => $inboxid },
        collapseThreads => $JSON::true,
    }, 'R1']]);

    $talk->create("INBOX.foo");
    $talk->select("INBOX");
    $talk->move("2", "INBOX.foo");
    $talk->select("INBOX.foo");
    $talk->move("1", "INBOX");
    $talk->select("INBOX");
    $talk->store("2", "+flags", "(\\Flagged)");

    # order is now A (B) C D B, and (B), C and B are "changed"

    my $old = $res->[0][1];

    $res = $jmap->CallMethods([['Email/queryChanges', {
        sort => [
         {
           property =>  "subject",
           isAscending => $JSON::true,
         }
        ],
        filter => { inMailbox => $inboxid },
        collapseThreads => $JSON::true,
        sinceQueryState => $old->{queryState},
    }, 'R2']]);

    my $new = $res->[0][1];
    $self->assert_str_equals($old->{queryState}, $new->{oldQueryState});
    $self->assert_str_not_equals($old->{queryState}, $new->{newQueryState});
    # with collased threads we have to check
    $self->assert_num_equals(2, scalar @{$new->{added}});
    $self->assert_num_equals(2, scalar @{$new->{removed}});
    $self->assert_str_equals($new->{added}[0]{id}, $old->{ids}[$new->{added}[0]{index}]);
    $self->assert_str_equals($new->{added}[1]{id}, $old->{ids}[$new->{added}[1]{index}]);
}

sub test_email_changes
    :min_version_3_1 :needs_component_jmap
{
    my ($self) = @_;
    my $jmap = $self->{jmap};
    my $res;
    my $state;

    my $store = $self->{store};
    my $talk = $store->get_client();
    my $draftsmbox;

    xlog "create drafts mailbox";
    $res = $jmap->CallMethods([
            ['Mailbox/set', { create => { "1" => {
                            name => "drafts",
                            parentId => undef,
                            role => "drafts"
             }}}, "R1"]
    ]);
    $draftsmbox = $res->[0][1]{created}{"1"}{id};

    xlog "get email updates (expect error)";
    $res = $jmap->CallMethods([['Email/changes', { sinceState => 0 }, "R1"]]);
    $self->assert_str_equals($res->[0][1]->{type}, "invalidArguments");
    $self->assert_str_equals($res->[0][1]->{arguments}[0], "sinceState");

    xlog "get email state";
    $res = $jmap->CallMethods([['Email/get', { ids => []}, "R1"]]);
    $state = $res->[0][1]->{state};
    $self->assert_not_null($state);

    xlog "get email updates";
    $res = $jmap->CallMethods([['Email/changes', { sinceState => $state }, "R1"]]);
    $self->assert_str_equals($state, $res->[0][1]->{oldState});
    $self->assert_str_equals($state, $res->[0][1]->{newState});
    $self->assert_equals(JSON::false, $res->[0][1]->{hasMoreChanges});
    $self->assert_deep_equals([], $res->[0][1]{created});
    $self->assert_deep_equals([], $res->[0][1]{updated});
    $self->assert_deep_equals([], $res->[0][1]{destroyed});

    xlog "Generate a email in INBOX via IMAP";
    $self->make_message("Email A") || die;

    xlog "Get email id";
    $res = $jmap->CallMethods([['Email/query', {}, "R1"]]);
    my $ida = $res->[0][1]->{ids}[0];
    $self->assert_not_null($ida);

    xlog "get email updates";
    $res = $jmap->CallMethods([['Email/changes', { sinceState => $state }, "R1"]]);
    $self->assert_str_equals($state, $res->[0][1]->{oldState});
    $self->assert_str_not_equals($state, $res->[0][1]->{newState});
    $self->assert_equals(JSON::false, $res->[0][1]->{hasMoreChanges});
    $self->assert_num_equals(1, scalar @{$res->[0][1]{created}});
    $self->assert_str_equals($ida, $res->[0][1]{created}[0]);
    $self->assert_deep_equals([], $res->[0][1]{updated});
    $self->assert_deep_equals([], $res->[0][1]{destroyed});
    $state = $res->[0][1]->{newState};

    xlog "get email updates (expect no changes)";
    $res = $jmap->CallMethods([['Email/changes', { sinceState => $state }, "R1"]]);
    $self->assert_str_equals($state, $res->[0][1]->{oldState});
    $self->assert_str_equals($state, $res->[0][1]->{newState});
    $self->assert_equals(JSON::false, $res->[0][1]->{hasMoreChanges});
    $self->assert_deep_equals([], $res->[0][1]{created});
    $self->assert_deep_equals([], $res->[0][1]{updated});
    $self->assert_deep_equals([], $res->[0][1]{destroyed});

    xlog "update email $ida";
    $res = $jmap->CallMethods([['Email/set', {
        update => { $ida => { keywords => { '$Seen' => JSON::true }}}
    }, "R1"]]);
    $self->assert(exists $res->[0][1]->{updated}{$ida});

    xlog "get email updates";
    $res = $jmap->CallMethods([['Email/changes', { sinceState => $state }, "R1"]]);
    $self->assert_str_equals($state, $res->[0][1]->{oldState});
    $self->assert_str_not_equals($state, $res->[0][1]->{newState});
    $self->assert_equals(JSON::false, $res->[0][1]->{hasMoreChanges});
    $self->assert_deep_equals([], $res->[0][1]{created});
    $self->assert_num_equals(1, scalar @{$res->[0][1]{updated}});
    $self->assert_str_equals($ida, $res->[0][1]{updated}[0]);
    $self->assert_deep_equals([], $res->[0][1]{destroyed});
    $state = $res->[0][1]->{newState};

    xlog "delete email $ida";
    $res = $jmap->CallMethods([['Email/set', {destroy => [ $ida ] }, "R1"]]);
    $self->assert_str_equals($ida, $res->[0][1]->{destroyed}[0]);

    xlog "get email updates";
    $res = $jmap->CallMethods([['Email/changes', { sinceState => $state }, "R1"]]);
    $self->assert_str_equals($state, $res->[0][1]->{oldState});
    $self->assert_str_not_equals($state, $res->[0][1]->{newState});
    $self->assert_equals(JSON::false, $res->[0][1]->{hasMoreChanges});
    $self->assert_deep_equals([], $res->[0][1]{created});
    $self->assert_deep_equals([], $res->[0][1]{updated});
    $self->assert_num_equals(1, scalar @{$res->[0][1]{destroyed}});
    $self->assert_str_equals($ida, $res->[0][1]{destroyed}[0]);
    $state = $res->[0][1]->{newState};

    xlog "get email updates (expect no changes)";
    $res = $jmap->CallMethods([['Email/changes', { sinceState => $state }, "R1"]]);
    $self->assert_str_equals($state, $res->[0][1]->{oldState});
    $self->assert_str_equals($state, $res->[0][1]->{newState});
    $self->assert_equals(JSON::false, $res->[0][1]->{hasMoreChanges});
    $self->assert_deep_equals([], $res->[0][1]{created});
    $self->assert_deep_equals([], $res->[0][1]{updated});
    $self->assert_deep_equals([], $res->[0][1]{destroyed});

    xlog "create email B";
    $res = $jmap->CallMethods(
        [[ 'Email/set', { create => { "1" => {
            mailboxIds           => {$draftsmbox =>  JSON::true},
            from                 => [ { name => "", email => "sam\@acme.local" } ],
            to                   => [ { name => "", email => "bugs\@acme.local" } ],
            subject              => "Email B",
            textBody             => [{ partId => '1' }],
            bodyValues           => { '1' => { value => "I'm givin' ya one last chance ta surrenda!" }},
            keywords             => { '$Draft' => JSON::true },
        }}}, "R1" ]]);
    my $idb = $res->[0][1]{created}{"1"}{id};
    $self->assert_not_null($idb);

    xlog "create email C";
    $res = $jmap->CallMethods(
        [[ 'Email/set', { create => { "1" => {
            mailboxIds           => {$draftsmbox =>  JSON::true},
            from                 => [ { name => "", email => "sam\@acme.local" } ],
            to                   => [ { name => "", email => "bugs\@acme.local" } ],
            subject              => "Email C",
            textBody             => [{ partId => '1' }],
            bodyValues           => { '1' => { value => "I *hate* that rabbit!" } },
            keywords             => { '$Draft' => JSON::true },
        }}}, "R1" ]]);
    my $idc = $res->[0][1]{created}{"1"}{id};
    $self->assert_not_null($idc);

    xlog "get max 1 email updates";
    $res = $jmap->CallMethods([['Email/changes', { sinceState => $state, maxChanges => 1 }, "R1"]]);
    $self->assert_str_equals($state, $res->[0][1]->{oldState});
    $self->assert_str_not_equals($state, $res->[0][1]->{newState});
    $self->assert_equals(JSON::true, $res->[0][1]->{hasMoreChanges});
    $self->assert_num_equals(1, scalar @{$res->[0][1]{created}});
    $self->assert_str_equals($idb, $res->[0][1]{created}[0]);
    $self->assert_deep_equals([], $res->[0][1]{updated});
    $self->assert_deep_equals([], $res->[0][1]{destroyed});
    $state = $res->[0][1]->{newState};

    xlog "get max 1 email updates";
    $res = $jmap->CallMethods([['Email/changes', { sinceState => $state, maxChanges => 1 }, "R1"]]);
    $self->assert_str_equals($state, $res->[0][1]->{oldState});
    $self->assert_str_not_equals($state, $res->[0][1]->{newState});
    $self->assert_equals(JSON::false, $res->[0][1]->{hasMoreChanges});
    $self->assert_num_equals(1, scalar @{$res->[0][1]{created}});
    $self->assert_str_equals($idc, $res->[0][1]{created}[0]);
    $self->assert_deep_equals([], $res->[0][1]{updated});
    $self->assert_deep_equals([], $res->[0][1]{destroyed});
    $state = $res->[0][1]->{newState};

    xlog "get email updates (expect no changes)";
    $res = $jmap->CallMethods([['Email/changes', { sinceState => $state }, "R1"]]);
    $self->assert_str_equals($state, $res->[0][1]->{oldState});
    $self->assert_str_equals($state, $res->[0][1]->{newState});
    $self->assert_equals(JSON::false, $res->[0][1]->{hasMoreChanges});
    $self->assert_deep_equals([], $res->[0][1]{created});
    $self->assert_deep_equals([], $res->[0][1]{updated});
    $self->assert_deep_equals([], $res->[0][1]{destroyed});
}

sub test_email_querychanges
    :min_version_3_1 :needs_component_jmap
{
    my ($self) = @_;
    my $jmap = $self->{jmap};
    my $res;
    my $state;

    my $store = $self->{store};
    my $talk = $store->get_client();

    xlog "Generate a email in INBOX via IMAP";
    $self->make_message("Email A") || die;

    xlog "Get email id";
    $res = $jmap->CallMethods([['Email/query', {}, "R1"]]);
    my $ida = $res->[0][1]->{ids}[0];
    $self->assert_not_null($ida);

    $state = $res->[0][1]->{queryState};

    $self->make_message("Email B") || die;

    $res = $jmap->CallMethods([['Email/query', {}, "R1"]]);

    my ($idb) = grep { $_ ne $ida } @{$res->[0][1]->{ids}};

    xlog "get email list updates";
    $res = $jmap->CallMethods([['Email/queryChanges', { sinceQueryState => $state }, "R1"]]);

    $self->assert_equals($res->[0][1]{added}[0]{id}, $idb);

    xlog "get email list updates with threads collapsed";
    $res = $jmap->CallMethods([['Email/queryChanges', { sinceQueryState => $state, collapseThreads => JSON::true }, "R1"]]);

    $self->assert_equals($res->[0][1]{added}[0]{id}, $idb);
}

sub test_email_querychanges_zerosince
    :min_version_3_1 :needs_component_jmap
{
    my ($self) = @_;
    my $jmap = $self->{jmap};
    my $res;
    my $state;

    my $store = $self->{store};
    my $talk = $store->get_client();

    xlog "Generate a email in INBOX via IMAP";
    $self->make_message("Email A") || die;

    xlog "Get email id";
    $res = $jmap->CallMethods([['Email/query', {}, "R1"]]);
    my $ida = $res->[0][1]->{ids}[0];
    $self->assert_not_null($ida);

    $state = $res->[0][1]->{queryState};

    $self->make_message("Email B") || die;

    $res = $jmap->CallMethods([['Email/query', {}, "R1"]]);

    my ($idb) = grep { $_ ne $ida } @{$res->[0][1]->{ids}};

    xlog "get email list updates";
    $res = $jmap->CallMethods([['Email/queryChanges', { sinceQueryState => $state }, "R1"]]);

    $self->assert_equals($res->[0][1]{added}[0]{id}, $idb);

    xlog "get email list updates with threads collapsed";
    $res = $jmap->CallMethods([['Email/queryChanges', { sinceQueryState => "0", collapseThreads => JSON::true }, "R1"]]);
    $self->assert_equals('error', $res->[0][0]);
}


sub test_email_querychanges_thread
    :min_version_3_1 :needs_component_jmap
{
    my ($self) = @_;
    my $jmap = $self->{jmap};
    my $res;
    my $state;
    my %exp;
    my $dt;

    my $store = $self->{store};
    my $talk = $store->get_client();

    xlog "generating email A";
    $dt = DateTime->now();
    $dt->add(DateTime::Duration->new(hours => -3));
    $exp{A} = $self->make_message("Email A", date => $dt, body => "a");
    $exp{A}->set_attributes(uid => 1, cid => $exp{A}->make_cid());

    xlog "Get email id";
    $res = $jmap->CallMethods([['Email/query', {}, "R1"]]);
    my $ida = $res->[0][1]->{ids}[0];
    $self->assert_not_null($ida);

    $state = $res->[0][1]->{queryState};

    xlog "generating email B";
    $exp{B} = $self->make_message("Email B", body => "b");
    $exp{B}->set_attributes(uid => 2, cid => $exp{B}->make_cid());

    xlog "generating email C referencing A";
    $dt = DateTime->now();
    $dt->add(DateTime::Duration->new(hours => -2));
    $exp{C} = $self->make_message("Re: Email A", references => [ $exp{A} ], date => $dt, body => "c");
    $exp{C}->set_attributes(uid => 3, cid => $exp{A}->get_attribute('cid'));

    xlog "generating email D referencing A";
    $dt = DateTime->now();
    $dt->add(DateTime::Duration->new(hours => -1));
    $exp{D} = $self->make_message("Re: Email A", references => [ $exp{A} ], date => $dt, body => "d");
    $exp{D}->set_attributes(uid => 4, cid => $exp{A}->get_attribute('cid'));

    $res = $jmap->CallMethods([['Email/queryChanges', { sinceQueryState => $state, collapseThreads => JSON::true }, "R1"]]);
    $state = $res->[0][1]{newQueryState};

    $self->assert_num_equals(2, $res->[0][1]{total});
    # assert that IDA got destroyed
    $self->assert_not_null(grep { $_ eq $ida } map { $_ } @{$res->[0][1]->{removed}});
    # and not recreated
    $self->assert_null(grep { $_ eq $ida } map { $_->{id} } @{$res->[0][1]->{added}});

    $talk->select("INBOX");
    $talk->store('3', "+flags", '\\Deleted');
    $talk->expunge();

    $res = $jmap->CallMethods([['Email/queryChanges', { sinceQueryState => $state, collapseThreads => JSON::true }, "R1"]]);
    $state = $res->[0][1]{newQueryState};

    $self->assert_num_equals(2, $res->[0][1]{total});
    $self->assert(ref($res->[0][1]{added}) eq 'ARRAY');
    $self->assert_num_equals(0, scalar @{$res->[0][1]{added}});
    $self->assert(ref($res->[0][1]{removed}) eq 'ARRAY');
    $self->assert_num_equals(0, scalar @{$res->[0][1]{removed}});

    $talk->store('3', "+flags", '\\Deleted');
    $talk->expunge();

    $res = $jmap->CallMethods([['Email/queryChanges', { sinceQueryState => $state, collapseThreads => JSON::true }, "R1"]]);

    $self->assert_num_equals(2, $res->[0][1]{total});
    $self->assert_num_equals(1, scalar(@{$res->[0][1]{added}}));
    $self->assert_num_equals(2, scalar(@{$res->[0][1]{removed}}));

    # same thread, back to ida
    $self->assert_str_equals($ida, $res->[0][1]{added}[0]{id});
    #$self->assert_str_equals($res->[0][1]{added}[0]{threadId}, $res->[0][1]{destroyed}[0]{threadId});
}

sub test_email_querychanges_order
    :min_version_3_1 :needs_component_jmap
{
    my ($self) = @_;
    my $jmap = $self->{jmap};
    my $res;
    my $state;

    my $store = $self->{store};
    my $talk = $store->get_client();

    xlog "Generate a email in INBOX via IMAP";
    $self->make_message("A") || die;

    # First order descending by subject. We expect Email/queryChanges
    # to return any items added after 'state' to show up at the start of
    # the result list.
    my $sort = [{ property => "subject", isAscending => JSON::false }];

    xlog "Get email id and state";
    $res = $jmap->CallMethods([['Email/query', { sort => $sort }, "R1"]]);
    my $ida = $res->[0][1]->{ids}[0];
    $self->assert_not_null($ida);
    $state = $res->[0][1]->{queryState};

    xlog "Generate a email in INBOX via IMAP";
    $self->make_message("B") || die;

    xlog "Fetch updated list";
    $res = $jmap->CallMethods([['Email/query', { sort => $sort }, "R1"]]);
    my $idb = $res->[0][1]->{ids}[0];
    $self->assert_str_not_equals($ida, $idb);

    xlog "get email list updates";
    $res = $jmap->CallMethods([['Email/queryChanges', { sinceQueryState => $state, sort => $sort }, "R1"]]);
    $self->assert_equals($idb, $res->[0][1]{added}[0]{id});
    $self->assert_num_equals(0, $res->[0][1]{added}[0]{index});

    # Now restart with sorting by ascending subject. We refetch the state
    # just to be sure. Then we expect an additional item to show up at the
    # end of the result list.
    xlog "Fetch reverse sorted list and state";
    $sort = [{ property => "subject" }];
    $res = $jmap->CallMethods([['Email/query', { sort => $sort }, "R1"]]);
    $ida = $res->[0][1]->{ids}[0];
    $self->assert_str_not_equals($ida, $idb);
    $idb = $res->[0][1]->{ids}[1];
    $state = $res->[0][1]->{queryState};

    xlog "Generate a email in INBOX via IMAP";
    $self->make_message("C") || die;

    xlog "get email list updates";
    $res = $jmap->CallMethods([['Email/queryChanges', { sinceQueryState => $state, sort => $sort }, "R1"]]);
    $self->assert_str_not_equals($ida, $res->[0][1]{added}[0]{id});
    $self->assert_str_not_equals($idb, $res->[0][1]{added}[0]{id});
    $self->assert_num_equals(2, $res->[0][1]{added}[0]{index});
}

sub test_email_querychanges_implementation
    :min_version_3_1 :needs_component_jmap
{
    my ($self) = @_;
    my $jmap = $self->{jmap};

    # Also see https://github.com/cyrusimap/cyrus-imapd/issues/2294

    my $store = $self->{store};
    my $talk = $store->get_client();

    xlog "Generate two emails via IMAP";
    $self->make_message("EmailA") || die;
    $self->make_message("EmailB") || die;

    # The JMAP implementation in Cyrus uses two strategies
    # for processing an Email/queryChanges request, depending
    # on the query arguments:
    #
    # (1) 'trivial': if collapseThreads is false
    #
    # (2) 'collapse': if collapseThreads is true
    #
    #  The results should be the same for (1) and (2), where
    #  updated message are reported as both 'added' and 'removed'.

    my $inboxid = $self->getinbox()->{id};

    xlog "Get email ids and state";
    my $res = $jmap->CallMethods([
        ['Email/query', {
            sort => [
                { isAscending => JSON::true, property => 'subject' }
            ],
            collapseThreads => JSON::false,
        }, "R1"],
        ['Email/query', {
            sort => [
                { isAscending => JSON::true, property => 'subject' }
            ],
            collapseThreads => JSON::true,
        }, "R2"],
    ]);
    my $msgidA = $res->[0][1]->{ids}[0];
    $self->assert_not_null($msgidA);
    my $msgidB = $res->[0][1]->{ids}[1];
    $self->assert_not_null($msgidB);

    my $state_trivial = $res->[0][1]->{queryState};
    $self->assert_not_null($state_trivial);
    my $state_collapsed = $res->[1][1]->{queryState};
    $self->assert_not_null($state_collapsed);

	xlog "update email B";
	$res = $jmap->CallMethods([['Email/set', {
		update => { $msgidB => {
			'keywords/$Seen' => JSON::true }
		},
	}, "R1"]]);
    $self->assert(exists $res->[0][1]->{updated}{$msgidB});

    xlog "Create two new emails via IMAP";
    $self->make_message("EmailC") || die;
    $self->make_message("EmailD") || die;

    xlog "Get email ids";
    $res = $jmap->CallMethods([['Email/query', {
        sort => [{ isAscending => JSON::true, property => 'subject' }],
    }, "R1"]]);
    my $msgidC = $res->[0][1]->{ids}[2];
    $self->assert_not_null($msgidC);
    my $msgidD = $res->[0][1]->{ids}[3];
    $self->assert_not_null($msgidD);

    xlog "Query changes up to first newly created message";
    $res = $jmap->CallMethods([
        ['Email/queryChanges', {
            sort => [
                { isAscending => JSON::true, property => 'subject' }
            ],
            sinceQueryState => $state_trivial,
            collapseThreads => JSON::false,
            upToId => $msgidC,
        }, "R1"],
        ['Email/queryChanges', {
            sort => [
                { isAscending => JSON::true, property => 'subject' }
            ],
            sinceQueryState => $state_collapsed,
            collapseThreads => JSON::true,
            upToId => $msgidC,
        }, "R2"],
    ]);

    # 'trivial' case
    $self->assert_num_equals(2, scalar @{$res->[0][1]{added}});
    $self->assert_str_equals($msgidB, $res->[0][1]{added}[0]{id});
    $self->assert_num_equals(1, $res->[0][1]{added}[0]{index});
    $self->assert_str_equals($msgidC, $res->[0][1]{added}[1]{id});
    $self->assert_num_equals(2, $res->[0][1]{added}[1]{index});
    $self->assert_deep_equals([$msgidB, $msgidC], $res->[0][1]{removed});
    $self->assert_num_equals(4, $res->[0][1]{total});
    $state_trivial = $res->[0][1]{newQueryState};

    # 'collapsed' case
    $self->assert_num_equals(2, scalar @{$res->[1][1]{added}});
    $self->assert_str_equals($msgidB, $res->[1][1]{added}[0]{id});
    $self->assert_num_equals(1, $res->[1][1]{added}[0]{index});
    $self->assert_str_equals($msgidC, $res->[1][1]{added}[1]{id});
    $self->assert_num_equals(2, $res->[1][1]{added}[1]{index});
    $self->assert_deep_equals([$msgidB, $msgidC], $res->[1][1]{removed});
    $self->assert_num_equals(4, $res->[0][1]{total});
    $state_collapsed = $res->[1][1]{newQueryState};

    xlog "delete email C ($msgidC)";
    $res = $jmap->CallMethods([['Email/set', { destroy => [ $msgidC ] }, "R1"]]);
    $self->assert_str_equals($msgidC, $res->[0][1]->{destroyed}[0]);

    xlog "Query changes";
    $res = $jmap->CallMethods([
        ['Email/queryChanges', {
            sort => [
                { isAscending => JSON::true, property => 'subject' }
            ],
            sinceQueryState => $state_trivial,
            collapseThreads => JSON::false,
        }, "R1"],
        ['Email/queryChanges', {
            sort => [
                { isAscending => JSON::true, property => 'subject' }
            ],
            sinceQueryState => $state_collapsed,
            collapseThreads => JSON::true,
        }, "R2"],
    ]);

    # 'trivial' case
    $self->assert_num_equals(0, scalar @{$res->[0][1]{added}});
    $self->assert_deep_equals([$msgidC], $res->[0][1]{removed});
    $self->assert_num_equals(3, $res->[0][1]{total});

    # 'collapsed' case
    $self->assert_num_equals(0, scalar @{$res->[1][1]{added}});
    $self->assert_deep_equals([$msgidC], $res->[1][1]{removed});
    $self->assert_num_equals(3, $res->[0][1]{total});
}

sub test_email_changes_shared
    :min_version_3_1 :needs_component_jmap
{
    my ($self) = @_;
    my $jmap = $self->{jmap};
    my $res;

    my $store = $self->{store};
    my $imaptalk = $self->{store}->get_client();
    my $admintalk = $self->{adminstore}->get_client();

    xlog "create user and share inbox";
    $self->{instance}->create_user("foo");
    $admintalk->setacl("user.foo", "cassandane", "lrwkxd") or die;

    xlog "create non-shared mailbox box1";
    $admintalk->create("user.foo.box1") or die;
    $admintalk->setacl("user.foo.box1", "cassandane", "") or die;

    xlog "get email state";
    $res = $jmap->CallMethods([['Email/get', { accountId => 'foo', ids => []}, "R1"]]);
    my $state = $res->[0][1]->{state};
    $self->assert_not_null($state);

    xlog "get email updates (expect empty changes)";
    $res = $jmap->CallMethods([['Email/changes', { accountId => 'foo', sinceState => $state }, "R1"]]);
    $self->assert_str_equals($state, $res->[0][1]->{oldState});
    # This could be the same as oldState, or not, as we might leak
    # unshared modseqs (but not the according mail!).
    $self->assert_not_null($res->[0][1]->{newState});
    $self->assert_equals(JSON::false, $res->[0][1]->{hasMoreChanges});
    $self->assert_deep_equals([], $res->[0][1]{created});
    $self->assert_deep_equals([], $res->[0][1]{updated});
    $self->assert_deep_equals([], $res->[0][1]{destroyed});

    xlog "Generate a email in shared account INBOX via IMAP";
    $self->{adminstore}->set_folder('user.foo');
    $self->make_message("Email A", store => $self->{adminstore}) || die;

    xlog "get email updates";
    $res = $jmap->CallMethods([['Email/changes', { accountId => 'foo', sinceState => $state }, "R1"]]);
    $self->assert_str_equals($state, $res->[0][1]->{oldState});
    $self->assert_str_not_equals($state, $res->[0][1]->{newState});
    $self->assert_equals(JSON::false, $res->[0][1]->{hasMoreChanges});
    $self->assert_num_equals(1, scalar @{$res->[0][1]{created}});
    $self->assert_deep_equals([], $res->[0][1]{updated});
    $self->assert_deep_equals([], $res->[0][1]{destroyed});
    $state = $res->[0][1]->{newState};
    my $ida = $res->[0][1]{created}[0];

    xlog "create email in non-shared mailbox";
    $self->{adminstore}->set_folder('user.foo.box1');
    $self->make_message("Email B", store => $self->{adminstore}) || die;

    xlog "get email updates (expect empty changes)";
    $res = $jmap->CallMethods([['Email/changes', { accountId => 'foo', sinceState => $state }, "R1"]]);
    $self->assert_str_equals($state, $res->[0][1]->{oldState});
    # This could be the same as oldState, or not, as we might leak
    # unshared modseqs (but not the according mail!).
    $self->assert_not_null($res->[0][1]->{newState});
    $self->assert_equals(JSON::false, $res->[0][1]->{hasMoreChanges});
    $self->assert_deep_equals([], $res->[0][1]{created});
    $self->assert_deep_equals([], $res->[0][1]{updated});
    $self->assert_deep_equals([], $res->[0][1]{destroyed});

    xlog "share private mailbox box1";
    $admintalk->setacl("user.foo.box1", "cassandane", "lr") or die;

    xlog "get email updates";
    $res = $jmap->CallMethods([['Email/changes', { accountId => 'foo', sinceState => $state }, "R1"]]);
    $self->assert_str_equals($state, $res->[0][1]->{oldState});
    $self->assert_str_not_equals($state, $res->[0][1]->{newState});
    $self->assert_equals(JSON::false, $res->[0][1]->{hasMoreChanges});
    $self->assert_num_equals(1, scalar @{$res->[0][1]{created}});
    $self->assert_deep_equals([], $res->[0][1]{updated});
    $self->assert_deep_equals([], $res->[0][1]{destroyed});
    $state = $res->[0][1]->{newState};

    xlog "delete email $ida";
    $res = $jmap->CallMethods([['Email/set', { accountId => 'foo', destroy => [ $ida ] }, "R1"]]);
    $self->assert_str_equals($ida, $res->[0][1]->{destroyed}[0]);

    xlog "get email updates";
    $res = $jmap->CallMethods([['Email/changes', { accountId => 'foo', sinceState => $state }, "R1"]]);
    $self->assert_str_equals($state, $res->[0][1]->{oldState});
    $self->assert_str_not_equals($state, $res->[0][1]->{newState});
    $self->assert_equals(JSON::false, $res->[0][1]->{hasMoreChanges});
    $self->assert_deep_equals([], $res->[0][1]{created});
    $self->assert_deep_equals([], $res->[0][1]{updated});
    $self->assert_num_equals(1, scalar @{$res->[0][1]{destroyed}});
    $self->assert_str_equals($ida, $res->[0][1]{destroyed}[0]);
    $state = $res->[0][1]->{newState};
}

sub test_misc_upload_download822
    :min_version_3_1 :needs_component_jmap
{
    my ($self) = @_;
    my $jmap = $self->{jmap};

    my $email = <<'EOF';
From: "Some Example Sender" <example@example.com>
To: baseball@vitaead.com
Subject: test email
Date: Wed, 7 Dec 2016 00:21:50 -0500
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Content-Transfer-Encoding: quoted-printable

This is a test email.
EOF
    $email =~ s/\r?\n/\r\n/gs;
    my $data = $jmap->Upload($email, "message/rfc822");
    my $blobid = $data->{blobId};

    my $download = $jmap->Download('cassandane', $blobid);

    $self->assert_str_equals($download->{content}, $email);
}

sub test_email_get_bogus_encoding
    :min_version_3_1 :needs_component_jmap
{
    my ($self) = @_;
    my $jmap = $self->{jmap};

    my $email = <<'EOF';
From: "Some Example Sender" <example@example.com>
To: baseball@vitaead.com
Subject: test email
Date: Wed, 7 Dec 2016 00:21:50 -0500
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Content-Transfer-Encoding: foobar

This is a test email.
EOF
    $email =~ s/\r?\n/\r\n/gs;
    my $data = $jmap->Upload($email, "message/rfc822");
    my $blobid = $data->{blobId};
    my $inboxid = $self->getinbox()->{id};

    xlog "import and get email from blob $blobid";
    my $res = $jmap->CallMethods([['Email/import', {
        emails => {
            "1" => {
                blobId => $blobid,
                mailboxIds => {$inboxid =>  JSON::true},
            },
        },
    }, "R1"], ["Email/get", {
        ids => ["#1"],
        properties => ['bodyStructure', 'bodyValues'],
        fetchAllBodyValues => JSON::true,
    }, "R2" ]]);

    $self->assert_str_equals("Email/import", $res->[0][0]);
    $self->assert_str_equals("Email/get", $res->[1][0]);

    my $msg = $res->[1][1]{list}[0];
    my $partId = $msg->{bodyStructure}{partId};
    $self->assert_equals(JSON::true, $msg->{bodyValues}{$partId}{isEncodingProblem});
}

sub test_misc_upload_sametype
    :min_version_3_1 :needs_component_jmap
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

sub test_misc_brokenrfc822_badendline
    :min_version_3_1 :needs_component_jmap
{
    my ($self) = @_;
    my $jmap = $self->{jmap};

    my $email = <<'EOF';
From: "Some Example Sender" <example@example.com>
To: baseball@vitaead.com
Subject: test email
Date: Wed, 7 Dec 2016 00:21:50 -0500
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Content-Transfer-Encoding: quoted-printable

This is a test email.
EOF
    $email =~ s/\r//gs;
    my $data = $jmap->Upload($email, "message/rfc822");
    my $blobid = $data->{blobId};

    xlog "create drafts mailbox";
    my $res = $jmap->CallMethods([
            ['Mailbox/set', { create => { "1" => {
                            name => "drafts",
                            parentId => undef,
                            role => "drafts"
             }}}, "R1"]
    ]);
    my $draftsmbox = $res->[0][1]{created}{"1"}{id};
    $self->assert_not_null($draftsmbox);

    xlog "import email from blob $blobid";
    $res = $jmap->CallMethods([['Email/import', {
            emails => {
                "1" => {
                    blobId => $blobid,
                    mailboxIds => {$draftsmbox =>  JSON::true},
                    keywords => {
                        '$Draft' => JSON::true,
                    },
                },
            },
        }, "R1"]]);
    my $error = $@;
    $self->assert_str_equals("invalidEmail", $res->[0][1]{notCreated}{1}{type});
}

sub test_email_import_zerobyte
    :min_version_3_1 :needs_component_jmap
{
    my ($self) = @_;
    my $jmap = $self->{jmap};

    # A bogus email with an unencoded zero byte
    my $email = <<"EOF";
From: \"Some Example Sender\" <example\@local>\r\n
To: baseball\@local\r\n
Subject: test email\r\n
Date: Wed, 7 Dec 2016 22:11:11 +1100\r\n
MIME-Version: 1.0\r\n
Content-Type: text/plain; charset="UTF-8"\r\n
\r\n
This is a test email with a \x{0}-byte.\r\n
EOF

    my $data = $jmap->Upload($email, "message/rfc822");
    my $blobid = $data->{blobId};

    xlog "create drafts mailbox";
    my $res = $jmap->CallMethods([
            ['Mailbox/set', { create => { "1" => {
                            name => "drafts",
                            parentId => undef,
                            role => "drafts"
             }}}, "R1"]
    ]);
    my $draftsmbox = $res->[0][1]{created}{"1"}{id};
    $self->assert_not_null($draftsmbox);

    xlog "import email from blob $blobid";
    $res = $jmap->CallMethods([['Email/import', {
            emails => {
                "1" => {
                    blobId => $blobid,
                    mailboxIds => {$draftsmbox =>  JSON::true},
                    keywords => {
                        '$Draft' => JSON::true,
                    },
                },
            },
        }, "R1"]]);
    $self->assert_str_equals("invalidEmail", $res->[0][1]{notCreated}{1}{type});
}


sub test_email_import_setdate
    :min_version_3_1 :needs_component_jmap
{
    my ($self) = @_;
    my $jmap = $self->{jmap};

    my $email = <<'EOF';
From: "Some Example Sender" <example@example.com>
To: baseball@vitaead.com
Subject: test email
Date: Wed, 7 Dec 2016 22:11:11 +1100
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Content-Transfer-Encoding: quoted-printable

This is a test email.
EOF
    $email =~ s/\r?\n/\r\n/gs;
    my $data = $jmap->Upload($email, "message/rfc822");
    my $blobid = $data->{blobId};

    xlog "create drafts mailbox";
    my $res = $jmap->CallMethods([
            ['Mailbox/set', { create => { "1" => {
                            name => "drafts",
                            parentId => undef,
                            role => "drafts"
             }}}, "R1"]
    ]);
    my $draftsmbox = $res->[0][1]{created}{"1"}{id};
    $self->assert_not_null($draftsmbox);

    my $receivedAt = '2016-12-10T01:02:03Z';
    xlog "import email from blob $blobid";
    $res = eval {
        $jmap->CallMethods([['Email/import', {
            emails => {
                "1" => {
                    blobId => $blobid,
                    mailboxIds => {$draftsmbox =>  JSON::true},
                    keywords => {
                        '$Draft' => JSON::true,
                    },
                    receivedAt => $receivedAt,
                },
            },
        }, "R1"], ['Email/get', {ids => ["#1"]}, "R2"]]);
    };

    $self->assert_str_equals("Email/import", $res->[0][0]);
    my $msg = $res->[0][1]->{created}{"1"};
    $self->assert_not_null($msg);

    my $sentAt = '2016-12-07T11:11:11Z';
    $self->assert_str_equals("Email/get", $res->[1][0]);
    $self->assert_str_equals($msg->{id}, $res->[1][1]{list}[0]->{id});
    $self->assert_str_equals($receivedAt, $res->[1][1]{list}[0]->{receivedAt});
    $self->assert_str_equals($sentAt, $res->[1][1]{list}[0]->{sentAt});
}

sub test_thread_get_onemsg
    :min_version_3_1 :needs_component_jmap
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
    $res = $jmap->CallMethods([
            ['Mailbox/set', { create => { "1" => {
                            name => "drafts",
                            parentId => undef,
                            role => "drafts"
             }}}, "R1"]
    ]);
    $draftsmbox = $res->[0][1]{created}{"1"}{id};
    $self->assert_not_null($draftsmbox);

    xlog "get thread state";
    $res = $jmap->CallMethods([['Thread/get', { ids => [ 'no' ] }, "R1"]]);
    $state = $res->[0][1]->{state};
    $self->assert_not_null($state);

    my $email = <<'EOF';
Return-Path: <Hannah.Smith@gmail.com>
Received: from gateway (gateway.vmtom.com [10.0.0.1])
    by ahost (ahost.vmtom.com[10.0.0.2]); Wed, 07 Dec 2016 11:43:25 +1100
Received: from mail.gmail.com (mail.gmail.com [192.168.0.1])
    by gateway.vmtom.com (gateway.vmtom.com [10.0.0.1]); Wed, 07 Dec 2016 11:43:25 +1100
Mime-Version: 1.0
Content-Type: text/plain; charset="us-ascii"
Content-Transfer-Encoding: 7bit
Subject: Email A
From: Hannah V. Smith <Hannah.Smith@gmail.com>
Message-ID: <fake.1481071405.58492@gmail.com>
Date: Wed, 07 Dec 2016 11:43:25 +1100
To: Test User <test@vmtom.com>
X-Cassandane-Unique: 294f71c341218d36d4bda75aad56599b7be3d15b

a
EOF
    $email =~ s/\r?\n/\r\n/gs;
    my $data = $jmap->Upload($email, "message/rfc822");
    my $blobid = $data->{blobId};
    xlog "import email from blob $blobid";
    $res = $jmap->CallMethods([['Email/import', {
        emails => {
            "1" => {
                blobId => $blobid,
                mailboxIds => {$draftsmbox =>  JSON::true},
                keywords => {
                    '$Draft' => JSON::true,
                },
            },
        },
    }, "R1"]]);

    xlog "get thread updates";
    $res = $jmap->CallMethods([['Thread/changes', { sinceState => $state, fetchRecords => $JSON::true }, "R1"]]);
    $self->assert_equals(JSON::false, $res->[0][1]->{hasMoreChanges});
}

sub test_thread_changes
    :min_version_3_1 :needs_component_jmap
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
    $res = $jmap->CallMethods([
            ['Mailbox/set', { create => { "1" => {
                            name => "drafts",
                            parentId => undef,
                            role => "drafts"
             }}}, "R1"]
    ]);
    $draftsmbox = $res->[0][1]{created}{"1"}{id};
    $self->assert_not_null($draftsmbox);

    xlog "Generate an email in drafts via IMAP";
    $self->{store}->set_folder("INBOX.drafts");
    $self->make_message("Email A") || die;

    xlog "get thread state";
    $res = $jmap->CallMethods([
        ['Email/query', { }, "R1"],
        ['Email/get', { '#ids' => { resultOf => 'R1', name => 'Email/query', path => '/ids' } }, 'R2' ],
    ]);
    $res = $jmap->CallMethods([
        ['Thread/get', { 'ids' => [ $res->[1][1]{list}[0]{threadId} ] }, 'R1'],
    ]);
    $state = $res->[0][1]->{state};
    $self->assert_not_null($state);

    xlog "get thread updates";
    $res = $jmap->CallMethods([['Thread/changes', { sinceState => $state }, "R1"]]);
    $self->assert_str_equals($state, $res->[0][1]->{oldState});
    $self->assert_str_equals($state, $res->[0][1]->{newState});
    $self->assert_equals(JSON::false, $res->[0][1]->{hasMoreChanges});
    $self->assert_deep_equals([], $res->[0][1]{created});
    $self->assert_deep_equals([], $res->[0][1]{updated});
    $self->assert_deep_equals([], $res->[0][1]{destroyed});

    xlog "generating email A";
    $dt = DateTime->now();
    $dt->add(DateTime::Duration->new(hours => -3));
    $exp{A} = $self->make_message("Email A", date => $dt, body => "a");
    $exp{A}->set_attributes(uid => 1, cid => $exp{A}->make_cid());

    xlog "get thread updates";
    $res = $jmap->CallMethods([['Thread/changes', { sinceState => $state }, "R1"]]);
    $self->assert_str_equals($state, $res->[0][1]->{oldState});
    $self->assert_str_not_equals($state, $res->[0][1]->{newState});
    $self->assert_equals(JSON::false, $res->[0][1]->{hasMoreChanges});
    $self->assert_num_equals(1, scalar @{$res->[0][1]{created}});
    $self->assert_deep_equals([], $res->[0][1]{updated});
    $self->assert_deep_equals([], $res->[0][1]{destroyed});
    $state = $res->[0][1]->{newState};
    $threadA = $res->[0][1]{created}[0];

    xlog "generating email C referencing A";
    $dt = DateTime->now();
    $dt->add(DateTime::Duration->new(hours => -2));
    $exp{C} = $self->make_message("Re: Email A", references => [ $exp{A} ], date => $dt, body => "c");
    $exp{C}->set_attributes(uid => 3, cid => $exp{A}->get_attribute('cid'));

    xlog "get thread updates";
    $res = $jmap->CallMethods([['Thread/changes', { sinceState => $state }, "R1"]]);
    $self->assert_str_equals($state, $res->[0][1]->{oldState});
    $self->assert_str_not_equals($state, $res->[0][1]->{newState});
    $self->assert_equals(JSON::false, $res->[0][1]->{hasMoreChanges});
    $self->assert_deep_equals([], $res->[0][1]{created});
    $self->assert_num_equals(1, scalar @{$res->[0][1]{updated}});
    $self->assert_str_equals($threadA, $res->[0][1]{updated}[0]);
    $self->assert_deep_equals([], $res->[0][1]{destroyed});
    $state = $res->[0][1]->{newState};

    xlog "get thread updates (expect no changes)";
    $res = $jmap->CallMethods([['Thread/changes', { sinceState => $state }, "R1"]]);
    $self->assert_str_equals($state, $res->[0][1]->{oldState});
    $self->assert_str_equals($state, $res->[0][1]->{newState});
    $self->assert_equals(JSON::false, $res->[0][1]->{hasMoreChanges});
    $self->assert_deep_equals([], $res->[0][1]{created});
    $self->assert_deep_equals([], $res->[0][1]{updated});
    $self->assert_deep_equals([], $res->[0][1]{destroyed});

    xlog "generating email B";
    $exp{B} = $self->make_message("Email B", body => "b");
    $exp{B}->set_attributes(uid => 2, cid => $exp{B}->make_cid());

    xlog "generating email D referencing A";
    $dt = DateTime->now();
    $dt->add(DateTime::Duration->new(hours => -1));
    $exp{D} = $self->make_message("Re: Email A", references => [ $exp{A} ], date => $dt, body => "d");
    $exp{D}->set_attributes(uid => 4, cid => $exp{A}->get_attribute('cid'));

    xlog "generating email E referencing A";
    $dt = DateTime->now();
    $dt->add(DateTime::Duration->new(minutes => -30));
    $exp{E} = $self->make_message("Re: Email A", references => [ $exp{A} ], date => $dt, body => "e");
    $exp{E}->set_attributes(uid => 5, cid => $exp{A}->get_attribute('cid'));

    xlog "get max 1 thread updates";
    $res = $jmap->CallMethods([['Thread/changes', { sinceState => $state, maxChanges => 1 }, "R1"]]);
    $self->assert_str_equals($state, $res->[0][1]->{oldState});
    $self->assert_str_not_equals($state, $res->[0][1]->{newState});
    $self->assert_equals(JSON::true, $res->[0][1]->{hasMoreChanges});
    $self->assert_num_equals(1, scalar @{$res->[0][1]{created}});
    $self->assert_str_not_equals($threadA, $res->[0][1]{created}[0]);
    $self->assert_deep_equals([], $res->[0][1]{updated});
    $self->assert_deep_equals([], $res->[0][1]{destroyed});
    $state = $res->[0][1]->{newState};
    $threadB = $res->[0][1]{created}[0];

    xlog "get max 2 thread updates";
    $res = $jmap->CallMethods([['Thread/changes', { sinceState => $state, maxChanges => 2 }, "R1"]]);
    $self->assert_str_equals($state, $res->[0][1]->{oldState});
    $self->assert_str_not_equals($state, $res->[0][1]->{newState});
    $self->assert_equals(JSON::false, $res->[0][1]->{hasMoreChanges});
    $self->assert_deep_equals([], $res->[0][1]{created});
    $self->assert_num_equals(1, scalar @{$res->[0][1]{updated}});
    $self->assert_str_equals($threadA, $res->[0][1]{updated}[0]);
    $self->assert_deep_equals([], $res->[0][1]{destroyed});
    $state = $res->[0][1]->{newState};

    xlog "fetch emails";
    $res = $jmap->CallMethods([
        ['Email/query', { }, "R1"],
        ['Email/get', {
            '#ids' => {
                resultOf => 'R1',
                name => 'Email/query',
                path => '/ids'
            },
            fetchAllBodyValues => JSON::true,
        }, 'R2' ],
    ]);

    # Map messages by body contents
    my %m = map { $_->{bodyValues}{$_->{textBody}[0]{partId}}{value} => $_ } @{$res->[1][1]{list}};
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

    xlog "destroy email b, update email d";
    $res = $jmap->CallMethods([['Email/set', {
        destroy => [ $msgB->{id} ],
        update =>  { $msgD->{id} => { 'keywords/$foo' => JSON::true }},
    }, "R1"]]);
    $self->assert_str_equals($res->[0][1]{destroyed}[0], $msgB->{id});
    $self->assert(exists $res->[0][1]->{updated}{$msgD->{id}});

    xlog "get thread updates";
    $res = $jmap->CallMethods([['Thread/changes', { sinceState => $state }, "R1"]]);
    $self->assert_str_equals($state, $res->[0][1]->{oldState});
    $self->assert_str_not_equals($state, $res->[0][1]->{newState});
    $self->assert_equals(JSON::false, $res->[0][1]->{hasMoreChanges});
    $self->assert_deep_equals([], $res->[0][1]{created});
    $self->assert_num_equals(1, scalar @{$res->[0][1]{updated}});
    $self->assert_str_equals($threadA, $res->[0][1]{updated}[0]);
    $self->assert_num_equals(1, scalar @{$res->[0][1]{destroyed}});
    $self->assert_str_equals($threadB, $res->[0][1]{destroyed}[0]);
    $state = $res->[0][1]->{newState};

    xlog "destroy emails c and e";
    $res = $jmap->CallMethods([['Email/set', {
        destroy => [ $msgC->{id}, $msgE->{id} ],
    }, "R1"]]);
    $self->assert_num_equals(2, scalar @{$res->[0][1]{destroyed}});

    xlog "get thread updates, fetch threads";
    $res = $jmap->CallMethods([
        ['Thread/changes', { sinceState => $state }, "R1"],
        ['Thread/get', { '#ids' => { resultOf => 'R1', name => 'Thread/changes', path => '/updated' }}, 'R2'],
    ]);
    $self->assert_str_equals($state, $res->[0][1]->{oldState});
    $self->assert_str_not_equals($state, $res->[0][1]->{newState});
    $self->assert_equals(JSON::false, $res->[0][1]->{hasMoreChanges});
    $self->assert_deep_equals([], $res->[0][1]{created});
    $self->assert_num_equals(1, scalar @{$res->[0][1]{updated}});
    $self->assert_str_equals($threadA, $res->[0][1]{updated}[0]);
    $self->assert_deep_equals([], $res->[0][1]{destroyed});
    $state = $res->[0][1]->{newState};

    $self->assert_str_equals('Thread/get', $res->[1][0]);
    $self->assert_num_equals(1, scalar @{$res->[1][1]{list}});
    $self->assert_str_equals($threadA, $res->[1][1]{list}[0]->{id});

    xlog "destroy emails a and d";
    $res = $jmap->CallMethods([['Email/set', {
        destroy => [ $msgA->{id}, $msgD->{id} ],
    }, "R1"]]);
    $self->assert_num_equals(2, scalar @{$res->[0][1]{destroyed}});

    xlog "get thread updates";
    $res = $jmap->CallMethods([['Thread/changes', { sinceState => $state }, "R1"]]);
    $self->assert_str_equals($state, $res->[0][1]->{oldState});
    $self->assert_str_not_equals($state, $res->[0][1]->{newState});
    $self->assert_equals(JSON::false, $res->[0][1]->{hasMoreChanges});
    $self->assert_deep_equals([], $res->[0][1]{created});
    $self->assert_deep_equals([], $res->[0][1]{updated});
    $self->assert_num_equals(1, scalar @{$res->[0][1]{destroyed}});
    $self->assert_str_equals($threadA, $res->[0][1]{destroyed}[0]);
    $state = $res->[0][1]->{newState};

    xlog "get thread updates (expect no changes)";
    $res = $jmap->CallMethods([['Thread/changes', { sinceState => $state }, "R1"]]);
    $self->assert_str_equals($state, $res->[0][1]->{oldState});
    $self->assert_str_equals($state, $res->[0][1]->{newState});
    $self->assert_equals(JSON::false, $res->[0][1]->{hasMoreChanges});
    $self->assert_deep_equals([], $res->[0][1]{created});
    $self->assert_deep_equals([], $res->[0][1]{updated});
    $self->assert_deep_equals([], $res->[0][1]{destroyed});
}

sub test_email_import
    :min_version_3_1 :needs_component_jmap
{
    my ($self) = @_;
    my $jmap = $self->{jmap};

    my $store = $self->{store};
    my $talk = $store->get_client();

    my $inbox = $self->getinbox()->{id};
    $self->assert_not_null($inbox);

    # Generate an embedded email to get a blob id
    xlog "Generate a email in INBOX via IMAP";
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
          . "An embedded email"
          . "\r\n--sub--\r\n",
    ) || die;

    xlog "get blobId";
    my $res = $jmap->CallMethods([
        ['Email/query', { }, "R1"],
        ['Email/get', {
            '#ids' => { resultOf => 'R1', name => 'Email/query', path => '/ids' },
            properties => ['attachments'],
        }, 'R2' ],
    ]);
    my $blobid = $res->[1][1]->{list}[0]->{attachments}[0]{blobId};
    $self->assert_not_null($blobid);

    xlog "create drafts mailbox";
    $res = $jmap->CallMethods([
            ['Mailbox/set', { create => { "1" => {
                            name => "drafts",
                            parentId => undef,
                            role => "drafts"
             }}}, "R1"]
    ]);
    my $drafts = $res->[0][1]{created}{"1"}{id};
    $self->assert_not_null($drafts);

    xlog "import and get email from blob $blobid";
    $res = $jmap->CallMethods([['Email/import', {
        emails => {
            "1" => {
                blobId => $blobid,
                mailboxIds => {$drafts =>  JSON::true},
                keywords => { '$Draft' => JSON::true },
            },
        },
    }, "R1"], ["Email/get", { ids => ["#1"] }, "R2" ]]);

    $self->assert_str_equals("Email/import", $res->[0][0]);
    my $msg = $res->[0][1]->{created}{"1"};
    $self->assert_not_null($msg);

    $self->assert_str_equals("Email/get", $res->[1][0]);
    $self->assert_str_equals($msg->{id}, $res->[1][1]{list}[0]->{id});

    xlog "load email";
    $res = $jmap->CallMethods([['Email/get', { ids => [$msg->{id}] }, "R1"]]);
    $self->assert_num_equals(1, scalar keys %{$res->[0][1]{list}[0]->{mailboxIds}});
    $self->assert_not_null($res->[0][1]{list}[0]->{mailboxIds}{$drafts});

    xlog "import existing email (expect email exists error)";
    $res = $jmap->CallMethods([['Email/import', {
        emails => {
            "1" => {
                blobId => $blobid,
                mailboxIds => {$drafts =>  JSON::true, $inbox => JSON::true},
                keywords => { '$Draft' => JSON::true },
            },
        },
    }, "R1"]]);
    $self->assert_str_equals("Email/import", $res->[0][0]);
    $self->assert_str_equals("alreadyExists", $res->[0][1]->{notCreated}{"1"}{type});
}

sub test_email_import_error
    :min_version_3_1 :needs_component_jmap
{
    my ($self) = @_;
    my $jmap = $self->{jmap};

    my $store = $self->{store};
    my $talk = $store->get_client();

    my $inboxid = $self->getinbox()->{id};

    my $res = $jmap->CallMethods([['Email/import', { emails => "nope" }, 'R1' ]]);
    $self->assert_str_equals('error', $res->[0][0]);
    $self->assert_str_equals('invalidArguments', $res->[0][1]{type});
    $self->assert_str_equals('emails', $res->[0][1]{arguments}[0]);

    $res = $jmap->CallMethods([['Email/import', { emails => { 1 => "nope" }}, 'R1' ]]);
    $self->assert_str_equals('error', $res->[0][0]);
    $self->assert_str_equals('invalidArguments', $res->[0][1]{type});
    $self->assert_str_equals('emails/1', $res->[0][1]{arguments}[0]);

    $res = $jmap->CallMethods([['Email/import', {
        emails => {
            "1" => {
                blobId => "nope",
                mailboxIds => {$inboxid =>  JSON::true},
            },
        },
    }, "R1"]]);

    $self->assert_str_equals('Email/import', $res->[0][0]);
    $self->assert_str_equals('invalidProperties', $res->[0][1]{notCreated}{1}{type});
    $self->assert_str_equals('blobId', $res->[0][1]{notCreated}{1}{properties}[0]);
}


sub test_email_import_shared
    :min_version_3_1 :needs_component_jmap
{
    my ($self) = @_;
    my $jmap = $self->{jmap};
    my $admintalk = $self->{adminstore}->get_client();

    # Create user and share mailbox
    xlog "create shared mailbox";
    $self->{instance}->create_user("foo");
    $admintalk->setacl("user.foo", "cassandane", "lkrwpsintex") or die;

    my $email = <<'EOF';
From: "Some Example Sender" <example@example.com>
To: baseball@vitaead.com
Subject: test email
Date: Wed, 7 Dec 2016 22:11:11 +1100
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Content-Transfer-Encoding: quoted-printable

This is a test email.
EOF
    $email =~ s/\r?\n/\r\n/gs;
    my $data = $jmap->Upload($email, "message/rfc822", "foo");
    my $blobid = $data->{blobId};

    my $mboxid = $self->getinbox({accountId => 'foo'})->{id};

    my $req = ['Email/import', {
                accountId => 'foo',
                emails => {
                    "1" => {
                        blobId => $blobid,
                        mailboxIds => {$mboxid =>  JSON::true},
                        keywords => {  },
                    },
                },
            }, "R1"
    ];

    xlog "import email from blob $blobid";
    my $res = eval { $jmap->CallMethods([$req]) };
    $self->assert(exists $res->[0][1]->{created}{"1"});
}

sub test_email_import_has_attachment
    :min_version_3_1 :needs_component_jmap
{
    my ($self) = @_;
    my $jmap = $self->{jmap};

    my $store = $self->{store};
    my $talk = $store->get_client();

    my $emailSimple = <<'EOF';
From: example@example.com
To: example@example.biz
Subject: This is a test
Message-Id: <15288246899.CBDb71cE.3455@cyrus-dev>
Date: Tue, 12 Jun 2018 13:31:29 -0400
MIME-Version: 1.0

This is a very simple message.
EOF
    $emailSimple =~ s/\r?\n/\r\n/gs;
    my $blobIdSimple = $jmap->Upload($emailSimple, "message/rfc822")->{blobId};

    my $emailMixed = <<'EOF';
From: example@example.com
To: example@example.biz
Subject: This is a test
Message-Id: <15288246899.CBDb71cE.3455@cyrus-dev>
Date: Tue, 12 Jun 2018 13:31:29 -0400
MIME-Version: 1.0
Content-Type: multipart/mixed;boundary=123456789

--123456789
Content-Type: text/plain

This is a mixed message.

--123456789
Content-Type: application/data

data

--123456789--
EOF
    $emailMixed =~ s/\r?\n/\r\n/gs;
    my $blobIdMixed = $jmap->Upload($emailMixed, "message/rfc822")->{blobId};

    my $inboxId = $self->getinbox()->{id};

    my $res = $jmap->CallMethods([['Email/import', {
        emails => {
            "1" => {
                blobId => $blobIdSimple,
                mailboxIds => {$inboxId =>  JSON::true},
            },
            "2" => {
                blobId => $blobIdMixed,
                mailboxIds => {$inboxId =>  JSON::true},
            },
        },
    }, "R1"], ["Email/get", { ids => ["#1", "#2"] }, "R2" ]]);

    my $msgSimple = $res->[1][1]{list}[0];
    $self->assert_equals(JSON::false, $msgSimple->{hasAttachment});
    my $msgMixed = $res->[1][1]{list}[1];
    $self->assert_equals(JSON::true, $msgMixed->{hasAttachment});
}

sub test_misc_refobjects_simple
    :min_version_3_1 :needs_component_jmap
{
    my ($self) = @_;
    my $jmap = $self->{jmap};

    my $store = $self->{store};
    my $talk = $store->get_client();

    xlog "get email state";
    my $res = $jmap->CallMethods([['Email/get', { ids => [] }, "R1"]]);
    my $state = $res->[0][1]->{state};
    $self->assert_not_null($state);

    xlog "Generate a email in INBOX via IMAP";
    $self->make_message("Email A") || die;

    xlog "get email updates and email using reference";
    $res = $jmap->CallMethods([
        ['Email/changes', {
            sinceState => $state,
        }, 'R1'],
        ['Email/get', {
            '#ids' => {
                resultOf => 'R1',
                name => 'Email/changes',
                path => '/created',
            },
        }, 'R2'],
    ]);

    # assert that the changed id equals the id of the returned email
    $self->assert_str_equals($res->[0][1]{created}[0], $res->[1][1]{list}[0]{id});
}

sub test_email_import_no_keywords
    :min_version_3_1 :needs_component_jmap
{
    my ($self) = @_;
    my $jmap = $self->{jmap};

    my $email = <<'EOF';
From: "Some Example Sender" <example@example.com>
To: baseball@vitaead.com
Subject: test email
Date: Wed, 7 Dec 2016 22:11:11 +1100
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Content-Transfer-Encoding: quoted-printable

This is a test email.
EOF
    $email =~ s/\r?\n/\r\n/gs;
    my $data = $jmap->Upload($email, "message/rfc822");
    my $blobid = $data->{blobId};

    my $mboxid = $self->getinbox()->{id};

    my $req = ['Email/import', {
                emails => {
                    "1" => {
                        blobId => $blobid,
                        mailboxIds => {$mboxid =>  JSON::true},
                    },
                },
            }, "R1"
    ];
    xlog "import email from blob $blobid";
    my $res = eval { $jmap->CallMethods([$req]) };
    $self->assert(exists $res->[0][1]->{created}{"1"});
}

sub test_misc_refobjects_extended
    :min_version_3_1 :needs_component_jmap
{
    my ($self) = @_;
    my $jmap = $self->{jmap};

    my $store = $self->{store};
    my $talk = $store->get_client();

    xlog "Generate a email in INBOX via IMAP";
    foreach my $i (1..10) {
        $self->make_message("Email$i") || die;
    }

    xlog "get email properties using reference";
    my $res = $jmap->CallMethods([
        ['Email/query', {
            sort => [{ property => 'receivedAt', isAscending => JSON::false }],
            collapseThreads => JSON::true,
            position => 0,
            limit => 10,
        }, 'R1'],
        ['Email/get', {
            '#ids' => {
                resultOf => 'R1',
                name => 'Email/query',
                path => '/ids',
            },
            properties => [ 'threadId' ],
        }, 'R2'],
        ['Thread/get', {
            '#ids' => {
                resultOf => 'R2',
                name => 'Email/get',
                path => '/list/*/threadId',
            },
        }, 'R3'],
    ]);
    $self->assert_num_equals(10, scalar @{$res->[2][1]{list}});
}

sub test_email_set_patch
    :min_version_3_1 :needs_component_jmap
{
    my ($self) = @_;
    my $jmap = $self->{jmap};

    my $store = $self->{store};
    my $talk = $store->get_client();

    my $res = $jmap->CallMethods([['Mailbox/get', { }, "R1"]]);
    my $inboxid = $res->[0][1]{list}[0]{id};

    my $draft =  {
        mailboxIds => { $inboxid => JSON::true },
        from => [ { name => "Yosemite Sam", email => "sam\@acme.local" } ] ,
        to => [ { name => "Bugs Bunny", email => "bugs\@acme.local" }, ],
        subject => "Memo",
        textBody => [{ partId => '1' }],
        bodyValues => { '1' => { value => "Whoa!" }},
        keywords => { '$Draft' => JSON::true, foo => JSON::true },
    };

    xlog "Create draft email";
    $res = $jmap->CallMethods([
        ['Email/set', { create => { "1" => $draft }}, "R1"],
    ]);
    my $id = $res->[0][1]{created}{"1"}{id};

    $res = $jmap->CallMethods([
        ['Email/get', { 'ids' => [$id] }, 'R2' ]
    ]);
    my $msg = $res->[0][1]->{list}[0];
    $self->assert_equals(JSON::true, $msg->{keywords}->{'$draft'});
    $self->assert_equals(JSON::true, $msg->{keywords}->{'foo'});
    $self->assert_num_equals(2, scalar keys %{$msg->{keywords}});
    $self->assert_equals(JSON::true, $msg->{mailboxIds}->{$inboxid});
    $self->assert_num_equals(1, scalar keys %{$msg->{mailboxIds}});

    xlog "Patch email keywords";
    $res = $jmap->CallMethods([
        ['Email/set', {
            update => {
                $id => {
                    "keywords/foo" => undef,
                    "keywords/bar" => JSON::true,
                }
            }
        }, "R1"],
        ['Email/get', { ids => [$id], properties => ['keywords'] }, 'R2'],
    ]);

    $msg = $res->[1][1]->{list}[0];
    $self->assert_equals(JSON::true, $msg->{keywords}->{'$draft'});
    $self->assert_equals(JSON::true, $msg->{keywords}->{'bar'});
    $self->assert_num_equals(2, scalar keys %{$msg->{keywords}});

    xlog "create mailbox";
    $res = $jmap->CallMethods([['Mailbox/set', {create => { "1" => { name => "baz", }}}, "R1"]]);
    my $mboxid = $res->[0][1]{created}{"1"}{id};
    $self->assert_not_null($mboxid);

    xlog "Patch email mailboxes";
    $res = $jmap->CallMethods([
        ['Email/set', {
            update => {
                $id => {
                    "mailboxIds/$inboxid" => undef,
                    "mailboxIds/$mboxid" => JSON::true,
                }
            }
        }, "R1"],
        ['Email/get', { ids => [$id], properties => ['mailboxIds'] }, 'R2'],
    ]);
    $msg = $res->[1][1]->{list}[0];
    $self->assert_equals(JSON::true, $msg->{mailboxIds}->{$mboxid});
    $self->assert_num_equals(1, scalar keys %{$msg->{mailboxIds}});
}

sub test_capability
    :min_version_3_1 :needs_component_jmap
{
    my ($self) = @_;

    my $jmap = $self->{jmap};

    my $Request;
    my $Response;

    xlog "get settings";
    $Request = {
        headers => {
            'Authorization' => $jmap->auth_header(),
        },
        content => '',
    };
    $Response = $jmap->ua->get($jmap->uri(), $Request);
    if ($ENV{DEBUGJMAP}) {
        warn "JMAP " . Dumper($Request, $Response);
    }
    $self->assert_str_equals('200', $Response->{status});

    my $settings;
    $settings = eval { decode_json($Response->{content}) } if $Response->{success};

    my $cap = $settings->{capabilities}->{"urn:ietf:params:jmap:mail"};
    $self->assert($cap->{maxSizeAttachmentsPerEmail} > 0);
}

sub test_misc_set_oldstate
    :min_version_3_1 :needs_component_jmap
{
    my ($self) = @_;
    my $jmap = $self->{jmap};

    # Assert that /set returns oldState (null, or a string)
    # See https://github.com/cyrusimap/cyrus-imapd/issues/2260

    xlog "create drafts mailbox and email";
    my $res = $jmap->CallMethods([
            ['Mailbox/set', {
                create => { "1" => {
                    name => "drafts",
                    parentId => undef,
                    role => "drafts"
                }}
            }, "R1"],
    ]);
    $self->assert(exists $res->[0][1]{oldState});
    my $draftsmbox = $res->[0][1]{created}{"1"}{id};

    my $draft =  {
        mailboxIds => { $draftsmbox => JSON::true },
        from => [ { name => "Yosemite Sam", email => "sam\@acme.local" } ] ,
        to => [
            { name => "Bugs Bunny", email => "bugs\@acme.local" },
        ],
        subject => "foo",
        textBody => [{partId => '1' }],
        bodyValues => { 1 => { value => "bar" }},
        keywords => { '$Draft' => JSON::true },
    };

    xlog "create a draft";
    $res = $jmap->CallMethods([['Email/set', { create => { "1" => $draft }}, "R1"]]);
    $self->assert(exists $res->[0][1]{oldState});
    my $msgid = $res->[0][1]{created}{"1"}{id};

    $res = $jmap->CallMethods( [ [ 'Identity/get', {}, "R1" ] ] );
    my $identityid = $res->[0][1]->{list}[0]->{id};

    xlog "create email submission";
    $res = $jmap->CallMethods( [ [ 'EmailSubmission/set', {
        create => {
            '1' => {
                identityId => $identityid,
                emailId  => $msgid,
            }
       }
    }, "R1" ] ] );
    $self->assert(exists $res->[0][1]{oldState});
}

sub test_email_set_text_crlf
    :min_version_3_1 :needs_component_jmap
{
    my ($self) = @_;
    my $jmap = $self->{jmap};

    my $inboxid = $self->getinbox()->{id};

    my $text = "ab\r\ncde\rfgh\nij";
    my $want = "ab\ncdefgh\nij";

    my $email =  {
        mailboxIds => { $inboxid => JSON::true },
        from => [ { email => q{test1@robmtest.vm}, name => q{} } ],
        to => [ {
            email => q{foo@bar.com},
            name => "foo",
        } ],
        textBody => [{partId => '1'}],
        bodyValues => {1 => { value => $text }},
    };

    xlog "create and get email";
    my $res = $jmap->CallMethods([
        ['Email/set', { create => { "1" => $email }}, "R1"],
        ['Email/get', { ids => [ "#1" ], fetchAllBodyValues => JSON::true }, "R2" ],
    ]);
    my $ret = $res->[1][1]->{list}[0];
    my $got = $ret->{bodyValues}{$ret->{textBody}[0]{partId}}{value};
    $self->assert_str_equals($want, $got);
}

sub test_email_set_text_split
    :min_version_3_1 :needs_component_jmap
{
    my ($self) = @_;
    my $jmap = $self->{jmap};

    my $inboxid = $self->getinbox()->{id};

    my $text = "x" x 2000;

    my $email =  {
        mailboxIds => { $inboxid => JSON::true },
        from => [ { email => q{test1@robmtest.vm}, name => q{} } ],
        to => [ {
            email => q{foo@bar.com},
            name => "foo",
        } ],
        textBody => [{partId => '1'}],
        bodyValues => {1 => { value => $text }},
    };

    xlog "create and get email";
    my $res = $jmap->CallMethods([
        ['Email/set', { create => { "1" => $email }}, "R1"],
        ['Email/get', { ids => [ "#1" ], fetchAllBodyValues => JSON::true }, "R2" ],
    ]);
    my $ret = $res->[1][1]->{list}[0];
    my $got = $ret->{bodyValues}{$ret->{textBody}[0]{partId}}{value};
}

sub test_email_get_attachedemails
    :min_version_3_1 :needs_component_jmap
{
    my ($self) = @_;
    my $jmap = $self->{jmap};

    my $store = $self->{store};
    my $talk = $store->get_client();
    my $inbox = 'INBOX';

    xlog "Generate a email in $inbox via IMAP";
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
    "Jeez....an embedded email".
    "\r\n--sub--\r\n";

    $exp_sub{A} = $self->make_message("foo",
        mime_type => "multipart/mixed",
        mime_boundary => "sub",
        body => $body
    );
    $talk->store('1', '+flags', '($HasAttachment)');

    xlog "get email list";
    my $res = $jmap->CallMethods([['Email/query', {}, "R1"]]);
    my $ids = $res->[0][1]->{ids};

    xlog "get email";
    $res = $jmap->CallMethods([['Email/get', { ids => $ids }, "R1"]]);
    my $msg = $res->[0][1]{list}[0];

    $self->assert_num_equals(1, scalar @{$msg->{attachments}});
    $self->assert_str_equals("message/rfc822", $msg->{attachments}[0]{type});
}

sub test_email_get_maxbodyvaluebytes_utf8
    :min_version_3_1 :needs_component_jmap
{
    my ($self) = @_;
    my $jmap = $self->{jmap};

    my $store = $self->{store};
    my $talk = $store->get_client();

    # A body containing a three-byte, two-byte and one-byte UTF-8 char
    my $body = "\N{EURO SIGN}\N{CENT SIGN}\N{DOLLAR SIGN}";
    my @wantbodies = (
        [1, ""],
        [2, ""],
        [3, "\N{EURO SIGN}"],
        [4, "\N{EURO SIGN}"],
        [5, "\N{EURO SIGN}\N{CENT SIGN}"],
        [6, "\N{EURO SIGN}\N{CENT SIGN}\N{DOLLAR SIGN}"],
    );

    utf8::encode($body);
    my %params = (
        mime_charset => "utf-8",
        body => $body
    );
    $self->make_message("1", %params) || die;

    xlog "get email id";
    my $res = $jmap->CallMethods([['Email/query', {}, 'R1']]);
    my $id = $res->[0][1]->{ids}[0];

    for my $tc ( @wantbodies ) {
        my $nbytes = $tc->[0];
        my $wantbody = $tc->[1];

        xlog "get email";
        my $res = $jmap->CallMethods([
            ['Email/get', {
                ids => [ $id ],
                properties => [ 'bodyValues' ],
                fetchAllBodyValues => JSON::true,
                maxBodyValueBytes => $nbytes + 0,
            }, "R1"],
        ]);
        my $msg = $res->[0][1]->{list}[0];
        $self->assert_str_equals($wantbody, $msg->{bodyValues}{'1'}{value});
    }
}

sub test_email_get_header_all
    :min_version_3_1 :needs_component_jmap
{
    my ($self) = @_;
    my $jmap = $self->{jmap};

    my $store = $self->{store};
    my $talk = $store->get_client();

    xlog "Generate a email in INBOX via IMAP";
    my %exp_inbox;
    my %params = (
        extra_headers => [
            ['x-tra', "foo"],
            ['x-tra', "bar"],
        ],
        body => "hello",
    );
    $self->make_message("Email A", %params) || die;

    xlog "get email list";
    my $res = $jmap->CallMethods([['Email/query', {}, "R1"]]);
    my $ids = $res->[0][1]->{ids};

    xlog "get email";
    $res = $jmap->CallMethods([['Email/get', { ids => $ids, properties => ['header:x-tra:all', 'header:x-tra:asRaw:all'] }, "R1"]]);
    my $msg = $res->[0][1]{list}[0];

    $self->assert_deep_equals([' foo', ' bar'], $msg->{'header:x-tra:all'});
    $self->assert_deep_equals([' foo', ' bar'], $msg->{'header:x-tra:asRaw:all'});
}

sub test_email_set_nullheader
    :min_version_3_1 :needs_component_jmap
{
    my ($self) = @_;
    my $jmap = $self->{jmap};

    my $inboxid = $self->getinbox()->{id};

    my $text = "x";

    # Prepare test email
    my $email =  {
        mailboxIds => { $inboxid => JSON::true },
        from => [ { email => q{test1@robmtest.vm}, name => q{} } ],
        'header:foo' => undef,
        'header:foo:asMessageIds' => undef,
    };

    # Create and get mail
    my $res = $jmap->CallMethods([
        ['Email/set', { create => { "1" => $email }}, "R1"],
        ['Email/get', {
            ids => [ "#1" ],
            properties => [ 'headers', 'header:foo' ],
        }, "R2" ],
    ]);
    my $msg = $res->[1][1]{list}[0];

    foreach (@{$msg->{headers}}) {
        xlog "Checking header $_->{name}";
        $self->assert_str_not_equals('foo', $_->{name});
    }
    $self->assert_null($msg->{'header:foo'});
}

sub test_email_set_headers
    :min_version_3_1 :needs_component_jmap
{
    my ($self) = @_;
    my $jmap = $self->{jmap};

    my $inboxid = $self->getinbox()->{id};

    my $text = "x";

    # Prepare test headers
    my $headers = {
        'header:X-TextHeader8bit' => {
            format  => 'asText',
            value   => "I feel \N{WHITE SMILING FACE}",
            wantRaw => " =?UTF-8?Q?I_feel_=E2=98=BA?="
        },
        'header:X-TextHeaderLong' => {
            format  => 'asText',
            value   => "x" x 80,
            wantRaw => " =?UTF-8?Q?xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx?=\r\n =?UTF-8?Q?xxxxxxxxxxxxxxxxxx?="
        },
        'header:X-TextHeaderShort' => {
            format  => 'asText',
            value   => "x",
            wantRaw => " x"
        },
       'header:X-MsgIdsShort' => {
           format => 'asMessageIds',
           value  => [ 'foobarbaz' ],
           wantRaw => " <foobarbaz>",
       },
       'header:X-MsgIdsLong' => {
           format => 'asMessageIds',
           value  => [
               'foobarbaz',
               'foobarbaz',
               'foobarbaz',
               'foobarbaz',
               'foobarbaz',
               'foobarbaz',
               'foobarbaz',
               'foobarbaz',
           ],
           wantRaw => (" <foobarbaz>" x 5)."\r\n".(" <foobarbaz>" x 3),
       },
       'header:X-AddrsShort' => {
           format => 'asAddresses',
           value => [{ 'name' => 'foo', email => 'bar@local' }],
           wantRaw => ' foo <bar@local>',
       },
       'header:X-Addrs8bit' => {
           format => 'asAddresses',
           value => [{ 'name' => "Rudi R\N{LATIN SMALL LETTER U WITH DIAERESIS}be", email => 'bar@local' }],
           wantRaw => ' =?UTF-8?Q?Rudi_R=C3=BCbe?= <bar@local>',
       },
       'header:X-AddrsLong' => {
           format => 'asAddresses',
           value => [{
               'name' => 'foo', email => 'bar@local'
           }, {
               'name' => 'foo', email => 'bar@local'
           }, {
               'name' => 'foo', email => 'bar@local'
           }, {
               'name' => 'foo', email => 'bar@local'
           }, {
               'name' => 'foo', email => 'bar@local'
           }, {
               'name' => 'foo', email => 'bar@local'
           }, {
               'name' => 'foo', email => 'bar@local'
           }, {
               'name' => 'foo', email => 'bar@local'
           }],
           wantRaw => (' foo <bar@local>,' x 3)."\r\n".(' foo <bar@local>,' x 4)."\r\n".' foo <bar@local>',
       },
       'header:X-URLsShort' => {
           format => 'asURLs',
           value => [ 'foourl' ],
           wantRaw => ' <foourl>',
       },
       'header:X-URLsLong' => {
           format => 'asURLs',
           value => [
               'foourl',
               'foourl',
               'foourl',
               'foourl',
               'foourl',
               'foourl',
               'foourl',
               'foourl',
               'foourl',
               'foourl',
               'foourl',
           ],
           wantRaw => (' <foourl>,' x 6)."\r\n".(' <foourl>,' x 4).' <foourl>',
       },
    };

    # Prepare test email
    my $email =  {
        mailboxIds => { $inboxid => JSON::true },
        from => [ { email => q{test1@robmtest.vm}, name => q{} } ],
    };
    while( my ($k, $v) = each %$headers ) {
        $email->{$k.':'.$v->{format}} = $v->{value},
    }

    my @properties = keys %$headers;
    while( my ($k, $v) = each %$headers ) {
        push @properties, $k.':'.$v->{format};
    }


    # Create and get mail
    my $res = $jmap->CallMethods([
        ['Email/set', { create => { "1" => $email }}, "R1"],
        ['Email/get', {
            ids => [ "#1" ],
            properties => \@properties,
        }, "R2" ],
    ]);
    my $msg = $res->[1][1]{list}[0];

    # Validate header values
    while( my ($k, $v) = each %$headers ) {
        xlog "Validating $k";
        my $raw = $msg->{$k};
        my $val = $msg->{$k.':'.$v->{format}};
        # Check raw header
        $self->assert_str_equals($v->{wantRaw}, $raw);
        # Check formatted header
        if (ref $v->{value} eq 'ARRAY') {
            $self->assert_deep_equals($v->{value}, $val);
        } else {
            $self->assert_str_equals($v->{value}, $val);
        }
    }
}

sub test_email_download
    :min_version_3_1 :needs_component_jmap
{
    my ($self) = @_;
    my $jmap = $self->{jmap};

    my $store = $self->{store};
    my $talk = $store->get_client();

    xlog "Generate a email in INBOX via IMAP";
    my $body = "--047d7b33dd729737fe04d3bde348\r\n";
    $body .= "Content-Type: text/plain; charset=UTF-8\r\n";
    $body .= "\r\n";
    $body .= "some text";
    $body .= "\r\n";
    $body .= "--047d7b33dd729737fe04d3bde348\r\n";
    $body .= "Content-Type: text/html;charset=\"UTF-8\"\r\n";
    $body .= "\r\n";
    $body .= "<p>some HTML text</p>";
    $body .= "\r\n";
    $body .= "--047d7b33dd729737fe04d3bde348--\r\n";
    $self->make_message("foo",
        mime_type => "multipart/alternative",
        mime_boundary => "047d7b33dd729737fe04d3bde348",
        body => $body
    );

    xlog "get email";
    my $res = $jmap->CallMethods([
        ['Email/query', { }, 'R1'],
        ['Email/get', {
            '#ids' => {
                resultOf => 'R1',
                name => 'Email/query',
                path => '/ids'
            },
            properties => [ 'blobId' ],
        }, 'R2'],
    ]);
    my $msg = $res->[1][1]->{list}[0];

    my $blob = $jmap->Download({ accept => 'message/rfc822' }, 'cassandane', $msg->{blobId});
    $self->assert_str_equals('message/rfc822', $blob->{headers}->{'content-type'});
    $self->assert_num_not_equals(0, $blob->{headers}->{'content-length'});
}

sub test_email_embedded_download
    :min_version_3_1 :needs_component_jmap
{
    my ($self) = @_;
    my $jmap = $self->{jmap};

    my $store = $self->{store};
    my $talk = $store->get_client();

    # Generate an embedded email
    xlog "Generate a email in INBOX via IMAP";
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
          . "An embedded email"
          . "\r\n--sub--\r\n",
    ) || die;

    xlog "get blobId";
    my $res = $jmap->CallMethods([
        ['Email/query', { }, "R1"],
        ['Email/get', {
            '#ids' => { resultOf => 'R1', name => 'Email/query', path => '/ids' },
            properties => ['attachments'],
        }, 'R2' ],
    ]);
    my $blobId = $res->[1][1]->{list}[0]->{attachments}[0]{blobId};

    my $blob = $jmap->Download({ accept => 'message/rfc822' }, 'cassandane', $blobId);
    $self->assert_str_equals('message/rfc822', $blob->{headers}->{'content-type'});
    $self->assert_num_not_equals(0, $blob->{headers}->{'content-length'});
}

sub test_blob_download
    :min_version_3_1 :needs_component_jmap
{
    my ($self) = @_;
    my $jmap = $self->{jmap};

    my $logofile = abs_path('data/logo.gif');
    open(FH, "<$logofile");
    local $/ = undef;
    my $binary = <FH>;
    close(FH);
    my $data = $jmap->Upload($binary, "image/gif");

    my $blob = $jmap->Download({ accept => 'image/gif' }, 'cassandane', $data->{blobId});
    $self->assert_str_equals('image/gif', $blob->{headers}->{'content-type'});
    $self->assert_num_not_equals(0, $blob->{headers}->{'content-length'});
    $self->assert_equals($binary, $blob->{content});
}

sub test_email_set_filename
    :min_version_3_1 :needs_component_jmap
{
    my ($self) = @_;
    my $jmap = $self->{jmap};

    my $store = $self->{store};
    my $talk = $store->get_client();

    xlog "Upload a data blob";
    my $binary = pack "H*", "beefcode";
    my $data = $jmap->Upload($binary, "image/gif");
    my $dataBlobId = $data->{blobId};

    my @testcases = ({
        name   => 'foo',
        wantCt => ' image/gif; name="foo"',
        wantCd => ' attachment;filename="foo"',
    }, {
        name   => "I feel \N{WHITE SMILING FACE}",
        wantCt => ' image/gif; name="=?UTF-8?Q?I_feel_=E2=98=BA?="',
        wantCd => " attachment;filename*=utf-8''%49%20%66%65%65%6c%20%e2%98%ba",
    }, {
        name   => "foo" . ("_foo" x 20),
        wantCt => " image/gif;\r\n name=\"=?UTF-8?Q?foo=5Ffoo=5Ffoo=5Ffoo=5Ffoo=5Ffoo=5Ffoo=5Ffoo=5Ffoo=5Ffoo=5Ffo?=\r\n =?UTF-8?Q?o=5Ffoo=5Ffoo=5Ffoo=5Ffoo=5Ffoo=5Ffoo=5Ffoo=5Ffoo=5Ffoo=5Ffoo?=\"",
        wantCd => " attachment;\r\n filename*0*=\"foo_foo_foo_foo_foo_foo_foo_foo_foo_foo_foo_foo_foo_foo_foo_\";\r\n filename*1*=\"foo_foo_foo_foo_foo_foo\"",
    }, {
        name   => 'Incoming Email Flow.xml',
        wantCt => ' image/gif; name="Incoming Email Flow.xml"',
        wantCd => ' attachment;filename="Incoming Email Flow.xml"',
    });

    foreach my $tc (@testcases) {
        xlog "Checking name $tc->{name}";
        my $bodyStructure = {
            type => "multipart/alternative",
            subParts => [{
                    type => 'text/plain',
                    partId => '1',
                }, {
                    type => 'image/gif',
                    disposition => 'attachment',
                    name => $tc->{name},
                    blobId => $dataBlobId,
                }],
        };

        xlog "Create email with body structure";
        my $inboxid = $self->getinbox()->{id};
        my $email = {
            mailboxIds => { $inboxid => JSON::true },
            from => [{ name => "Test", email => q{foo@bar} }],
            subject => "test",
            bodyStructure => $bodyStructure,
            bodyValues => {
                "1" => {
                    value => "A text body",
                },
            },
        };
        my $res = $jmap->CallMethods([
                ['Email/set', { create => { '1' => $email } }, 'R1'],
                ['Email/get', {
                        ids => [ '#1' ],
                        properties => [ 'bodyStructure' ],
                        bodyProperties => [ 'partId', 'blobId', 'type', 'name', 'disposition', 'header:Content-Type', 'header:Content-Disposition' ],
                        fetchAllBodyValues => JSON::true,
                    }, 'R2' ],
            ]);

        my $gotBodyStructure = $res->[1][1]{list}[0]{bodyStructure};
        my $gotName = $gotBodyStructure->{subParts}[1]{name};
        $self->assert_str_equals($tc->{name}, $gotName);
        my $gotCt = $gotBodyStructure->{subParts}[1]{'header:Content-Type'};
        $self->assert_str_equals($tc->{wantCt}, $gotCt);
        my $gotCd = $gotBodyStructure->{subParts}[1]{'header:Content-Disposition'};
        $self->assert_str_equals($tc->{wantCd}, $gotCd);
    }
}

sub test_email_get_size
    :min_version_3_1 :needs_component_jmap
{
    my ($self) = @_;
    my $jmap = $self->{jmap};

    $self->make_message("foo",
        mime_type => 'text/plain; charset="UTF-8"',
        mime_encoding => 'quoted-printable',
        body => '=C2=A1Hola, se=C3=B1or!',
    ) || die;
    my $res = $jmap->CallMethods([
        ['Email/query', { }, "R1"],
        ['Email/get', {
            '#ids' => { resultOf => 'R1', name => 'Email/query', path => '/ids' },
            properties => ['bodyStructure', 'size'],
        }, 'R2' ],
    ]);

    my $msg = $res->[1][1]{list}[0];
    $self->assert_num_equals(15, $msg->{bodyStructure}{size});
}

sub test_email_get_references
    :min_version_3_1 :needs_component_jmap
{
    my ($self) = @_;
    my $jmap = $self->{jmap};

    my $rawReferences = '<bar>, <baz>';
    my $parsedReferences = [ 'bar', 'baz' ];

    $self->make_message("foo",
        mime_type => 'text/plain',
        extra_headers => [
            ['References', $rawReferences],
        ],
        body => 'foo',
    ) || die;
    my $res = $jmap->CallMethods([
        ['Email/query', { }, "R1"],
        ['Email/get', {
            '#ids' => { resultOf => 'R1', name => 'Email/query', path => '/ids' },
            properties => ['references', 'header:references', 'header:references:asMessageIds'],
        }, 'R2' ],
    ]);
    my $msg = $res->[1][1]{list}[0];
    $self->assert_str_equals(' ' . $rawReferences, $msg->{'header:references'});
    $self->assert_deep_equals($parsedReferences, $msg->{'header:references:asMessageIds'});
    $self->assert_deep_equals($parsedReferences, $msg->{references});
}

sub test_email_get_groupaddr
    :min_version_3_1 :needs_component_jmap
{
    my ($self) = @_;
    my $jmap = $self->{jmap};

    # Straight from Appendix A.1.3 of RFC 5322
    my $rawTo = 'A Group:Ed Jones <c@a.test>,joe@where.test,John <jdoe@one.test>';
    my $wantTo = [{
        name => 'A Group',
        email => undef,
    }, {
        name => 'Ed Jones',
        email => 'c@a.test',
    }, {
        name => undef,
        email => 'joe@where.test'
    }, {
        name => 'John',
        email => 'jdoe@one.test',
    }, {
        name => undef,
        email => undef
    }];

    my $msg = $self->{gen}->generate();
    $msg->set_headers('To', ($rawTo));
    $self->_save_message($msg);

    my $res = $jmap->CallMethods([
        ['Email/query', { }, "R1"],
        ['Email/get', {
            '#ids' => { resultOf => 'R1', name => 'Email/query', path => '/ids' },
            properties => ['to'],
        }, 'R2' ],
    ]);
    $self->assert_deep_equals($wantTo, $res->[1][1]{list}[0]->{to});
}

sub test_email_parse
    :min_version_3_1 :needs_component_jmap
{
    my ($self) = @_;
    my $jmap = $self->{jmap};

    my $store = $self->{store};
    my $talk = $store->get_client();

    $self->make_message("foo",
        mime_type => "multipart/mixed",
        mime_boundary => "sub",
        body => ""
          . "--sub\r\n"
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
          . "An embedded email"
          . "\r\n--sub--\r\n",
    ) || die;
    my $res = $jmap->CallMethods([
        ['Email/query', { }, "R1"],
        ['Email/get', {
            '#ids' => { resultOf => 'R1', name => 'Email/query', path => '/ids' },
            properties => ['attachments'],
        }, 'R2' ],
    ]);
    my $blobId = $res->[1][1]{list}[0]{attachments}[0]{blobId};

    my @props = $self->defaultprops_for_email_get();
    push @props, "bodyStructure";
    push @props, "bodyValues";

    $res = $jmap->CallMethods([['Email/parse', {
        blobIds => [ $blobId ], properties => \@props, fetchAllBodyValues => JSON::true,
    }, 'R1']]);
    my $email = $res->[0][1]{parsed}{$blobId};
    $self->assert_not_null($email);

    $self->assert_null($email->{id});
    $self->assert_null($email->{threadId});
    $self->assert_null($email->{mailboxIds});
    $self->assert_null($email->{keywords});
    $self->assert_deep_equals(['fake.1475639947.6507@local'], $email->{messageId});
    $self->assert_deep_equals([{name=>'Ava T. Nguyen', email=>'Ava.Nguyen@local'}], $email->{from});
    $self->assert_deep_equals([{name=>'Test User', email=>'test@local'}], $email->{to});
    $self->assert_null($email->{cc});
    $self->assert_null($email->{bcc});
    $self->assert_null($email->{references});
    $self->assert_null($email->{sender});
    $self->assert_null($email->{replyTo});
    $self->assert_str_equals('bar', $email->{subject});
    $self->assert_str_equals('2016-10-05T03:59:07Z', $email->{sentAt});
    $self->assert_not_null($email->{blobId});
    $self->assert_str_equals('text/plain', $email->{bodyStructure}{type});
    $self->assert_null($email->{bodyStructure}{subParts});
    $self->assert_num_equals(1, scalar @{$email->{textBody}});
    $self->assert_num_equals(1, scalar @{$email->{htmlBody}});
    $self->assert_num_equals(0, scalar @{$email->{attachedFiles}});
    $self->assert_num_equals(0, scalar @{$email->{attachedEmails}});

    my $bodyValue = $email->{bodyValues}{$email->{bodyStructure}{partId}};
    $self->assert_str_equals('An embedded email', $bodyValue->{value});
}

sub test_email_parse_digest
    :min_version_3_1 :needs_component_jmap
{
    my ($self) = @_;
    my $jmap = $self->{jmap};

    my $store = $self->{store};
    my $talk = $store->get_client();

    $self->make_message("foo",
        mime_type => "multipart/digest",
        mime_boundary => "sub",
        body => ""
          . "\r\n--sub\r\n"
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
          . "An embedded email"
          . "\r\n--sub--\r\n",
    ) || die;
    my $res = $jmap->CallMethods([
        ['Email/query', { }, "R1"],
        ['Email/get', {
            '#ids' => { resultOf => 'R1', name => 'Email/query', path => '/ids' },
            properties => ['bodyStructure']
        }, 'R2' ],
    ]);
    my $blobId = $res->[1][1]{list}[0]{bodyStructure}{subParts}[0]{blobId};
    $self->assert_not_null($blobId);

    $res = $jmap->CallMethods([['Email/parse', { blobIds => [ $blobId ] }, 'R1']]);
    $self->assert_not_null($res->[0][1]{parsed}{$blobId});
}

sub test_email_parse_blob822
    :min_version_3_1 :needs_component_jmap
{
    my ($self) = @_;
    my $jmap = $self->{jmap};

    my $store = $self->{store};
    my $talk = $store->get_client();

    my $rawEmail = <<'EOF';
From: "Some Example Sender" <example@example.com>
To: baseball@vitaead.com
Subject: test email
Date: Wed, 7 Dec 2016 00:21:50 -0500
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Content-Transfer-Encoding: quoted-printable

This is a test email.
EOF
    $rawEmail =~ s/\r?\n/\r\n/gs;
    my $data = $jmap->Upload($rawEmail, "application/data");
    my $blobId = $data->{blobId};

    my @props = $self->defaultprops_for_email_get();
    push @props, "bodyStructure";
    push @props, "bodyValues";

    my $res = $jmap->CallMethods([['Email/parse', {
        blobIds => [ $blobId ],
        properties => \@props,
        fetchAllBodyValues => JSON::true,
    }, 'R1']]);
    my $email = $res->[0][1]{parsed}{$blobId};

    $self->assert_not_null($email);
    $self->assert_deep_equals([{name=>'Some Example Sender', email=>'example@example.com'}], $email->{from});

    my $bodyValue = $email->{bodyValues}{$email->{bodyStructure}{partId}};
    $self->assert_str_equals("This is a test email.\n", $bodyValue->{value});
}

sub test_email_parse_base64
    :min_version_3_1 :needs_component_jmap
{
    my ($self) = @_;
    my $jmap = $self->{jmap};

    my $store = $self->{store};
    my $talk = $store->get_client();

    my $rawEmail = <<'EOF';
From: "Some Example Sender" <example@example.com>
To: baseball@vitaead.com
Subject: test email
Date: Wed, 7 Dec 2016 00:21:50 -0500
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Content-Transfer-Encoding: quoted-printable

This is a test email.
EOF
    $rawEmail =~ s/\r?\n/\r\n/gs;

    $self->make_message("foo",
        mime_type => "multipart/mixed",
        mime_boundary => "sub",
        body => ""
          . "--sub\r\n"
          . "Content-Type: message/rfc822\r\n"
          . "Content-Transfer-Encoding: base64\r\n"
          . "\r\n"
          . MIME::Base64::encode_base64($rawEmail, "\r\n")
          . "\r\n--sub--\r\n",
    ) || die;

    my $res = $jmap->CallMethods([
        ['Email/query', { }, "R1"],
        ['Email/get', {
            '#ids' => { resultOf => 'R1', name => 'Email/query', path => '/ids' },
            properties => ['attachments'],
        }, 'R2' ],
    ]);
    my $blobId = $res->[1][1]{list}[0]{attachments}[0]{blobId};

    my @props = $self->defaultprops_for_email_get();
    push @props, "bodyStructure";
    push @props, "bodyValues";

    $res = $jmap->CallMethods([['Email/parse', {
        blobIds => [ $blobId ],
        properties => \@props,
        fetchAllBodyValues => JSON::true,
    }, 'R1']]);

    my $email = $res->[0][1]{parsed}{$blobId};
    $self->assert_not_null($email);
    $self->assert_deep_equals(
        [{
            name => 'Some Example Sender',
            email => 'example@example.com'
        }],
        $email->{from}
    );
    my $bodyValue = $email->{bodyValues}{$email->{bodyStructure}{partId}};
    $self->assert_str_equals("This is a test email.\n", $bodyValue->{value});
}

sub test_email_parse_contenttype_default
    :min_version_3_1 :needs_component_jmap
{
    my ($self) = @_;
    my $jmap = $self->{jmap};

    my $store = $self->{store};
    my $talk = $store->get_client();

    my $emailWithoutContentType = <<'EOF';
From: "Some Example Sender" <example@example.com>
To: baseball@vitaead.com
Subject: test email
Date: Wed, 7 Dec 2016 00:21:50 -0500
MIME-Version: 1.0

This is a test email.
EOF

    my $emailWithoutCharset = <<'EOF';
From: "Some Example Sender" <example@example.com>
To: baseball@vitaead.com
Subject: test email
Date: Wed, 7 Dec 2016 00:21:50 -0500
Content-Type: text/plain
MIME-Version: 1.0

This is a test email.
EOF

    my @testCases = ({
        desc => "Email without Content-Type header",
        rawEmail => $emailWithoutContentType,
        wantContentType => 'text/plain',
        wantCharset => 'us-ascii',
    }, {
        desc => "Email without charset parameter",
        rawEmail => $emailWithoutCharset,
        wantContentType => 'text/plain',
        wantCharset => undef,
    });

    foreach (@testCases) {
        xlog "Running test: $_->{desc}";
        my $rawEmail = $_->{rawEmail};
        $rawEmail =~ s/\r?\n/\r\n/gs;
        my $data = $jmap->Upload($rawEmail, "application/data");
        my $blobId = $data->{blobId};

        my $res = $jmap->CallMethods([['Email/parse', {
            blobIds => [ $blobId ],
            properties => ['bodyStructure'],
        }, 'R1']]);
        my $email = $res->[0][1]{parsed}{$blobId};
        $self->assert_str_equals($_->{wantContentType}, $email->{bodyStructure}{type});
        if (defined $_->{wantCharset}) {
            $self->assert_str_equals($_->{wantCharset}, $email->{bodyStructure}{charset});
        } else {
            $self->assert_null($email->{bodyStructure}{charset});
        }
    }
}

sub test_email_parse_encoding
    :min_version_3_1 :needs_component_jmap
{
    my ($self) = @_;
    my $jmap = $self->{jmap};

    my $store = $self->{store};
    my $talk = $store->get_client();

    my $decodedBody = "\N{LATIN SMALL LETTER A WITH GRAVE} la carte";
    my $encodedBody = '=C3=A0 la carte';
    $encodedBody =~ s/\r?\n/\r\n/gs;

    my $Header = <<'EOF';
From: "Some Example Sender" <example@example.com>
To: baseball@vitaead.com
Subject: test email
Date: Wed, 7 Dec 2016 00:21:50 -0500
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Content-Transfer-Encoding: quoted-printable
EOF
    $Header =~ s/\r?\n/\r\n/gs;
    my $emailBlob = $Header . "\r\n" . $encodedBody;

    my $email;
    my $res;
    my $partId;

    $self->make_message("foo",
        mime_type => "multipart/mixed;boundary=1234567",
        body => ""
        . "--1234567\r\n"
        . "Content-Type: text/plain; charset=utf-8\r\n"
        . "Content-Transfer-Encoding: quoted-printable\r\n"
        . "\r\n"
        . $encodedBody
        . "\r\n--1234567\r\n"
        . "Content-Type: message/rfc822\r\n"
        . "\r\n"
        . "X-Header: ignore\r\n" # make this blob id unique
        . $emailBlob
        . "\r\n--1234567--\r\n"
    );

    # Assert content decoding for top-level message.
    xlog "get email";
    $res = $jmap->CallMethods([
        ['Email/query', { }, 'R1'],
        ['Email/get', {
            '#ids' => {
                resultOf => 'R1',
                name => 'Email/query',
                path => '/ids'
            },
            properties => ['bodyValues', 'bodyStructure', 'textBody'],
            bodyProperties => ['partId', 'blobId'],
            fetchAllBodyValues => JSON::true,
        }, 'R2'],
    ]);
    $self->assert_num_equals(scalar @{$res->[0][1]->{ids}}, 1);
    $email = $res->[1][1]->{list}[0];
    $partId = $email->{textBody}[0]{partId};
    $self->assert_str_equals($decodedBody, $email->{bodyValues}{$partId}{value});

    # Assert content decoding for embedded message.
    xlog "parse embedded email";
    my $embeddedBlobId = $email->{bodyStructure}{subParts}[1]{blobId};
    $res = $jmap->CallMethods([['Email/parse', {
        blobIds => [ $email->{bodyStructure}{subParts}[1]{blobId} ],
        properties => ['bodyValues', 'textBody'],
        fetchAllBodyValues => JSON::true,
    }, 'R1']]);
    $email = $res->[0][1]{parsed}{$embeddedBlobId};
    $partId = $email->{textBody}[0]{partId};
    $self->assert_str_equals($decodedBody, $email->{bodyValues}{$partId}{value});

    # Assert content decoding for message blob.
    my $data = $jmap->Upload($emailBlob, "application/data");
    my $blobId = $data->{blobId};

    $res = $jmap->CallMethods([['Email/parse', {
        blobIds => [ $blobId ],
        properties => ['bodyValues', 'textBody'],
        fetchAllBodyValues => JSON::true,
    }, 'R1']]);
    $email = $res->[0][1]{parsed}{$blobId};
    $partId = $email->{textBody}[0]{partId};
    $self->assert_str_equals($decodedBody, $email->{bodyValues}{$partId}{value});
}

sub test_email_parse_notparsable
    :min_version_3_1 :needs_component_jmap
{
    my ($self) = @_;
    my $jmap = $self->{jmap};

    my $store = $self->{store};
    my $talk = $store->get_client();

    my $rawEmail = <<'EOF';
This is a test email.
EOF
    $rawEmail =~ s/\r?\n/\r\n/gs;
    my $data = $jmap->Upload($rawEmail, "application/data");
    my $blobId = $data->{blobId};

    my $res = $jmap->CallMethods([['Email/parse', { blobIds => [ $blobId ] }, 'R1']]);
    $self->assert_str_equals($blobId, $res->[0][1]{notParsable}[0]);
}

sub test_email_get_bodystructure
    :min_version_3_1 :needs_component_jmap
{
    my ($self) = @_;
    my $jmap = $self->{jmap};

    my $store = $self->{store};
    my $talk = $store->get_client();

    $self->make_message("foo",
        mime_type => "multipart/mixed",
        mime_boundary => "boundary_1",
        body => ""
        # body A
          . "\r\n--boundary_1\r\n"
          . "X-Body-Id:A\r\n"
          . "Content-Type: text/plain\r\n"
          . "Content-Disposition: inline\r\n"
          . "\r\n"
          . "A"
        # multipart/mixed
          . "\r\n--boundary_1\r\n"
          . "Content-Type: multipart/mixed; boundary=\"boundary_1_1\"\r\n"
        # multipart/alternative
          . "\r\n--boundary_1_1\r\n"
          . "Content-Type: multipart/alternative; boundary=\"boundary_1_1_1\"\r\n"
        # multipart/mixed
          . "\r\n--boundary_1_1_1\r\n"
          . "Content-Type: multipart/mixed; boundary=\"boundary_1_1_1_1\"\r\n"
        # body B
          . "\r\n--boundary_1_1_1_1\r\n"
          . "X-Body-Id:B\r\n"
          . "Content-Type: text/plain\r\n"
          . "Content-Disposition: inline\r\n"
          . "\r\n"
          . "B"
        # body C
          . "\r\n--boundary_1_1_1_1\r\n"
          . "X-Body-Id:C\r\n"
          . "Content-Type: image/jpeg\r\n"
          . "Content-Disposition: inline\r\n"
          . "\r\n"
          . "C"
        # body D
          . "\r\n--boundary_1_1_1_1\r\n"
          . "X-Body-Id:D\r\n"
          . "Content-Type: text/plain\r\n"
          . "Content-Disposition: inline\r\n"
          . "\r\n"
          . "D"
        # end multipart/mixed
          . "\r\n--boundary_1_1_1_1--\r\n"
        # multipart/mixed
          . "\r\n--boundary_1_1_1\r\n"
          . "Content-Type: multipart/related; boundary=\"boundary_1_1_1_2\"\r\n"
        # body E
          . "\r\n--boundary_1_1_1_2\r\n"
          . "X-Body-Id:E\r\n"
          . "Content-Type: text/html\r\n"
          . "\r\n"
          . "E"
        # body F
          . "\r\n--boundary_1_1_1_2\r\n"
          . "X-Body-Id:F\r\n"
          . "Content-Type: image/jpeg\r\n"
          . "\r\n"
          . "F"
        # end multipart/mixed
          . "\r\n--boundary_1_1_1_2--\r\n"
        # end multipart/alternative
          . "\r\n--boundary_1_1_1--\r\n"
        # body G
          . "\r\n--boundary_1_1\r\n"
          . "X-Body-Id:G\r\n"
          . "Content-Type: image/jpeg\r\n"
          . "Content-Disposition: attachment\r\n"
          . "\r\n"
          . "G"
        # body H
          . "\r\n--boundary_1_1\r\n"
          . "X-Body-Id:H\r\n"
          . "Content-Type: application/x-excel\r\n"
          . "\r\n"
          . "H"
        # body J
          . "\r\n--boundary_1_1\r\n"
          . "Content-Type: message/rfc822\r\n"
          . "X-Body-Id:J\r\n"
          . "\r\n"
          . "From: foo\@local\r\n"
          . "Date: Thu, 10 May 2018 15:15:38 +0200\r\n"
          . "\r\n"
          . "J"
          . "\r\n--boundary_1_1--\r\n"
        # body K
          . "\r\n--boundary_1\r\n"
          . "X-Body-Id:K\r\n"
          . "Content-Type: text/plain\r\n"
          . "Content-Disposition: inline\r\n"
          . "\r\n"
          . "K"
          . "\r\n--boundary_1--\r\n"
    ) || die;

    my $bodyA = {
        'header:x-body-id' => 'A',
        type => 'text/plain',
        disposition => 'inline',
    };
    my $bodyB = {
        'header:x-body-id' => 'B',
        type => 'text/plain',
        disposition => 'inline',
    };
    my $bodyC = {
        'header:x-body-id' => 'C',
        type => 'image/jpeg',
        disposition => 'inline',
    };
    my $bodyD = {
        'header:x-body-id' => 'D',
        type => 'text/plain',
        disposition => 'inline',
    };
    my $bodyE = {
        'header:x-body-id' => 'E',
        type => 'text/html',
        disposition => undef,
    };
    my $bodyF = {
        'header:x-body-id' => 'F',
        type => 'image/jpeg',
        disposition => undef,
    };
    my $bodyG = {
        'header:x-body-id' => 'G',
        type => 'image/jpeg',
        disposition => 'attachment',
    };
    my $bodyH = {
        'header:x-body-id' => 'H',
        type => 'application/x-excel',
        disposition => undef,
    };
    my $bodyJ = {
        'header:x-body-id' => 'J',
        type => 'message/rfc822',
        disposition => undef,
    };
    my $bodyK = {
        'header:x-body-id' => 'K',
        type => 'text/plain',
        disposition => 'inline',
    };

    my $wantBodyStructure = {
        'header:x-body-id' => undef,
        type => 'multipart/mixed',
        disposition => undef,
        subParts => [
            $bodyA,
            {
                'header:x-body-id' => undef,
                type => 'multipart/mixed',
                disposition => undef,
                subParts => [
                    {
                        'header:x-body-id' => undef,
                        type => 'multipart/alternative',
                        disposition => undef,
                        subParts => [
                            {
                                'header:x-body-id' => undef,
                                type => 'multipart/mixed',
                                disposition => undef,
                                subParts => [
                                    $bodyB,
                                    $bodyC,
                                    $bodyD,
                                ],
                            },
                            {
                                'header:x-body-id' => undef,
                                type => 'multipart/related',
                                disposition => undef,
                                subParts => [
                                    $bodyE,
                                    $bodyF,
                                ],
                            },
                        ],
                    },
                    $bodyG,
                    $bodyH,
                    $bodyJ,
                ],
            },
            $bodyK,
        ],
    };

    my $wantTextBody = [ $bodyA, $bodyB, $bodyC, $bodyD, $bodyK ];
    my $wantHtmlBody = [ $bodyA, $bodyE, $bodyK ];
    my $wantAttachments = [ $bodyC, $bodyF, $bodyG, $bodyH, $bodyJ ];

    my $res = $jmap->CallMethods([
        ['Email/query', { }, "R1"],
        ['Email/get', {
            '#ids' => { resultOf => 'R1', name => 'Email/query', path => '/ids' },
            properties => ['bodyStructure', 'textBody', 'htmlBody', 'attachments' ],
            bodyProperties => ['type', 'disposition', 'header:x-body-id'],
        }, 'R2' ],
    ]);
    my $msg = $res->[1][1]{list}[0];
    $self->assert_deep_equals($wantBodyStructure, $msg->{bodyStructure});
    $self->assert_deep_equals($wantTextBody, $msg->{textBody});
    $self->assert_deep_equals($wantHtmlBody, $msg->{htmlBody});
    $self->assert_deep_equals($wantAttachments, $msg->{attachments});
}

sub test_email_get_calendarevents
    :min_version_3_1 :needs_component_jmap
{
    my ($self) = @_;
    my $jmap = $self->{jmap};

    my $store = $self->{store};
    my $talk = $store->get_client();

    $self->make_message("foo",
        mime_type => "multipart/related",
        mime_boundary => "boundary_1",
        body => ""
          . "\r\n--boundary_1\r\n"
          . "Content-Type: text/plain\r\n"
          . "\r\n"
          . "txt body"
          . "\r\n--boundary_1\r\n"
          . "Content-Type: text/calendar;charset=utf-8\r\n"
          . "Content-Transfer-Encoding: quoted-printable\r\n"
          . "\r\n"
          . "BEGIN:VCALENDAR\r\n"
          . "VERSION:2.0\r\n"
          . "PRODID:-//CyrusIMAP.org/Cyrus 3.1.3-606//EN\r\n"
          . "CALSCALE:GREGORIAN\r\n"
          . "BEGIN:VTIMEZONE\r\n"
          . "TZID:Europe/Vienna\r\n"
          . "BEGIN:STANDARD\r\n"
          . "DTSTART:19700101T000000\r\n"
          . "RRULE:FREQ=YEARLY;BYDAY=-1SU;BYMONTH=10\r\n"
          . "TZOFFSETFROM:+0200\r\n"
          . "TZOFFSETTO:+0100\r\n"
          . "END:STANDARD\r\n"
          . "BEGIN:DAYLIGHT\r\n"
          . "DTSTART:19700101T000000\r\n"
          . "RRULE:FREQ=YEARLY;BYDAY=-1SU;BYMONTH=3\r\n"
          . "TZOFFSETFROM:+0100\r\n"
          . "TZOFFSETTO:+0200\r\n"
          . "END:DAYLIGHT\r\n"
          . "END:VTIMEZONE\r\n"
          . "BEGIN:VEVENT\r\n"
          . "CREATED:20180518T090306Z\r\n"
          . "DTEND;TZID=Europe/Vienna:20180518T100000\r\n"
          . "DTSTAMP:20180518T090306Z\r\n"
          . "DTSTART;TZID=Europe/Vienna:20180518T090000\r\n"
          . "LAST-MODIFIED:20180518T090306Z\r\n"
          . "SEQUENCE:1\r\n"
          . "SUMMARY:K=C3=A4se\r\n"
          . "TRANSP:OPAQUE\r\n"
          . "UID:d9e7f7d6-ce1a-4a71-94c0-b4edd41e5959\r\n"
          . "END:VEVENT\r\n"
          . "END:VCALENDAR\r\n"
          . "\r\n--boundary_1--\r\n"
    ) || die;

    my $res = $jmap->CallMethods([
        ['Email/query', { }, "R1"],
        ['Email/get', {
            '#ids' => { resultOf => 'R1', name => 'Email/query', path => '/ids' },
            properties => ['textBody', 'attachments', 'calendarEvents'],
        }, 'R2' ],
    ]);
    my $msg = $res->[1][1]{list}[0];

    $self->assert_num_equals(1, scalar @{$msg->{attachments}});
    $self->assert_str_equals('text/calendar', $msg->{attachments}[0]{type});

    $self->assert_num_equals(1, scalar keys %{$msg->{calendarEvents}});
    my $partId = $msg->{attachments}[0]{partId};
    my $jsevent =$msg->{calendarEvents}{$partId};
    $self->assert_not_null($jsevent);
    $self->assert_str_equals("K\N{LATIN SMALL LETTER A WITH DIAERESIS}se", $jsevent->{title});
    $self->assert_str_equals('2018-05-18T09:00:00', $jsevent->{start});
    $self->assert_str_equals('Europe/Vienna', $jsevent->{timeZone});
    $self->assert_str_equals('PT1H', $jsevent->{duration});
}

sub test_email_set_blobencoding
    :min_version_3_1 :needs_component_jmap
{
    my ($self) = @_;
    my $jmap = $self->{jmap};

    my $store = $self->{store};
    my $talk = $store->get_client();

    xlog "Upload a data blob";
    my $logofile = abs_path('data/logo.gif');
    open(FH, "<$logofile");
    local $/ = undef;
    my $binary = <FH>;
    close(FH);
    my $data = $jmap->Upload($binary, "image/gif");
    my $dataBlobId = $data->{blobId};

    my $emailBlob = <<'EOF';
From: "Some Example Sender" <example@example.com>
To: baseball@vitaead.com
Subject: test email
Date: Wed, 7 Dec 2016 00:21:50 -0500
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Content-Transfer-Encoding: quoted-printable

This is a test email.
EOF
    $emailBlob =~ s/\r?\n/\r\n/gs;
    $data = $jmap->Upload($emailBlob, "application/octet");
    my $rfc822Blobid = $data->{blobId};

    xlog "Create email with body structure";
    my $inboxid = $self->getinbox()->{id};
    my $email = {
        mailboxIds => { $inboxid => JSON::true },
        from => [{ name => "Test", email => q{foo@bar} }],
        subject => "test",
        textBody => [{
            type => 'text/plain',
            partId => '1',
        }],
        bodyValues => {
            '1' => {
                value => "A text body",
            },
        },
        attachments => [{
            type => 'image/gif',
            blobId => $dataBlobId,
        }, {
            type => 'message/rfc822',
            blobId => $rfc822Blobid,
        }],
    };
    my $res = $jmap->CallMethods([
        ['Email/set', { create => { '1' => $email } }, 'R1'],
        ['Email/get', {
            ids => [ '#1' ],
            properties => [ 'bodyStructure' ],
            bodyProperties => [ 'type', 'header:Content-Transfer-Encoding' ],
        }, 'R2' ],
    ]);

    my $gotPart;
    $gotPart = $res->[1][1]{list}[0]{bodyStructure}{subParts}[1];
    $self->assert_str_equals('message/rfc822', $gotPart->{type});
    $self->assert_str_equals(' 7BIT', $gotPart->{'header:Content-Transfer-Encoding'});
    $gotPart = $res->[1][1]{list}[0]{bodyStructure}{subParts}[2];
    $self->assert_str_equals('image/gif', $gotPart->{type});
    $self->assert_str_equals(' BASE64', uc($gotPart->{'header:Content-Transfer-Encoding'}));
}

sub test_email_body_alternative_without_html
    :min_version_3_1 :needs_component_jmap
{
    my ($self) = @_;
    my $jmap = $self->{jmap};

    my $store = $self->{store};
    my $talk = $store->get_client();

    my %exp_sub;
    $store->set_folder("INBOX");
    $store->_select();
    $self->{gen}->set_next_uid(1);

    my $body = "".
    "--sub\r\n".
    "Content-Type: text/plain\r\n".
    "\r\n" .
    "plain text".
    "\r\n--sub\r\n".
    "Content-Type: some/part\r\n".
    "Content-Transfer-Encoding: base64\r\n".
    "\r\n" .
    "abc=".
    "\r\n--sub--\r\n";

    $exp_sub{A} = $self->make_message("foo",
        mime_type => "multipart/alternative",
        mime_boundary => "sub",
        body => $body
    );

    xlog "get email list";
    my $res = $jmap->CallMethods([['Email/query', {}, "R1"]]);
    my $ids = $res->[0][1]->{ids};

    xlog "get email";
    $res = $jmap->CallMethods([['Email/get', {
        ids => $ids,
        properties => ['textBody', 'htmlBody', 'bodyStructure'],
        fetchAllBodyValues => JSON::true
    }, "R1"]]);
    my $msg = $res->[0][1]{list}[0];
    $self->assert_num_equals(1, scalar @{$msg->{textBody}});
    $self->assert_num_equals(1, scalar @{$msg->{htmlBody}});
    $self->assert_str_equals($msg->{textBody}[0]->{partId}, $msg->{htmlBody}[0]->{partId});
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

sub test_mailbox_intermediate_folders
    :min_version_3_1 :needs_component_jmap
{
    my ($self) = @_;

    my $jmap = $self->{jmap};

    my $imaptalk = $self->{store}->get_client();

    $imaptalk->create("INBOX.A.B.C");

    xlog "get existing mailboxes";
    my $res = $jmap->CallMethods([['Mailbox/get', {}, "R1"]]);
    $self->assert_not_null($res);
    $self->assert_str_equals($res->[0][0], 'Mailbox/get');
    $self->assert_str_equals($res->[0][2], 'R1');

    my %m = map { $_->{name} => $_ } @{$res->[0][1]{list}};
    $self->assert_num_equals(scalar keys %m, 4);
    my $inbox = $m{"Inbox"};
    my $a = $m{"A"};
    my $b = $m{"B"};
    my $c = $m{"C"};

    $self->assert_null($inbox->{parentId});
    $self->assert_null($a->{parentId});
    $self->assert_str_equals($b->{parentId}, $a->{id});
    $self->assert_str_equals($c->{parentId}, $b->{id});

    $res = $jmap->CallMethods([
            ['Mailbox/set', { create => { "1" => {
                            name => "A",
             }}}, "R1"]
    ]);

    $self->assert_not_null($res->[0][1]{created}{1});

    $res = $jmap->CallMethods([['Mailbox/get', {}, "R1"]]);
    $self->assert_not_null($res);
    $self->assert_str_equals($res->[0][0], 'Mailbox/get');
    $self->assert_str_equals($res->[0][2], 'R1');
    %m = map { $_->{name} => $_ } @{$res->[0][1]{list}};
    $self->assert_num_equals(scalar keys %m, 4);
    $a = $m{"A"};
    $b = $m{"B"};

    $self->assert_null($a->{parentId});
    $self->assert_str_equals($b->{parentId}, $a->{id});
}

sub test_implementation_email_query
    :min_version_3_1 :needs_component_jmap
{
    my ($self) = @_;
    my $jmap = $self->{jmap};

    my $store = $self->{store};
    my $talk = $store->get_client();

    my $now = DateTime->now();

    xlog "Generate a email in INBOX via IMAP";
    my $res = $self->make_message("foo") || die;
    my $uid = $res->{attrs}->{uid};
    my $msg;

    my $inbox = $self->getinbox();

    xlog "non-filtered query can calculate changes";
    $res = $jmap->CallMethods([['Email/query', {}, "R1"]]);
    $self->assert($res->[0][1]{canCalculateChanges});

    xlog "inMailbox query can calculate changes";
    $res = $jmap->CallMethods([
        ['Email/query', {
          filter => { inMailbox => $inbox->{id} },
          sort => [ {
            isAscending => $JSON::false,
            property => 'receivedAt',
          } ],
        }, "R1"],
    ]);
    $self->assert($res->[0][1]{canCalculateChanges});

    xlog "inMailbox query can calculate changes with mutable sort";
    $res = $jmap->CallMethods([
        ['Email/query', {
          filter => { inMailbox => $inbox->{id} },
          sort => [ {
            property => "someInThreadHaveKeyword",
            keyword => "\$seen",
            isAscending => $JSON::false,
          }, {
            property => 'receivedAt',
            isAscending => $JSON::false,
          } ],
        }, "R1"],
    ]);
    $self->assert($res->[0][1]{canCalculateChanges});

    xlog "inMailbox query with keyword can not calculate changes";
    $res = $jmap->CallMethods([
        ['Email/query', {
          filter => {
            conditions => [
              { inMailbox => $inbox->{id} },
              { conditions => [ { allInThreadHaveKeyword => "\$seen" } ],
                operator => 'NOT',
              },
            ],
            operator => 'AND',
          },
            sort => [ {
                isAscending => $JSON::false,
                property => 'receivedAt',
            } ],
        }, "R1"],
    ]);
    $self->assert(not $res->[0][1]{canCalculateChanges});
}

1;
