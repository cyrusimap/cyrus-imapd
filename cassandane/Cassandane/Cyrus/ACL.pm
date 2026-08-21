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

package Cassandane::Cyrus::ACL;
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
    my $config = Cassandane::Config->default()->clone();
    $config->set(imapidlepoll => 1);
    return $class->SUPER::new({
        config => $config,
        deliver => 1,
        adminstore => 1,
    }, @_);
}

sub set_up
{
    my ($self) = @_;

    $self->SUPER::set_up();

    my $admintalk = $self->{adminstore}->get_client();

    # let's create ourselves an archive user
    # sub folders of another user - one is subscribable
    $self->{instance}->create_user("archive",
                                   subdirs => [ 'cassandane', ['cassandane', 'sent'] ]);
    $admintalk->setacl("user.archive.cassandane.sent", "cassandane", "lrswp");
}

sub tear_down
{
    my ($self) = @_;
    $self->SUPER::tear_down();
}

#
# Test regular delete
#
sub test_delete
    :NoAltNameSpace
{
    my ($self) = @_;

    my $admintalk = $self->{adminstore}->get_client();
    my $talk = $self->{store}->get_client();

    $self->{adminstore}->set_folder('user.archive.cassandane.sent');
    $self->make_message("Message A", store => $self->{adminstore});

    $self->{store}->set_folder('user.archive.cassandane.sent');
    $self->{store}->_select();

    my $res = $talk->store('1', '+flags', '(\\deleted)');
    $self->assert_null($res); # means it failed
    $self->assert_str_equals('no', $talk->get_last_completion_response());
    $self->assert($talk->get_last_error() =~ m/permission denied/i);
}

sub test_many_users
    :NoAltNameSpace
{
    my ($self) = @_;

    my $admintalk = $self->{adminstore}->get_client();
    my $talk = $self->{store}->get_client();
    $self->make_message("Message A");

    $talk->create("INBOX.multi");
    $self->assert_str_equals('ok', $talk->get_last_completion_response());

    for (1..100) {
        $admintalk->setacl("user.cassandane.multi", "test$_", "lrswipcd");
        $self->assert_str_equals('ok', $admintalk->get_last_completion_response());
    }

    my $res = $talk->select("INBOX.multi");
    $self->assert_str_equals('ok', $talk->get_last_completion_response());
}

sub test_move
    :NoAltNameSpace
{
    my ($self) = @_;

    my $admintalk = $self->{adminstore}->get_client();
    my $talk = $self->{store}->get_client();

    $self->{adminstore}->set_folder('user.archive.cassandane.sent');
    $self->make_message("Message A", store => $self->{adminstore});

    $self->{store}->set_folder('user.archive.cassandane.sent');
    $self->{store}->_select();

    my $res = $talk->move('1', "INBOX");
    $self->assert_null($res); # means it failed
    $self->assert_str_equals('no', $talk->get_last_completion_response());
    $self->assert($talk->get_last_error() =~ m/permission denied/i);
}

sub test_setacl_badacl
    :NoAltNameSpace
{
    my ($self) = @_;

    my $admintalk = $self->{adminstore}->get_client();
    my $talk = $self->{store}->get_client();

    $talk->create("INBOX.badacl");
    $self->assert_str_equals('ok', $talk->get_last_completion_response());

    $admintalk->setacl("user.cassandane.badacl", "foo", "ylrswipcd");
    $self->assert_str_equals('bad', $admintalk->get_last_completion_response());
}

sub test_setacl_addacl
    :NoAltNameSpace
{
    my ($self) = @_;

    my $admintalk = $self->{adminstore}->get_client();
    my $talk = $self->{store}->get_client();

    $talk->create("INBOX.addacl");
    $self->assert_str_equals('ok', $talk->get_last_completion_response());

    $admintalk->setacl("user.cassandane.addacl", "foo", "lrswipkxtecdn");
    $admintalk->setacl("user.cassandane.addacl", "foo", "+a");
    $self->assert_str_equals('ok', $admintalk->get_last_completion_response());
}

sub test_setacl_rmacl
    :NoAltNameSpace
{
    my ($self) = @_;

    my $admintalk = $self->{adminstore}->get_client();
    my $talk = $self->{store}->get_client();

    $talk->create("INBOX.rmacl");
    $self->assert_str_equals('ok', $talk->get_last_completion_response());

    $admintalk->setacl("user.cassandane.rmacl", "foo", "lrswipkxtecdan");
    $admintalk->setacl("user.cassandane.rmacl", "foo", "-a");
    $self->assert_str_equals('ok', $admintalk->get_last_completion_response());
}

sub test_setacl_addacl_exists
    :NoAltNameSpace
{
    my ($self) = @_;

    my $admintalk = $self->{adminstore}->get_client();
    my $talk = $self->{store}->get_client();

    $talk->create("INBOX.exists");
    $self->assert_str_equals('ok', $talk->get_last_completion_response());

    $admintalk->setacl("user.cassandane.exists", "foo", "lrswipkxtecdan");
    $admintalk->setacl("user.cassandane.exists", "foo", "+a");
    $self->assert_str_equals('ok', $admintalk->get_last_completion_response());
}

sub test_setacl_rmacl_unexists
    :NoAltNameSpace
{
    my ($self) = @_;

    my $admintalk = $self->{adminstore}->get_client();
    my $talk = $self->{store}->get_client();

    $talk->create("INBOX.rmunexists");
    $self->assert_str_equals('ok', $talk->get_last_completion_response());

    $admintalk->setacl("user.cassandane.rmunexists", "foo", "lrswipkxtecdn");
    $admintalk->setacl("user.cassandane.rmunexists", "foo", "-a");
    $self->assert_str_equals('ok', $admintalk->get_last_completion_response());
}

sub test_reconstruct
{
    my ($self) = @_;

    my $admintalk = $self->{adminstore}->get_client();
    my $talk = $self->{store}->get_client();

    my $oldacl = $admintalk->getacl("user.archive.cassandane.sent");

    $self->{instance}->run_command({ cyrus => 1 }, 'reconstruct');

    my $newacl = $admintalk->getacl("user.archive.cassandane.sent");
    $self->assert_deep_equals($oldacl, $newacl);
}

sub test_setacl_emptyid
{
    my ($self) = @_;

    my $admintalk = $self->{adminstore}->get_client();
    my $talk = $self->{store}->get_client();

    $talk->create("INBOX.emptyid");
    $self->assert_str_equals('ok', $talk->get_last_completion_response());

    # send an empty identifier for SETACL
    $admintalk->setacl("user.cassandane.emptyid", "", "lrswipcd");
    $self->assert_str_equals('no', $admintalk->get_last_completion_response());
}

sub test_setacl_badrights
    :NoAltNameSpace
{
    my ($self) = @_;

    my $admintalk = $self->{adminstore}->get_client();
    my $talk = $self->{store}->get_client();

    $talk->create("INBOX.badrights");
    $self->assert_str_equals('ok', $talk->get_last_completion_response());

    my $origacl = $admintalk->getacl("user.cassandane.badrights");

    $admintalk->setacl("user.cassandane.badrights", "cassandane", "b");
    $self->assert_str_equals('bad', $admintalk->get_last_completion_response());

    my $newacl = $admintalk->getacl("user.cassandane.badrights");
    $self->assert_deep_equals($origacl, $newacl);
}

#Magic word virtdomains in name sets config virtdomains = userid
sub test_virtdomains_noinherit1
    :NoAltNamespace :CrossDomains
{
    my ($self) = @_;

    my $defaultdomain = $self->{instance}->{config}->get('defaultdomain')
                        // 'internal';
    my $cass_defdom = "cassandane\@$defaultdomain";
    my $cass_dom = 'cassandane@uhoh.org';

    # get stores that authenticate as each username
    $self->{instance}->create_user($cass_dom);
    my $imap = $self->{instance}->get_service('imap');
    my $defdom_store = $imap->create_store(username => $cass_defdom);
    my $dom_store = $imap->create_store(username => $cass_dom);

    # set up a target folder and some permissions
    $self->{instance}->create_user('banana');
    my $folder = 'user.banana';
    my $admintalk = $self->{adminstore}->get_client();
    $admintalk->setacl($folder, cassandane => 'lrswip');
    $admintalk->setacl($folder, $cass_dom => 'lrs');
    $admintalk->getacl($folder);

    # make the stores all look at the same folder
    $self->{store}->set_folder($folder);
    $defdom_store->set_folder($folder);
    $dom_store->set_folder($folder);

    # 'cassandane' should be able to make a message
    $self->make_message("message from cassandane", store => $self->{store});

    # 'cassandane@{defaultdomain}' should be able to make a message
    $self->make_message("message from $cass_defdom", store => $defdom_store);

    # 'cassandane@somedomain' should NOT be able to make a message
    eval {
        $self->make_message("message from $cass_dom", store => $dom_store);
    };
    my $err = q{} . $@;
    $self->assert_matches(qr/permission denied/i, $err);
}

#Magic word virtdomains in name sets config virtdomains = userid
sub test_virtdomains_noinherit2
    :NoAltNamespace :CrossDomains
{
    my ($self) = @_;

    my $defaultdomain = $self->{instance}->{config}->get('defaultdomain')
                        // 'internal';
    my $cass_defdom = "cassandane\@$defaultdomain";
    my $cass_dom = 'cassandane@uhoh.org';

    # get stores that authenticate as each username
    $self->{instance}->create_user($cass_dom);
    my $imap = $self->{instance}->get_service('imap');
    my $defdom_store = $imap->create_store(username => $cass_defdom);
    my $dom_store = $imap->create_store(username => $cass_dom);

    # set up a target folder and some permissions
    $self->{instance}->create_user('banana');
    my $folder = 'user.banana';
    my $admintalk = $self->{adminstore}->get_client();
    $admintalk->setacl($folder, cassandane => 'lrs');
    $admintalk->setacl($folder, $cass_dom => 'lrswip');
    $admintalk->getacl($folder);

    # make the stores all look at the same folder
    $self->{store}->set_folder($folder);
    $defdom_store->set_folder($folder);
    $dom_store->set_folder($folder);

    # 'cassandane' should NOT be able to make a message
    eval {
        $self->make_message("message from cassandane",
                            store => $self->{store});
    };
    my $err = q{} . $@;
    $self->assert_matches(qr/permission denied/i, $err);

    # 'cassandane@{defaultdomain}' should NOT be able to make a message
    eval {
        $self->make_message("message from $cass_defdom",
                            store => $defdom_store);
    };
    $err = q{} . $@;
    $self->assert_matches(qr/permission denied/i, $err);

    # 'cassandane@somedomain' should be able to make a message
    $self->make_message("message from $cass_dom", store => $dom_store);
}

sub test_listrights_other_user
{
    my ($self) = @_;

    my $talk = $self->{store}->get_client;

    # Create a victim user.  We grant the attacker no explicit rights on the
    # victim's mailbox: the default ACL "anyone p" is enough to expose the
    # bug.  (LISTRIGHTS gates only on "has any right at all", where it ought
    # to require ACL_ADMIN; ACL_POST from the anyone grant is sufficient to
    # slip past.)
    $self->{instance}->create_user('victim');

    my $seen;
    $talk->_imap_cmd(
        'LISTRIGHTS', 0,
        { listrights => sub { $seen = 1 } },
        'Other Users.victim', 'victim',
    );

    $self->assert_str_equals('no', $talk->get_last_completion_response);
    $self->assert_null($seen);
}

#
# Test revoking and restoring rights while mailbox is selected
#
sub test_revoke_restore
    :NoAltNameSpace
{
    my ($self) = @_;

    my $admintalk = $self->{adminstore}->get_client();
    my $store = $self->{store};
    my $talk = $store->get_client();
    my $folder = 'user.archive.cassandane.sent';

    # Add message to INBOX
    $self->make_message("Message X");

    # Add message to $folder
    $self->{adminstore}->set_folder($folder);
    $self->make_message("Message A", store => $self->{adminstore});

    # Set ACL to full read-write
    $admintalk->setacl($folder, "cassandane", "lrswipkxtean");

    # Examine mailbox - should be read-only
    my $res = $talk->examine($folder);
    $self->assert_str_equals('read-only', $res);
    $self->assert_str_equals('ok', $talk->get_last_completion_response());
    $talk->clear_response_code('read-only');

    # Store \Flagged should be disallowed
    $res = $talk->store('1', '-flags', '(\\flagged)');
    $self->assert_null($res); # means it failed
    $self->assert_str_equals('no', $talk->get_last_completion_response());
    $self->assert($talk->get_last_error() =~ m/permission denied/i);

    # Idle updates should be allowed
    $store->idle_begin()
        or die "IDLE failed: $@";

    my $msg = $self->{gen}->generate(subject => "Message 1");
    $self->{instance}->deliver($msg, user => 'archive+cassandane.sent');

    $store->idle_response({}, 1);
    $self->assert_num_equals(2, $talk->get_response_code('exists'));
    $talk->clear_response_code('exists');
    $store->idle_end({});

    # Remove 'r' right
    $admintalk->setacl($folder, "cassandane", "-r");

    # Polled updates should be disallowed
    $msg = $self->{gen}->generate(subject => "Message 2");
    $self->{instance}->deliver($msg, user => 'archive+cassandane.sent');

    $res = $talk->noop();
    $store->idle_response({}, 3);
    $self->assert_null($talk->get_response_code('exists'));

    # Idle updates should be disallowed
    $store->idle_begin()
        or die "IDLE failed: $@";

    $msg = $self->{gen}->generate(subject => "Message 3");
    $self->{instance}->deliver($msg, user => 'archive+cassandane.sent');

    $store->idle_response({}, 3);
    $self->assert_null($talk->get_response_code('exists'));
    $store->idle_end({});

    # Any read command should be disallowed
    $res = $talk->fetch('1', '(flags)');
    $self->assert_null($res); # means it failed
    $self->assert_str_equals('no', $talk->get_last_completion_response());
    $self->assert($talk->get_last_error() =~ m/permission denied/i);

    $res = $talk->copy('1', 'INBOX');
    $self->assert_null($res); # means it failed
    $self->assert_str_equals('no', $talk->get_last_completion_response());
    $self->assert($talk->get_last_error() =~ m/permission denied/i);

    $res = $talk->search('all');
    $self->assert_null($res); # means it failed
    $self->assert_str_equals('no', $talk->get_last_completion_response());
    $self->assert($talk->get_last_error() =~ m/permission denied/i);

    $res = $talk->sort('(size)', 'us-ascii', 'all');
    $self->assert_null($res); # means it failed
    $self->assert_str_equals('no', $talk->get_last_completion_response());
    $self->assert($talk->get_last_error() =~ m/permission denied/i);

    $res = $talk->thread('references', 'us-ascii', 'all');
    $self->assert_null($res); # means it failed
    $self->assert_str_equals('no', $talk->get_last_completion_response());
    $self->assert($talk->get_last_error() =~ m/permission denied/i);

    my @results;
    my %handlers =
    (
        esearch => sub
        {
            my (undef, $esearch) = @_;
            push(@results, $esearch);
        },
    );

    $res = $talk->_imap_cmd('ESEARCH', 0, 'esearch', 'ALL');
    $self->assert_str_equals('ok', $talk->get_last_completion_response());
    $self->assert_num_equals(0, scalar @results);

    @results = ();
    $res = $talk->_imap_cmd('ESEARCH', 0, \%handlers, #'esearch',
                            'IN', '(PERSONAL SELECTED)');
    $self->assert_str_equals('ok', $talk->get_last_completion_response());
    $self->assert_num_equals(1, scalar @results);
    $self->assert_str_equals('INBOX', $results[0][0][3]);

    # Add 'r' right
    $admintalk->setacl($folder, "cassandane", "+r");

    # Select mailbox - should be read-write
    $res = $talk->select($folder);
    $self->assert_str_equals('read-write', $res);
    $self->assert_str_equals('ok', $talk->get_last_completion_response());
    $talk->clear_response_code('read-write');

    # Should be allowed to set flags
    $res = $talk->store('1', '+flags', '(\\seen \\flagged \\deleted)');
    $self->assert_not_null($res);
    $self->assert_str_equals('ok', $talk->get_last_completion_response());

    # Remove ALL write rights
    $admintalk->setacl($folder, "cassandane", "-switen");

    # Any write command should be disallowed
    $res = $talk->store('1', '-flags', '(\\seen)');
    $self->assert_null($res); # means it failed
    $self->assert_str_equals('no', $talk->get_last_completion_response());
    $self->assert($talk->get_last_error() =~ m/permission denied/i);

    # Mailbox should be reported as read-only
    $self->assert_not_null($talk->get_response_code('read-only'));
    $talk->clear_response_code('read-only');

    $res = $talk->store('1', '-flags', '(\\flagged)');
    $self->assert_null($res); # means it failed
    $self->assert_str_equals('no', $talk->get_last_completion_response());
    $self->assert($talk->get_last_error() =~ m/permission denied/i);

    $res = $talk->store('1', '-flags', '(\\deleted)');
    $self->assert_null($res); # means it failed
    $self->assert_str_equals('no', $talk->get_last_completion_response());
    $self->assert($talk->get_last_error() =~ m/permission denied/i);

    $res = $talk->expunge();
    $self->assert_null($res); # means it failed
    $self->assert_str_equals('no', $talk->get_last_completion_response());
    $self->assert($talk->get_last_error() =~ m/permission denied/i);

    # Re-Select mailbox - should be read-only
    $res = $talk->unselect();
    $res = $talk->select($folder);
    $self->assert_str_equals('read-only', $res);
    $self->assert_str_equals('ok', $talk->get_last_completion_response());
    $talk->clear_response_code('read-only');

    # Add 't' right
    $admintalk->setacl($folder, "cassandane", "+t");

    # Should be allowed to unset \Deleted
    $res = $talk->store('1', '-flags', '(\\deleted)');
    $self->assert_not_null($res);
    $self->assert_str_equals('ok', $talk->get_last_completion_response());

    # Mailbox should be reported as read-write
    $self->assert_not_null($talk->get_response_code('read-write'));
    $talk->clear_response_code('read-write');

    # Expunge should still be disallowed
    $res = $talk->expunge();
    $self->assert_null($res); # means it failed
    $self->assert_str_equals('no', $talk->get_last_completion_response());
    $self->assert($talk->get_last_error() =~ m/permission denied/i);
}

# see also LDAP.pm for groupid tests

1;
