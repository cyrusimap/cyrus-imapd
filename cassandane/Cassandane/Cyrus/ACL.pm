# SPDX-License-Identifier: BSD-3-Clause-CMU
# See COPYING file at the root of the distribution for more details.

package Cassandane::Cyrus::ACL;
use strict;
use warnings;
use DateTime;
use Data::Dumper;

use base qw(Cassandane::Cyrus::TestCase);
use Cassandane::Util::Log;
use Cassandane::Generator;
use Cassandane::MessageStoreFactory;
use Cassandane::Instance;

sub new
{
    my $class = shift;
    return  $class->SUPER::new({adminstore => 1}, @_);
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

# see also LDAP.pm for groupid tests

1;
