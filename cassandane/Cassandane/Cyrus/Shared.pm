# SPDX-License-Identifier: BSD-3-Clause-CMU
# See COPYING file at the root of the distribution for more details.

package Cassandane::Cyrus::Shared;
use strict;
use warnings;
use DateTime;
use Data::Dumper;

use base qw(Cassandane::Cyrus::TestCase);
use Cassandane::Instance;
use Cassandane::Mboxname;
use Cassandane::Util::Log;
use Cassandane::Util::Words;

$Data::Dumper::Sortkeys = 1;

sub new
{
    my ($class, @args) = @_;

    my $self = $class->SUPER::new({ adminstore => 1 }, @args);

    return $self;
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

# A mailbox created without anyone being granted 'x' must still be
# deletable by an admin: admins are not subject to ACL checks anywhere
# else, and a top-level shared folder only ever gets 'defaultacl'.
sub shared_admin_delete_common
{
    my ($self) = @_;

    my $admintalk = $self->{adminstore}->get_client();

    xlog $self, "create a top-level shared folder";
    $admintalk->create('shared');
    $self->assert_str_equals('ok', $admintalk->get_last_completion_response());

    xlog $self, "nobody has been granted 'x' on it";
    my %acl = @{$admintalk->getacl('shared')};
    $self->assert_str_equals('ok', $admintalk->get_last_completion_response());
    $self->assert_does_not_match(qr/x/, $acl{admin} // '');

    xlog $self, "admin can delete it anyway";
    $admintalk->delete('shared');
    $self->assert_str_equals('ok', $admintalk->get_last_completion_response());

    xlog $self, "same for a user mailbox with no admin entry in its acl";
    $admintalk->create('user.orphan');
    $self->assert_str_equals('ok', $admintalk->get_last_completion_response());

    %acl = @{$admintalk->getacl('user.orphan')};
    $self->assert_str_equals('ok', $admintalk->get_last_completion_response());
    $self->assert_does_not_match(qr/x/, $acl{admin} // '');

    $admintalk->delete('user.orphan');
    $self->assert_str_equals('ok', $admintalk->get_last_completion_response());
}

sub shared_subscribe_common
{
    my ($self, $user1, $user2) = @_;

    my $service = $self->{instance}->get_service('imap');
    my $config = $self->{instance}->{config};
    my $sep = $config->get_bool('unixhierarchysep', 'on') ? '/' : '.';

    my $user1_inbox = Cassandane::Mboxname->new(config => $config);
    $user1_inbox->from_username($user1);

    my @user1_mailboxes = map {
        $user1_inbox->make_child($_);
    } random_words(3);
    $self->{instance}->create_user($user1,
                                   subdirs => \@user1_mailboxes);

    my $user1_store = $service->create_store(username => $user1);
    my $user1_talk = $user1_store->get_client();

    foreach my $mb ($user1_inbox, @user1_mailboxes) {
        $user1_talk->subscribe($mb->to_external('owner'));
        $user1_talk->setacl($mb->to_external('owner'), $user2, 'lrs');
    }

    my $user2_inbox = Cassandane::Mboxname->new(config => $config);
    $user2_inbox->from_username($user2);

    my @user2_mailboxes = map {
        $user2_inbox->make_child($_);
    } random_words(3);
    $self->{instance}->create_user($user2,
                                   subdirs => \@user2_mailboxes);

    my $user2_store = $service->create_store(username => $user2);
    my $user2_talk = $user2_store->get_client();

    foreach my $mb ($user2_inbox, @user2_mailboxes) {
        $user2_talk->subscribe($mb->to_external('owner'));
        $user2_talk->setacl($mb->to_external('owner'), $user1, 'lrs');
    }

    xlog("subscribe as $user1 to $user2\'s shared mb's");
    foreach my $mb ($user2_inbox, @user2_mailboxes) {
        $user1_talk->subscribe($mb->to_external('other'));
        $self->assert_equals('ok', $user1_talk->get_last_completion_response());
    }

    xlog("make sure $user1 has the right subscriptions");
    my $user1_subs = $user1_talk->list([qw(SUBSCRIBED)],
                                       '', '*',
                                       'RETURN', [qw(CHILDREN)]);
    $self->assert_mailbox_structure($user1_subs, $sep, {
        $user1_inbox->to_external('owner') => [ '\\Subscribed' ],
        (map {(
            $_->to_external('owner') => [ '\\Subscribed', '\\HasNoChildren' ]
        )} @user1_mailboxes),
        $user2_inbox->to_external('other') => [ '\\Subscribed' ],
        (map {(
            $_->to_external('other') => [
                '\\Subscribed',
                '\\HasNoChildren',
            ]
        )} @user2_mailboxes),
    });

    xlog("unsub as $user1 from $user2\'s folders");
    foreach my $mb ($user2_inbox, @user2_mailboxes) {
        $user1_talk->unsubscribe($mb->to_external('other'));
        $self->assert_equals('ok', $user1_talk->get_last_completion_response());
    }

    xlog("make sure $user1 has the right subscriptions");
    $user1_subs = $user1_talk->list([qw(SUBSCRIBED)],
                                    '', '*',
                                    'RETURN', [qw(CHILDREN)]);
    $self->assert_mailbox_structure($user1_subs, $sep, {
        $user1_inbox->to_external('owner') => [ '\\Subscribed' ],
        (map {(
            $_->to_external('owner') => [ '\\Subscribed', '\\HasNoChildren' ]
        )} @user1_mailboxes),
    });

    xlog("subscribe as $user2 to $user1\'s shared mb's");
    foreach my $mb ($user1_inbox, @user1_mailboxes) {
        $user2_talk->subscribe($mb->to_external('other'));
        $self->assert_equals('ok',
                             $user2_talk->get_last_completion_response());
    }

    xlog("make sure $user2 has the right subscriptions");
    my $user2_subs = $user2_talk->list([qw(SUBSCRIBED)],
                                       '', '*',
                                       'RETURN', [qw(CHILDREN)]);
    $self->assert_mailbox_structure($user2_subs, $sep, {
        $user2_inbox->to_external('owner') => [ '\\Subscribed' ],
        (map {(
            $_->to_external('owner') => [ '\\Subscribed', '\\HasNoChildren' ]
        )} @user2_mailboxes),
        $user1_inbox->to_external('other') => [ '\\Subscribed' ],
        (map {(
            $_->to_external('other') => [
                '\\Subscribed',
                '\\HasNoChildren',
            ]
        )} @user1_mailboxes),
    });

    xlog("unsub as $user2 from $user1\'s folders");
    foreach my $mb ($user1_inbox, @user1_mailboxes) {
        $user2_talk->unsubscribe($mb->to_external('other'));
        $self->assert_equals('ok',
                             $user2_talk->get_last_completion_response());
    }

    xlog("make sure $user2 has the right subscriptions");
    $user2_subs = $user2_talk->list([qw(SUBSCRIBED)],
                                    '', '*',
                                    'RETURN', [qw(CHILDREN)]);
    $self->assert_mailbox_structure($user2_subs, $sep, {
        $user1_inbox->to_external('owner') => [ '\\Subscribed' ],
        (map {(
            $_->to_external('owner') => [ '\\Subscribed', '\\HasNoChildren' ]
        )} @user2_mailboxes),
    });
}

use Cassandane::Tiny::Loader;

1;
