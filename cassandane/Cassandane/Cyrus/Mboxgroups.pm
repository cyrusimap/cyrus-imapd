#!/usr/bin/perl
#
#  Copyright (c) 2024 Fastmail Pty Ltd. All rights reserved.
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

package Cassandane::Cyrus::Mboxgroups;
use strict;
use warnings;
use Cwd qw(realpath);
use JSON;
use Data::Dumper;

use lib '.';
use base qw(Cassandane::Cyrus::TestCase);
use base qw(Cassandane::Unit::TestCase);
use Cassandane::Util::Log;

sub new
{
    my ($class, @args) = @_;

    my $config = Cassandane::Config->default()->clone();
    $config->set(
        auth_mech => 'mboxgroups',
    );

    my $self = $class->SUPER::new({
        config => $config,
        adminstore => 1,
        services => [qw( imap )],
        start_instances => 0,
    }, @args);

    return $self;
}

sub set_up
{
    my ($self) = @_;

    $self->SUPER::set_up();

    $self->_start_instances();

    $self->{instance}->create_user("otheruser");

    my $admintalk = $self->{adminstore}->get_client();

    $admintalk->_imap_cmd('SETUSERGROUP', 0, '', 'cassandane', 'group:group c');
    $admintalk->_imap_cmd('SETUSERGROUP', 0, '', 'cassandane', 'group:group co');
    $admintalk->_imap_cmd('SETUSERGROUP', 0, '', 'otheruser', 'group:group co');
    $admintalk->_imap_cmd('SETUSERGROUP', 0, '', 'otheruser', 'group:group o');
}

sub tear_down
{
    my ($self) = @_;

    # clean this up as soon as we're done with it, cause it's holding a
    # port open!
    delete $self->{server};

    $self->SUPER::tear_down();
}

sub imap_getusergroup
{
    my ($self, $talk, $item) = @_;

    my $usergroups = {};
    my $handlers = {
        'usergroup' => sub {
            my (undef, $response) = @_;

            my %ug = @{$response};
            while (my ($user, $groups) = each %ug) {
                $usergroups->{$user} = { map { $_ => 1 } @{$groups} };
            }
        },
    };

    $talk->_imap_cmd('GETUSERGROUP', 0, $handlers, $item);
    $self->assert_str_equals('ok', $talk->get_last_completion_response());

    return $usergroups;
}

sub test_setacl_groupid
{
    my ($self) = @_;

    my $admintalk = $self->{adminstore}->get_client();

    $admintalk->create("user.cassandane.groupid");
    $self->assert_str_equals('ok',
        $admintalk->get_last_completion_response());

    $admintalk->setacl("user.cassandane.groupid",
                       "group:foo",
                       "lrswipkxtecdan");
    $self->assert_str_equals('ok',
        $admintalk->get_last_completion_response());
}

sub test_setacl_groupid_spaces
{
    my ($self) = @_;

    my $admintalk = $self->{adminstore}->get_client();

    $admintalk->create("user.cassandane.groupid_spaces");
    $self->assert_str_equals('ok',
        $admintalk->get_last_completion_response());

    $admintalk->setacl("user.cassandane.groupid_spaces",
                       "group:this group name has spaces",
                       "lrswipkxtecdan");
    $self->assert_str_equals('ok',
        $admintalk->get_last_completion_response());

    my $data = $admintalk->getacl("user.cassandane.groupid_spaces");
    $self->assert_str_equals('ok',
        $admintalk->get_last_completion_response());

    $self->assert(scalar @{$data} % 2 == 0);
    my %acl = @{$data};
    $self->assert_str_equals($acl{"group:this group name has spaces"},
                             "lrswipkxtecdan");

    $admintalk->select("user.cassandane.groupid_spaces");
    $self->assert_str_equals('ok',
        $admintalk->get_last_completion_response());
}

sub test_list_groupaccess_noracl
    :NoAltNamespace
{
    my ($self) = @_;

    my $admintalk = $self->{adminstore}->get_client();
    my $imaptalk = $self->{store}->get_client();

    $admintalk->create("user.otheruser.groupaccess");
    $self->assert_str_equals('ok',
        $admintalk->get_last_completion_response());

    $admintalk->setacl("user.otheruser.groupaccess",
                       "group:group co", "lrswipkxtecdan");
    $self->assert_str_equals('ok',
        $admintalk->get_last_completion_response());

    my $list = $imaptalk->list("", "*");
    my @boxes = sort map { $_->[2] } @{$list};

    $self->assert_deep_equals(\@boxes,
                              ['INBOX', 'user.otheruser.groupaccess']);
}

sub test_list_groupaccess_racl
    :ReverseACLs :NoAltNamespace
{
    my ($self) = @_;

    my $admintalk = $self->{adminstore}->get_client();
    my $imaptalk = $self->{store}->get_client();

    $admintalk->create("user.otheruser.groupaccess");
    $self->assert_str_equals('ok',
        $admintalk->get_last_completion_response());

    $admintalk->setacl("user.otheruser.groupaccess",
                       "group:group co", "lrswipkxtecdn");
    $self->assert_str_equals('ok',
        $admintalk->get_last_completion_response());

    if (get_verbose()) {
        my $format = $self->{instance}->{config}->get('mboxlist_db');
        $self->{instance}->run_command(
            { cyrus => 1, },
            'cyr_dbtool',
            "$self->{instance}->{basedir}/conf/mailboxes.db",
            $format,
            'show'
        );
    }

    my $list = $imaptalk->list("", "*");
    my @boxes = sort map { $_->[2] } @{$list};

    $self->assert_deep_equals(\@boxes,
                              ['INBOX', 'user.otheruser.groupaccess']);
}

sub do_test_list_order
{
    my ($self) = @_;

    my $admintalk = $self->{adminstore}->get_client();
    my $imaptalk = $self->{store}->get_client();

    $imaptalk->create("INBOX.zzz");
    $self->assert_str_equals('ok',
        $imaptalk->get_last_completion_response());

    $imaptalk->create("INBOX.aaa");
    $self->assert_str_equals('ok',
        $imaptalk->get_last_completion_response());

    my %adminfolders = (
        'user.otheruser.order-user' => 'cassandane',
        'user.otheruser.order-co' => 'group:group co',
        'user.otheruser.order-c' => 'group:group c',
        'user.otheruser.order-o' => 'group:group o',
        'shared.order-co' => 'group:group co',
        'shared.order-c' => 'group:group c',
        'shared.order-o' => 'group:group o',
    );

    while (my ($folder, $identifier) = each %adminfolders) {
        $admintalk->create($folder);
        $self->assert_str_equals('ok',
            $admintalk->get_last_completion_response(),
            "created folder $folder successfully");

        $admintalk->setacl($folder, $identifier, "lrswipkxtecdn");
        $self->assert_str_equals('ok',
            $admintalk->get_last_completion_response(),
            "setacl folder $folder for $identifier successfully");

        if ($folder =~ m/^shared/) {
            # subvert default permissions on shared namespace for
            # purpose of testing ordering
            $admintalk->setacl($folder, "anyone", "p");
            $self->assert_str_equals('ok',
                $admintalk->get_last_completion_response(),
                "setacl folder $folder for anyone successfully");
        }
    }

    if (get_verbose()) {
        my $format = $self->{instance}->{config}->get('mboxlist_db');
        $self->{instance}->run_command(
            { cyrus => 1, },
            'cyr_dbtool',
            "$self->{instance}->{basedir}/conf/mailboxes.db",
            $format,
            'show'
        );
    }

    my $list = $imaptalk->list("", "*");
    my @boxes = map { $_->[2] } @{$list};

    # Note: order is
    # * mine, alphabetically,
    # * other users', alphabetically,
    # * shared, alphabetically
    # ... which is not the order we created them ;)
    # Also, the "order-o" folders are not returned, because cassandane
    # is not a member of that group
    my @expect = qw(
        INBOX
        INBOX.aaa
        INBOX.zzz
        user.otheruser.order-c
        user.otheruser.order-co
        user.otheruser.order-user
    );
    my ($maj, $min) = Cassandane::Instance->get_version();
    if ($maj > 3 || ($maj == 3 && $min > 4)) {
        push @expect, qw(shared);
    }
    push @expect, qw( shared.order-c shared.order-co );
    $self->assert_deep_equals(\@boxes, \@expect);
}

sub test_list_order_noracl
    :NoAltNamespace
{
    my $self = shift;
    return $self->do_test_list_order(@_);
}

sub test_list_order_racl
    :ReverseACLs :NoAltNamespace
{
    my $self = shift;
    return $self->do_test_list_order(@_);
}

sub test_nonadmin_group_mgmt
{
    my ($self) = @_;

    my $talk = $self->{store}->get_client();

    # should have the xusergroups capability
    $self->assert_not_null($talk->capability()->{xusergroups});

    # group management commands are admin-only
    $talk->_imap_cmd('GETUSERGROUP', 0, '', 'cassandane');
    $self->assert_str_equals('no', $talk->get_last_completion_response());

    $talk->_imap_cmd('SETUSERGROUP', 0, '', 'cassandane', 'group:foo');
    $self->assert_str_equals('no', $talk->get_last_completion_response());

    $talk->_imap_cmd('UNSETUSERGROUP', 0, '', 'cassandane', 'group:foo');
    $self->assert_str_equals('no', $talk->get_last_completion_response());
}

sub test_admin_getusergroup
{
    my ($self) = @_;

    my $admintalk = $self->{adminstore}->get_client();

    # should have the xusergroups capability
    $self->assert_not_null($admintalk->capability()->{xusergroups});

    # get a user's groups
    my $usergroups = $self->imap_getusergroup($admintalk, 'cassandane');
    $self->assert_not_null($usergroups->{'cassandane'});
    $self->assert_not_null($usergroups->{'cassandane'}->{'group:group c'});
    $self->assert_not_null($usergroups->{'cassandane'}->{'group:group co'});
    $self->assert_null($usergroups->{'cassandane'}->{'group:group o'});

    # get a group's users
    $usergroups = $self->imap_getusergroup($admintalk, 'group:group co');
    $self->assert_not_null($usergroups->{'group:group co'});
    $self->assert_not_null($usergroups->{'group:group co'}->{'cassandane'});
    $self->assert_not_null($usergroups->{'group:group co'}->{'otheruser'});
    $self->assert_null($usergroups->{'group:group co'}->{'nobody'});
}

sub test_admin_setusergroup
{
    my ($self) = @_;

    my $admintalk = $self->{adminstore}->get_client();

    # should have the xusergroups capability
    $self->assert_not_null($admintalk->capability()->{xusergroups});

    # get a user's groups
    my $usergroups = $self->imap_getusergroup($admintalk, 'cassandane');
    $self->assert_not_null($usergroups->{'cassandane'});
    $self->assert_not_null($usergroups->{'cassandane'}->{'group:group c'});
    $self->assert_not_null($usergroups->{'cassandane'}->{'group:group co'});
    $self->assert_null($usergroups->{'cassandane'}->{'group:group o'});
    $self->assert_null($usergroups->{'cassandane'}->{'group:new group'});

    # set membership in a new group
    $admintalk->_imap_cmd('SETUSERGROUP', 0, '',
                          'cassandane', 'group:new group');
    $self->assert_str_equals('ok', $admintalk->get_last_completion_response());

    # get the groups again, should be in new group now
    $usergroups = $self->imap_getusergroup($admintalk, 'cassandane');
    $self->assert_not_null($usergroups->{'cassandane'});
    $self->assert_not_null($usergroups->{'cassandane'}->{'group:group c'});
    $self->assert_not_null($usergroups->{'cassandane'}->{'group:group co'});
    $self->assert_null($usergroups->{'cassandane'}->{'group:group o'});
    $self->assert_not_null($usergroups->{'cassandane'}->{'group:new group'});

    # get the new group's membership, should contain (only) the user
    $usergroups = $self->imap_getusergroup($admintalk, 'group:new group');
    $self->assert_not_null($usergroups->{'group:new group'});
    $self->assert_not_null($usergroups->{'group:new group'}->{'cassandane'});
    $self->assert_equals(1, scalar keys %{$usergroups->{'group:new group'}});
}

sub test_admin_unsetusergroup
{
    my ($self) = @_;

    my $admintalk = $self->{adminstore}->get_client();

    # should have the xusergroups capability
    $self->assert_not_null($admintalk->capability()->{xusergroups});

    # get a user's groups
    my $usergroups = $self->imap_getusergroup($admintalk, 'cassandane');
    $self->assert_not_null($usergroups->{'cassandane'});
    $self->assert_not_null($usergroups->{'cassandane'}->{'group:group c'});
    $self->assert_not_null($usergroups->{'cassandane'}->{'group:group co'});
    $self->assert_null($usergroups->{'cassandane'}->{'group:group o'});
    $self->assert_null($usergroups->{'cassandane'}->{'group:new group'});

    # remove membership from a group
    $admintalk->_imap_cmd('UNSETUSERGROUP', 0, '',
                          'cassandane', 'group:group c');
    $self->assert_str_equals('ok', $admintalk->get_last_completion_response());

    # get the groups again, shouldn't be in the group anymore
    $usergroups = $self->imap_getusergroup($admintalk, 'cassandane');
    $self->assert_not_null($usergroups->{'cassandane'});
    $self->assert_null($usergroups->{'cassandane'}->{'group:group c'});
    $self->assert_not_null($usergroups->{'cassandane'}->{'group:group co'});
    $self->assert_null($usergroups->{'cassandane'}->{'group:group o'});

    # get the group's membership, shouldn't contain the user
    $usergroups = $self->imap_getusergroup($admintalk, 'group:group c');
    $self->assert_not_null($usergroups->{'group:group c'});
    $self->assert_null($usergroups->{'group:group c'}->{'cassandane'});
}

1;
