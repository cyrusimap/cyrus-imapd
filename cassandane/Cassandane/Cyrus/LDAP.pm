# SPDX-License-Identifier: BSD-3-Clause-CMU
# See COPYING file at the root of the distribution for more details.

# XXX Most of these tests are tagged with :min_version_3_0_8, as
# XXX the architecture used for testing LDAP depends on the fix
# XXX for https://github.com/cyrusimap/cyrus-imapd/issues/2282

package Cassandane::Cyrus::LDAP;
use strict;
use warnings;
use Cwd qw(realpath);
use Data::Dumper;

use base qw(Cassandane::Cyrus::TestCase);
use Cassandane::Util::Log;

sub new
{
    my ($class, @args) = @_;

    my $config = Cassandane::Config->default()->clone();
    $config->set(
        ldap_base => "o=cyrus",
        ldap_group_base => "ou=groups,o=cyrus",
        ldap_domain_base_dn => "ou=domains,o=cyrus",
        ldap_user_attribute => "uid",
        ldap_member_attribute => "memberof",
        ldap_group_hasmember_attribute => "hasmember",
        ldap_sasl => "no",
        auth_mech => 'pts',
        pts_module => 'ldap',
        ptloader_sock => '@basedir@/conf/ptsock',
    );

    my $self = $class->SUPER::new({
        config => $config,
        adminstore => 1,
        services => [qw( imap ptloader )],
        start_instances => 0,
    }, @args);

    $self->needs('dependency', 'ldap');
    return $self;
}

sub set_up
{
    my ($self) = @_;

    $self->SUPER::set_up();

    $self->{ldapport} = Cassandane::PortManager::alloc("localhost");

    $self->{instance}->{config}->set(
        ldap_uri => "ldap://localhost:$self->{ldapport}/",
    );

    # arrange for the fakeldapd to be started
    my ($maj, $min) = Cassandane::Instance->get_version($self->{installation});
    if ($maj < 3 || ($maj == 3 && $min < 4)) {
        $self->{instance}->add_start(
            name => 'fakeldapd',
            argv => [
                realpath('utils/fakeldapd'),
                '-p', $self->{ldapport},
                '-l', realpath('data/directory.ldif'),
            ],
        );
    }
    elsif (not exists $self->{daemons}->{fakeldapd}) {
        $self->{instance}->add_daemon(
            name => 'fakeldapd',
            argv => [
                realpath('utils/fakeldapd'),
                '-p', $self->{ldapport},
                '-l', realpath('data/directory.ldif'),
            ],
            wait => 'y',
        );
    }

    $self->_start_instances();
    $self->{instance}->create_user("otheruser");
}

sub tear_down
{
    my ($self) = @_;

    $self->SUPER::tear_down();
}

sub test_alternate_ptscache_db_path
    :min_version_3_0_8 :AltPTSDBPath
{
    my ($self) = @_;

    # just interact with the store, and it should work
    my $admintalk = $self->{adminstore}->get_client();

    $admintalk->list('user.cassandane', '*');
    $self->assert_str_equals('ok',
        $admintalk->get_last_completion_response());

    my $confdir = $self->{instance}->{basedir} . "/conf";
    $self->assert_file_test($confdir . "/non-default-ptscache.db");
    $self->assert_not_file_test($confdir . "/ptclient/ptscache.db");
}

sub test_setacl_groupid
    :min_version_3_0_8
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
    :min_version_3_0_8
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
    :min_version_3_0_8 :NoAltNamespace
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
    :ReverseACLs :min_version_3_1 :NoAltNamespace :Conversations
{
    my ($self) = @_;

    my $admintalk = $self->{adminstore}->get_client();
    my $imaptalk = $self->{store}->get_client();

    $admintalk->create("user.otheruser.groupaccess");
    $self->assert_str_equals('ok',
        $admintalk->get_last_completion_response());

    my $precounters = $self->{store}->get_counters();

    $admintalk->setacl("user.otheruser.groupaccess",
                       "group:group co", "lrswipkxtecdn");
    $self->assert_str_equals('ok',
        $admintalk->get_last_completion_response());

    my $postcounters = $self->{store}->get_counters();
    $self->assert_num_not_equals($precounters->{raclmodseq}, $postcounters->{raclmodseq}, "RACL modseq changed");

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
    :min_version_3_0_8 :NoAltNamespace
{
    my $self = shift;
    return $self->do_test_list_order(@_);
}

sub test_list_order_racl
    :ReverseACLs :min_version_3_1 :NoAltNamespace
{
    my $self = shift;
    return $self->do_test_list_order(@_);
}

1;
