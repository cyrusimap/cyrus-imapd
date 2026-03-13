#!/usr/bin/perl

package Cassandane::Cyrus::UnixGroups;
use strict;
use warnings;

use base qw(Cassandane::Cyrus::TestCase);
use base qw(Cassandane::Unit::TestCase);
use Cassandane::Util::Log;

sub new
{
    my ($class, @args) = @_;

    my $config = Cassandane::Config->default()->clone();
    $config->set(
        auth_mech => 'unix',
        auth_unix_group_enable => 'yes',
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

    my $userid = 'cassandane';
    my @member_groups;
    my %seen;

    my @pw = getpwnam($userid);
    if (@pw) {
        my $primary_gid = $pw[3];
        my $primary_group = getgrgid($primary_gid);
        if (defined $primary_group) {
            push @member_groups, $primary_group;
            $seen{$primary_group} = 1;
        }
    }

    setgrent();
    while (my ($name, $passwd, $gid, $members) = getgrent()) {
        my @members = split(/\s+/, $members || '');
        next unless grep { $_ eq $userid } @members;
        next if $seen{$name};
        push @member_groups, $name;
        $seen{$name} = 1;
    }
    endgrent();

    my $nonmember_group;
    setgrent();
    while (my ($name, $passwd, $gid, $members) = getgrent()) {
        my @members = split(/\s+/, $members || '');
        next if grep { $_ eq $userid } @members;
        next if $seen{$name};
        $nonmember_group = $name;
        last;
    }
    endgrent();

    $self->{unix_member_groups} = \@member_groups;
    $self->{unix_nonmember_group} = $nonmember_group;
}

sub skip_check
{
    my ($self) = @_;

    if ($self->{_name} =~ /list_order_racl/) {
        return "requires at least two unix groups containing user 'cassandane'"
            if scalar(@{$self->{unix_member_groups} || []}) < 2;
        return "requires at least one unix group not containing user 'cassandane'"
            unless $self->{unix_nonmember_group};
    }

    if ($self->{_name} =~ /groupaccess/) {
        return "requires at least one unix group containing user 'cassandane'"
            if scalar(@{$self->{unix_member_groups} || []}) < 1;
    }

    return;
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

    my $group_c = 'group:' . $self->{unix_member_groups}[0];
    my $group_co = 'group:' . $self->{unix_member_groups}[1];
    my $group_o = 'group:' . $self->{unix_nonmember_group};

    my %adminfolders = (
        'user.otheruser.order-user' => 'cassandane',
        'user.otheruser.order-co' => $group_co,
        'user.otheruser.order-c' => $group_c,
        'user.otheruser.order-o' => $group_o,
        'shared.order-co' => $group_co,
        'shared.order-c' => $group_c,
        'shared.order-o' => $group_o,
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
    push @expect, qw(shared.order-c shared.order-co);
    $self->assert_deep_equals(\@boxes, \@expect);
}

use Cassandane::Tiny::Loader;

1;
