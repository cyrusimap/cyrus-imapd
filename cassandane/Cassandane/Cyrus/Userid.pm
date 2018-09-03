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

package Cassandane::Cyrus::Userid;
use strict;
use warnings;

use lib '.';
use base qw(Cassandane::Cyrus::TestCase);
use Cassandane::Util::Log;

Cassandane::Cyrus::TestCase::magic(NoAutocreate => sub {
    shift->config_set('autocreate_users' => 'nobody');
});
Cassandane::Cyrus::TestCase::magic(PopUseACL => sub {
    shift->config_set('popuseacl' => 'yes');
});


sub new
{
    my $class = shift;
    return $class->SUPER::new({
        adminstore => 1,
        services => ['imap', 'pop3']
    }, @_);
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

# Tests userid with dots and unix hierarchy separator
sub test_dots_unix
    :UnixHierarchySep NoAutocreate PopUseACL
{
    my ($self) = @_;

    my $user = 'userid.with.dots';
    # We will also play a bit with the internal form of this userid
    (my $user_internal = $user) =~ s/\./^/g;

    # Create user per instance->create_user() - see builds 1170-1176
    $self->{instance}->create_user($user);

    # There should only be ACLs for (external) userid
    my $adminclient = $self->{adminstore}->get_client();
    my $mb = Cassandane::Mboxname->new(
            config => $self->{instance}->{config},
            userid => $user
        )->to_external();

    my %acls = $adminclient->getacl($mb);
    $self->assert(defined($acls{$user}));
    $self->assert(!defined($acls{$user_internal}));


    # User should be able to login and enter its INBOX
    my $store = $self->{instance}->get_service('imap')->create_store(username => $user);
    my $client = $store->get_client();
    $client->select('INBOX');
    $self->assert_str_equals('ok', $client->get_last_completion_response());
    $store->disconnect();

    # Same thing in POP
    $store = $self->{instance}->get_service('pop3')->create_store(username => $user);
    $client = $store->get_client();
    $store->disconnect();


    # Internal userid shall not be able to enter its INBOX
    $store = $self->{instance}->get_service('imap')->create_store(username => $user_internal);
    $client = $store->get_client();
    $client->select('INBOX');
    $self->assert_str_equals('no', $client->get_last_completion_response());
    $store->disconnect();

    # Same thing in POP
    $store = $self->{instance}->get_service('pop3')->create_store(username => $user_internal);
    {
        # shut up
        local $SIG{__DIE__};
        local $SIG{__WARN__} = sub { 1 };

        eval { $client = $store->get_client(); };
        my $Err = $@;
        $store->disconnect();
        $self->assert_matches(qr/Cannot login via POP3/, $Err);
    };


    # We should be able to set ACLs for internal userid
    $adminclient->setacl($mb, $user_internal => 'lrswipkxtecd')
        or die "Cannot setacl for $mb: $@";
    %acls = $adminclient->getacl($mb);
    $self->assert(defined($acls{$user_internal}));

    # XXX - In an ideal world, internal userid should still not be able to enter
    # its INBOX. However, since we set its rights, it will be able to access the
    # external userid mailbox: the '^' character is not forbidden, and since it
    # is converted to itself in internal form, the code is such that both
    # external and internal userid have the same mailbox name.


    # We should be able to delete ACLs for external/internal userid
    # But external one, as mailbox owner, should still keep some
    $adminclient->deleteacl($mb, $user)
        or die "Cannot deleteacl for $mb: $@";
    $adminclient->deleteacl($mb, $user_internal)
        or die "Cannot deleteacl for $mb: $@";
    %acls = $adminclient->getacl($mb);
    $self->assert(defined($acls{$user}));
    $self->assert(!defined($acls{$user_internal}));
}

1;
