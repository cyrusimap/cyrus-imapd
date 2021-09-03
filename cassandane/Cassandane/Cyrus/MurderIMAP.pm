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

package Cassandane::Cyrus::MurderIMAP;
use strict;
use warnings;
use Data::Dumper;

use lib '.';
use base qw(Cassandane::Cyrus::TestCase);
use Cassandane::Util::Log;
use Cassandane::Instance;

$Data::Dumper::Sortkeys = 1;

sub new
{
    my $class = shift;
    return $class->SUPER::new({ imapmurder => 1, adminstore => 1 }, @_);
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

sub test_aaasetup
{
    my ($self) = @_;

    # does everything set up and tear down cleanly?
    $self->assert(1);
}

sub test_frontend_commands
{
    my ($self) = @_;
    my $result;

    my $frontend = $self->{frontend_store}->get_client();

    # should be able to list
    $result = $frontend->list("", "*");
    $self->assert_not_null($result);

    # select a folder that doesn't exist yet
    $result = $frontend->select('INBOX.newfolder');
    $self->assert_null($result);
    $self->assert_matches(qr/Mailbox does not exist/i,
                          $frontend->get_last_error());

    # create should be proxied through
    $result = $frontend->create('INBOX.newfolder');
    $self->assert_not_null($result);
    $self->assert_str_equals('ok', $frontend->get_last_completion_response());

    # should be able to select it now
    $result = $frontend->select('INBOX.newfolder');
    $self->assert_not_null($result);
    $self->assert_str_equals('ok', $frontend->get_last_completion_response());

    # should be able to getmetadata
    $result = $frontend->getmetadata('INBOX',
                                     '/shared/vendor/cmu/cyrus-imapd/size');
    $self->assert_not_null($result);
    $self->assert_str_equals('ok', $frontend->get_last_completion_response());
    $result = $frontend->getmetadata('(INBOX INBOX.newfolder)',
                                     '/shared/vendor/cmu/cyrus-imapd/size');
    $self->assert_not_null($result);
    $self->assert_str_equals('ok', $frontend->get_last_completion_response());

    # XXX test other commands
}

sub test_list_specialuse
{
    my ($self) = @_;

    my $frontend = $self->{frontend_store}->get_client();
    my $backend = $self->{backend1_store}->get_client();

    my %specialuse = map { $_ => 1 } qw( Drafts Junk Sent Trash );
    my %other = map { $_ => 1 } qw( lists personal timesheets );

    # create some special-use folders
    foreach my $f (keys %specialuse) {
        $frontend->create("INBOX.$f");
        $self->assert_str_equals('ok', $frontend->get_last_completion_response());

        $frontend->subscribe("INBOX.$f");
        $self->assert_str_equals('ok', $frontend->get_last_completion_response());

        $frontend->setmetadata("INBOX.$f",
                               '/private/specialuse', "\\$f");
        $self->assert_str_equals('ok', $frontend->get_last_completion_response());
    }

    # create some other non special-use folders (control group)
    foreach my $f (keys %other) {
        $frontend->create("INBOX.$f");
        $self->assert_str_equals('ok', $frontend->get_last_completion_response());

        $frontend->subscribe("INBOX.$f");
        $self->assert_str_equals('ok', $frontend->get_last_completion_response());
    }

    # ask the backend about them
    my $bresult = $backend->list([qw(SPECIAL-USE)], "", "*",
        'RETURN', [qw(SUBSCRIBED)]);
    $self->assert_str_equals('ok', $backend->get_last_completion_response());
    xlog $self, Dumper $bresult;

    # check the responses
    my %found;
    foreach my $r (@{$bresult}) {
        my ($flags, $sep, $name) = @{$r};
        # carve out the interesting part of the name
        $self->assert_matches(qr/^INBOX$sep/, $name);
        $name = substr($name, 6);
        $found{$name} = 1;
        # only want specialuse folders
        $self->assert(exists $specialuse{$name});
        # must be flagged with appropriate flag
        $self->assert_equals(1, scalar grep { $_ eq "\\$name" } @{$flags});
        # must be flagged with \subscribed
        $self->assert_equals(1, scalar grep { $_ eq '\\Subscribed' } @{$flags});
    }

    # make sure no expected responses were missing
    $self->assert_deep_equals(\%specialuse, \%found);

    # ask the frontend about them
    my $fresult = $frontend->list([qw(SPECIAL-USE)], "", "*",
        'RETURN', [qw(SUBSCRIBED)]);
    $self->assert_str_equals('ok', $frontend->get_last_completion_response());
    xlog $self, Dumper $fresult;

    # expect the same results as on backend
    $self->assert_deep_equals($bresult, $fresult);
}

sub test_xlist
{
    my ($self) = @_;

    my $frontend = $self->{frontend_store}->get_client();
    my $backend = $self->{backend1_store}->get_client();

    my %specialuse = map { $_ => 1 } qw( Drafts Junk Sent Trash );
    my %other = map { $_ => 1 } qw( lists personal timesheets );

    # create some special-use folders
    foreach my $f (keys %specialuse) {
        $frontend->create("INBOX.$f");
        $self->assert_str_equals('ok', $frontend->get_last_completion_response());

        $frontend->setmetadata("INBOX.$f",
                               '/private/specialuse', "\\$f");
        $self->assert_str_equals('ok', $frontend->get_last_completion_response());
    }

    # create some other non special-use folders (control group)
    foreach my $f (keys %other) {
        $frontend->create("INBOX.$f");
        $self->assert_str_equals('ok', $frontend->get_last_completion_response());
    }

    # ask the backend about them
    my $bresult = $backend->xlist("", "*");
    $self->assert_str_equals('ok', $backend->get_last_completion_response());
    xlog $self, "backend: " . Dumper $bresult;

    # check the responses
    my %found;
    foreach my $r (@{$bresult}) {
        my ($flags, $sep, $name) = @{$r};
        if ($name eq 'INBOX') {
            $found{$name} = 1;
            # must be flagged with \Inbox
            $self->assert_equals(1, scalar grep { $_ eq '\\Inbox' } @{$flags});
        }
        else {
            # carve out the interesting part of the name
            $self->assert_matches(qr/^INBOX$sep/, $name);
            $name = substr($name, 6);
            $found{$name} = 1;
            $self->assert(exists $specialuse{$name} or exists $other{$name});
            if (exists $specialuse{$name}) {
                # must be flagged with appropriate flag
                $self->assert_equals(1, scalar grep { $_ eq "\\$name" } @{$flags});
            }
            else {
                # must not be flagged with name-based flag
                $self->assert_equals(0, scalar grep { $_ eq "\\$name" } @{$flags});
            }
        }
    }

    # make sure no expected responses were missing
    $self->assert_deep_equals({ 'INBOX' => 1, %specialuse, %other }, \%found);

    # ask the frontend about them
    my $fresult = $frontend->xlist("", "*");
    $self->assert_str_equals('ok', $frontend->get_last_completion_response());
    xlog $self, "frontend: " . Dumper $fresult;

    # expect the same results as on backend
    $self->assert_deep_equals($bresult, $fresult);
}

sub test_move_to_backend_nonexistent
{
    my ($self) = @_;

    my $dest_folder = 'INBOX.dest';

    # put some messages into the INBOX
    my %exp;
    $exp{A} = $self->make_message("Message A", store => $self->{frontend_store});
    $exp{B} = $self->make_message("Message B", store => $self->{frontend_store});
    $exp{C} = $self->make_message("Message C", store => $self->{frontend_store});

    my $frontend = $self->{frontend_store}->get_client();
    my $backend = $self->{backend1_store}->get_client();

    # create a destination folder (on both frontend and backend)
    $frontend->create($dest_folder);
    $self->assert_str_equals('ok', $frontend->get_last_completion_response());

    # nuke the destination folder (on the backend only)
    $backend->localdelete($dest_folder);
    $self->assert_str_equals('ok', $backend->get_last_completion_response());

    my $f_folders = $frontend->list('', '*');
    $self->assert_deep_equals(
        [[[ '\\HasChildren' ], '.', 'INBOX' ],
         [[ '\\HasNoChildren' ], '.', 'INBOX.dest' ]],
        $f_folders);

    my $b_folders = $backend->list('', '*');
    $self->assert_deep_equals(
        [[[ '\\HasNoChildren' ], '.', 'INBOX' ]],
        $b_folders);

    # try to move a message to dest
    $frontend->move($exp{A}->get_attribute('uid'), $dest_folder);

    # it should fail nicely
    $self->assert_str_equals('no', $frontend->get_last_completion_response());
    $self->assert_matches(qr/Mailbox does not exist/, $frontend->get_last_error());

    # try to copy a message to dest
    $frontend->copy($exp{B}->get_attribute('uid'), $dest_folder);

    # it should fail nicely
    $self->assert_str_equals('no', $frontend->get_last_completion_response());
    $self->assert_matches(qr/Mailbox does not exist/, $frontend->get_last_error());
}

sub test_move_to_nonexistent
{
    my ($self) = @_;

    my $dest_folder = 'INBOX.nonexistent';

    # put some messages into the INBOX
    my %exp;
    $exp{A} = $self->make_message("Message A", store => $self->{frontend_store});
    $exp{B} = $self->make_message("Message B", store => $self->{frontend_store});
    $exp{C} = $self->make_message("Message C", store => $self->{frontend_store});

    my $frontend = $self->{frontend_store}->get_client();
    my $backend = $self->{backend1_store}->get_client();

    # make sure we don't unexpectedly have the nonexistent folder
    my $f_folders = $frontend->list('', '*');
    $self->assert_deep_equals(
        [[[ '\\HasNoChildren' ], '.', 'INBOX' ]],
        $f_folders);

    my $b_folders = $backend->list('', '*');
    $self->assert_deep_equals(
        [[[ '\\HasNoChildren' ], '.', 'INBOX' ]],
        $b_folders);

    # try to move a message to dest
    $frontend->move($exp{A}->get_attribute('uid'), $dest_folder);

    # it should fail nicely
    $self->assert_str_equals('no', $frontend->get_last_completion_response());
    $self->assert_matches(qr/Mailbox does not exist/, $frontend->get_last_error());

    # try to copy a message to dest
    $frontend->copy($exp{B}->get_attribute('uid'), $dest_folder);

    # it should fail nicely
    $self->assert_str_equals('no', $frontend->get_last_completion_response());
    $self->assert_matches(qr/Mailbox does not exist/, $frontend->get_last_error());
}

sub test_rename_with_location
    :AllowMoves
{
    my ($self) = @_;

    my $frontend_adminstore = $self->{frontend_adminstore}->get_client();

    my $backend2_servername = $self->{backend2}->get_servername();

    xlog $self, "backend2 servername: $backend2_servername";

    # not allowed to change mailbox name if location also specified
    $frontend_adminstore->rename('user.cassandane', 'user.foo', "$backend2_servername!");
    $self->assert_str_equals('no', $frontend_adminstore->get_last_completion_response());

    # but can change location if mailbox name remains the same
    $frontend_adminstore->rename('user.cassandane', 'user.cassandane', "$backend2_servername!");
    # XXX need to check for "* NO USER cassandane (some error)" untagged response
    $self->assert_str_equals('ok', $frontend_adminstore->get_last_completion_response());

    # verify that it moved
    my $backend1_store = $self->{backend1_store}->get_client();
    $backend1_store->select('INBOX');
    $self->assert_str_equals('no', $backend1_store->get_last_completion_response());

    my $backend2_store = $self->{backend2_store}->get_client();
    $backend2_store->select('INBOX');
    $self->assert_str_equals('ok', $backend2_store->get_last_completion_response());
}

1;
