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
use Cassandane::Util::Words;
use Cassandane::Instance;

$Data::Dumper::Sortkeys = 1;

sub new
{
    my $class = shift;
    return $class->SUPER::new({
        imapmurder => 1, adminstore => 1, deliver => 1,
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

sub test_aaasetup
    :needs_component_murder
{
    my ($self) = @_;

    # does everything set up and tear down cleanly?
    $self->assert(1);
}

sub test_frontend_commands
    :needs_component_murder
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
    :needs_component_murder
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
    :needs_component_murder
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
    :needs_component_murder
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
    :needs_component_murder
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
    :needs_component_murder :AllowMoves
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

sub test_xfer_nonexistent_unixhs
    :needs_component_murder :UnixHierarchySep
{
    my ($self) = @_;

    my $admintalk = $self->{backend1_adminstore}->get_client();
    my $backend2_servername = $self->{backend2}->get_servername();

    # xfer a user that doesn't exist
    $admintalk->_imap_cmd('xfer', 0, {},
                          'user/nonexistent', $backend2_servername);
    $self->assert_str_equals(
        'no', $admintalk->get_last_completion_response()
    );

    # xfer a mailbox that doesn't exist
    $admintalk->_imap_cmd('xfer', 0, {},
                          'user/cassandane/nonexistent', $backend2_servername);
    $self->assert_str_equals(
        'no', $admintalk->get_last_completion_response()
    );

    # xfer a pattern that doesn't match anything
    $admintalk->_imap_cmd('xfer', 0, {},
                          'user/cassandane/non%', $backend2_servername);
    $self->assert_str_equals(
        'no', $admintalk->get_last_completion_response()
    );

    # xfer a partition that doesn't exist
    $admintalk->_imap_cmd('xfer', 0, {},
                          'nonexistent', $backend2_servername);
    $self->assert_str_equals(
        'no', $admintalk->get_last_completion_response()
    );
}

sub test_xfer_user_altns_unixhs
    :AllowMoves :AltNamespace :UnixHierarchySep
    :needs_component_murder :min_version_3_2
{
    my ($self) = @_;

    # set up some data for cassandane on backend1
    my $expected = $self->populate_user($self->{instance},
                                        $self->{backend1_store},
                                        [qw(INBOX Drafts)]);

    my $imaptalk = $self->{backend1_store}->get_client();
    my $admintalk = $self->{backend1_adminstore}->get_client();
    my $backend2_servername = $self->{backend2}->get_servername();

    # what's the frontend mailboxes.db say before we move?
    my $mailboxes_db = $self->{frontend}->read_mailboxes_db();
    xlog "XXX before move, frontend mailboxes.db:" . Dumper $mailboxes_db;

    # what's imap LIST say before we move?
    # original backend:
    my $data = $imaptalk->list("", "*");
    $self->assert_mailbox_structure($data, '/', {
        'INBOX' => [qw( \\HasNoChildren )],
        'Drafts' => [qw( \\HasNoChildren \\Drafts )],
    });

    # frontend doesn't know about annotations
    my $frontendtalk = $self->{frontend_store}->get_client();
    $data = $frontendtalk->list("", "*");
    $self->assert_mailbox_structure($data, '/', {
        'INBOX' => [qw( \\HasNoChildren )],
        'Drafts' => [qw( \\HasNoChildren )],
    });

    # ... but if we ask for them it'll proxy the request and find them
    $data = $frontendtalk->list("", "*", 'RETURN', [ 'SPECIAL-USE' ]);
    $self->assert_mailbox_structure($data, '/', {
        'INBOX' => [qw( \\HasNoChildren )],
        'Drafts' => [qw( \\HasNoChildren \\Drafts )],
    });

    # now xfer the cassandane user to backend2
    my $ret = $admintalk->_imap_cmd('xfer', 0, {},
                                    'user/cassandane', $backend2_servername);
    xlog "XXX xfer returned: " . Dumper $ret;
    # XXX 3.2+ with 3.0 target fails here: syntax error in parameters
    $self->assert_str_equals('ok', $ret);
    # XXX 3.2+ with 2.5 target fails here: mailbox has an invalid format
    $self->assert_str_equals(
        'ok', $admintalk->get_last_completion_response()
    );

    # account contents should be on the other store now
    $self->check_user($self->{backend2}, $self->{backend2_store}, $expected);

    # frontend should now say the user is on the other store
    # XXX is there a better way to discover this?
    $mailboxes_db = $self->{frontend}->read_mailboxes_db();
    xlog "XXX after move, frontend mailboxes.db: " . Dumper $mailboxes_db;
    # XXX 3.0 with 2.5 frontend fails here: server field is blank
    $self->assert_str_equals(
        $backend2_servername,
        $mailboxes_db->{'user.cassandane'}->{server}
    );
    $self->assert_str_equals(
        $backend2_servername,
        $mailboxes_db->{'user.cassandane.Drafts'}->{server}
    );

    # what's imap LIST say after the move?
    undef $imaptalk;
    $self->{store}->disconnect();
    $imaptalk = $self->{store}->get_client();
    xlog "checking LIST on old backend";
    $data = $imaptalk->list("", "*");
    $self->assert_mailbox_structure($data, '/', {});

    my $backend2talk = $self->{backend2_store}->get_client();
    xlog "checking LIST on new backend";
    $data = $backend2talk->list("", "*");
    $self->assert_mailbox_structure($data, '/', {
        'INBOX' => [qw( \\HasNoChildren )],
        'Drafts' => [qw( \\HasNoChildren \\Drafts )],
    });

    # frontend doesn't know about annotations
    $frontendtalk = $self->{frontend_store}->get_client();
    xlog "checking LIST on frontend";
    $data = $frontendtalk->list("", "*");
    $self->assert_mailbox_structure($data, '/', {
        'INBOX' => [qw( \\HasNoChildren )],
        'Drafts' => [qw( \\HasNoChildren )],
    });

    # ... but if we ask for them it'll proxy the request and find them
    $data = $frontendtalk->list("", "*", 'RETURN', [ 'SPECIAL-USE' ]);
    $self->assert_mailbox_structure($data, '/', {
        'INBOX' => [qw( \\HasNoChildren )],
        'Drafts' => [qw( \\HasNoChildren \\Drafts )],
    });
}

sub test_xfer_user_noaltns_nounixhs
    :AllowMoves :NoAltNamespace
    :needs_component_murder :min_version_3_2
{
    my ($self) = @_;

    # set up some data for cassandane on backend1
    my $expected = $self->populate_user($self->{instance},
                                        $self->{backend1_store},
                                        [qw(INBOX INBOX.Drafts)]);

    my $imaptalk = $self->{backend1_store}->get_client();
    my $admintalk = $self->{backend1_adminstore}->get_client();
    my $backend2_servername = $self->{backend2}->get_servername();

    # what's the frontend mailboxes.db say before we move?
    my $mailboxes_db = $self->{frontend}->read_mailboxes_db();
    xlog "XXX before move, frontend mailboxes.db:" . Dumper $mailboxes_db;

    # what's imap LIST say before we move?
    # original backend:
    my $data = $imaptalk->list("", "*");
    $self->assert_mailbox_structure($data, '.', {
        'INBOX' => [qw( \\HasChildren )],
        'INBOX.Drafts' => [qw( \\HasNoChildren \\Drafts )],
    });

    # frontend doesn't know about annotations
    my $frontendtalk = $self->{frontend_store}->get_client();
    $data = $frontendtalk->list("", "*");
    $self->assert_mailbox_structure($data, '.', {
        'INBOX' => [qw( \\HasChildren )],
        'INBOX.Drafts' => [qw( \\HasNoChildren )],
    });

    # ... but if we ask for them it'll proxy the request and find them
    $data = $frontendtalk->list("", "*", 'RETURN', [ 'SPECIAL-USE' ]);
    $self->assert_mailbox_structure($data, '.', {
        'INBOX' => [qw( \\HasChildren )],
        'INBOX.Drafts' => [qw( \\HasNoChildren \\Drafts )],
    });

    # now xfer the cassandane user to backend2
    my $ret = $admintalk->_imap_cmd('xfer', 0, {},
                                    'user.cassandane', $backend2_servername);
    xlog "XXX xfer returned: " . Dumper $ret;
    # XXX 3.2+ with 3.0 target fails here: syntax error in parameters
    $self->assert_str_equals('ok', $ret);
    # XXX 3.2+ with 2.5 target fails here: mailbox has an invalid format
    $self->assert_str_equals(
        'ok', $admintalk->get_last_completion_response()
    );

    # account contents should be on the other store now
    $self->check_user($self->{backend2}, $self->{backend2_store}, $expected);

    # frontend should now say the user is on the other store
    # XXX is there a better way to discover this?
    $mailboxes_db = $self->{frontend}->read_mailboxes_db();
    xlog "XXX after move, frontend mailboxes.db: " . Dumper $mailboxes_db;
    # XXX 3.0 with 2.5 frontend fails here: server field is blank
    $self->assert_str_equals(
        $backend2_servername,
        $mailboxes_db->{'user.cassandane'}->{server}
    );
    $self->assert_str_equals(
        $backend2_servername,
        $mailboxes_db->{'user.cassandane.Drafts'}->{server}
    );

    # what's imap LIST say after the move?
    undef $imaptalk;
    $self->{store}->disconnect();
    $imaptalk = $self->{store}->get_client();
    xlog "checking LIST on old backend";
    $data = $imaptalk->list("", "*");
    $self->assert_mailbox_structure($data, '.', {});

    my $backend2talk = $self->{backend2_store}->get_client();
    xlog "checking LIST on new backend";
    $data = $backend2talk->list("", "*");
    $self->assert_mailbox_structure($data, '.', {
        'INBOX' => [qw( \\HasChildren )],
        'INBOX.Drafts' => [qw( \\HasNoChildren \\Drafts )],
    });

    # frontend doesn't know about annotations
    $frontendtalk = $self->{frontend_store}->get_client();
    xlog "checking LIST on frontend";
    $data = $frontendtalk->list("", "*");
    $self->assert_mailbox_structure($data, '.', {
        'INBOX' => [qw( \\HasChildren )],
        'INBOX.Drafts' => [qw( \\HasNoChildren )],
    });

    # ... but if we ask for them it'll proxy the request and find them
    $data = $frontendtalk->list("", "*", 'RETURN', [ 'SPECIAL-USE' ]);
    $self->assert_mailbox_structure($data, '.', {
        'INBOX' => [qw( \\HasChildren )],
        'INBOX.Drafts' => [qw( \\HasNoChildren \\Drafts )],
    });
}

sub test_xfer_user_altns_unixhs_virtdom
    :AllowMoves :AltNamespace :UnixHierarchySep :VirtDomains
    :needs_component_murder :min_version_3_2
{
    my ($self) = @_;

    # set up a user with a domain
    my $admintalk = $self->{backend1_adminstore}->get_client();
    $admintalk->create('user/foo@example.com');
    $self->assert_str_equals('ok',
                             $admintalk->get_last_completion_response());

    my $frontend_store = $self->{frontend}->get_service('imap')->create_store(
        username => 'foo@example.com');
    my $backend1_store = $self->{instance}->get_service('imap')->create_store(
        username => 'foo@example.com');
    my $backend2_store = $self->{backend2}->get_service('imap')->create_store(
        username => 'foo@example.com');

    # set up some data for cassandane on backend1
    my $expected = $self->populate_user($self->{instance},
                                        $backend1_store,
                                        [qw(INBOX Drafts)]);

    my $imaptalk = $backend1_store->get_client();
    my $backend2_servername = $self->{backend2}->get_servername();

    # what's the frontend mailboxes.db say before we move?
    my $mailboxes_db = $self->{frontend}->read_mailboxes_db();
    xlog "XXX before move, frontend mailboxes.db:" . Dumper $mailboxes_db;

    # what's imap LIST say before we move?
    # original backend:
    my $data = $imaptalk->list("", "*");
    $self->assert_mailbox_structure($data, '/', {
        'INBOX' => [qw( \\HasNoChildren )],
        'Drafts' => [qw( \\HasNoChildren \\Drafts )],
    });

    # frontend doesn't know about annotations
    my $frontendtalk = $frontend_store->get_client();
    $data = $frontendtalk->list("", "*");
    $self->assert_mailbox_structure($data, '/', {
        'INBOX' => [qw( \\HasNoChildren )],
        'Drafts' => [qw( \\HasNoChildren )],
    });

    # ... but if we ask for them it'll proxy the request and find them
    $data = $frontendtalk->list("", "*", 'RETURN', [ 'SPECIAL-USE' ]);
    $self->assert_mailbox_structure($data, '/', {
        'INBOX' => [qw( \\HasNoChildren )],
        'Drafts' => [qw( \\HasNoChildren \\Drafts )],
    });

    # now xfer the cassandane user to backend2
    my $ret = $admintalk->_imap_cmd('xfer', 0, {},
                                    'user/foo@example.com',
                                    $backend2_servername);
    xlog "XXX xfer returned: " . Dumper $ret;
    # XXX 3.2+ with 3.0 target fails here: syntax error in parameters
    $self->assert_str_equals('ok', $ret);
    # XXX 3.2+ with 2.5 target fails here: mailbox has an invalid format
    $self->assert_str_equals(
        'ok', $admintalk->get_last_completion_response()
    );

    # account contents should be on the other store now
    $self->check_user($self->{backend2}, $backend2_store, $expected);

    # frontend should now say the user is on the other store
    # XXX is there a better way to discover this?
    $mailboxes_db = $self->{frontend}->read_mailboxes_db();
    xlog "XXX after move, frontend mailboxes.db: " . Dumper $mailboxes_db;
    # XXX 3.0 with 2.5 frontend fails here: server field is blank
    $self->assert_str_equals(
        $backend2_servername,
        $mailboxes_db->{'example.com!user.foo'}->{server}
    );
    $self->assert_str_equals(
        $backend2_servername,
        $mailboxes_db->{'example.com!user.foo.Drafts'}->{server}
    );

    # what's imap LIST say after the move?
    undef $imaptalk;
    $backend1_store->disconnect();
    $imaptalk = $backend1_store->get_client();
    xlog "checking LIST on old backend";
    $data = $imaptalk->list("", "*");
    $self->assert_mailbox_structure($data, '/', {});

    my $backend2talk = $backend2_store->get_client();
    xlog "checking LIST on new backend";
    $data = $backend2talk->list("", "*");
    $self->assert_mailbox_structure($data, '/', {
        'INBOX' => [qw( \\HasNoChildren )],
        'Drafts' => [qw( \\HasNoChildren \\Drafts )],
    });

    # frontend doesn't know about annotations
    $frontendtalk = $frontend_store->get_client();
    xlog "checking LIST on frontend";
    $data = $frontendtalk->list("", "*");
    $self->assert_mailbox_structure($data, '/', {
        'INBOX' => [qw( \\HasNoChildren )],
        'Drafts' => [qw( \\HasNoChildren )],
    });

    # ... but if we ask for them it'll proxy the request and find them
    $data = $frontendtalk->list("", "*", 'RETURN', [ 'SPECIAL-USE' ]);
    $self->assert_mailbox_structure($data, '/', {
        'INBOX' => [qw( \\HasNoChildren )],
        'Drafts' => [qw( \\HasNoChildren \\Drafts )],
    });
}

sub test_xfer_user_noaltns_nounixhs_virtdom
    :AllowMoves :NoAltNamespace :VirtDomains
    :needs_component_murder :min_version_3_2
{
    my ($self) = @_;

    # set up a user with a domain
    my $admintalk = $self->{backend1_adminstore}->get_client();
    $admintalk->create('user.foo@example.com');
    $self->assert_str_equals('ok',
                             $admintalk->get_last_completion_response());

    my $frontend_store = $self->{frontend}->get_service('imap')->create_store(
        username => 'foo@example.com');
    my $backend1_store = $self->{instance}->get_service('imap')->create_store(
        username => 'foo@example.com');
    my $backend2_store = $self->{backend2}->get_service('imap')->create_store(
        username => 'foo@example.com');

    # set up some data for cassandane on backend1
    my $expected = $self->populate_user($self->{instance},
                                        $backend1_store,
                                        [qw(INBOX INBOX.Drafts)]);

    my $imaptalk = $backend1_store->get_client();
    my $backend2_servername = $self->{backend2}->get_servername();

    # what's the frontend mailboxes.db say before we move?
    my $mailboxes_db = $self->{frontend}->read_mailboxes_db();
    xlog "XXX before move, frontend mailboxes.db:" . Dumper $mailboxes_db;

    # what's imap LIST say before we move?
    # original backend:
    my $data = $imaptalk->list("", "*");
    $self->assert_mailbox_structure($data, '.', {
        'INBOX' => [qw( \\HasChildren )],
        'INBOX.Drafts' => [qw( \\HasNoChildren \\Drafts )],
    });

    # frontend doesn't know about annotations
    my $frontendtalk = $frontend_store->get_client();
    $data = $frontendtalk->list("", "*");
    $self->assert_mailbox_structure($data, '.', {
        'INBOX' => [qw( \\HasChildren )],
        'INBOX.Drafts' => [qw( \\HasNoChildren )],
    });

    # ... but if we ask for them it'll proxy the request and find them
    $data = $frontendtalk->list("", "*", 'RETURN', [ 'SPECIAL-USE' ]);
    $self->assert_mailbox_structure($data, '.', {
        'INBOX' => [qw( \\HasChildren )],
        'INBOX.Drafts' => [qw( \\HasNoChildren \\Drafts )],
    });

    # now xfer the cassandane user to backend2
    my $ret = $admintalk->_imap_cmd('xfer', 0, {},
                                    'user.foo@example.com',
                                    $backend2_servername);
    xlog "XXX xfer returned: " . Dumper $ret;
    # XXX 3.2+ with 3.0 target fails here: syntax error in parameters
    $self->assert_str_equals('ok', $ret);
    # XXX 3.2+ with 2.5 target fails here: mailbox has an invalid format
    $self->assert_str_equals(
        'ok', $admintalk->get_last_completion_response()
    );

    # account contents should be on the other store now
    $self->check_user($self->{backend2}, $backend2_store, $expected);

    # frontend should now say the user is on the other store
    # XXX is there a better way to discover this?
    $mailboxes_db = $self->{frontend}->read_mailboxes_db();
    xlog "XXX after move, frontend mailboxes.db: " . Dumper $mailboxes_db;
    # XXX 3.0 with 2.5 frontend fails here: server field is blank
    $self->assert_str_equals(
        $backend2_servername,
        $mailboxes_db->{'example.com!user.foo'}->{server}
    );
    $self->assert_str_equals(
        $backend2_servername,
        $mailboxes_db->{'example.com!user.foo.Drafts'}->{server}
    );

    # what's imap LIST say after the move?
    undef $imaptalk;
    $backend1_store->disconnect();
    $imaptalk = $backend1_store->get_client();
    xlog "checking LIST on old backend";
    $data = $imaptalk->list("", "*");
    $self->assert_mailbox_structure($data, '.', {});

    my $backend2talk = $backend2_store->get_client();
    xlog "checking LIST on new backend";
    $data = $backend2talk->list("", "*");
    $self->assert_mailbox_structure($data, '.', {
        'INBOX' => [qw( \\HasChildren )],
        'INBOX.Drafts' => [qw( \\HasNoChildren \\Drafts )],
    });

    # frontend doesn't know about annotations
    $frontendtalk = $frontend_store->get_client();
    xlog "checking LIST on frontend";
    $data = $frontendtalk->list("", "*");
    $self->assert_mailbox_structure($data, '.', {
        'INBOX' => [qw( \\HasChildren )],
        'INBOX.Drafts' => [qw( \\HasNoChildren )],
    });

    # ... but if we ask for them it'll proxy the request and find them
    $data = $frontendtalk->list("", "*", 'RETURN', [ 'SPECIAL-USE' ]);
    $self->assert_mailbox_structure($data, '.', {
        'INBOX' => [qw( \\HasChildren )],
        'INBOX.Drafts' => [qw( \\HasNoChildren \\Drafts )],
    });
}

sub test_xfer_mailbox_altns_unixhs
    :AllowMoves :AltNamespace :UnixHierarchySep
    :needs_component_murder :min_version_3_2 :max_version_3_4
{
    my ($self) = @_;

    # what we expect from this test will depend on the cyrus version being
    # run on backend2
    my $backend2_permits_single_mailbox = 1;
    my ($maj, $min) = Cassandane::Instance->get_version('murder');
    if ($maj > 3 || ($maj == 3 && $min >= 5)) {
        $backend2_permits_single_mailbox = 0;
    }

    # set up some data for cassandane on backend1
    my $expected_stay = $self->populate_user(
        $self->{instance},
        $self->{backend1_store},
        [qw(INBOX Big Big/Red Big/Red/Dog)]
    );

    # we're planning to only XFER "Big/Red" (but not the others!)
    my $expected_move->{mailboxes}->{'Big/Red'}
        = $expected_stay->{mailboxes}->{'Big/Red'};
    delete $expected_stay->{mailboxes}->{'Big/Red'};

    my $imaptalk = $self->{backend1_store}->get_client();
    my $admintalk = $self->{backend1_adminstore}->get_client();
    my $backend1_servername = $self->{instance}->get_servername();
    my $backend2_servername = $self->{backend2}->get_servername();

    # what's the frontend mailboxes.db say before we move?
    my $mailboxes_db = $self->{frontend}->read_mailboxes_db();
    xlog "XXX before move, frontend mailboxes.db:" . Dumper $mailboxes_db;

    # what's imap LIST say before we move?
    # original backend:
    my $data = $imaptalk->list("", "*");
    $self->assert_mailbox_structure($data, '/', {
        'INBOX' => [qw( \\HasNoChildren )],
        'Big' => [qw( \\HasChildren )],
        'Big/Red' => [qw( \\HasChildren )],
        'Big/Red/Dog' => [qw( \\HasNoChildren )],
    });

    my $frontendtalk = $self->{frontend_store}->get_client();
    $data = $frontendtalk->list("", "*");
    $self->assert_mailbox_structure($data, '/', {
        'INBOX' => [qw( \\HasNoChildren )],
        'Big' => [qw( \\HasChildren )],
        'Big/Red' => [qw( \\HasChildren )],
        'Big/Red/Dog' => [qw( \\HasNoChildren )],
    });

    # now xfer the BigRed folder (only) to backend2
    my $ret = $admintalk->_imap_cmd('xfer', 0, {},
                                    'user/cassandane/Big/Red',
                                    $backend2_servername);

    # 3.5+ won't permit receiving just one mid-tree mailbox
    if (not $backend2_permits_single_mailbox) {
        $self->assert_str_equals(
            'no', $admintalk->get_last_completion_response()
        );
        return; # nothing more to test here!
    }

    $self->assert_str_equals('ok', $ret);
    $self->assert_str_equals(
        'ok', $admintalk->get_last_completion_response()
    );

    # most of the account should have remained on the original backend
    $self->check_user($self->{instance},
                      $self->{backend1_store},
                      $expected_stay);
    # but Big/Red should have been moved
    $self->check_user($self->{backend2},
                      $self->{backend2_store},
                      $expected_move);

    # frontend should now say the new mailbox locations
    # XXX is there a better way to discover this?
    $mailboxes_db = $self->{frontend}->read_mailboxes_db();
    xlog "XXX after move, frontend mailboxes.db: " . Dumper $mailboxes_db;
    # XXX 3.0 with 2.5 frontend fails here: server field is blank
    $self->assert_str_equals(
        $backend1_servername,
        $mailboxes_db->{'user.cassandane'}->{server}
    );
    $self->assert_str_equals(
        $backend1_servername,
        $mailboxes_db->{'user.cassandane.Big'}->{server}
    );
    $self->assert_str_equals(
        $backend2_servername,
        $mailboxes_db->{'user.cassandane.Big.Red'}->{server}
    );
    $self->assert_str_equals(
        $backend1_servername,
        $mailboxes_db->{'user.cassandane.Big.Red.Dog'}->{server}
    );

    # what's imap LIST say after the move?
    undef $imaptalk;
    $self->{store}->disconnect();
    $imaptalk = $self->{store}->get_client();
    xlog "checking LIST on old backend";
    $data = $imaptalk->list("", "*");
    $self->assert_mailbox_structure($data, '/', {
        'INBOX' => [qw( \\HasNoChildren )],
        'Big' => [qw( \\HasChildren )],
        'Big/Red/Dog' => [qw( \\HasNoChildren )],
    });

    my $backend2talk = $self->{backend2_store}->get_client();
    xlog "checking LIST on new backend";
    $data = $backend2talk->list("", "*");
    $self->assert_mailbox_structure($data, '/', {
        'Big/Red' => [qw( \\HasNoChildren )],
    });

    $frontendtalk = $self->{frontend_store}->get_client();
    xlog "checking LIST on frontend";
    $data = $frontendtalk->list("", "*");
    $self->assert_mailbox_structure($data, '/', {
        'INBOX' => [qw( \\HasNoChildren )],
        'Big' => [qw( \\HasChildren )],
        'Big/Red' => [qw( \\HasChildren )],
        'Big/Red/Dog' => [qw( \\HasNoChildren )],
    });
}

sub test_xfer_no_user_intermediates
    :AllowMoves :AltNamespace :UnixHierarchySep
    :needs_component_murder :min_version_3_5
{
    my ($self) = @_;

    # set up some data for cassandane on backend1
    my $expected = $self->populate_user(
        $self->{instance},
        $self->{backend1_store},
        [qw(INBOX Big Big/Red Big/Red/Dog)]
    );

    my $admintalk = $self->{backend1_adminstore}->get_client();
    my $backend2_servername = $self->{backend2}->get_servername();

    # what's the frontend mailboxes.db say before we move?
    my $mailboxes_db = $self->{frontend}->read_mailboxes_db();
    xlog "XXX before move, frontend mailboxes.db:" . Dumper $mailboxes_db;

    # try to xfer individual non-INBOX mailboxes, all should be refused
    foreach my $folder (qw(Big Big/Red Big/Red/Dog)) {
        $admintalk->_imap_cmd('xfer', 0, {},
                              "user/cassandane/$folder",
                              $backend2_servername);
        $self->assert_str_equals(
            'no', $admintalk->get_last_completion_response()
        );
        $self->assert_matches(
            qr{Operation is not supported on mailbox},
            $admintalk->get_last_error()
        );
    }

    # everything should still be on the original backend
    $self->check_user($self->{instance}, $self->{backend1_store}, $expected);
}

# XXX test_xfer_partition
# XXX test_xfer_mboxpattern
# XXX shared mailboxes!

1;
