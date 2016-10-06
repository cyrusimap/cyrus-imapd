#!/usr/bin/perl
#
#  Copyright (c) 2016 FastMail Pty. Ltd.  All rights reserved.
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
#  3. The name "FastMail" must not be used to
#     endorse or promote products derived from this software without
#     prior written permission. For permission or any legal
#     details, please contact
#         FastMail Pty. Ltd.
#         Level 1, 91 William St
#         Melbourne 3000
#         Victoria
#         Australia
#
#  4. Redistributions of any form whatsoever must retain the following
#     acknowledgment:
#     "This product includes software developed by FastMail Pty. Ltd."
#
#  FASTMAIL PTY LTD DISCLAIMS ALL WARRANTIES WITH REGARD TO
#  THIS SOFTWARE, INCLUDING ALL IMPLIED WARRANTIES OF MERCHANTABILITY
#  AND FITNESS, IN NO EVENT SHALL OPERA SOFTWARE AUSTRALIA BE LIABLE
#  FOR ANY SPECIAL, INDIRECT OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES
#  WHATSOEVER RESULTING FROM LOSS OF USE, DATA OR PROFITS, WHETHER IN
#  AN ACTION OF CONTRACT, NEGLIGENCE OR OTHER TORTIOUS ACTION, ARISING
#  OUT OF OR IN CONNECTION WITH THE USE OR PERFORMANCE OF THIS SOFTWARE.
#

package Cassandane::Cyrus::Murder;
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
    return $class->SUPER::new({ murder => 1 }, @_);
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
    $self->assert_matches(qr/Mailbox does not exist/i, $frontend->get_last_error());

    # create should be proxied through
    $result = $frontend->create('INBOX.newfolder');
    $self->assert_not_null($result);

    # should be able to select it now
    $result = $frontend->select('INBOX.newfolder');
    $self->assert_not_null($result);

    # XXX test other commands
}

sub test_list_specialuse
{
    my ($self) = @_;

    my $frontend = $self->{frontend_store}->get_client();
    my $backend = $self->{backend_store}->get_client();

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
    xlog Dumper $bresult;

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
    xlog Dumper $fresult;

    # expect the same results as on backend
    $self->assert_deep_equals($bresult, $fresult);
}

1;
