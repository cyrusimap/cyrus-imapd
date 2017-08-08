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

package Cassandane::Cyrus::Delivery;
use strict;
use warnings;
use IO::File;

use lib '.';
use base qw(Cassandane::Cyrus::TestCase);
use Cassandane::Util::Log;

Cassandane::Cyrus::TestCase::magic(DuplicateSuppressionOff => sub {
    shift->config_set(duplicatesuppression => 0);
});
Cassandane::Cyrus::TestCase::magic(DuplicateSuppressionOn => sub {
    shift->config_set(duplicatesuppression => 1);
});
Cassandane::Cyrus::TestCase::magic(FuzzyMatch => sub {
    shift->config_set(lmtp_fuzzy_mailbox_match => 1);
});
sub new
{
    my $class = shift;
    return $class->SUPER::new({
	    deliver => 1,
            adminstore => 1,
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

sub test_plus_address_exact
    :FuzzyMatch
{
    my ($self) = @_;

    xlog "Testing behaviour of plus addressing where case matches";

    my $folder = "INBOX.telephone";

    xlog "Create folders";
    my $imaptalk = $self->{store}->get_client();
    $imaptalk->create($folder)
        or die "Cannot create $folder: $@";
    $self->{store}->set_fetch_attributes('uid');

    xlog "Deliver a message";
    my %msgs;
    $msgs{1} = $self->{gen}->generate(subject => "Message 1");
    $msgs{1}->set_attribute(uid => 1);
    $self->{instance}->deliver($msgs{1}, user => "cassandane+telephone");

    xlog "Check that the message made it";
    $self->{store}->set_folder($folder);
    $self->check_messages(\%msgs, check_guid => 0, keyed_on => 'uid');
}

sub test_plus_address_underscore
    :FuzzyMatch
{
    my ($self) = @_;

    xlog "Testing behaviour of plus addressing where case matches";

    my $folder = "INBOX.- minusland";

    xlog "Create folders";
    my $imaptalk = $self->{store}->get_client();
    $imaptalk->create($folder)
        or die "Cannot create $folder: $@";
    $self->{store}->set_fetch_attributes('uid');

    xlog "Deliver a message";
    my %msgs;
    $msgs{1} = $self->{gen}->generate(subject => "Message 1");
    $msgs{1}->set_attribute(uid => 1);
    $self->{instance}->deliver($msgs{1}, user => "cassandane+-_minusland");

    xlog "Check that the message made it";
    $self->{store}->set_folder($folder);
    $self->check_messages(\%msgs, check_guid => 0, keyed_on => 'uid');
}

sub test_plus_address_case
    :FuzzyMatch
{
    my ($self) = @_;

    xlog "Testing behaviour of plus addressing where case matches";

    my $folder = "INBOX.ApplePie";

    xlog "Create folders";
    my $imaptalk = $self->{store}->get_client();
    $imaptalk->create($folder)
        or die "Cannot create $folder: $@";
    $self->{store}->set_fetch_attributes('uid');

    xlog "Deliver a message";
    my %msgs;
    $msgs{1} = $self->{gen}->generate(subject => "Message 1");
    $msgs{1}->set_attribute(uid => 1);
    $self->{instance}->deliver($msgs{1}, user => "cassandane+applepie");

    xlog "Check that the message made it";
    $self->{store}->set_folder($folder);
    $self->check_messages(\%msgs, check_guid => 0, keyed_on => 'uid');
}

sub test_plus_address_case_defdomain
    :FuzzyMatch :VirtDomains
{
    my ($self) = @_;

    xlog "Testing behaviour of plus addressing where case matches";

    my $folder = "INBOX.ApplePie";

    xlog "Create folders";
    my $imaptalk = $self->{store}->get_client();
    $imaptalk->create($folder)
        or die "Cannot create $folder: $@";
    $self->{store}->set_fetch_attributes('uid');

    xlog "Deliver a message";
    my %msgs;
    $msgs{1} = $self->{gen}->generate(subject => "Message 1");
    $msgs{1}->set_attribute(uid => 1);
    $self->{instance}->deliver($msgs{1}, user => "cassandane+applepie\@defdomain");

    xlog "Check that the message made it";
    $self->{store}->set_folder($folder);
    $self->check_messages(\%msgs, check_guid => 0, keyed_on => 'uid');
}

sub test_plus_address_case_bogusdomain
    :FuzzyMatch :VirtDomains
{
    my ($self) = @_;

    xlog "Testing behaviour of plus addressing where case matches";

    my $folder = "INBOX.ApplePie";

    xlog "Create folders";
    my $imaptalk = $self->{store}->get_client();
    $imaptalk->create($folder)
        or die "Cannot create $folder: $@";
    $self->{store}->set_fetch_attributes('uid');

    xlog "Deliver a message";
    my %msgs;
    $msgs{1} = $self->{gen}->generate(subject => "Message 1");
    $msgs{1}->set_attribute(uid => 1);
    $self->{instance}->deliver($msgs{1}, user => "cassandane+applepie\@bogusdomain");

    xlog "Check that the message didn't make it";
    $self->{store}->set_folder($folder);
    $self->check_messages({}, check_guid => 0, keyed_on => 'uid');
}

sub test_plus_address_bothupper
    :FuzzyMatch
{
    my ($self) = @_;

    xlog "Testing behaviour of plus addressing where case matches";

    my $folder = "INBOX.FlatPack";

    xlog "Create folders";
    my $imaptalk = $self->{store}->get_client();
    $imaptalk->create($folder)
        or die "Cannot create $folder: $@";
    $self->{store}->set_fetch_attributes('uid');

    xlog "Deliver a message";
    my %msgs;
    $msgs{1} = $self->{gen}->generate(subject => "Message 1");
    $msgs{1}->set_attribute(uid => 1);
    $self->{instance}->deliver($msgs{1}, user => "cassandane+FlatPack");

    xlog "Check that the message made it";
    $self->{store}->set_folder($folder);
    $self->check_messages(\%msgs, check_guid => 0, keyed_on => 'uid');
}

sub test_plus_address_partial
    :FuzzyMatch
{
    my ($self) = @_;

    xlog "Testing behaviour of plus addressing where subfolder doesn't exist";

    my $folder = "INBOX.lists";

    xlog "Create folders";
    my $imaptalk = $self->{store}->get_client();
    $imaptalk->create($folder)
        or die "Cannot create $folder: $@";
    $self->{store}->set_fetch_attributes('uid');

    xlog "Deliver a message";
    my %msgs;
    $msgs{1} = $self->{gen}->generate(subject => "Message 1");
    $msgs{1}->set_attribute(uid => 1);
    $self->{instance}->deliver($msgs{1}, user => "cassandane+lists.nonexists");

    xlog "Check that the message made it";
    $self->{store}->set_folder($folder);
    $self->check_messages(\%msgs, check_guid => 0, keyed_on => 'uid');
}

sub test_plus_address_partial_case
    :FuzzyMatch
{
    my ($self) = @_;

    xlog "Testing behaviour of plus addressing where subfolder doesn't exist";

    my $folder = "INBOX.Twists";

    xlog "Create folders";
    my $imaptalk = $self->{store}->get_client();
    $imaptalk->create($folder)
        or die "Cannot create $folder: $@";
    $self->{store}->set_fetch_attributes('uid');

    xlog "Deliver a message";
    my %msgs;
    $msgs{1} = $self->{gen}->generate(subject => "Message 1");
    $msgs{1}->set_attribute(uid => 1);
    $self->{instance}->deliver($msgs{1}, user => "cassandane+twists.nonexists");

    xlog "Check that the message made it";
    $self->{store}->set_folder($folder);
    $self->check_messages(\%msgs, check_guid => 0, keyed_on => 'uid');
}

sub test_plus_address_partial_bothupper
    :FuzzyMatch
{
    my ($self) = @_;

    xlog "Testing behaviour of plus addressing where subfolder doesn't exist";

    my $folder = "INBOX.Projects";

    xlog "Create folders";
    my $imaptalk = $self->{store}->get_client();
    $imaptalk->create($folder)
        or die "Cannot create $folder: $@";
    $self->{store}->set_fetch_attributes('uid');

    xlog "Deliver a message";
    my %msgs;
    $msgs{1} = $self->{gen}->generate(subject => "Message 1");
    $msgs{1}->set_attribute(uid => 1);
    $self->{instance}->deliver($msgs{1}, user => "cassandane+Projects.Grass");

    xlog "Check that the message made it";
    $self->{store}->set_folder($folder);
    $self->check_messages(\%msgs, check_guid => 0, keyed_on => 'uid');
}

sub test_plus_address_partial_virtdom
    :FuzzyMatch :VirtDomains
{
    my ($self) = @_;

    xlog "Testing behaviour of plus addressing with virtdomains";

    my $admintalk = $self->{adminstore}->get_client();

    $self->{instance}->create_user("domuser\@example.com");
    my $domstore = $self->{instance}->get_service('imap')->create_store(username => "domuser\@example.com") || die "can't create store";
    $self->{store} = $domstore;
    my $domtalk = $domstore->get_client();

    my $folder = "INBOX.Projects";

    xlog "Create folders";
    $domtalk->create($folder)
        or die "Cannot create $folder: $@";
    $domstore->set_fetch_attributes('uid');

    xlog "Deliver a message";
    my %msgs;
    $msgs{1} = $self->{gen}->generate(subject => "Message 1");
    $msgs{1}->set_attribute(uid => 1);
    $self->{instance}->deliver($msgs{1}, user => "domuser+Projects.Grass\@example.com");

    xlog "Check that the message made it";
    $domstore->set_folder($folder);
    $self->check_messages(\%msgs, check_guid => 0, keyed_on => 'uid');
}


sub test_duplicate_suppression_off
    :DuplicateSuppressionOff
{
    my ($self) = @_;

    xlog "Testing behaviour with duplicate suppression off";

    # test data from hipsteripsum.me
    my $folder = "INBOX.thundercats";

    xlog "Create the target folder";
    my $imaptalk = $self->{store}->get_client();
    $imaptalk->create($folder)
	or die "Cannot create $folder: $@";
    $self->{store}->set_fetch_attributes('uid');

    xlog "Deliver a message";
    my %msgs;
    $msgs{1} = $self->{gen}->generate(subject => "Message 1");
    $msgs{1}->set_attribute(uid => 1);
    $self->{instance}->deliver($msgs{1}, folder => $folder);

    xlog "Check that the message made it";
    $self->{store}->set_folder($folder);
    $self->check_messages(\%msgs, check_guid => 0, keyed_on => 'uid');

    xlog "Try to deliver the same message again";
    $self->{instance}->deliver($msgs{1}, folder => $folder);

    xlog "Check that second copy of the message made it";
    $msgs{2} = $msgs{1}->clone();
    $msgs{2}->set_attribute(uid => 2);
    $self->{store}->set_folder($folder);
    $self->check_messages(\%msgs, check_guid => 0, keyed_on => 'uid');
}


sub test_duplicate_suppression_on
    :DuplicateSuppressionOn
{
    my ($self) = @_;

    xlog "Testing behaviour with duplicate suppression on";

    # test data from hipsteripsum.me
    my $folder1 = "INBOX.sustainable";
    my $folder2 = "INBOX.artisan";

    xlog "Create the target folder";
    my $imaptalk = $self->{store}->get_client();
    $imaptalk->create($folder1)
	or die "Cannot create $folder1: $@";
    $self->{store}->set_fetch_attributes('uid');

    xlog "Deliver a message";
    my %msgs;
    $msgs{1} = $self->{gen}->generate(subject => "Message 1");
    $msgs{1}->set_attribute(uid => 1);
    $self->{instance}->deliver($msgs{1}, folder => $folder1);

    xlog "Check that the message made it";
    $self->{store}->set_folder($folder1);
    $self->check_messages(\%msgs, check_guid => 0, keyed_on => 'uid');

    xlog "Try to deliver the same message again";
    $self->{instance}->deliver($msgs{1}, folder => $folder1);

    xlog "Check that second copy of the message didn't make it";
    $self->{store}->set_folder($folder1);
    $self->check_messages(\%msgs, check_guid => 0, keyed_on => 'uid');

    xlog "Rename the folder";
    $imaptalk->rename($folder1, $folder2)
	or die "Cannot rename $folder1 to $folder2: $@";

    xlog "Try to deliver the same message again";
    $self->{instance}->deliver($msgs{1}, folder => $folder2);

    xlog "Check that third copy of the message DIDN'T make it";
    # This is the whole point of duplicate_mailbox_mode = uniqueid.
    $self->{store}->set_folder($folder2);
    $self->check_messages(\%msgs, check_guid => 0, keyed_on => 'uid');
}

sub test_duplicate_suppression_on_delete
    :DuplicateSuppressionOn
{
    my ($self) = @_;

    xlog "Testing behaviour with duplicate suppression on";
    xlog "interaction with DELETE + CREATE [IRIS-723]";

    # test data from hipsteripsum.me
    my $folder = "INBOX.mixtape";

    xlog "Create the target folder";
    my $imaptalk = $self->{store}->get_client();
    $imaptalk->create($folder)
	or die "Cannot create $folder: $@";

    xlog "Deliver a message";
    my %msgs;
    $msgs{1} = $self->{gen}->generate(subject => "Message 1");
    $self->{instance}->deliver($msgs{1}, folder => $folder);

    xlog "Check that the message made it";
    $self->{store}->set_folder($folder);
    $self->check_messages(\%msgs, check_guid => 0, keyed_on => 'uid');

    xlog "Delete the folder";
    $imaptalk->unselect();
    $imaptalk->delete($folder)
	or die "Cannot delete $folder: $@";

    xlog "Create another folder of the same name";
    $imaptalk->create($folder)
	or die "Cannot create another $folder: $@";

    xlog "Check that all messages are gone";
    $self->{store}->set_folder($folder);
    $self->check_messages({}, check_guid => 0, keyed_on => 'uid');

    xlog "Try to deliver the same message to the new folder";
    $self->{instance}->deliver($msgs{1}, folder => $folder);

    xlog "Check that the message made it";
    $self->{store}->set_folder($folder);
    $self->check_messages(\%msgs, check_guid => 0, keyed_on => 'uid');
}

sub test_duplicate_suppression_on_badmbox
    :DuplicateSuppressionOn
{
    my ($self) = @_;

    xlog "Testing behaviour with duplicate suppression on";
    xlog "interaction with attempted delivery to a";
    xlog "non-existant mailbox";

    my $folder = "INBOX.nonesuch";
    # DO NOT create the target folder

    $self->{store}->set_fetch_attributes('uid');

    xlog "Deliver a message";
    my %msgs;
    $msgs{1} = $self->{gen}->generate(subject => "Message 1");
    $msgs{1}->set_attribute(uid => 1);
    $self->{instance}->deliver($msgs{1}, folder => $folder);

    xlog "Check that the message made it, to INBOX";
    $self->{store}->set_folder('INBOX');
    $self->check_messages(\%msgs, check_guid => 0, keyed_on => 'uid');

    xlog "Create a folder of the given name";
    my $imaptalk = $self->{store}->get_client();
    $imaptalk->create($folder)
	or die "Cannot create $folder: $@";

    xlog "Try to deliver the same message to the new folder";
    $self->{instance}->deliver($msgs{1}, folder => $folder);

    xlog "Check that the message made it, to the given folder";
    $self->{store}->set_folder($folder);
    $self->check_messages(\%msgs, check_guid => 0, keyed_on => 'uid');
}

1;
