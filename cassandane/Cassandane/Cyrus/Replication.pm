#!/usr/bin/perl
#
#  Copyright (c) 2011 Opera Software Australia Pty. Ltd.  All rights
#  reserved.
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
#  3. The name "Opera Software Australia" must not be used to
#     endorse or promote products derived from this software without
#     prior written permission. For permission or any legal
#     details, please contact
# 	Opera Software Australia Pty. Ltd.
# 	Level 50, 120 Collins St
# 	Melbourne 3000
# 	Victoria
# 	Australia
#
#  4. Redistributions of any form whatsoever must retain the following
#     acknowledgment:
#     "This product includes software developed by Opera Software
#     Australia Pty. Ltd."
#
#  OPERA SOFTWARE AUSTRALIA DISCLAIMS ALL WARRANTIES WITH REGARD TO
#  THIS SOFTWARE, INCLUDING ALL IMPLIED WARRANTIES OF MERCHANTABILITY
#  AND FITNESS, IN NO EVENT SHALL OPERA SOFTWARE AUSTRALIA BE LIABLE
#  FOR ANY SPECIAL, INDIRECT OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES
#  WHATSOEVER RESULTING FROM LOSS OF USE, DATA OR PROFITS, WHETHER IN
#  AN ACTION OF CONTRACT, NEGLIGENCE OR OTHER TORTIOUS ACTION, ARISING
#  OUT OF OR IN CONNECTION WITH THE USE OR PERFORMANCE OF THIS SOFTWARE.
#

use strict;
use warnings;
package Cassandane::Cyrus::Replication;
use base qw(Cassandane::Cyrus::TestCase);
use DateTime;
use Cassandane::Util::Log;
use Cassandane::Service;
use Cassandane::Config;

sub new
{
    my $class = shift;
    return $class->SUPER::new({ replica => 1 }, @_);
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

#
# Test replication of messages APPENDed to the master
#
sub test_append
{
    my ($self) = @_;

    my $master_store = $self->{master_store};
    my $replica_store = $self->{replica_store};

    xlog "generating messages A..D";
    my %exp;
    $exp{A} = $self->make_message("Message A", store => $master_store);
    $exp{B} = $self->make_message("Message B", store => $master_store);
    $exp{C} = $self->make_message("Message C", store => $master_store);
    $exp{D} = $self->make_message("Message D", store => $master_store);

    xlog "Before replication, the master should have all four messages";
    $self->check_messages(\%exp, store => $master_store);
    xlog "Before replication, the replica should have no messages";
    $self->check_messages({}, store => $replica_store);

    $self->run_replication();

    xlog "After replication, the master should still have all four messages";
    $self->check_messages(\%exp, store => $master_store);
    xlog "After replication, the replica should now have all four messages";
    $self->check_messages(\%exp, store => $replica_store);
}

#
# Test replication of messages APPENDed to the master
#
sub test_splitbrain
{
    my ($self) = @_;

    my $master_store = $self->{master_store};
    my $replica_store = $self->{replica_store};

    xlog "generating messages A..D";
    my %exp;
    $exp{A} = $self->make_message("Message A", store => $master_store);
    $exp{B} = $self->make_message("Message B", store => $master_store);
    $exp{C} = $self->make_message("Message C", store => $master_store);
    $exp{D} = $self->make_message("Message D", store => $master_store);

    xlog "Before replication, the master should have all four messages";
    $self->check_messages(\%exp, store => $master_store);
    xlog "Before replication, the replica should have no messages";
    $self->check_messages({}, store => $replica_store);

    $self->run_replication();

    xlog "After replication, the master should still have all four messages";
    $self->check_messages(\%exp, store => $master_store);
    xlog "After replication, the replica should now have all four messages";
    $self->check_messages(\%exp, store => $replica_store);

    my %mexp = %exp;
    my %rexp = %exp;

    $mexp{E} = $self->make_message("Message E", store => $master_store);
    $rexp{F} = $self->make_message("Message F", store => $replica_store);

    # uid is 5 at both ends
    $rexp{F}->set_attribute(uid => 5);

    xlog "No replication, the master should have its 5 messages";
    $self->check_messages(\%mexp, store => $master_store);
    xlog "No replication, the replica should have the other 5 messages";
    $self->check_messages(\%rexp, store => $replica_store);

    $self->run_replication();

    %exp = (%mexp, %rexp);
    # we could calculate 6 and 7 by sorting from GUID, but easiest is to ignore UIDs
    $exp{E}->set_attribute(uid => undef);
    $exp{F}->set_attribute(uid => undef);
    xlog "After replication, the master should have all 6 messages";
    $self->check_messages(\%exp, store => $master_store);
    xlog "After replication, the replica should have all 6 messages";
    $self->check_messages(\%exp, store => $replica_store);
}

#
# Test replication of messages APPENDed to the master
#
sub test_splitbrain_masterexpunge
{
    my ($self) = @_;

    my $master_store = $self->{master_store};
    my $replica_store = $self->{replica_store};

    xlog "generating messages A..D";
    my %exp;
    $exp{A} = $self->make_message("Message A", store => $master_store);
    $exp{B} = $self->make_message("Message B", store => $master_store);
    $exp{C} = $self->make_message("Message C", store => $master_store);
    $exp{D} = $self->make_message("Message D", store => $master_store);

    xlog "Before replication, the master should have all four messages";
    $self->check_messages(\%exp, store => $master_store);
    xlog "Before replication, the replica should have no messages";
    $self->check_messages({}, store => $replica_store);

    $self->run_replication();

    xlog "After replication, the master should still have all four messages";
    $self->check_messages(\%exp, store => $master_store);
    xlog "After replication, the replica should now have all four messages";
    $self->check_messages(\%exp, store => $replica_store);

    my %mexp = %exp;
    my %rexp = %exp;

    $mexp{E} = $self->make_message("Message E", store => $master_store);
    $rexp{F} = $self->make_message("Message F", store => $replica_store);

    # uid is 5 at both ends
    $rexp{F}->set_attribute(uid => 5);

    xlog "No replication, the master should have its 5 messages";
    $self->check_messages(\%mexp, store => $master_store);
    xlog "No replication, the replica should have the other 5 messages";
    $self->check_messages(\%rexp, store => $replica_store);

    xlog "Delete and expunge the message on the master";
    my $talk = $master_store->get_client();
    $master_store->_select();
    $talk->store('5', '+flags', '(\\Deleted)');
    $talk->expunge();
    delete $mexp{E};

    xlog "No replication, the master now only has 4 messages";
    $self->check_messages(\%mexp, store => $master_store);

    $self->run_replication();

    %exp = (%mexp, %rexp);
    # we know that the message should be prompoted to UID 6
    $exp{F}->set_attribute(uid => 6);
    xlog "After replication, the master should have all 5 messages";
    $self->check_messages(\%exp, store => $master_store);
    xlog "After replication, the replica should have the same 5 messages";
    $self->check_messages(\%exp, store => $replica_store);
}

#
# Test replication of messages APPENDed to the master
#
sub test_splitbrain_replicaexpunge
{
    my ($self) = @_;

    my $master_store = $self->{master_store};
    my $replica_store = $self->{replica_store};

    xlog "generating messages A..D";
    my %exp;
    $exp{A} = $self->make_message("Message A", store => $master_store);
    $exp{B} = $self->make_message("Message B", store => $master_store);
    $exp{C} = $self->make_message("Message C", store => $master_store);
    $exp{D} = $self->make_message("Message D", store => $master_store);

    xlog "Before replication, the master should have all four messages";
    $self->check_messages(\%exp, store => $master_store);
    xlog "Before replication, the replica should have no messages";
    $self->check_messages({}, store => $replica_store);

    $self->run_replication();

    xlog "After replication, the master should still have all four messages";
    $self->check_messages(\%exp, store => $master_store);
    xlog "After replication, the replica should now have all four messages";
    $self->check_messages(\%exp, store => $replica_store);

    my %mexp = %exp;
    my %rexp = %exp;

    $mexp{E} = $self->make_message("Message E", store => $master_store);
    $rexp{F} = $self->make_message("Message F", store => $replica_store);

    # uid is 5 at both ends
    $rexp{F}->set_attribute(uid => 5);

    xlog "No replication, the master should have its 5 messages";
    $self->check_messages(\%mexp, store => $master_store);
    xlog "No replication, the replica should have the other 5 messages";
    $self->check_messages(\%rexp, store => $replica_store);

    xlog "Delete and expunge the message on the master";
    my $rtalk = $replica_store->get_client();
    $replica_store->_select();
    $rtalk->store('5', '+flags', '(\\Deleted)');
    $rtalk->expunge();
    delete $rexp{F};

    xlog "No replication, the replica now only has 4 messages";
    $self->check_messages(\%rexp, store => $replica_store);

    $self->run_replication();

    %exp = (%mexp, %rexp);
    # we know that the message should be prompoted to UID 6
    $exp{E}->set_attribute(uid => 6);
    xlog "After replication, the master should have all 5 messages";
    $self->check_messages(\%exp, store => $master_store);
    xlog "After replication, the replica should have the same 5 messages";
    $self->check_messages(\%exp, store => $replica_store);
}

#
# Test replication of messages APPENDed to the master
#
sub test_splitbrain_bothexpunge
{
    my ($self) = @_;

    my $master_store = $self->{master_store};
    my $replica_store = $self->{replica_store};

    xlog "generating messages A..D";
    my %exp;
    $exp{A} = $self->make_message("Message A", store => $master_store);
    $exp{B} = $self->make_message("Message B", store => $master_store);
    $exp{C} = $self->make_message("Message C", store => $master_store);
    $exp{D} = $self->make_message("Message D", store => $master_store);

    xlog "Before replication, the master should have all four messages";
    $self->check_messages(\%exp, store => $master_store);
    xlog "Before replication, the replica should have no messages";
    $self->check_messages({}, store => $replica_store);

    $self->run_replication();

    xlog "After replication, the master should still have all four messages";
    $self->check_messages(\%exp, store => $master_store);
    xlog "After replication, the replica should now have all four messages";
    $self->check_messages(\%exp, store => $replica_store);

    my %mexp = %exp;
    my %rexp = %exp;

    $mexp{E} = $self->make_message("Message E", store => $master_store);
    $rexp{F} = $self->make_message("Message F", store => $replica_store);

    # uid is 5 at both ends
    $rexp{F}->set_attribute(uid => 5);

    xlog "No replication, the master should have its 5 messages";
    $self->check_messages(\%mexp, store => $master_store);
    xlog "No replication, the replica should have the other 5 messages";
    $self->check_messages(\%rexp, store => $replica_store);

    xlog "Delete and expunge the message on the master";
    my $talk = $master_store->get_client();
    $master_store->_select();
    $talk->store('5', '+flags', '(\\Deleted)');
    $talk->expunge();
    delete $mexp{E};

    xlog "Delete and expunge the message on the master";
    my $rtalk = $replica_store->get_client();
    $replica_store->_select();
    $rtalk->store('5', '+flags', '(\\Deleted)');
    $rtalk->expunge();
    delete $rexp{F};

    $self->run_replication();

    xlog "After replication, the master should have just the original 4 messages";
    $self->check_messages(\%exp, store => $master_store);
    xlog "After replication, the replica should have the same 4 messages";
    $self->check_messages(\%exp, store => $replica_store);
}

# trying to reproduce error reported in https://git.cyrus.foundation/T228
sub test_alternate_globalannots
    :NoStartInstances
{
    my ($self) = @_;

    # first, set a different annotation_db_path on the master server
    my $annotation_db_path = $self->{instance}->get_basedir()
                             . "/conf/non-default-annotations.db";
    $self->{instance}->{config}->set('annotation_db_path' => $annotation_db_path);

    # now we can start the instances
    $self->_start_instances();

    # A replication will automatically occur when the instances are started,
    # in order to make sure the cassandane user exists on both hosts.
    # So if we get here without crashing, replication works.
    xlog "initial replication was successful";

    $self->assert(1);
}

1;
