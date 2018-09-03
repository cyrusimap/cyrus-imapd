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

package Cassandane::Cyrus::Replication;
use strict;
use warnings;
use Data::Dumper;
use DateTime;

use lib '.';
use base qw(Cassandane::Cyrus::TestCase);
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
    $self->check_replication('cassandane');

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
    $self->check_replication('cassandane');

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
    $self->check_replication('cassandane');

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
    $self->check_replication('cassandane');

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
    $self->check_replication('cassandane');

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
    $self->check_replication('cassandane');

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
    $self->check_replication('cassandane');

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
    $self->check_replication('cassandane');

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
    $self->check_replication('cassandane');

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

sub assert_sieve_exists
{
    my ($self, $instance, $user, $scriptname) = @_;

    my $sieve_dir = $instance->get_sieve_script_dir($user);

    $self->assert(( -f "$sieve_dir/$scriptname.bc" ));
    $self->assert(( -f "$sieve_dir/$scriptname.script" ));
}

sub assert_sieve_not_exists
{
    my ($self, $instance, $user, $scriptname) = @_;

    my $sieve_dir = $instance->get_sieve_script_dir($user);

    $self->assert(( ! -f "$sieve_dir/$scriptname.bc" ));
    $self->assert(( ! -f "$sieve_dir/$scriptname.script" ));
}

sub assert_sieve_active
{
    my ($self, $instance, $user, $scriptname) = @_;

    my $sieve_dir = $instance->get_sieve_script_dir($user);

    $self->assert(( -l "$sieve_dir/defaultbc" ));
    $self->assert_str_equals("$scriptname.bc", readlink "$sieve_dir/defaultbc");
}

sub assert_sieve_noactive
{
    my ($self, $instance, $user) = @_;

    my $sieve_dir = $instance->get_sieve_script_dir($user);

    $self->assert(( ! -e "$sieve_dir/defaultbc" ),
                  "$sieve_dir/defaultbc exists");
    $self->assert(( ! -l "$sieve_dir/defaultbc" ),
                  "dangling $sieve_dir/defaultbc symlink exists");
}

sub assert_sieve_matches
{
    my ($self, $instance, $user, $scriptname, $scriptcontent) = @_;

    my $sieve_dir = $instance->get_sieve_script_dir($user);

    my $filename = "$sieve_dir/$scriptname.script";

    $self->assert(( -f $filename ));

    open my $f, '<', $filename or die "open $filename: $!\n";
    my $filecontent = do { local $/; <$f> };
    close $f;

    $self->assert_str_equals($scriptcontent, $filecontent);

    my $bcname = "$sieve_dir/$scriptname.bc";

    $self->assert(( -f $bcname ));
    my $filemtime = (stat $filename)[9];
    my $bcmtime = (stat $bcname)[9];

    $self->assert($bcmtime >= $filemtime);
}

sub test_sieve_replication
    :needs_component_sieve
{
    my ($self) = @_;

    my $user = 'cassandane';
    my $scriptname = 'test1';
    my $scriptcontent = <<'EOF';
require ["reject","fileinto"];
if address :is :all "From" "autoreject@example.org"
{
        reject "testing";
}
EOF

    # first, verify that sieve script does not exist on master or replica
    $self->assert_sieve_not_exists($self->{instance}, $user, $scriptname);
    $self->assert_sieve_noactive($self->{instance}, $user);

    $self->assert_sieve_not_exists($self->{replica}, $user, $scriptname);
    $self->assert_sieve_noactive($self->{replica}, $user);

    # then, install sieve script on master
    $self->{instance}->install_sieve_script($scriptcontent, name=>$scriptname);

    # then, verify that sieve script exists on master but not on replica
    $self->assert_sieve_exists($self->{instance}, $user, $scriptname);
    $self->assert_sieve_active($self->{instance}, $user, $scriptname);

    $self->assert_sieve_not_exists($self->{replica}, $user, $scriptname);
    $self->assert_sieve_noactive($self->{replica}, $user);

    # then, run replication,
    $self->run_replication();
    $self->check_replication('cassandane');

    # then, verify that sieve script exists on both master and replica
    $self->assert_sieve_exists($self->{instance}, $user, $scriptname);
    $self->assert_sieve_active($self->{instance}, $user, $scriptname);

    $self->assert_sieve_exists($self->{replica}, $user, $scriptname);
    $self->assert_sieve_active($self->{replica}, $user, $scriptname);
}

sub test_sieve_replication_exists
    :needs_component_sieve
{
    my ($self) = @_;

    my $user = 'cassandane';
    my $scriptname = 'test1';
    my $scriptcontent = <<'EOF';
require ["reject","fileinto"];
if address :is :all "From" "autoreject@example.org"
{
        reject "testing";
}
EOF

    # first, verify that sieve script does not exist on master or replica
    $self->assert_sieve_not_exists($self->{instance}, $user, $scriptname);
    $self->assert_sieve_noactive($self->{instance}, $user);

    $self->assert_sieve_not_exists($self->{replica}, $user, $scriptname);
    $self->assert_sieve_noactive($self->{replica}, $user);

    # then, install sieve script on both master and replica
    $self->{instance}->install_sieve_script($scriptcontent, name=>$scriptname);
    $self->{replica}->install_sieve_script($scriptcontent, name=>$scriptname);

    # then, verify that sieve script exists on both
    $self->assert_sieve_exists($self->{instance}, $user, $scriptname);
    $self->assert_sieve_active($self->{instance}, $user, $scriptname);

    $self->assert_sieve_exists($self->{replica}, $user, $scriptname);
    $self->assert_sieve_active($self->{replica}, $user, $scriptname);

    # then, run replication,
    $self->run_replication();
    $self->check_replication('cassandane');

    # then, verify that sieve script still exists on both master and replica
    $self->assert_sieve_exists($self->{instance}, $user, $scriptname);
    $self->assert_sieve_active($self->{instance}, $user, $scriptname);

    $self->assert_sieve_exists($self->{replica}, $user, $scriptname);
    $self->assert_sieve_active($self->{replica}, $user, $scriptname);
}

sub test_sieve_replication_different
    :needs_component_sieve
{
    my ($self) = @_;

    my $user = 'cassandane';
    my $script1name = 'test1';
    my $script1content = <<'EOF';
require ["reject","fileinto"];
if address :is :all "From" "autoreject@example.org"
{
        reject "testing";
}
EOF

    my $script2name = 'test2';
    my $script2content = <<'EOF';
require ["reject","fileinto"];
if address :is :all "From" "autoreject@example.org"
{
        reject "more testing";
}
EOF

    # first, verify that neither script exists on master or replica
    $self->assert_sieve_not_exists($self->{instance}, $user, $script1name);
    $self->assert_sieve_not_exists($self->{instance}, $user, $script2name);
    $self->assert_sieve_noactive($self->{instance}, $user);

    $self->assert_sieve_not_exists($self->{replica}, $user, $script1name);
    $self->assert_sieve_not_exists($self->{replica}, $user, $script2name);
    $self->assert_sieve_noactive($self->{replica}, $user);

    # then, install different sieve script on master and replica
    $self->{instance}->install_sieve_script($script1content, name=>$script1name);
    $self->{replica}->install_sieve_script($script2content, name=>$script2name);

    # then, verify that each sieve script exists on one only
    $self->assert_sieve_exists($self->{instance}, $user, $script1name);
    $self->assert_sieve_active($self->{instance}, $user, $script1name);
    $self->assert_sieve_not_exists($self->{instance}, $user, $script2name);

    $self->assert_sieve_exists($self->{replica}, $user, $script2name);
    $self->assert_sieve_active($self->{replica}, $user, $script2name);
    $self->assert_sieve_not_exists($self->{replica}, $user, $script1name);

    # then, run replication,
    # the one that exists on master only will be replicated
    # the one that exists on replica only will be deleted
    $self->run_replication();
    $self->check_replication('cassandane');

    # then, verify that scripts are in expected state
    $self->assert_sieve_exists($self->{instance}, $user, $script1name);
    $self->assert_sieve_active($self->{instance}, $user, $script1name);
    $self->assert_sieve_not_exists($self->{instance}, $user, $script2name);

    $self->assert_sieve_exists($self->{replica}, $user, $script1name);
    $self->assert_sieve_active($self->{replica}, $user, $script1name);
    $self->assert_sieve_not_exists($self->{replica}, $user, $script2name);
}

sub test_sieve_replication_stale
    :needs_component_sieve
{
    my ($self) = @_;

    my $user = 'cassandane';
    my $scriptname = 'test1';
    my $scriptoldcontent = <<'EOF';
require ["reject","fileinto"];
if address :is :all "From" "autoreject@example.org"
{
        reject "testing";
}
EOF

    my $scriptnewcontent = <<'EOF';
require ["reject","fileinto"];
if address :is :all "From" "autoreject@example.org"
{
        reject "more testing";
}
EOF

    # first, verify that script does not exist on master or replica
    $self->assert_sieve_not_exists($self->{instance}, $user, $scriptname);
    $self->assert_sieve_noactive($self->{instance}, $user);

    $self->assert_sieve_not_exists($self->{replica}, $user, $scriptname);
    $self->assert_sieve_noactive($self->{replica}, $user);

    # then, install "old" script on replica...
    $self->{replica}->install_sieve_script($scriptoldcontent, name=>$scriptname);

    # ... and "new" script on master, a little later
    sleep 2;
    $self->{instance}->install_sieve_script($scriptnewcontent, name=>$scriptname);

    # then, verify that different sieve script content exists at each end
    $self->assert_sieve_exists($self->{instance}, $user, $scriptname);
    $self->assert_sieve_active($self->{instance}, $user, $scriptname);
    $self->assert_sieve_matches($self->{instance}, $user, $scriptname,
                                $scriptnewcontent);

    $self->assert_sieve_exists($self->{replica}, $user, $scriptname);
    $self->assert_sieve_active($self->{replica}, $user, $scriptname);
    $self->assert_sieve_matches($self->{replica}, $user, $scriptname,
                                $scriptoldcontent);

    # then, run replication,
    # the one that exists on replica is different to and older than the one
    # on master, so it will be replaced with the one from master
    $self->run_replication();
    $self->check_replication('cassandane');

    # then, verify that scripts are in expected state
    $self->assert_sieve_exists($self->{instance}, $user, $scriptname);
    $self->assert_sieve_active($self->{instance}, $user, $scriptname);
    $self->assert_sieve_matches($self->{instance}, $user, $scriptname,
                                $scriptnewcontent);

    $self->assert_sieve_exists($self->{replica}, $user, $scriptname);
    $self->assert_sieve_active($self->{replica}, $user, $scriptname);
    $self->assert_sieve_matches($self->{replica}, $user, $scriptname,
                                $scriptnewcontent);
}

sub test_sieve_replication_delete_unactivate
    :needs_component_sieve
{
    my ($self) = @_;

    my $user = 'cassandane';
    my $scriptname = 'test1';
    my $scriptcontent = <<'EOF';
require ["reject","fileinto"];
if address :is :all "From" "autoreject@example.org"
{
        reject "testing";
}
EOF

    # first, verify that sieve script does not exist on master or replica
    $self->assert_sieve_not_exists($self->{instance}, $user, $scriptname);
    $self->assert_sieve_noactive($self->{instance}, $user);

    $self->assert_sieve_not_exists($self->{replica}, $user, $scriptname);
    $self->assert_sieve_noactive($self->{replica}, $user);

    # then, install sieve script on replica only
    $self->{replica}->install_sieve_script($scriptcontent, name=>$scriptname);

    # then, verify that sieve script exists on replica only
    $self->assert_sieve_not_exists($self->{instance}, $user, $scriptname);
    $self->assert_sieve_noactive($self->{instance}, $user, $scriptname);

    $self->assert_sieve_exists($self->{replica}, $user, $scriptname);
    $self->assert_sieve_active($self->{replica}, $user, $scriptname);

    # then, run replication,
    $self->run_replication();
    $self->check_replication('cassandane');

    # then, verify that sieve script no longer exists on either
    $self->assert_sieve_not_exists($self->{instance}, $user, $scriptname);
    $self->assert_sieve_noactive($self->{instance}, $user, $scriptname);

    $self->assert_sieve_not_exists($self->{replica}, $user, $scriptname);
    $self->assert_sieve_noactive($self->{replica}, $user, $scriptname);
}

sub slurp_file
{
    my ($filename) = @_;

    local $/;
    open my $f, '<', $filename
        or die "Cannot open $filename for reading: $!\n";
    my $str = <$f>;
    close $f;

    return $str;
}

sub test_replication_mailbox_too_old
{
    my ($self) = @_;

    my $user = 'cassandane';
    my $exit_code;

    my $master_instance = $self->{instance};
    my $replica_instance = $self->{replica};

    # logs will all be in the master instance, because that's where
    # sync_client runs from.
    my $log_base = "$master_instance->{basedir}/$self->{_name}";

    # add a version9 mailbox to the replica only, and try to replicate.
    # replication will fail, because the initial GET USER will barf
    # upon encountering the old mailbox.
    $replica_instance->install_old_mailbox($user, 9);
    my $log_firstreject = "$log_base-firstreject.stderr";
    $exit_code = 0;
    $self->run_replication(
        user => $user,
        handlers => {
            exited_abnormally => sub { (undef, $exit_code) = @_; },
        },
        redirects => { stderr => $log_firstreject },
    );
    $self->assert_equals(1, $exit_code);
    $self->assert(qr/USER received NO response: IMAP_MAILBOX_NOTSUPPORTED/,
                  slurp_file($log_firstreject));

    # add the version9 mailbox to the master, and try to replicate.
    # mailbox will be found and rejected locally, and replication will
    # fail.
    $master_instance->install_old_mailbox($user, 9);
    my $log_localreject = "$log_base-localreject.stderr";
    $exit_code = 0;
    $self->run_replication(
        user => $user,
        handlers => {
            exited_abnormally => sub { (undef, $exit_code) = @_; },
        },
        redirects => { stderr => $log_localreject },
    );
    $self->assert_equals(1, $exit_code);
    $self->assert(qr/Operation is not supported on mailbox/,
                  slurp_file($log_localreject));

    # upgrade the version9 mailbox on the master, and try to replicate.
    # replication will fail, because the initial GET USER will barf
    # upon encountering the old mailbox.
    $master_instance->run_command({ cyrus => 1 }, qw(reconstruct -V max -u), $user);
    my $log_remotereject = "$log_base-remotereject.stderr";
    $exit_code = 0;
    $self->run_replication(
        user => $user,
        handlers => {
            exited_abnormally => sub { (undef, $exit_code) = @_; },
        },
        redirects => { stderr => $log_remotereject },
    );
    $self->assert_equals(1, $exit_code);
    $self->assert(qr/USER received NO response: IMAP_MAILBOX_NOTSUPPORTED/,
                  slurp_file($log_remotereject));

    # upgrade the version9 mailbox on the replica, and try to replicate.
    # replication will succeed because both ends are capable of replication.
    $replica_instance->run_command({ cyrus => 1 }, qw(reconstruct -V max -u), $user);
    $exit_code = 0;
    $self->run_replication(
        user => $user,
        handlers => {
            exited_abnormally => sub { (undef, $exit_code) = @_; },
        },
    );
    $self->assert_equals(0, $exit_code);
}

# XXX need a test for version 10 mailbox without guids in it!

sub test_replication_mailbox_new_enough
{
    my ($self) = @_;

    my $user = 'cassandane';
    my $exit_code = 0;

    # successfully replicate a mailbox new enough to contain guids
    my $mailbox10 = $self->{instance}->install_old_mailbox($user, 10);
    $self->run_replication(mailbox => $mailbox10);

    # successfully replicate a mailbox new enough to contain guids
    my $mailbox12 = $self->{instance}->install_old_mailbox($user, 12);
    $self->run_replication(mailbox => $mailbox12);
}

#* create mailbox on master with no messages
#* sync_client to get it copied to replica
#* create a message in the mailbox on replica (imaptalk on replica_store)
#* delete the message from the replica (with expunge_mode default or expunge_mode immediate... try both)
#* run sync_client on the master again and make sure it successfully syncs up

sub test_replication_repair_zero_msgs
{
    my ($self) = @_;

    my $mastertalk = $self->{master_store}->get_client();
    my $replicatalk = $self->{replica_store}->get_client();

    # raise the modseq on the master end
    $mastertalk->setmetadata("INBOX", "/shared/comment", "foo");
    $mastertalk->setmetadata("INBOX", "/shared/comment", "");
    $mastertalk->setmetadata("INBOX", "/shared/comment", "foo");
    $mastertalk->setmetadata("INBOX", "/shared/comment", "");

    my $msg = $self->make_message("to be deleted", store => $self->{replica_store});

    $replicatalk->store($msg->{attrs}->{uid}, '+flags', '(\\deleted)');
    $replicatalk->expunge();

    $self->run_replication(user => 'cassandane');
}

sub test_replication_with_modified_seen_flag
{
    my ($self) = @_;

    my $master_store = $self->{master_store};
    $master_store->set_fetch_attributes(qw(uid flags));

    my $replica_store = $self->{replica_store};
    $replica_store->set_fetch_attributes(qw(uid flags));


    xlog "generating messages A & B";
    my %exp;
    $exp{A} = $self->make_message("Message A", store => $master_store);
    $exp{A}->set_attributes(id => 1, uid => 1, flags => []);
    $exp{B} = $self->make_message("Message B", store => $master_store);
    $exp{B}->set_attributes(id => 2, uid => 2, flags => []);

    xlog "Before replication: Ensure that master has two messages";
    $self->check_messages(\%exp, store => $master_store);
    xlog "Before replication: Ensure that replica has no messages";
    $self->check_messages({}, store => $replica_store);

    xlog "Run Replication!";
    $self->run_replication();
    $self->check_replication('cassandane');

    xlog "After replication: Ensure that master has two messages";
    $self->check_messages(\%exp, store => $master_store);
    xlog "After replication: Ensure replica now has two messages";
    $self->check_messages(\%exp, store => $replica_store);

    xlog "Set \\Seen on Message B";
    my $mtalk = $master_store->get_client();
    $master_store->_select();
    $mtalk->store('2', '+flags', '(\\Seen)');
    $exp{B}->set_attributes(flags => ['\\Seen']);
    $mtalk->unselect();
    xlog "Before replication: Ensure that master has two messages and flags are set";
    $self->check_messages(\%exp, store => $master_store);

    xlog "Before replication: Ensure that replica does not have the \\Seen flag set on Message B";
    my $rtalk = $replica_store->get_client();
    $replica_store->_select();
    my $res = $rtalk->fetch("2", "(flags)");
    my $flags = $res->{2}->{flags};
    $self->assert(not grep { $_ eq "\\Seen"} @$flags);

    xlog "Run Replication!";
    $self->run_replication();
    $self->check_replication('cassandane');

    xlog "After replication: Ensure that replica does have the \\Seen flag set on Message B";
    $rtalk = $replica_store->get_client();
    $replica_store->_select();
    $res = $rtalk->fetch("2", "(flags)");
    $flags = $res->{2}->{flags};
    $self->assert(grep { $_ eq "\\Seen"} @$flags);

    xlog "Clear \\Seen flag on Message B on master.";
    $mtalk = $master_store->get_client();
    $master_store->_select();
    $mtalk->store('2', '-flags', '(\\Seen)');

    xlog "Run Replication!";
    $self->run_replication();
    $self->check_replication('cassandane');

    xlog "After replication: Check both master and replica has no \\Seen flag on Message C";
    $mtalk = $master_store->get_client();
    $master_store->_select();
    $res = $mtalk->fetch("2", "(flags)");
    $flags = $res->{2}->{flags};
    $self->assert(not grep { $_ eq "\\Seen"} @$flags);

    $rtalk = $replica_store->get_client();
    $replica_store->_select();
    $res = $rtalk->fetch("3", "(flags)");
    $flags = $res->{3}->{flags};
    $self->assert(not grep { $_ eq "\\Seen"} @$flags);
}

1;
