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

package Cassandane::Cyrus::Quota;
use strict;
use warnings;
use Cwd qw(abs_path);
use File::Path qw(mkpath);
use DateTime;
use Data::Dumper;

use lib '.';
use base qw(Cassandane::Cyrus::TestCase);
use Cassandane::Util::Log;
use Cassandane::Util::NetString;
use Cassandane::Util::Slurp;

sub res_mailbox { 'MAILBOX' }
sub res_annot_storage { 'ANNOTATION-STORAGE' }

sub new
{
    my $class = shift;
    return $class->SUPER::new({ adminstore => 1, services => ['smmap', 'imap'] }, @_);
}

sub set_up
{
    my ($self) = @_;
    $self->SUPER::set_up();

    my ($maj, $min) = Cassandane::Instance->get_version();
    if ($maj < 3 || ($maj == 3 && $min < 9)) {
        $self->res_mailbox = 'X-NUM-FOLDERS';
        $self->res_annot_storage = 'X-ANNOTATION-STORAGE';
    }
}

sub tear_down
{
    my ($self) = @_;
    $self->SUPER::tear_down();
}

sub _set_quotaroot
{
    my ($self, $quotaroot) = @_;
    $self->{quotaroot} = $quotaroot;
}

# Utility function to set quota limits and check that it stuck
sub _set_limits
{
    my ($self, %resources) = @_;
    my $admintalk = $self->{adminstore}->get_client();

    my $quotaroot = delete $resources{quotaroot} || $self->{quotaroot};
    my @quotalist;
    foreach my $resource (keys %resources)
    {
        my $limit = $resources{$resource}
            or die "No limit specified for $resource";
        push(@quotalist, uc($resource), $limit);
    }
    $self->{limits}->{$quotaroot} = { @quotalist };
    $admintalk->setquota($quotaroot, \@quotalist);
    $self->assert_str_equals('ok', $admintalk->get_last_completion_response());
}

# Utility function to check that quota's usages
# and limits are where we expect it to be
sub _check_usages
{
    my ($self, %expecteds) = @_;
    my $admintalk = $self->{adminstore}->get_client();

    my $quotaroot = delete $expecteds{quotaroot} || $self->{quotaroot};
    my $limits = $self->{limits}->{$quotaroot};

    my @result = $admintalk->getquota($quotaroot);
    $self->assert_str_equals('ok', $admintalk->get_last_completion_response());

    # check actual and expected number of resources do match
    $self->assert_num_equals(scalar(keys %$limits) * 3, scalar(@result));

    # Convert the IMAP result to a conveniently checkable hash.
    # By checkable, we mean that a failure in assert_deep_equals()
    # will give a human some idea of what went wrong.
    my %act;
    while (scalar(@result)) {
        my ($res, $used, $limit) = splice(@result, 0, 3);
        $res = uc($res);
        die "Resource $res appears twice in result"
            if defined $act{$res};
        $act{$res} = {
            used => $used,
            limit => $limit,
        };
    }

    # Build a conveniently checkable hash from %expecteds
    # and limits previously by _set_limits().
    my %exp;
    foreach my $res (keys %expecteds)
    {
        $exp{uc($res)} = {
            used => $expecteds{$res},
            limit => $limits->{uc($res)},
        };
    }

    # Now actually compare
    $self->assert_deep_equals(\%exp, \%act);
}

# Reset the recorded usage in the database.  Used for testing
# quota -f.  Rather hacky.  Both _set_quotaroot() and _set_limits()
# can be used to set default values.
sub _zap_quota
{
    my ($self, %params) = @_;

    my $quotaroot = $params{quotaroot} || $self->{quotaroot};
    my $limits = $params{limits} || $self->{limits}->{$quotaroot};
    my $useds = $params{useds} || {};
    $useds = { map { uc($_) => $useds->{$_} } keys %$useds };

    # double check that some other part of Cassandane didn't
    # accidentally futz with the expected quota db backend
    my $backend = $self->{instance}->{config}->get('quota_db');
    $self->assert_str_equals('quotalegacy', $backend)
        if defined $backend;        # the default value is also ok

    my ($uc) = ($quotaroot =~ m/^user[\.\/](.)/);
    my ($domain, $dirname);
    ($quotaroot, $domain) = split '@', $quotaroot;
    if ($domain) {
        my ($dc) = ($domain =~ m/^(.)/);
        $dirname = $self->{instance}->{basedir} . "/conf/domain/$dc/$domain";
    }
    else {
        $dirname = $self->{instance}->{basedir} . "/conf";
    }
    $dirname .= "/quota/$uc";
    my $qfn = $quotaroot;
    $qfn =~ s/\//\./g;
    my $filename = "$dirname/$qfn";
    mkpath $dirname;

    open QUOTA,'>',$filename
        or die "Failed to open $filename for writing: $!";

    # STORAGE is special and always present, but -1 if unlimited
    my $limit = $limits->{STORAGE} || -1;
    my $used = $useds->{STORAGE} || 0;
    print QUOTA "$used\n$limit";

    # other resources have a leading keyword if present
    my %keywords = ( MESSAGE => 'M', $self->res_annot_storage => 'AS' );
    foreach my $resource (keys %$limits)
    {
        my $kw = $keywords{$resource} or next;
        $limit = $limits->{$resource};
        $used = $useds->{$resource} || 0;
        print QUOTA " $kw $used $limit";
    }

    print QUOTA "\n";
    close QUOTA;

    $self->{instance}->_fix_ownership($self->{instance}{basedir} . "/conf/quota");
}

# Utility function to check that there is no quota
sub _check_no_quota
{
    my ($self) = @_;
    my $admintalk = $self->{adminstore}->get_client();

    my @res = $admintalk->getquota($self->{quotaroot});
    $self->assert_str_equals('no', $admintalk->get_last_completion_response());
}

sub _check_smmap
{
    my ($self, $name, $expected) = @_;
    my $service = $self->{instance}->get_service('smmap');
    my $sock = $service->get_socket();

    print_netstring($sock, "0 $name");
    my $res = get_netstring($sock);

    $self->assert($res =~ m/$expected/);
}

sub bogus_test_upgrade_v2_4
{
    my ($self) = @_;

    xlog $self, "test resources usage computing upon upgrading a cyrus v2.4 mailbox";

    $self->_set_quotaroot('user.cassandane');
    my $talk = $self->{store}->get_client();
    my $admintalk = $self->{adminstore}->get_client();

    xlog $self, "set ourselves a basic limit";
    $self->_set_limits($self->res_annot_storage => 100000);
    $self->_check_usages($self->res_annot_storage => 0);

    xlog $self, "store annotations";
    my $data = $self->make_random_data(10);
    my $expected_annotation_storage = length($data);
    $talk->setmetadata($self->{store}->{folder}, '/private/comment', { Quote => $data });
    $self->assert_str_equals('ok', $talk->get_last_completion_response());
    $self->_check_usages($self->res_annot_storage => int($expected_annotation_storage/1024));

    xlog $self, "restore cyrus v2.4 mailbox content and quota file";
    $self->{instance}->unpackfile(abs_path('data/cyrus/quota_upgrade_v2_4.user.tar.gz'), 'data/user');
    $self->{instance}->unpackfile(abs_path('data/cyrus/quota_upgrade_v2_4.quota.tar.gz'), 'conf/quota/c');

    xlog $self, "upgrade to version 13 format (v2.5.0)";
    $self->{instance}->run_command({ cyrus => 1 }, 'reconstruct', '-V' => 13);

    # count messages and size from restored mailbox
    my $expected_storage = 0;
    my $expected_message = 0;
    $talk->select($self->{store}->{folder});
    my $responses = $talk->fetch('1:*', 'RFC822.SIZE');
    $self->assert_str_equals('ok', $talk->get_last_completion_response());
    $self->assert_not_null($responses);
    foreach my $response (values(%$responses)) {
        $expected_message++;
        $expected_storage += $response->{'rfc822.size'};
    }
    $talk->close();

    # check we did restore something
    $self->assert_num_not_equals($expected_storage, 0);
    $self->assert_num_not_equals($expected_message, 0);

    # set quota limits on resources which did not exist in previous cyrus versions;
    # when the mailbox was upgraded, new resources quota usage shall have been
    # computed automatically
    $self->_set_limits(
        storage => 100000,
        message => 50000,
        $self->res_annot_storage => 10000,
    );
    $self->_check_usages(
        storage => int($expected_storage/1024),
        message => $expected_message,
        $self->res_annot_storage => int($expected_annotation_storage/1024),
    );
}

sub XXtest_getset_multiple
{
    my ($self) = @_;

    xlog $self, "testing getting and setting multiple quota resources";

    my $admintalk = $self->{adminstore}->get_client();
    my $folder = "user.cassandane";
    my @res;

    xlog $self, "checking there are no initial quotas";
    @res = $admintalk->getquota($folder);
    $self->assert_str_equals('no', $admintalk->get_last_completion_response());
    $self->assert($admintalk->get_last_error() =~ m/Quota root does not exist/i);

    xlog $self, "set both X-ANNOT-COUNT and X-ANNOT-SIZE quotas";
    $admintalk->setquota($folder, "(x-annot-count 20 x-annot-size 16384)");
    $self->assert_str_equals('ok', $admintalk->get_last_completion_response());

    xlog $self, "get both resources back, and not STORAGE";
    @res = $admintalk->getquota($folder);
    $self->assert_str_equals('ok', $admintalk->get_last_completion_response());
    $self->assert_deep_equals(['X-ANNOT-COUNT', 0, 20, 'X-ANNOT-SIZE', 0, 16384], \@res);

    xlog $self, "set the X-ANNOT-SIZE resource only";
    $admintalk->setquota($folder, "(x-annot-size 32768)");
    $self->assert_str_equals('ok', $admintalk->get_last_completion_response());

    xlog $self, "get new -SIZE only and neither STORAGE nor -COUNT";
    @res = $admintalk->getquota($folder);
    $self->assert_str_equals('ok', $admintalk->get_last_completion_response());
    $self->assert_deep_equals(['X-ANNOT-SIZE', 0, 32768], \@res);

    xlog $self, "set all of -COUNT -SIZE and STORAGE";
    $admintalk->setquota($folder, "(x-annot-count 123 storage 123456 x-annot-size 65536)");
    $self->assert_str_equals('ok', $admintalk->get_last_completion_response());

    xlog $self, "get back all three new values";
    @res = $admintalk->getquota($folder);
    $self->assert_str_equals('ok', $admintalk->get_last_completion_response());
    $self->assert_deep_equals(['STORAGE', 0, 123456, 'X-ANNOT-COUNT', 0, 123, 'X-ANNOT-SIZE', 0, 65536], \@res);

    xlog $self, "clear all quotas";
    $admintalk->setquota($folder, "()");
    $self->assert_str_equals('ok', $admintalk->get_last_completion_response());

    # Note: the RFC does not define what happens if you remove all the
    # quotas from a quotaroot.  Cyrus leaves the quotaroot around until
    # quota -f is run to clean it up.
    xlog $self, "get back an empty set of quotas, but the quota root still exists";
    @res = $admintalk->getquota($folder);
    $self->assert_str_equals('ok', $admintalk->get_last_completion_response());
    $self->assert_deep_equals([], \@res);
}

# Magic: the word 'replication' in the name enables a replica
sub XXtest_replication_multiple
    :needs_component_replication
{
    my ($self) = @_;

    xlog $self, "testing replication of multiple quotas";

    my $mastertalk = $self->{master_adminstore}->get_client();
    my $replicatalk = $self->{replica_adminstore}->get_client();

    my $folder = "user.cassandane";
    my @res;

    xlog $self, "checking there are no initial quotas";
    @res = $mastertalk->getquota($folder);
    $self->assert_str_equals('no', $mastertalk->get_last_completion_response());
    $self->assert($mastertalk->get_last_error() =~ m/Quota root does not exist/i);
    @res = $replicatalk->getquota($folder);
    $self->assert_str_equals('no', $replicatalk->get_last_completion_response());
    $self->assert($replicatalk->get_last_error() =~ m/Quota root does not exist/i);

    xlog $self, "set a X-ANNOT-COUNT and X-ANNOT-SIZE quotas on the master";
    $mastertalk->setquota($folder, "(x-annot-count 20 x-annot-size 16384)");
    $self->assert_str_equals('ok', $mastertalk->get_last_completion_response());

    xlog $self, "run replication";
    $self->run_replication();
    $self->check_replication('cassandane');
    $mastertalk = $self->{master_adminstore}->get_client();
    $replicatalk = $self->{replica_adminstore}->get_client();

    xlog $self, "check that the new quota is at both ends";
    @res = $mastertalk->getquota($folder);
    $self->assert_str_equals('ok', $mastertalk->get_last_completion_response());
    $self->assert_deep_equals(['X-ANNOT-COUNT', 0, 20, 'X-ANNOT-SIZE', 0, 16384], \@res);
    @res = $replicatalk->getquota($folder);
    $self->assert_str_equals('ok', $replicatalk->get_last_completion_response());
    $self->assert_deep_equals(['X-ANNOT-COUNT', 0, 20, 'X-ANNOT-SIZE', 0, 16384], \@res);

    xlog $self, "set the X-ANNOT-SIZE quota on the master";
    $mastertalk->setquota($folder, "(x-annot-size 32768)");
    $self->assert_str_equals('ok', $mastertalk->get_last_completion_response());

    xlog $self, "run replication";
    $self->run_replication();
    $self->check_replication('cassandane');
    $mastertalk = $self->{master_adminstore}->get_client();
    $replicatalk = $self->{replica_adminstore}->get_client();

    xlog $self, "check that the new quota is at both ends";
    @res = $mastertalk->getquota($folder);
    $self->assert_str_equals('ok', $mastertalk->get_last_completion_response());
    $self->assert_deep_equals(['X-ANNOT-SIZE', 0, 32768], \@res);
    @res = $replicatalk->getquota($folder);
    $self->assert_str_equals('ok', $replicatalk->get_last_completion_response());
    $self->assert_deep_equals(['X-ANNOT-SIZE', 0, 32768], \@res);

    xlog $self, "clear all the quotas";
    $mastertalk->setquota($folder, "()");
    $self->assert_str_equals('ok', $mastertalk->get_last_completion_response());

    xlog $self, "run replication";
    $self->run_replication();
    $self->check_replication('cassandane');
    $mastertalk = $self->{master_adminstore}->get_client();
    $replicatalk = $self->{replica_adminstore}->get_client();

    xlog $self, "check that the new quota is at both ends";
    @res = $mastertalk->getquota($folder);
    $self->assert_str_equals('ok', $mastertalk->get_last_completion_response());
    $self->assert_deep_equals([], \@res);
    @res = $replicatalk->getquota($folder);
    $self->assert_str_equals('ok', $replicatalk->get_last_completion_response());
    $self->assert_deep_equals([], \@res);
}

Cassandane::Cyrus::TestCase::magic(Bug3735 => sub {
    my ($testcase) = @_;
    $testcase->config_set(quota_db => 'quotalegacy');
    $testcase->config_set(hashimapspool => 1);
    $testcase->config_set(fulldirhash => 1);
    $testcase->config_set(virtdomains => 0);
});

use Cassandane::Tiny::Loader 'tiny-tests/Quota';

1;
