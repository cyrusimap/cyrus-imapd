#!/usr/bin/perl
#
#  Copyright (c) 2011-2024 FastMail Pty Ltd. All rights reserved.
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

package Cassandane::Mixin::QuotaHelper;
use strict;
use warnings;

use File::Path ();

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
    # and limits previously by _set_quotalimits().
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
# quota -f.  Rather hacky.  Both _set_quotaroot() and _set_quotalimits()
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
    File::Path::mkpath($dirname);

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


sub _set_quotaroot
{
    my ($self, $quotaroot) = @_;
    $self->{quotaroot} = $quotaroot;
}

# Utility function to set quota limits and check that it stuck
sub _set_quotalimits
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

1;
