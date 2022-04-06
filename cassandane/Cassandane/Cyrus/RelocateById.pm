#!/usr/bin/perl
#
#  Copyright (c) 2022-2022 FastMail Pty Ltd. All rights reserved.
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

package Cassandane::Cyrus::RelocateById;
use strict;
use warnings;
use Data::Dumper;

use lib '.';
use base qw(Cassandane::Cyrus::TestCase);
use Cassandane::Util::Log;

sub new
{
    my ($class, @args) = @_;
    my $config = Cassandane::Config->default()->clone();
    $config->set(
        conversations => 'yes',
        mailbox_legacy_dirs => 'yes',
        delete_mode => 'delayed',
        unixhierarchysep => 'no', # XXX need a :NoUnixHierarchySep
    );
    return $class->SUPER::new({
        config => $config,
        adminstore => 1,
    }, @args);
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

sub test_user_nomatch
    :min_version_3_6
{
    my ($self) = @_;

    my $errfile = $self->{instance}->get_basedir() . '/relocate.err';

    my $user = 'nonexistent';

    $self->{instance}->run_command({
        cyrus => 1,
        redirects => {
            stderr => $errfile,
        },
    }, 'relocate_by_id', '-u', $user);

    my $output;

    { # XXX we should dedup all these slurps sometime...
        local $/;
        open my $fh, '<', $errfile
            or die "Cannot open $errfile for reading: $!";
        $output = <$fh>;
        close $fh;
    }

    # better complain if the user requested doesn't exist!
    $self->assert_matches(qr{$user: user not found}, $output);
}

sub test_mailbox_nomatch
    :min_version_3_6
{
    my ($self) = @_;

    my $errfile = $self->{instance}->get_basedir() . '/relocate.err';

    my $mailbox = 'user.nonexistent';

    $self->{instance}->run_command({
        cyrus => 1,
        redirects => {
            stderr => $errfile,
        },
    }, 'relocate_by_id', $mailbox);

    my $output;

    { # XXX we should dedup all these slurps sometime...
        local $/;
        open my $fh, '<', $errfile
            or die "Cannot open $errfile for reading: $!";
        $output = <$fh>;
        close $fh;
    }

    # better complain if the mailbox requested doesn't exist!
    $self->assert_matches(qr{$mailbox: mailbox not found}, $output);
}

sub test_mailbox_inbox_domain
    :min_version_3_6 :NoAltNamespace :VirtDomains
{
    my ($self) = @_;

    my $adminstore = $self->{adminstore};
    my $admintalk = $adminstore->get_client();

    my $inbox = "user.magicuser\@example.com";
    my $subfolder = "user.magicuser.foo\@example.com";

    $admintalk->create($inbox);
    $admintalk->setacl($inbox, admin => 'lrswipkxtecdan');
    $admintalk->create($subfolder);
    $self->assert_str_equals('ok', $admintalk->get_last_completion_response());

    $adminstore->set_folder($subfolder);
    $self->make_message("Email", store => $adminstore) or die;

    # Create the search database.
    xlog $self, "Run squatter";
    $self->{instance}->run_command({cyrus => 1}, 'squatter');

    my $basedir = $self->{instance}{basedir};
    open(FH, "-|", "find", $basedir);
    my @files = grep { m{/magicuser/} and not m{/conf/lock/} } <FH>;
    close(FH);

    xlog $self, "files exist";
    $self->assert_not_equals(0, scalar @files);

    $self->{instance}->run_command({ cyrus => 1 },
        'relocate_by_id', "user.magicuser\@example.com" );

    open(FH, "-|", "find", $basedir);
    @files = grep { m{/magicuser/} and not m{/conf/lock/} } <FH>;
    close(FH);

    xlog $self, "no files left for this user";
    $self->assert_equals(0, scalar @files);
}

sub test_mailbox_inbox_nodomain
    :min_version_3_6
{
    my ($self) = @_;

    my $adminstore = $self->{adminstore};
    my $admintalk = $adminstore->get_client();

    my $inbox = "user.magicuser";
    my $subfolder = "user.magicuser.foo";

    $admintalk->create($inbox);
    $admintalk->setacl($inbox, admin => 'lrswipkxtecdan');
    $admintalk->create($subfolder);
    $self->assert_str_equals('ok', $admintalk->get_last_completion_response());

    $adminstore->set_folder($subfolder);
    $self->make_message("Email", store => $adminstore) or die;

    # Create the search database.
    xlog $self, "Run squatter";
    $self->{instance}->run_command({cyrus => 1}, 'squatter');

    my $basedir = $self->{instance}{basedir};
    open(FH, "-|", "find", $basedir);
    my @files = grep { m{/magicuser/} and not m{/conf/lock/} } <FH>;
    close(FH);

    xlog $self, "files exist";
    $self->assert_not_equals(0, scalar @files);

    $self->{instance}->run_command({ cyrus => 1 },
        'relocate_by_id', "user.magicuser" );

    open(FH, "-|", "find", $basedir);
    @files = grep { m{/magicuser/} and not m{/conf/lock/} } <FH>;
    close(FH);

    xlog $self, "no files left for this user";
    $self->assert_equals(0, scalar @files);
}

sub test_mailbox_shared_domain
    :min_version_3_6 :NoAltNamespace :VirtDomains
{
    my ($self) = @_;

    my $adminstore = $self->{adminstore};
    my $admintalk = $adminstore->get_client();

    my $mbox = "shared.magic\@example.com";
    my $subfolder = "shared.magic.foo\@example.com";

    $admintalk->create($mbox);
    $admintalk->setacl($mbox, admin => 'lrswipkxtecdan');
    $admintalk->create($subfolder);
    $self->assert_str_equals('ok', $admintalk->get_last_completion_response());

    $adminstore->set_folder($subfolder);
    $self->make_message("Email", store => $adminstore) or die;

    # Create the search database.
    xlog $self, "Run squatter";
    $self->{instance}->run_command({cyrus => 1}, 'squatter');

    my $basedir = $self->{instance}{basedir};
    open(FH, "-|", "find", $basedir);
    my @files = grep { m{/magic/} and not m{/conf/lock/} } <FH>;
    close(FH);

    xlog $self, "files exist";
    $self->assert_not_equals(0, scalar @files);

    $self->{instance}->run_command({ cyrus => 1 },
        'relocate_by_id', $mbox );

    open(FH, "-|", "find", $basedir);
    @files = grep { m{/magic/} and not m{/conf/lock/} } <FH>;
    close(FH);

    xlog $self, "no files left for this hierarchy";
    $self->assert_equals(0, scalar @files);
}

sub test_mailbox_shared_nodomain
    :min_version_3_6
{
    my ($self) = @_;

    my $adminstore = $self->{adminstore};
    my $admintalk = $adminstore->get_client();

    my $mbox = "shared.magic";
    my $subfolder = "shared.magic.foo";

    $admintalk->create($mbox);
    $admintalk->setacl($mbox, admin => 'lrswipkxtecdan');
    $admintalk->create($subfolder);
    $self->assert_str_equals('ok', $admintalk->get_last_completion_response());

    $adminstore->set_folder($subfolder);
    $self->make_message("Email", store => $adminstore) or die;

    # Create the search database.
    xlog $self, "Run squatter";
    $self->{instance}->run_command({cyrus => 1}, 'squatter');

    my $basedir = $self->{instance}{basedir};
    open(FH, "-|", "find", $basedir);
    my @files = grep { m{/magic/} and not m{/conf/lock/} } <FH>;
    close(FH);

    xlog $self, "files exist";
    $self->assert_not_equals(0, scalar @files);

    $self->{instance}->run_command({ cyrus => 1 },
        'relocate_by_id', $mbox );

    open(FH, "-|", "find", $basedir);
    @files = grep { m{/magic/} and not m{/conf/lock/} } <FH>;
    close(FH);

    xlog $self, "no files left for this user";
    $self->assert_equals(0, scalar @files);
}

1;
