# SPDX-License-Identifier: BSD-3-Clause-CMU
# See COPYING file at the root of the distribution for more details.

package Cassandane::Cyrus::RelocateById;
use strict;
use warnings;
use Data::Dumper;

use base qw(Cassandane::Cyrus::TestCase);
use Cassandane::Util::Log;
use Cassandane::Util::Slurp;

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

    my $output = slurp_file($errfile);

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

    my $output = slurp_file($errfile);

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
