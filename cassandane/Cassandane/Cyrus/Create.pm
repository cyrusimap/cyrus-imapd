# SPDX-License-Identifier: BSD-3-Clause-CMU
# See COPYING file at the root of the distribution for more details.

package Cassandane::Cyrus::Create;
use strict;
use warnings;
use Data::Dumper;

use base qw(Cassandane::Cyrus::TestCase);
use Cassandane::Util::Log;
use Cassandane::Util::Slurp;
use Cassandane::Instance;
use Cyrus::IndexFile;

$Data::Dumper::Sortkeys = 1;

sub new
{
    my $class = shift;
    return $class->SUPER::new({ adminstore => 1 }, @_);
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

sub test_bad_userids
{
    my ($self) = @_;

    my $admintalk = $self->{adminstore}->get_client();

    my @bad_userids = (
        'user',
        'user.anyone',
        'user.anonymous',
        'user.%SHARED',
        #'user..foo', # silently fixed by namespace conversion
    );

    foreach my $u (@bad_userids) {
        $admintalk->create($u);
        $self->assert_str_equals('no',
            $admintalk->get_last_completion_response());
    }
}

sub test_bad_userids_unixhs
    :UnixHierarchySep
{
    my ($self) = @_;

    my $admintalk = $self->{adminstore}->get_client();

    my @bad_userids = (
        'user',
        'user/anyone',
        'user/anonymous',
        'user/%SHARED',
        #'user//foo', # silently fixed by namespace conversion
    );

    foreach my $u (@bad_userids) {
        $admintalk->create($u);
        $self->assert_str_equals('no',
            $admintalk->get_last_completion_response());
    }
}

sub test_good_userids
{
    my ($self) = @_;

    my $admintalk = $self->{adminstore}->get_client();

    my @good_userids = (
        'user.$RACL',
    );

    foreach my $u (@good_userids) {
        $admintalk->create($u);
        $self->assert_str_equals('ok',
            $admintalk->get_last_completion_response());
    }
}

sub test_good_userids_unixhs
    :UnixHierarchySep
{
    my ($self) = @_;

    my $admintalk = $self->{adminstore}->get_client();

    my @good_userids = (
        'user/$RACL',
        'user/.foo', # with unixhs, this is not a double-sep!
    );

    foreach my $u (@good_userids) {
        $admintalk->create($u);
        $self->assert_str_equals('ok',
            $admintalk->get_last_completion_response());
    }
}

sub test_bad_mailboxes
{
    my ($self) = @_;

    my $admintalk = $self->{adminstore}->get_client();

    my @bad_mailboxes = (
        '$RACL',
        '$RACL$U$anyone$user.foo',
        'domain.com!user.foo', # virtdomains=off
        #'user.cassandane..blah', # silently fixed by namespace conversion
    );

    foreach my $m (@bad_mailboxes) {
        $admintalk->create($m);
        $self->assert_str_equals('no',
            $admintalk->get_last_completion_response());
    }
}

sub test_good_mailboxes_unixhs
    :UnixHierarchySep
{
    my ($self) = @_;

    my $admintalk = $self->{adminstore}->get_client();

    my @good_mailboxes = (
        'user/cassandane/$RACL',
        'user/cassandane/.foo', # with unixhs, this is not a double-sep!
        'user/foo.',
        'user/foo./bar', # with unixhs, this is not a double-sep!
    );

    foreach my $m (@good_mailboxes) {
        $admintalk->create($m);
        $self->assert_str_equals('ok',
            $admintalk->get_last_completion_response());
    }
}

sub test_good_mailboxes_virtdomains
    :VirtDomains
{
    my ($self) = @_;

    my $admintalk = $self->{adminstore}->get_client();

    my @good_mailboxes = (
        'user.cassandane.$RACL',
        'user.foo@domain.com',
    );

    foreach my $m (@good_mailboxes) {
        $admintalk->create($m);
        $self->assert_str_equals('ok',
            $admintalk->get_last_completion_response());
    }
}

sub test_mailbox_version
    :Conversations
{
    my ($self) = @_;

    my $admintalk = $self->{adminstore}->get_client();

    xlog $self, "Create user INBOX with index v19";
    $admintalk->_imap_cmd('CREATE', 0, '',
                          "user.other", [ 'VERSION', '19' ]);
    $self->assert_str_equals('ok', $admintalk->get_last_completion_response());

    xlog $self, "Verify INBOX with index v19";
    my $dir = $self->{instance}->folder_to_directory('user.other');
    my $file = "$dir/cyrus.index";
    my $fh = IO::File->new($file, "+<");
    die "NO SUCH FILE $file" unless $fh;
    my $index = Cyrus::IndexFile->new($fh);
    $self->assert_num_equals(19, $index->header('MinorVersion'));

    xlog $self, "Create user INBOX.foo";
    $admintalk->create('user.other.foo');

    xlog $self, "Verify INBOX.foo with index v19";
    $dir = $self->{instance}->folder_to_directory('user.other.foo');
    $file = "$dir/cyrus.index";
    $fh = IO::File->new($file, "+<");
    die "NO SUCH FILE $file" unless $fh;
    $index = Cyrus::IndexFile->new($fh);
    $self->assert_num_equals(19, $index->header('MinorVersion'));

    xlog $self, "Verify conv.db is v1";
    my $basedir = $self->{instance}->{basedir};
    my $outfile = "$basedir/conv-output.txt";
    $self->{instance}->run_command({ cyrus => 1,
                                     redirects => { stdout => $outfile } },
                                   'ctl_conversationsdb', '-d', 'other');
    my $data = slurp_file($outfile);
    $self->assert_matches(qr/\$VERSION\t1/, $data);

    xlog $self, "Create user INBOX with index v20 and enable compactids";
    $admintalk->_imap_cmd('CREATE', 0, '',
                          "user.other2", [ 'VERSION', '20', 'COMPACTIDS' ]);
    $self->assert_str_equals('ok', $admintalk->get_last_completion_response());

    xlog $self, "Verify INBOX with index v20";
    $dir = $self->{instance}->folder_to_directory('user.other2');
    $file = "$dir/cyrus.index";
    $fh = IO::File->new($file, "+<");
    die "NO SUCH FILE $file" unless $fh;
    $index = Cyrus::IndexFile->new($fh);
    $self->assert_num_equals(20, $index->header('MinorVersion'));

    xlog $self, "Verify conv.db is v2 and compactids are enabled";
    my $outfile2 = "$basedir/conv-output.txt";
    $self->{instance}->run_command({ cyrus => 1,
                                     redirects => { stdout => $outfile2 } },
                                   'ctl_conversationsdb', '-d', 'other2');
    $data = slurp_file($outfile2);
    $self->assert_matches(qr/\$VERSION\t2/, $data);
    $self->assert_matches(qr/\$COMPACT_EMAILIDS\t1/, $data);
}

1;
