# SPDX-License-Identifier: BSD-3-Clause-CMU
# See COPYING file at the root of the distribution for more details.

package Cassandane::Cyrus::ChkCyrus;
use strict;
use warnings;

use File::Path qw(make_path remove_tree);
use JSON::XS;

use base qw(Cassandane::Cyrus::TestCase);
use Cassandane::Util::Log;
use Cassandane::Util::Slurp;
use Cassandane::Instance;

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

# Run chk_cyrus in audit mode and return its findings as an arrayref of
# hashrefs, one per JSON line.
sub audit_json
{
    my ($self, @args) = @_;

    my $outfile = $self->{instance}->get_basedir() . "/chk_cyrus.out";

    $self->{instance}->run_command(
        { cyrus => 1, redirects => { stdout => $outfile } },
        'chk_cyrus', '--json', @args);

    my @findings;
    foreach my $line (split /\n/, slurp_file($outfile)) {
        next unless length $line;
        push @findings, decode_json($line);
    }

    return \@findings;
}

# The set of finding codes present, for the common "did X get reported"
# assertion.
sub codes
{
    my ($findings) = @_;
    return map { $_->{code} } @{$findings};
}

sub assert_has_code
{
    my ($self, $findings, $code) = @_;
    my @codes = codes($findings);
    $self->assert(scalar(grep { $_ eq $code } @codes),
                  "expected finding '$code', got: " . join(q{,}, @codes));
}

sub assert_lacks_code
{
    my ($self, $findings, $code) = @_;
    my @codes = codes($findings);
    $self->assert(!scalar(grep { $_ eq $code } @codes),
                  "unexpected finding '$code'");
}

# The mailboxes.db path and backend, for tests that damage the database.
sub mailboxes_db
{
    my ($self) = @_;
    return $self->{instance}->get_basedir() . "/conf/mailboxes.db";
}

sub mailboxes_db_format
{
    my ($self) = @_;
    return $self->{instance}->{config}->get('mboxlist_db');
}


# Count tombstone (deleted-marker) N records in mailboxes.db.
sub count_tombstones
{
    my ($self) = @_;
    my %db = $self->{instance}->run_dbcommand(
        $self->mailboxes_db(), $self->mailboxes_db_format(), ['SHOW']);
    my $n = 0;
    foreach my $k (keys %db) {
        next unless $k =~ m/^N/;
        $n++ if $db{$k} =~ m/\bT\s+\S*d/;
    }
    return $n;
}

# Does an I record exist for this uniqueid?
sub has_i_record
{
    my ($self, $uniqueid) = @_;
    my %db = $self->{instance}->run_dbcommand(
        $self->mailboxes_db(), $self->mailboxes_db_format(), ['SHOW']);
    return exists $db{"I$uniqueid"} ? 1 : 0;
}

# Backdate every tombstone's mtime so that pruning will consider it.
# Cassandane creates everything fresh, so nothing is otherwise old enough.
sub backdate_tombstones
{
    my ($self, $days) = @_;
    $days //= 30;

    my $db = $self->mailboxes_db();
    my $fmt = $self->mailboxes_db_format();
    my %all = $self->{instance}->run_dbcommand($db, $fmt, ['SHOW']);
    my $when = time() - ($days * 86400);

    foreach my $k (keys %all) {
        next unless $k =~ m/^N/;
        next unless $all{$k} =~ m/\bT\s+\S*d/;
        my $v = $all{$k};
        $v =~ s/(\sM\s+)\d+/$1$when/;
        $self->{instance}->run_dbcommand($db, $fmt, ['SET', $k, $v]);
    }
}

use Cassandane::Tiny::Loader;

1;
