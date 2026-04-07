# SPDX-License-Identifier: BSD-3-Clause-CMU
# See COPYING file at the root of the distribution for more details.

package Cassandane::Cyrus::Backup;
use strict;
use warnings;
use experimental 'signatures';
use DBI;
use File::Path;

use base qw(Cassandane::Cyrus::TestCase);
use Cassandane::Util::Log;

sub new ($class, @args)
{
    my $config = Cassandane::Config->default()->clone();
    $config->set(servername => 'backuptest');

    return $class->SUPER::new({
        config => $config,
    }, @args);
}

sub set_up ($self)
{
    $self->SUPER::set_up();
}

sub tear_down ($self)
{
    $self->SUPER::tear_down();
}

# Helper: set up backup directories and return ($meta, $data, $service, $servername)
sub _backup_setup ($self)
{
    my $servername = $self->{instance}->get_servername;
    my $service = $self->{instance}->get_service('backupcyrusd');

    my $data = "$self->{instance}->{basedir}/backupdata";
    my $meta = "$self->{instance}->{basedir}/backupmeta";
    mkdir($data);
    mkdir($meta);

    return ($meta, $data, $service, $servername);
}

# Helper: run BackupUser and return ($version, $size)
sub _do_backup ($self, $meta, $data, $service, $servername)
{
    local $ENV{DEBUGIO} = 1 if $self->{store}->{verbose};

    return Cyrus::Backup::BackupUser(
        $service->host, $service->port,
        $meta, $data, $servername, 'cassandane',
    );
}

# Helper: open the backup state database (read-only)
sub _open_backup_db ($self, $meta)
{
    return DBI->connect(
        "dbi:SQLite:dbname=$meta/backupstate.sqlite3",
        undef, undef,
        { RaiseError => 1 },
    );
}

use Cassandane::Tiny::Loader;

1;
