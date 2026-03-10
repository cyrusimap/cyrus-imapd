# SPDX-License-Identifier: BSD-3-Clause-CMU
# See COPYING file at the root of the distribution for more details.

package Cassandane::Cyrus::InProgress;
use strict;
use warnings;
use DateTime;
use JSON;
use JSON::XS;
use Data::Dumper;
use Storable 'dclone';
use File::Basename;
use IO::File;
use Cwd qw(abs_path getcwd);

use base qw(Cassandane::Cyrus::TestCase);
use Cassandane::Util::Log;

use charnames ':full';

sub new
{
    my $class = shift;

    my $config = Cassandane::Config->default()->clone();
    $config->set(mailbox_legacy_dirs => 'yes');
    $config->set(singleinstancestore => 'no');
    $config->set(imap_inprogress_interval => '1s');

    my $self = $class->SUPER::new({
        adminstore => 1,
        config => $config,
        services => ['imap'],
    }, @_);

    $self->needs('component', 'slowio');
    return $self;
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

use Cassandane::Tiny::Loader;

1;
