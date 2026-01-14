# SPDX-License-Identifier: BSD-3-Clause-CMU
# See COPYING file at the root of the distribution for more details.

package Cassandane::Cyrus::Admin;
use strict;
use warnings;
use Data::Dumper;

use base qw(Cassandane::Cyrus::TestCase);
use Cassandane::Util::Log;
use Cassandane::Instance;

sub new
{
    my $class = shift;
    my $config = Cassandane::Config::default()->clone();
    $config->set( imap_admins => 'admin imapadmin' );
    return $class->SUPER::new({ config => $config, adminstore => 1 }, @_);
}

sub set_up
{
    my ($self) = @_;
    $self->SUPER::set_up();

    my $imap = $self->{instance}->get_service('imap');
    $self->{imapadminstore} = $imap->create_store(username => 'imapadmin');
}

sub tear_down
{
    my ($self) = @_;

    $self->{imapadminstore}->disconnect();
    delete $self->{imapadminstore};

    $self->SUPER::tear_down();
}

use Cassandane::Tiny::Loader;

1;
