# SPDX-License-Identifier: BSD-3-Clause-CMU
# See COPYING file at the root of the distribution for more details.

package Cassandane::Cyrus::MurderDAV;
use strict;
use warnings;
use URI;
use Data::Dumper;

use base qw(Cassandane::Cyrus::TestCase);
use Cassandane::Util::Log;
use Cassandane::Instance;

$Data::Dumper::Sortkeys = 1;

sub new
{
    my ($class, @args) = @_;

    my $config = Cassandane::Config->default()->clone();
    $config->set('conversations' => 'yes');
    $config->set_bits('httpmodules', 'caldav', 'carddav');

    my $self = $class->SUPER::new({
        config => $config,
        httpmurder => 1,
        jmap => 1,
        adminstore => 1
    }, @args);

    $self->needs('component', 'murder');
    $self->needs('component', 'httpd');
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

# XXX This can't pass because we don't support multiple murder services
# XXX at once, but renaming out the "bogus" and running it, and it failing,
# XXX proves the infrastructure to prevent requesting both works.
sub bogustest_aaa_imapdav_setup
    :IMAPMurder
{
    my ($self) = @_;

    # does everything set up and tear down cleanly?
    $self->assert(1);
}

use Cassandane::Tiny::Loader;

1;
