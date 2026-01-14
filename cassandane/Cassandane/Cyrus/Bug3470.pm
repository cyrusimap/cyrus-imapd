# SPDX-License-Identifier: BSD-3-Clause-CMU
# See COPYING file at the root of the distribution for more details.

package Cassandane::Cyrus::Bug3470;
use strict;
use warnings;
use DateTime;
use Data::Dumper;

use base qw(Cassandane::Cyrus::TestCase);

sub new
{
    my $class = shift;

    my $config = Cassandane::Config->default()->clone();
    $config->set(virtdomains => 'userid');
    $config->set(unixhierarchysep => 'on');
    $config->set(altnamespace => 'yes');

    return $class->SUPER::new({ config => $config }, @_);
}

sub set_up
{
    my ($self) = @_;
    $self->SUPER::set_up();

    my $imaptalk = $self->{store}->get_client();

    # Bug #3470 folders
    # sub folders only
    $imaptalk->create("Drafts") || die;
    $imaptalk->create("2001/05/wk18") || die;
    $imaptalk->create("2001/05/wk19") || die;
    $imaptalk->create("2001/05/wk20") || die;
    $imaptalk->subscribe("2001/05/wk20") || die;
}

sub tear_down
{
    my ($self) = @_;
    $self->SUPER::tear_down();
}

use Cassandane::Tiny::Loader;

1;
