# SPDX-License-Identifier: BSD-3-Clause-CMU
# See COPYING file at the root of the distribution for more details.

package Cassandane::Cyrus::Carddav;
use strict;
use warnings;
use DateTime;
use JSON::XS;
use Net::DAVTalk 0.14;
use Net::CardDAVTalk 0.05;
use Net::CardDAVTalk::VCard;
use Data::Dumper;
use XML::Spice;
use XML::Simple;

use base qw(Cassandane::Cyrus::TestCase);
use Cassandane::Util::Log;

sub new
{
    my $class = shift;

    my $config = Cassandane::Config->default()->clone();
    $config->set(caldav_realm => 'Cassandane');
    $config->set(httpmodules => 'carddav caldav');
    $config->set(httpallowcompress => 'no');
    $config->set(vcard_max_size => 100000);

    my $self = $class->SUPER::new({
        adminstore => 1,
        config => $config,
        services => ['imap', 'http'],
    }, @_);

    $self->needs('component', 'httpd');
    return $self;
}

sub set_up
{
    my ($self) = @_;
    $self->SUPER::set_up();
    $ENV{DEBUGDAV} = 1;
}

sub tear_down
{
    my ($self) = @_;
    $self->SUPER::tear_down();
}

use Cassandane::Tiny::Loader 'tiny-tests/Carddav';

1;
