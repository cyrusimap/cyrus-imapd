# SPDX-License-Identifier: BSD-3-Clause-CMU
# See COPYING file at the root of the distribution for more details.

package Cassandane::Cyrus::DBLookup;
use strict;
use warnings;
use DateTime;
use JSON::XS;
use Net::DAVTalk 0.24;
use Net::CardDAVTalk 0.11;
use Text::JSContact 0.01 qw(vcard_to_jscontact);
use Data::Dumper;
use XML::Spice;

use base qw(Cassandane::Cyrus::TestCase);
use Cassandane::Util::Log;

sub new
{
    my $class = shift;

    my $config = Cassandane::Config->default()->clone();
    $config->set(caldav_realm => 'Cassandane');
    $config->set(httpmodules => 'carddav caldav');
    $config->set(httpallowcompress => 'no');
    return $class->SUPER::new({
        adminstore => 1,
        config => $config,
        services => ['imap', 'http'],
    }, @_);
}

sub set_up
{
    my ($self) = @_;
    $self->SUPER::set_up();
    my $service = $self->{instance}->get_service("http");
    $ENV{DEBUGDAV} = 1;
    $self->{carddav} = Net::CardDAVTalk->new(
        user => 'cassandane',
        password => 'pass',
        host => $service->host(),
        port => $service->port(),
        scheme => 'http',
        url => '/',
        expandurl => 1,
    );
}

sub tear_down
{
    my ($self) = @_;
    $self->SUPER::tear_down();
}

use Cassandane::Tiny::Loader;

1;
