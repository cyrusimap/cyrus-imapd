# SPDX-License-Identifier: BSD-3-Clause-CMU
# See COPYING file at the root of the distribution for more details.

package Cassandane::Cyrus::JMAPQuota;
use strict;
use warnings;
use JSON;
use JSON::XS;
use Data::Dumper;

use base qw(Cassandane::Cyrus::TestCase Cassandane::Mixin::QuotaHelper);
use Cassandane::Util::Log;

use charnames ':full';

sub new
{
    my ($class, @args) = @_;

    my $config = Cassandane::Config->default()->clone();

    $config->set(caldav_realm => 'Cassandane',
                 conversations => 'yes',
                 httpmodules => 'jmap caldav carddav',
                 httpallowcompress => 'no');

    return $class->SUPER::new({
        config => $config,
        jmap => 1,
        deliver => 1,
        adminstore => 1,
        services => [ 'imap', 'sieve', 'http' ]
    }, @args);
}

sub set_up
{
    my ($self) = @_;
    $self->SUPER::set_up();
    $self->{jmap}->DefaultUsing([
        'urn:ietf:params:jmap:core',
        'urn:ietf:params:jmap:quota',
        'urn:ietf:params:jmap:mail',
        'urn:ietf:params:jmap:calendars',
        'urn:ietf:params:jmap:sieve',
    ]);
}

sub tear_down
{
    my ($self) = @_;
    $self->SUPER::tear_down();
}

use Cassandane::Tiny::Loader 'tiny-tests/JMAPQuota';

1;
