# SPDX-License-Identifier: BSD-3-Clause-CMU
# See COPYING file at the root of the distribution for more details.

package Cassandane::TestSuite::JMAPMetadata;
use v5.28.0;
use warnings;
use experimental 'signatures';

use base qw(Cassandane::Unit::TestSuite::Cyrus);
use Cassandane::Util::Log;

sub new ($class, @args)
{
    my $config = Cassandane::Config->default()->clone();
    $config->set(caldav_realm => 'Cassandane',
                 caldav_historical_age => -1,
                 conversations => 'yes',
                 httpmodules => 'carddav caldav jmap',
                 httpallowcompress => 'no',
                 jmap_nonstandard_extensions => 'yes',
                 calendar_user_address_set => 'example.com',
                 virtdomains => 'no');

    my $self = $class->SUPER::new({
        config => $config,
        jmap => 1,
        adminstore => 1,
        services => [ 'imap', 'sieve', 'http' ]
    }, @args);

    $self->needs('component', 'jmap');
    return $self;
}

sub jmap_default_using ($self)
{
    return [
        'urn:ietf:params:jmap:core',
        'urn:ietf:params:jmap:blob',
        'urn:ietf:params:jmap:mail',
        'urn:ietf:params:jmap:calendars',
        'urn:ietf:params:jmap:contacts',
        'urn:ietf:params:jmap:sieve',
        'urn:ietf:params:jmap:metadata',
        'https://cyrusimap.org/ns/jmap/mail',
        'https://cyrusimap.org/ns/jmap/calendars',
        'https://cyrusimap.org/ns/jmap/contacts',
    ];
}

use Cassandane::Tiny::Loader;

1;
