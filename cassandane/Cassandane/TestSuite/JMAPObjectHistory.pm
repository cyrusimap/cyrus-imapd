# SPDX-License-Identifier: BSD-3-Clause-CMU
# See COPYING file at the root of the distribution for more details.

package Cassandane::TestSuite::JMAPObjectHistory;
use v5.28.0;
use warnings;

use base qw(Cassandane::Unit::TestSuite::Cyrus);
use Cassandane::Util::Log;

sub new
{
    my ($class, @args) = @_;

    my $config = Cassandane::Config->default()->clone();
    $config->set(caldav_realm => 'Cassandane',
                 caldav_historical_age => -1,
                 conversations => 'yes',
                 httpmodules => 'carddav caldav jmap',
                 httpallowcompress => 'no',
                 notesmailbox => 'Notes',
                 jmap_nonstandard_extensions => 'yes',
                 delete_mode => 'delayed',
                 expunge_mode => 'delayed');

    my $self = $class->SUPER::new({
        config => $config,
        jmap => 1,
        adminstore => 1,
        services => [ 'imap', 'sieve', 'http' ]
    }, @args);

    $self->needs('component', 'jmap');
    return $self;
}

sub jmap_default_using {
    return [
        'urn:ietf:params:jmap:core',
        'urn:ietf:params:jmap:mail',
        'urn:ietf:params:jmap:submission',
        'urn:ietf:params:jmap:vacationresponse',
        'urn:ietf:params:jmap:sieve',
        'urn:ietf:params:jmap:contacts',
        'urn:ietf:params:jmap:calendars',
        'urn:ietf:params:jmap:object-history',
        'https://cyrusimap.org/ns/jmap/mail',
        'https://cyrusimap.org/ns/jmap/contacts',
        'https://cyrusimap.org/ns/jmap/calendars',
        'https://cyrusimap.org/ns/jmap/notes',
    ];
}

use Cassandane::Tiny::Loader;

1;
