# SPDX-License-Identifier: BSD-3-Clause-CMU
# See COPYING file at the root of the distribution for more details.

package Cassandane::Cyrus::JMAPAdmin;
use strict;
use warnings;

use DateTime;
use JSON::XS;
use Net::CalDAVTalk 0.14;
use Net::CardDAVTalk 0.11;
use Data::Dumper;
use Storable 'dclone';
use File::Basename;

use base qw(Cassandane::Cyrus::TestCase);
use Cassandane::Util::Log;
use Cassandane::Util::Slurp;

use charnames ':full';

sub new
{
    my ($class, @args) = @_;

    my $config = Cassandane::Config->default()->clone();
    $config->set(caldav_create_default => 'no',
                 carddav_create_default => 'no',
                 conversations => 'yes',
                 implicit_owner_rights => "lrsp",
                 httpmodules => 'jmap',
                 httpallowcompress => 'no',
                 virtdomains => 'userid',
                 jmap_nonstandard_extensions => 'yes');

    my $self = $class->SUPER::new({
        config => $config,
        jmap => 1,
        adminstore => 1,
        services => [ 'imap', 'http' ]
    }, @args);

    $self->needs('component', 'jmap');
    return $self;
}

sub jmap_default_using
{
    return [
        'urn:ietf:params:jmap:core',
        'urn:ietf:params:jmap:calendars',
        'urn:ietf:params:jmap:contacts',
        'urn:ietf:params:jmap:mail',
        'urn:ietf:params:jmap:quota',
        'https://cyrusimap.org/ns/jmap/admin',
        'https://cyrusimap.org/ns/jmap/calendars',
        'https://cyrusimap.org/ns/jmap/contacts',
        'https://cyrusimap.org/ns/jmap/mail',
        'https://cyrusimap.org/ns/jmap/jscalendarbis'
    ];
}

sub set_up
{
    my ($self) = @_;
    $self->SUPER::set_up();

    $ENV{DEBUGDAV} = 1;
}

use Cassandane::Tiny::Loader;

1;
