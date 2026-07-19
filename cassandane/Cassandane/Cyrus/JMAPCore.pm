# SPDX-License-Identifier: BSD-3-Clause-CMU
# See COPYING file at the root of the distribution for more details.

package Cassandane::Cyrus::JMAPCore;
use strict;
use warnings;
use DateTime;
use JSON::XS;
use Net::CalDAVTalk 0.14;
use Net::CardDAVTalk 0.11;
use Data::Dumper;
use Storable 'dclone';
use MIME::Base64 qw(encode_base64);
use Encode qw(decode_utf8);
use Cwd qw(abs_path getcwd);

use base qw(Cassandane::Cyrus::TestCase);
use Cassandane::Util::Log;
use Cassandane::Util::Slurp;

use charnames ':full';

sub new
{
    my ($class, @args) = @_;

    my $config = Cassandane::Config->default()->clone();
    $config->set(caldav_realm => 'Cassandane',
                 conversations => 'yes',
                 httpmodules => 'carddav caldav jmap',
                 jmap_max_size_upload => '1k',
                 jmap_max_size_request => '4k',
                 jmap_mail_max_size_attachments_per_email => '1m',
                 jmap_nonstandard_extensions => 'yes',
                 notesmailbox => 'Notes',
                 httpallowcompress => 'no');

    my $self = $class->SUPER::new({
        config => $config,
        jmap => 1,
        adminstore => 1,
        smtpdaemon => 1,
        services => [ 'imap', 'http', 'sieve' ]
    }, @args);

    $self->needs('component', 'jmap');
    $self->needs('component', 'sieve');
    return $self;
}

sub jmap_default_using
{
    return [
        'urn:ietf:params:jmap:core',
        'urn:ietf:params:jmap:mail',
        'urn:ietf:params:jmap:submission',
        'urn:ietf:params:jmap:vacationresponse',
        'urn:ietf:params:jmap:calendars',
        'urn:ietf:params:jmap:contacts',
        'urn:ietf:params:jmap:sieve',
        'https://cyrusimap.org/ns/jmap/notes',
    ];
}

use Cassandane::Tiny::Loader;

1;
