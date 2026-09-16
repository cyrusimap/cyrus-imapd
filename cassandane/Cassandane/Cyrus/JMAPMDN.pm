# SPDX-License-Identifier: BSD-3-Clause-CMU
# See COPYING file at the root of the distribution for more details.

package Cassandane::Cyrus::JMAPMDN;
use strict;
use warnings;
use JSON;

use base qw(Cassandane::Cyrus::TestCase);
use Cassandane::Util::Log;
use Cassandane::Util::CRLF;

use charnames ':full';

sub new
{
    my ($class, @args) = @_;

    my $config = Cassandane::Config->default()->clone();
    $config->set(conversations => 'yes',
                 httpmodules => 'jmap',
                 httpallowcompress => 'no');

    my $self = $class->SUPER::new({
        config => $config,
        jmap => 1,
        adminstore => 1,
        smtpdaemon => 1,
        services => [ 'imap', 'http' ],
    }, @args);

    $self->needs('component', 'jmap');
    return $self;
}

sub jmap_default_using
{
    [
        'urn:ietf:params:jmap:core',
        'urn:ietf:params:jmap:mail',
        'urn:ietf:params:jmap:submission',
        'urn:ietf:params:jmap:mdn',
    ];
}

# Upload a raw message and return its blobId.
sub upload_message
{
    my ($self, $raw) = @_;

    my $res = $self->{jmap}->upload({
        type => 'message/rfc822',
        blob => \$raw,
        accountId => 'cassandane',
    });
    $self->assert($res->is_success);
    return $res->blobId;
}

use Cassandane::Tiny::Loader;

1;
