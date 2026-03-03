# SPDX-License-Identifier: BSD-3-Clause-CMU
# See COPYING file at the root of the distribution for more details.

package Cassandane::Cyrus::JMAPVacationResponse;
use strict;
use warnings;
use DateTime;
use JSON;
use JSON::XS;
use Data::Dumper;
use Storable 'dclone';
use File::Basename;
use IO::File;

use base qw(Cassandane::Cyrus::TestCase);
use Cassandane::Util::Log;

use charnames ':full';

sub new
{
    my ($class, @args) = @_;

    my $config = Cassandane::Config->default()->clone();

    my ($maj, $min) = Cassandane::Instance->get_version();
    if ($maj == 3 && $min == 0) {
        # need to explicitly add 'body' to sieve_extensions for 3.0
        $config->set(sieve_extensions =>
            "fileinto reject vacation vacation-seconds imap4flags notify " .
            "envelope relational regex subaddress copy date index " .
            "imap4flags mailbox mboxmetadata servermetadata variables " .
            "body");
    }
    elsif ($maj < 3) {
        # also for 2.5 (the earliest Cyrus that Cassandane can test)
        $config->set(sieve_extensions =>
            "fileinto reject vacation vacation-seconds imap4flags notify " .
            "envelope relational regex subaddress copy date index " .
            "imap4flags body");
    }

    $config->set(caldav_realm => 'Cassandane',
                 conversations => 'yes',
                 httpmodules => 'jmap',
                 httpallowcompress => 'no');

    my $self = $class->SUPER::new({
        config => $config,
        jmap => 1,
        deliver => 1,
        adminstore => 1,
        services => [ 'imap', 'sieve', 'http' ]
    }, @args);

    $self->needs('component', 'jmap');
    return $self;
}

sub set_up
{
    my ($self) = @_;
    $self->SUPER::set_up();
    $self->{jmap}->DefaultUsing([
        'urn:ietf:params:jmap:core',
        'urn:ietf:params:jmap:vacationresponse'
    ]);
}

sub tear_down
{
    my ($self) = @_;
    $self->SUPER::tear_down();
}

use Cassandane::Tiny::Loader;

1;
