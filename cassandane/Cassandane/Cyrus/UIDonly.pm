# SPDX-License-Identifier: BSD-3-Clause-CMU
# See COPYING file at the root of the distribution for more details.

package Cassandane::Cyrus::UIDonly;
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

    $config->set(conversations => 'yes');

    my $self = $class->SUPER::new({
        config => $config,
        deliver => 1,
        adminstore => 1,
        services => [ 'imap', 'sieve' ]
    }, @args);

    $self->needs('component', 'sieve');
    return $self;
}

sub set_up
{
    my ($self) = @_;
    $self->SUPER::set_up();
}

sub tear_down
{
    my ($self) = @_;
    $self->SUPER::tear_down();
}

sub uidonly_cmd
{
    my $self = shift;
    my $imaptalk = shift;
    my $cmd = shift;

    my %fetched;
    my %handlers =
    (
        uidfetch => sub
        {
            my (undef, $items, $uid) = @_;

            if (ref($items) ne 'HASH') {
                # IMAPTalk < 4.06. Convert the key/value list into a hash
                my %hash;
                my $kvlist = $imaptalk->_next_atom();
                while (@$kvlist) {
                    my ($key, $val) = (shift @$kvlist, shift @$kvlist);
                    $hash{lc($key)} = $val;
                }
                $items = \%hash;
            }

            $fetched{$uid} = $items;
        },
    );

    $imaptalk->_imap_cmd($cmd, 0, \%handlers, @_);
    $self->assert_str_equals('ok', $imaptalk->get_last_completion_response());

    return %fetched;
}

use Cassandane::Tiny::Loader 'tiny-tests/UIDonly';

1;
