# SPDX-License-Identifier: BSD-3-Clause-CMU
# See COPYING file at the root of the distribution for more details.

package Cassandane::Cyrus::Autocreate;
use strict;
use warnings;
use Cwd qw(getcwd);
use Data::Dumper;
use File::Temp qw(tempdir);

use base qw(Cassandane::Cyrus::TestCase);
use Cassandane::Util::Log;

sub new
{
    my $class = shift;
    my $config = Cassandane::Config->default()->clone();

    $config->set(
        autocreate_post => 'yes',
        autocreate_quota => '500000',
        autocreate_inbox_folders => 'Drafts|Sent|Trash|SPAM|plus',
        autocreate_subscribe_folder => 'Drafts|Sent|Trash|SPAM|plus',
        autocreate_sieve_script => '@basedir@/conf/foo_sieve.script',
        autocreate_acl => 'plus anyone p',
        'xlist-drafts' => 'Drafts',
        'xlist-junk' => 'SPAM',
        'xlist-sent' => 'Sent',
        'xlist-trash' => 'Trash',
    );
    my $self = $class->SUPER::new({
        config => $config,
        adminstore => 1,
        deliver => 1,
    }, @_);

    $self->needs('component', 'autocreate');
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

use Cassandane::Tiny::Loader;

1;
