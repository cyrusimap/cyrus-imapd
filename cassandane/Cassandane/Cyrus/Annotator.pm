# SPDX-License-Identifier: BSD-3-Clause-CMU
# See COPYING file at the root of the distribution for more details.

package Cassandane::Cyrus::Annotator;
use strict;
use warnings;
use Cwd qw(abs_path);

use base qw(Cassandane::Cyrus::TestCase);
use Cassandane::Util::Log;
use Cassandane::Util::Slurp;
use Cassandane::Util::Wait;

sub new
{
    my $class = shift;
    my $config = Cassandane::Config->default()->clone();

    $config->set(
        annotation_callout => '@basedir@/conf/socket/annotator.sock',
        conversations => 'yes',
        httpmodules => 'jmap',
        jmap_nonstandard_extensions => 'yes',
    );

    my $self = $class->SUPER::new({
        config => $config,
        deliver => 1,
        start_instances => 0,
        adminstore => 1,

        jmap => 1,
        services => [ 'imap', 'sieve', 'http' ]
    }, @_);

    $self->needs('component', 'jmap');

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

sub start_my_instances
{
    my ($self) = @_;

    $self->{instance}->add_generic_listener(
        name => 'annotator',
        port => $self->{instance}->{config}->get('annotation_callout'),
        argv => sub {
            my ($listener) = @_;
            return (
                abs_path('utils/annotator.pl'),
                '--port', $listener->port(),
                '--pidfile', '@basedir@/run/annotator.pid',
                );
        });

    $self->_start_instances();
}

# Note: remove_annotation can't really be tested with local
# delivery, just with the APPEND command.

use Cassandane::Tiny::Loader;

1;
