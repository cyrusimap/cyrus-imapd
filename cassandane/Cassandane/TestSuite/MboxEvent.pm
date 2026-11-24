# SPDX-License-Identifier: BSD-3-Clause-CMU
# See COPYING file at the root of the distribution for more details.

package Cassandane::TestSuite::MboxEvent;
use strict;
use warnings;

use experimental q{signatures};

use Data::Dumper;
use JSON;
use Test::Deep qw(bag);

use base qw(Cassandane::Unit::TestSuite::Cyrus);
use Cassandane::Util::Log;
use Cassandane::Generator;
use Cassandane::MessageStoreFactory;
use Cassandane::Instance;

sub new
{
    my ($class, @args) = @_;

    # all of them!
    my @event_groups = qw(
        message
        quota
        flags
        access
        mailbox
        subscription
        calendar
        applepushservice
        metadata
    );

    my $config = Cassandane::Config->default()->clone();
    $config->set(event_groups => join(' ', @event_groups));

    # The default value of event_extra_params is just 'timestamp'; opt in
    # to the parameters individual tests want to inspect.
    $config->set(event_extra_params =>
        'timestamp vnd.fastmail.traceId vnd.fastmail.jmapStates'
        . ' vnd.fastmail.specialUse vnd.cmu.visibleUsers');

    # Enable enough HTTP to drive CalDAV requests from tests that want to
    # exercise the http engine's contribution to events (e.g. X-Trace-Id).
    $config->set(httpmodules => 'caldav carddav jmap');
    $config->set(caldav_realm => 'Cassandane');
    $config->set(jmap_nonstandard_extensions => 'yes');

    return $class->SUPER::new({
        config => $config,
        deliver => 1,
        adminstore => 1,
        services => ['imap', 'http'],
    }, @args);
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

# Creates a folder of user "other" named after $desc, applies the ACL entries
# in $arg->{acl} in order, and asserts that the AclChange for the last of them
# reports exactly the users in $arg->{visible} as vnd.cmu.visibleUsers.  The
# owner, "other", inherits full rights from the parent, so it always belongs
# in $arg->{visible}.
sub assert_visible_users ($self, $desc, $arg)
{
    my $admintalk = $self->{adminstore}->get_client();
    my $mboxname = 'user.other.' . ($desc =~ s/\W+/_/gr);

    $admintalk->create($mboxname) or die "create $mboxname: $@";
    $self->{instance}->getnotify();

    my @acl = $arg->{acl}->@*;
    while (my ($identifier, $rights) = splice @acl, 0, 2) {
        $admintalk->setacl($mboxname, $identifier, $rights)
            or die "setacl $mboxname $identifier: $@";
    }

    my ($event) = reverse
                  grep { $_->{event} eq q{AclChange} }
                  map  { decode_json($_->{MESSAGE}) }
                  $self->{instance}->getnotify->@*;

    $self->assert_cmp_deeply(
        bag($arg->{visible}->@*),
        [ split /\t/, $event->{'vnd.cmu.visibleUsers'} // q{} ],
        $desc,
    );
}

use Cassandane::Tiny::Loader;

1;
