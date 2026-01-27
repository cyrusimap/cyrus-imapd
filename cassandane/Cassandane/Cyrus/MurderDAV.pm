# SPDX-License-Identifier: BSD-3-Clause-CMU
# See COPYING file at the root of the distribution for more details.

package Cassandane::Cyrus::MurderDAV;
use strict;
use warnings;
use URI;
use Data::Dumper;

use base qw(Cassandane::Cyrus::TestCase);
use Cassandane::Util::Log;
use Cassandane::Instance;

$Data::Dumper::Sortkeys = 1;

sub new
{
    my ($class, @args) = @_;

    my $config = Cassandane::Config->default()->clone();
    $config->set('conversations' => 'yes');
    $config->set_bits('httpmodules', 'caldav', 'carddav');

    my $self = $class->SUPER::new({
        config => $config,
        httpmurder => 1,
        jmap => 1,
        adminstore => 1
    }, @args);

    $self->needs('component', 'murder');
    $self->needs('component', 'httpd');
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

sub test_aaa_setup
{
    my ($self) = @_;

    # does everything set up and tear down cleanly?
    $self->assert(1);
}

# XXX This can't pass because we don't support multiple murder services
# XXX at once, but renaming out the "bogus" and running it, and it failing,
# XXX proves the infrastructure to prevent requesting both works.
sub bogustest_aaa_imapdav_setup
    :IMAPMurder
{
    my ($self) = @_;

    # does everything set up and tear down cleanly?
    $self->assert(1);
}

sub test_frontend_commands
    :min_version_3_5
{
    my ($self) = @_;
    my $result;

    my $frontend_svc = $self->{frontend}->get_service("http");
    my $frontend_host = $frontend_svc->host();
    my $frontend_port = $frontend_svc->port();
    my $proxy_re = qr{
        \b
        ( localhost | $frontend_host )
        : $frontend_port
        \b
    }x;

    my $frontend_caldav = Net::CalDAVTalk->new(
        user => 'cassandane',
        password => 'pass',
        host => $frontend_host,
        port => $frontend_port,
        scheme => 'http',
        url => "http://$frontend_host:$frontend_port"
    );

    my $CALDAV  = "urn:ietf:params:xml:ns:caldav";
    my $CARDDAV = "urn:ietf:params:xml:ns:carddav";
    my $xml = <<EOF;
<?xml version="1.0" encoding="UTF-8"?>
<D:propfind xmlns:D="DAV:" xmlns:C="$CALDAV" xmlns:A="$CARDDAV">
  <D:prop>
    <C:calendar-home-set/>
    <A:addressbook-home-set/>
  </D:prop>
</D:propfind>
EOF

    xlog $self, "Get current-user-principal";
    my $url = $frontend_caldav->GetCurrentUserPrincipal();
    $self->assert_not_null($url);

    # Copied from Net::DAVTalk::SetURL
    my (undef, undef, undef, $cur_princ) =
        $url =~ m{^http(s)?://([^/:]+)(?::(\d+))?(.*)?};

    xlog $self, "PROPFIND for home-sets";
    my $res = $frontend_caldav->Request('PROPFIND', $cur_princ,
                                     $xml, 'Content-Type' => 'text/xml');

    my $propstat = $res->{'{DAV:}response'}[0]{'{DAV:}propstat'}[0];
    my $props = $propstat->{'{DAV:}prop'};
    $self->assert_str_equals('HTTP/1.1 200 OK',
                             $propstat->{'{DAV:}status'}{content});
    my $cal_home = $props->{"{$CALDAV}calendar-home-set"}{'{DAV:}href'}{content};
    my $card_home =
        $props->{"{$CARDDAV}addressbook-home-set"}{'{DAV:}href'}{content};
    $self->assert_not_null($cal_home);
    $self->assert_not_null($card_home);

    xlog $self, "Create new calendar";
    $frontend_caldav->SetURL($cal_home);
    my $calid1 = $frontend_caldav->NewCalendar({name => 'foo'});
    $self->assert_not_null($calid1);

    xlog $self, "Change calendar name";
    my $newid = $frontend_caldav->UpdateCalendar({ id => $calid1,
                                                   name => 'bar'});
    $self->assert_str_equals($calid1, $newid);

    xlog $self, "Create new event";
    my $eventid1 = $frontend_caldav->NewEvent($calid1, {
        timeZone => 'Etc/UTC',
        start => '2015-01-01T12:00:00',
        duration => 'PT1H',
        title => 'waterfall',
    });
    $self->assert_not_null($eventid1);

    xlog $self, "GET event";
    $res = $frontend_caldav->Request('GET', $cal_home . $eventid1);
    $self->assert_matches(qr/SUMMARY:waterfall/, $res->{content});

    xlog $self, "Get calendars";
    $res = $frontend_caldav->GetCalendars();
    $self->assert_num_equals(2, scalar @{$res});

    my $sync1;
    my $sync2;;
    my $calid2;
    if ($res->[0]{id} eq $calid1) {
        $sync1 = $res->[0]{syncToken};
        $sync2 = $res->[1]{syncToken};
        $calid2 = $res->[1]{id};
    }
    else {
        $sync1 = $res->[1]{syncToken};
        $sync2 = $res->[0]{syncToken};
        $calid2 = $res->[0]{id};
    }
    $self->assert_not_null($calid1);
    $self->assert_not_null($sync1);
    $self->assert_not_null($sync2);

    xlog $self, "Move event";
    my $eventid2 = $frontend_caldav->MoveEvent($eventid1, $calid2);
    $self->assert_not_null($eventid2);

    xlog $self, "Sync Calendars";
    my ($adds, $removes, $errors) =
        $frontend_caldav->SyncEvents($calid1, syncToken => $sync1);
    $self->assert_num_equals(0, scalar @{$adds});
    $self->assert_num_equals(1, scalar @{$removes});
    $self->assert_str_equals($removes->[0],
                             $frontend_caldav->fullpath($eventid1));

    ($adds, $removes, $errors) =
        $frontend_caldav->SyncEvents($calid2, syncToken => $sync2);
    $self->assert_num_equals(1, scalar @{$adds});
    $self->assert_str_equals($adds->[0]{href},
                             $frontend_caldav->fullpath($eventid2));
    $self->assert_str_equals('waterfall', $adds->[0]{title});
    $self->assert_num_equals(0, scalar @{$removes});

    xlog $self, "Delete event";
    $res = $frontend_caldav->DeleteEvent($eventid2);
    $self->assert_num_equals(1, $res);

    xlog $self, "Delete calendar";
    $frontend_caldav->DeleteCalendar($calid1);
    $res = $frontend_caldav->GetCalendar($calid1);
    $self->assert_null($res);

    # XXX test other commands
}

1;
