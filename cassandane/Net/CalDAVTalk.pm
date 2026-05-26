package Net::CalDAVTalk;

use 5.006;
use strict;
use warnings FATAL => 'all';

use Net::DAVTalk;
use base qw(Net::DAVTalk);

use Carp;
use DateTime::Format::ICal;
use DateTime::TimeZone;
use JSON::XS qw(encode_json);
use Text::JSCalendar;
use Text::VCardFast qw(vcard2hash);
use XML::Spice;
use Digest::SHA qw(sha1_hex);
use URI::Escape qw(uri_unescape);
use JSON;

our $BATCHSIZE = 100;




our (
  $DefaultCalendarColour,
  $DefaultDisplayName,
);

our $UTC = DateTime::TimeZone::UTC->new();
our $FLOATING = DateTime::TimeZone::Floating->new();
our $LOCALE = DateTime::Locale->load('en_US');

# Beginning and End of time as used for "all event" date ranges
# Reducing this range may result in events disappearing from FastMail
# calendars, as we think they have been deleted from the other end,
# so best to avoid this.
# However, from my tests, the events should be resurrected once this date
# window includes them again.

my $BoT = '1970-01-01T00:00:00';
my $EoT = '2038-01-19T00:00:00';

my (
  %ColourNames,
  %UTCLinks,
  %EventKeys,
);

BEGIN {
  $DefaultCalendarColour = '#0252D4';
  $DefaultDisplayName    = 'Untitled Calendar';

  %EventKeys = (
    '' => {
      uid                  => [0, 'string',    1, undef],
      relatedTo            => [0, 'string',    0, undef],
      prodId               => [0, 'string',    0, undef],
      created              => [0, 'utcdate',   0, undef],
      updated              => [0, 'utcdate',   1, undef],
      sequence             => [0, 'number',    0, undef],
      title                => [0, 'string',    0, ''],
      description          => [0, 'string',    0, ''],
      links                => [0, 'object',    0, undef],
      locale               => [0, 'string',    0, undef],
      localizations        => [0, 'patch',     0, undef],
      locations            => [0, 'object',    0, undef],
      showWithoutTime      => [0, 'bool',      0, $JSON::false],
      start                => [0, 'localdate', 1, undef],
      timeZone             => [0, 'timezone',  0, undef],
      duration             => [0, 'duration',  0, undef],
      recurrenceRule       => [0, 'object',    0, undef],
      recurrenceOverrides  => [0, 'patch',     0, undef],
      status               => [0, 'string',    0, undef],
      freeBusyStatus       => [0, 'string',    0, undef],
      organizerCalendarAddress => [0, 'string', 0, undef],
      participants         => [0, 'object',    0, undef],
      alerts               => [0, 'object',    0, undef],
    },
    links => {
      href                 => [0, 'string',    1, undef],
      type                 => [0, 'string',    0, undef],
      size                 => [0, 'number',    0, undef],
      rel                  => [0, 'string',    1, undef],
      title                => [0, 'string',    1, undef],
      properties           => [0, 'string',    1, undef],
    },
    locations => {
      name                 => [0, 'string',    0, undef],
      accessInstructions   => [0, 'string',    0, undef],
      rel                  => [0, 'string',    0, 'unknown'],
      timeZone             => [0, 'timezone',  0, undef],
      address              => [0, 'object',    0, undef],
      coordinates          => [0, 'string',    0, undef],
      uri                  => [0, 'string',    0, undef],
    },
    recurrenceRule => {
      frequency            => [0, 'string',    1, undef],
      interval             => [0, 'number',    0, undef],
      rscale               => [0, 'string',    0, 'gregorian'],
      skip                 => [0, 'string',    0, 'omit'],
      firstDayOfWeek       => [0, 'string',    0, 'mo'],
      byDay                => [1, 'object',    0, undef],
      byMonthDay           => [1, 'number',    0, undef],
      byMonth              => [1, 'string',    0, undef],
      byYearDay            => [1, 'number',    0, undef],
      byWeekNo             => [1, 'number',    0, undef],
      byHour               => [1, 'number',    0, undef],
      byMinute             => [1, 'number',    0, undef],
      bySecond             => [1, 'number',    0, undef],
      bySetPosition        => [1, 'number',    0, undef],
      count                => [0, 'number',    0, undef],
      until                => [0, 'localdate', 0, undef],
    },
    byDay => {
      day                  => [0, 'string',    1, undef],
      nthOfPeriod          => [0, 'number',    0, undef],
    },
    participants => {
      name                 => [0, 'string',    1, undef],
      email                => [0, 'string',    1, undef],
      kind                 => [0, 'string',    0, 'individual'],
      roles                => [0, 'object',    0, undef],
      calendarAddress      => [0, 'string',    0, undef],
      participationStatus  => [0, 'string',    0, 'needs-action'],
      expectReply          => [0, 'bool',      0, $JSON::false],
      scheduleAgent        => [0, 'string',    0, undef],
      scheduleUpdated      => [0, 'utcdate',   0, undef],
      memberOf             => [0, 'object',    0, undef],
    },
    alerts => {
      action               => [0, 'string',    1, undef],
      trigger              => [0, 'object',    1, undef],
    },
  );

  # Colour names defined in CSS Color Module Level 3
  # http://www.w3.org/TR/css3-color/

  %ColourNames
    = map { $_ => 1 }
      qw{
        aliceblue
        antiquewhite
        aqua
        aquamarine
        azure
        beige
        bisque
        black
        blanchedalmond
        blue
        blueviolet
        brown
        burlywood
        cadetblue
        chartreuse
        chocolate
        coral
        cornflowerblue
        cornsilk
        crimson
        cyan
        darkblue
        darkcyan
        darkgoldenrod
        darkgray
        darkgreen
        darkgrey
        darkkhaki
        darkmagenta
        darkolivegreen
        darkorange
        darkorchid
        darkred
        darksalmon
        darkseagreen
        darkslateblue
        darkslategray
        darkslategrey
        darkturquoise
        darkviolet
        deeppink
        deepskyblue
        dimgray
        dimgrey
        dodgerblue
        firebrick
        floralwhite
        forestgreen
        fuchsia
        gainsboro
        ghostwhite
        gold
        goldenrod
        gray
        green
        greenyellow
        grey
        honeydew
        hotpink
        indianred
        indigo
        ivory
        khaki
        lavender
        lavenderblush
        lawngreen
        lemonchiffon
        lightblue
        lightcoral
        lightcyan
        lightgoldenrodyellow
        lightgray
        lightgreen
        lightgrey
        lightpink
        lightsalmon
        lightseagreen
        lightskyblue
        lightslategray
        lightslategrey
        lightsteelblue
        lightyellow
        lime
        limegreen
        linen
        magenta
        maroon
        mediumaquamarine
        mediumblue
        mediumorchid
        mediumpurple
        mediumseagreen
        mediumslateblue
        mediumspringgreen
        mediumturquoise
        mediumvioletred
        midnightblue
        mintcream
        mistyrose
        moccasin
        navajowhite
        navy
        oldlace
        olive
        olivedrab
        orange
        orangered
        orchid
        palegoldenrod
        palegreen
        paleturquoise
        palevioletred
        papayawhip
        peachpuff
        peru
        pink
        plum
        powderblue
        purple
        red
        rosybrown
        royalblue
        saddlebrown
        salmon
        sandybrown
        seagreen
        seashell
        sienna
        silver
        skyblue
        slateblue
        slategray
        slategrey
        snow
        springgreen
        steelblue
        tan
        teal
        thistle
        tomato
        turquoise
        violet
        wheat
        white
        whitesmoke
        yellow
        yellowgreen
      };

  %UTCLinks = (
    'Etc/GMT-0'     => 1,
    'Etc/GMT+0'     => 1,
    'Etc/GMT0'      => 1,
    'Etc/GMT'       => 1,
    'Etc/Greenwich' => 1,
    'Etc/UCT'       => 1,
    'Etc/Universal' => 1,
    'Etc/UTC'       => 1,
    'Etc/Zulu'      => 1,
    'GMT'           => 1,
    'UCT'           => 1,
    'UTC'           => 1,
  );
}


=head1 NAME

Net::CalDAVTalk - Module to talk CalDAV and give a JSON interface to the data

=head1 VERSION

Version 0.16

=cut

our $VERSION = '0.17';


=head1 SYNOPSIS

This module is the initial release of the code used at FastMail for talking
to CalDAV servers.  It's quite specific to an early version of our API, so
while it might be useful to others, it's being pushed to CPAN more because
the Cassandane test suite needs it.

See Net::DAVTalk for details on how to specify hosts and paths.

    my $CalDAV = Net::CalDAVTalk->new(
        user => $service->user(),
        password => $service->pass(),
        host => $service->host(),
        port => $service->port(),
        scheme => 'http',
        url => '/',
        expandurl => 1,
    );

or using DNS:

    my $domain = $user;
    $domain =~ s/.*\@//;

    my $url;
    my ($reply) = $Resolver->search("_caldavs._tcp.$domain", "srv");
    if ($reply) {
      my @d = $reply->answer;
      if (@d) {
        my $host = $d[0]->target();
        my $port = $d[0]->port();
        $url = "https://$host";
        $url .= ":$port" unless $port eq 443;
      }
    }

This will use the '/.well-known/caldav' address to find the actual current user
principal, and from there the calendar-home-set for further operations.

    my $foo = Net::CalDAVTalk->new(
       user => $user,
       password => $password,
       url => $url,
       expandurl => 1,
    );


=head1 SUBROUTINES/METHODS

=head2 new(%args)

Takes the same arguments as Net::DAVTalk and adds the caldav namespaces
and some Cyrus specific namespaces for all XML requests.

  A => 'http://apple.com/ns/ical/'
  C => 'urn:ietf:params:xml:ns:caldav'
  CY => 'http://cyrusimap.org/ns/'
  UF => 'http://cyrusimap.org/ns/userflag/'
  SF => 'http://cyrusimap.org/ns/sysflag/'

=cut

sub new {
  my ($Class, %Params) = @_;

  $Params{homesetns} = 'C';
  $Params{homeset} = 'calendar-home-set';
  $Params{wellknown} = 'caldav';

  my $Self = $Class->SUPER::new(%Params);

  $Self->ns(A => 'http://apple.com/ns/ical/');
  $Self->ns(C => 'urn:ietf:params:xml:ns:caldav');
  $Self->ns(CY => 'http://cyrusimap.org/ns/');
  $Self->ns(UF => 'http://cyrusimap.org/ns/userflag/');
  $Self->ns(SF => 'http://cyrusimap.org/ns/sysflag/');

  return $Self;
}

sub _jscal {
  my $Self = shift;
  $Self->{_jscal} ||= Text::JSCalendar->new();
  return $Self->{_jscal};
}

=head2 $self->tz($name)

Returns a DateTime::TimeZone object for the given name, but caches
the result for speed.

=cut

sub tz {
  my $Self = shift;
  my $tzName = shift;
  return $FLOATING unless defined $tzName;
  return $UTC if $UTCLinks{$tzName};
  unless (exists $Self->{_tz}{$tzName}) {
    $Self->{_tz}{$tzName} = DateTime::TimeZone->new(name => $tzName);
  }
  return $Self->{_tz}{$tzName};
}

=head2 $self->logger(sub { })

Sets a function to receive all log messages.  Gets called with the first
argument being a level name, and then a list of items to log:

e.g.

   $CalDAV->logger(sub {
      my $level = shift;
      return if ($level eq 'debug' and not $ENV{DEBUG_CALDAV});
      warn "LOG $level: $_\n" for @_;
   });

=cut

sub logger {
  my $Self = shift;

  if ($@) {
    $Self->{logger} = shift;
  }

  return $Self->{logger};
}

=head2 $self->DeleteCalendar($calendarId)

Delete the named calendar from the server (shorturl - see Net::DAVTalk)

=cut

=head2 $Cal->DeleteCalendar($calendarId)

Delete the calendar with collection name $calendarId (full or relative path)

e.g.

    $Cal->DeleteCalendar('Default');

=cut

sub DeleteCalendar {
  my ($Self, $calendarId) = @_;

  unless ($calendarId) {
    confess 'Calendar not specified';
  }

  $Self->Request(
    'DELETE',
    "$calendarId/",
  );

  return 1;
}

sub _fixColour {
  my $color = lc(shift || '');

  return $color if $ColourNames{$color};
  return $DefaultCalendarColour unless $color =~ m/^\s*(\#[a-f0-9]{3,8})\s*$/;
  $color = $1;
  return uc($color) if length($color) == 7;

  # Optional digit is for transparency (RGBA)
  if ( $color =~ m/^#(.)(.)(.).?$/ ) {
    return uc "#$1$1$2$2$3$3";
  }

  # Last two digits are for transparency (RGBA)
  if ( length($color) == 9 ) {
    return uc(substr($color,0,7));
  }

  return $DefaultCalendarColour;
}


=head2 $self->GetCalendar($calendarId)

Get a single calendar from the server by calendarId
(currently implemented very inefficiently as a get
of all calendars.  Returns undef if the calendar
doesn't exist.

e.g
   my $Calendar = $CalDAV->GetCalendar('Default');

=cut

sub GetCalendar {
  my ($Self, $CalendarId) = @_;
  my $Calendars = $Self->GetCalendars();
  die "No calendars" unless ($Calendars and @$Calendars);
  my ($Calendar) = grep { $_->{id} eq $CalendarId } @$Calendars;
  return $Calendar;
}

=head2 $self->GetCalendars(Properties => [])

Fetch all the calendars on the server.  You can request additional
properties, but they aren't parsed well yet.

e.g

   my $Calendars = $CalDAV->GetCalendars();
   foreach my $Cal (@$Calendars) {
      # do stuff
   }

=cut

sub GetCalendars {
  my ($Self, %Args) = @_;

  # XXX To generalise for CPAN:
  # XXX   - the PROPFIND should be D:allprop unless $Args{Properties} is set
  # XXX   - return all properties as object attributes without renaming
  # XXX   - translate property names to our own liking within ME::CalDAV

  my %Properties = map { $_ => 1 } (
    'D:displayname',
    'D:resourcetype',
    'A:calendar-color',
    'D:current-user-privilege-set',
    'D:acl',
    'A:calendar-order',
    'C:calendar-timezone',
    'D:sync-token',
    'D:supported-report-set',
    'C:supported-calendar-data',
    @{$Args{Properties} || []},
  );

  my $Response = $Self->Request(
    'PROPFIND',
    '',
    x('D:propfind', $Self->NS(),
      x('D:prop',
        map { x($_) } keys %Properties,
      ),
    ),
    Depth => 1,
  );

  my @Calendars;

  my $NS_A = $Self->ns('A');
  my $NS_C = $Self->ns('C');
  my $NS_CY = $Self->ns('CY');
  my $NS_D = $Self->ns('D');
  foreach my $Response (@{$Response->{"{$NS_D}response"} || []}) {
    next unless $Response->{"{$NS_D}href"}{content};
    my $href = uri_unescape($Response->{"{$NS_D}href"}{content});

    # grab the short version of the path
    my $calendarId = $Self->shortpath($href);
    # and remove trailing slash always
    $calendarId =~ s{/$}{};

    foreach my $Propstat (@{$Response->{"{$NS_D}propstat"} || []}) {
      next unless $Propstat->{"{$NS_D}prop"}{"{$NS_D}resourcetype"}{"{$NS_C}calendar"};

      # XXX - this should be moved into ME::CalDAV::GetCalendars()
      my $visData = $Propstat->{"{$NS_D}prop"}{"{$NS_C}X-FM-isVisible"}{content};
      my $isVisible = (not defined($visData) or $visData) ? $JSON::true : $JSON::false;

      my %Privileges = (
        mayAdmin => $JSON::false,
        mayWrite => $JSON::false,
        mayRead => $JSON::false,
        mayReadFreeBusy => $JSON::false,
      );

      my $Priv = $Propstat->{"{$NS_D}prop"}{"{$NS_D}current-user-privilege-set"}{"{$NS_D}privilege"};
      $Priv = [] unless ($Priv and ref($Priv) eq 'ARRAY');
      foreach my $item (@$Priv) {
        $Privileges{'mayAdmin'} = $JSON::true if $item->{"{$NS_CY}admin"};
        $Privileges{'mayWrite'} = $JSON::true if $item->{"{$NS_D}write-content"};
        $Privileges{'mayRead'} = $JSON::true if $item->{"{$NS_D}read"};
        $Privileges{'mayReadFreeBusy'} = $JSON::true if $item->{"{$NS_C}read-free-busy"};
      }

      my $CanSync;
      my $Report = $Propstat->{"{$NS_D}prop"}{"{$NS_D}supported-report-set"}{"{$NS_D}supported-report"};
      $Report = [] unless ($Report and ref($Report) eq 'ARRAY');
      foreach my $item (@$Report) {
        # XXX - do we want to check the other things too?
        $CanSync = 1 if $item->{"{$NS_D}report"}{"{$NS_D}sync-collection"};
      }

      my $CanEvent;
      my $Type = $Propstat->{"{$NS_D}prop"}{"{$NS_C}supported-calendar-data"}{"{$NS_C}calendar-data"};
      $Type = [] unless ($Type and ref($Type) eq 'ARRAY');
      foreach my $item (@$Type) {
        next unless $item->{"\@content-type"};
        $CanEvent = 1 if $item->{"\@content-type"}{content} eq "application/event+json";
      }

      # XXX - temporary compat
      $Privileges{isReadOnly} = $Privileges{mayWrite} ? $JSON::false : $JSON::true;

      my @ShareWith;
      my $ace = $Propstat->{"{$NS_D}prop"}{"{$NS_D}acl"}{"{$NS_D}ace"};
      $ace = [] unless ($ace and ref($ace) eq 'ARRAY');
      foreach my $Acl (@$ace) {
        next if $Acl->{"{$NS_D}protected"};  # ignore admin ACLs
        next unless $Acl->{"{$NS_D}grant"};
        next unless $Acl->{"{$NS_D}grant"}{"{$NS_D}privilege"};
        next unless ref($Acl->{"{$NS_D}grant"}{"{$NS_D}privilege"}) eq 'ARRAY';
        # XXX - freeBusyPublic here?  Or should we do it via the web server?
        my $user = uri_unescape($Acl->{"{$NS_D}principal"}{"{$NS_D}href"}{content} // '');
        next unless $user =~ m{^/dav/principals/user/([^/]+)};
        my $email = $1;
        next if $email eq 'admin';
        my %ShareObject = (
          email => $email,
          mayAdmin => $JSON::false,
          mayWrite => $JSON::false,
          mayRead => $JSON::false,
          mayReadFreeBusy => $JSON::false,
        );
        foreach my $item (@{$Acl->{"{$NS_D}grant"}{"{$NS_D}privilege"}}) {
          $ShareObject{'mayAdmin'} = $JSON::true if $item->{"{$NS_CY}admin"};
          $ShareObject{'mayWrite'} = $JSON::true if $item->{"{$NS_D}write-content"};
          $ShareObject{'mayRead'} = $JSON::true if $item->{"{$NS_D}read"};
          $ShareObject{'mayReadFreeBusy'} = $JSON::true if $item->{"{$NS_C}read-free-busy"};
        }

        push @ShareWith, \%ShareObject;
      }

      my %Cal = (
        id         => $calendarId,
        name       => ($Propstat->{"{$NS_D}prop"}{"{$NS_D}displayname"}{content} || $DefaultDisplayName),
        href       => $href,
        color      => _fixColour($Propstat->{"{$NS_D}prop"}{"{$NS_A}calendar-color"}{content}),
        timeZone   => $Propstat->{"{$NS_D}prop"}{"{$NS_C}calendar-timezone"}{content},
        isVisible  => $isVisible,
        precedence => int($Propstat->{"{$NS_D}prop"}{"{$NS_A}calendar-order"}{content} || 1),
        syncToken  => ($Propstat->{"{$NS_D}prop"}{"{$NS_D}sync-token"}{content} || ''),
        shareWith  => (@ShareWith ? \@ShareWith : $JSON::false),
        canSync    => ($CanSync ? $JSON::true : $JSON::false),
        _can_event => ($CanEvent ? $JSON::true : $JSON::false),
        %Privileges,
      );


      push @Calendars, \%Cal;
    }
  }

  return \@Calendars;
}

=head2 $self->NewCalendar($Args)

Create a new calendar.  The Args are the as the things returned by GetCalendars,
except that if you don't provide 'id' (same as shorturl), then a UUID will be
generated for you.  It's recommended to not provide 'id' unless you need to
create a specific path for compatibility with other things, and to use 'name'
to identify the calendar for users.  'name' is stored as DAV:displayname.

e.g.

   my $Id = $CalDAV->NewCalendar({name => 'My Calendar', color => 'aqua'});

(Color names will be translated based on the CSS name list)

=cut

sub NewCalendar {
  my ($Self, $Args) = @_;

  unless (ref($Args) eq 'HASH') {
    confess 'Invalid calendar';
  }

  # The URL should be "/$calendarId/" but this isn't true with Zimbra (Yahoo!
  # Calendar). It will accept a MKCALENDAR at "/$calendarId/" but will rewrite
  # the calendar's URL to be "/$HTMLEscapedDisplayName/". I'm sure MKCALENDAR
  # should follow WebDAV's MKCOL method here, but it's not specified in CalDAV.

  # default values
  $Args->{id} //= $Self->genuuid();
  $Args->{name} //= $DefaultDisplayName;

  my $calendarId = $Args->{id};

  my @Properties;

  push @Properties, x('D:displayname', $Args->{name});

  if (exists $Args->{isVisible}) {
    push @Properties, x('C:X-FM-isVisible', ($Args->{isVisible} ? 1 : 0));
  }

  if (exists $Args->{color}) {
    push @Properties, x('A:calendar-color', _fixColour($Args->{color}));
  }

  if (exists $Args->{timeZone}) {
    push @Properties, x('C:calendar-timezone', $Args->{timeZone});
  }

  if (exists $Args->{precedence}) {
    unless (($Args->{precedence} // '') =~ /^\d+$/) {
      confess "Invalid precedence ($Args->{precedence}) (expected int >= 0)";
    }

    push @Properties, x('A:calendar-order', $Args->{precedence});
  }

  $Self->Request(
    'MKCALENDAR',
    "$calendarId/",
    x('C:mkcalendar', $Self->NS(),
      x('D:set',
        x('D:prop', @Properties),
      ),
    ),
  );

  return $calendarId;
}

=head2 $self->UpdateCalendar($Args)

Like 'NewCalendar', but updates an existing calendar, and 'id' is required.
Returns the id, just like NewCalendar.

=cut

sub UpdateCalendar {
  my ($Self, $Args, $Prev) = @_;

  unless (ref($Args) eq 'HASH') {
    confess 'Invalid calendar';
  }

  my %Calendar   = %{$Args};
  my $calendarId = $Calendar{id};

  unless ($calendarId) {
    confess 'Calendar not specified';
  }

  my @Params;

  if (defined $Calendar{name}) {
    push @Params, x('D:displayname', $Calendar{name});
  }

  if (defined $Calendar{color}) {
    push @Params, x('A:calendar-color', _fixColour($Calendar{color}));
  }

  if (exists $Args->{timeZone}) {
    push @Params, x('C:calendar-timezone', $Args->{timeZone});
  }

  if (exists $Calendar{isVisible}) {
    push @Params, x('C:X-FM-isVisible', $Calendar{isVisible} ? 1 : 0);
  }

  if (exists $Calendar{precedence}) {
    unless (($Calendar{precedence} ||'') =~ /^\d+$/) {
      confess "Invalid precedence ($Calendar{precedence})";
    }

    push @Params, x('A:calendar-order', $Calendar{precedence});
  }

  return $calendarId unless @Params;

  $Self->Request(
    'PROPPATCH',
    "$calendarId/",
    x('D:propertyupdate', $Self->NS(),
      x('D:set',
        x('D:prop',
          @Params,
        ),
      ),
    ),
  );

  return $calendarId;
}

# Event methods

=head2 $self->DeleteEvent($Event|$href)

Given a single event or the href to the event, delete that event,
delete it from the server.

Returns true.

=cut

sub DeleteEvent {
  my ($Self) = shift;
  my ($Event) = @_;

  confess "Need an event" unless $Event;

  $Event = { href => $Event, summary => $Event } unless ref($Event) eq 'HASH';

  $Self->Request(
    'DELETE',
    $Event->{href},
  );

  return 1;
}

=head2 $self->GetEvents($calendarId, %Args)

Fetches some or all of the events in a calendar.

Supported args:

  href => [] - perform a multi-get on just these fullpath urls.
  after+before => ISO8601 - date range to query

In scalar context returns an arrayref of events.  In list context
returns both an arrayref of events and an arrayref of errors:

e.g.

    my ($Events, $Errors) = $CalDAV->GetEvents('Default');

=cut

sub GetEvents {
  my ($Self, $calendarId, %Args) = @_;

  my $urls = $Self->GetEventLinks($calendarId, %Args);

  my @AllUrls = sort keys %$urls;

  my ($Events, $Errors, $Links) = $Self->GetEventsMulti($calendarId, \@AllUrls, %Args);

  return wantarray ? ($Events, $Errors, $Links) : $Events;
}

=head2 $self->GetEventsMulti($calendarId, $Urls, %Args)

Fetches the events in Urs from the calendar

Supported args:

  * ContentType
  * Version

For the calendar-data response

In scalar context returns an arrayref of events.  In list context
returns an array of:

* arrayref of events
* arrayref of errors:
* hash of href to getetag

=cut

sub GetEventsMulti {
  my ($Self, $calendarId, $Urls, %Args) = @_;

  confess "Need a calendarId" unless $calendarId;

  my @Annotations;
  my $AnnotNames = $Args{Annotations} || [];
  foreach my $key (@$AnnotNames) {
    my $name = ($key =~ m/:/ ? $key : "C:$key");
    push @Annotations, x($name);
  }

  my %CalProps;
  if ($Args{ContentType}) {
    $CalProps{'content-type'} = $Args{ContentType};
  }
  if ($Args{Version}) {
    $CalProps{'version'} = $Args{Version};
  }

  my (@Events, @Errors, %Links);

  while (my @urls = splice(@$Urls, 0, $BATCHSIZE)) {
    my $Response = $Self->Request(
      'REPORT',
      "$calendarId/",
      x('C:calendar-multiget', $Self->NS(),
        x('D:prop',
          x('C:calendar-data', \%CalProps),
          x('D:getetag'),
          @Annotations,
        ),
        map { x('D:href', $_) } @urls,

      ),
      Depth => 1,
    );

    my $NS_A = $Self->ns('A');
    my $NS_C = $Self->ns('C');
    my $NS_D = $Self->ns('D');
    foreach my $Response (@{$Response->{"{$NS_D}response"} || []}) {
      my $href = uri_unescape($Response->{"{$NS_D}href"}{content} // '');
      next unless $href;
      foreach my $Propstat (@{$Response->{"{$NS_D}propstat"} || []}) {
        my $etag = $Propstat->{"{$NS_D}prop"}{"{$NS_D}getetag"}{content};
        $Links{$href} = $etag;
        my $Prop = $Propstat->{"{$NS_D}prop"}{"{$NS_C}calendar-data"};
        my $Data = $Prop->{content};
        next unless $Data;

        my $Event;

        if ($Prop->{'-content-type'} and $Prop->{'-content-type'} =~ m{application/event\+json}) {
          # JSON event is in API format already
          $Event = eval { decode_json($Data) };
        }
        else {
          # returns an array, but there should only be one UID per file
          ($Event) = eval { $Self->vcalendarToEvents($Data) };
        }

        if ($@) {
          push @Errors, $@;
          next;
        }
        next unless $Event;

        if ($Args{Full}) {
          $Event->{_raw} = $Data;
        }

        $Event->{href} = $href;
        $Event->{id} = $Self->shortpath($href);

        foreach my $key (@$AnnotNames) {
          my $propns = $NS_C;
          my $name = $key;
          if ($key =~ m/(.*):(.*)/) {
            $name = $2;
            $propns = $Self->ns($1);
          }
          my $AData = $Propstat->{"{$NS_D}prop"}{"{$propns}$name"}{content};
          next unless $AData;
          $Event->{annotation}{$name} = $AData;
        }

        push @Events, $Event;
      }
    }
  }

  return wantarray ? (\@Events, \@Errors, \%Links) : \@Events;
}

=head2 $self->GetEventLinks($calendarId, %Args)

Fetches the URLs of calendar events in a calendar.

Supported args:

  after+before => ISO8601 - date range to query

returns a hash of href to etag

=cut

sub GetEventLinks {
  my ($Self, $calendarId, %Args) = @_;
  confess "Need a calendarId" unless $calendarId;

  my @Extra;
  if ($Args{AlwaysRange} || $Args{after} || $Args{before}) {
    my $Start = _wireDate($Args{after} || $BoT);
    my $End = _wireDate($Args{before} || $EoT);
    push @Extra, x('C:time-range', {
      start => $Start->strftime('%Y%m%dT000000Z'),
      end   => $End->strftime('%Y%m%dT000000Z'),
    });
  }

  my $Response = $Self->Request(
    'REPORT',
    "$calendarId/",
    x('C:calendar-query', $Self->NS(),
      x('D:prop',
        x('D:getetag'),
      ),
      x('C:filter',
        x('C:comp-filter', { name => 'VCALENDAR' },
          x('C:comp-filter', { name => 'VEVENT' },
            @Extra,
          ),
        ),
      ),
    ),
    Depth => 1,
  );

  my (%Links, @Errors);

  my $NS_A = $Self->ns('A');
  my $NS_C = $Self->ns('C');
  my $NS_D = $Self->ns('D');
  foreach my $Response (@{$Response->{"{$NS_D}response"} || []}) {
    my $href = uri_unescape($Response->{"{$NS_D}href"}{content} // '');
    next unless $href;
    foreach my $Propstat (@{$Response->{"{$NS_D}propstat"} || []}) {
      my $etag = $Propstat->{"{$NS_D}prop"}{"{$NS_D}getetag"}{content};
      $Links{$href} = $etag;
    }
  }

  return \%Links;
}

=head2 $self->GetEvent($href)

Just get a single event (calls GetEvents with that href)

=cut

sub GetEvent {
  my ($Self, $href, %Args) = @_;

  # XXX - API
  my $calendarId = $href;
  $calendarId =~ s{/[^/]*$}{};

  my ($Events, $Errors) = $Self->GetEventsMulti($calendarId, [$Self->fullpath($href)], %Args);

  die "Errors @$Errors" if @$Errors;
  die "Multiple items returned for $href" if @$Events > 1;

  return $Events->[0];
}

=head2 $self->GetFreeBusy($calendarId, %Args)

Like 'GetEvents' but uses a free-busy-query and then generates
synthetic events out of the result.

Doesn't have a 'href' parameter, just the before/after range.

=cut

sub GetFreeBusy {
  my ($Self, $calendarId, %Args) = @_;

  # validate parameters {{{

  confess "Need a calendarId" unless $calendarId;

  my @Query;
  if ($Args{AlwaysRange} || $Args{after} || $Args{before}) {
    my $Start = _wireDate($Args{after} || $BoT);
    my $End = _wireDate($Args{before} || $EoT);

    push @Query,
            x('C:time-range', {
              start => $Start->strftime('%Y%m%dT000000Z'),
              end   => $End->strftime('%Y%m%dT000000Z'),
            });
  }

  # }}}

  my $Response = $Self->Request(
    'REPORT',
    "$calendarId/",
    x('C:free-busy-query', $Self->NS(),
      @Query,
    ),
    Depth => 1,
  );

  my $Data = eval { vcard2hash($Response->{content}, multival => ['rrule'], only_one => 1) }
    or confess "Error parsing VFreeBusy data: $@";

  my @result;
  my @errors;
  my $now = DateTime->now();
  foreach my $item (@{$Data->{objects}[0]{objects}}) {
    next unless $item->{type} eq 'vfreebusy';
    foreach my $line (@{$item->{properties}{freebusy}}) {
      my ($Start, $End) = split '/', $line->{value};
      my ($StartTime, $IsAllDay) = $Self->_makeDateObj($Start, 'UTC', 'UTC');
      my $EndTime;
      if ($End =~ m/^[+-]?P/i) {
          my $Duration = eval { DateTime::Format::ICal->parse_duration(uc $End) }
            || next;
          $EndTime = $StartTime->clone()->add($Duration);
      } else {
        ($EndTime) = $Self->_makeDateObj($End, 'UTC', 'UTC');
      }
      my $duration = $Self->_make_duration($EndTime->subtract_datetime($StartTime));
      my $NewEvent = {
        timeZone => 'Etc/UTC',
        start => $StartTime->iso8601(),
        duration => $duration,
        title => ($Args{name} // ''),
        isAllDay => ($IsAllDay ? $JSON::true : $JSON::false),
        updated => $now->iso8601(),
      };

      # Generate a uid that should remain the same for this freebusy entry
      $NewEvent->{uid} = _hexkey($NewEvent) . '-freebusyauto';
      $NewEvent->{isAllDay} =
        $NewEvent->{isAllDay} ? $JSON::true : $JSON::false;
      push @result, $NewEvent;
    }
  }

  return (\@result, \@errors);
}

=head2 $self->SyncEvents($calendarId, %Args)

Like GetEvents, but if you pass a syncToken argument, then it will
fetch changes since that token (obtained from an earlier GetCalendars
call).

In scalar context still just returns new events, in list context returns
Events, Removed and Errors.

e.g.

   my ($Events, $Removed, $Errors) = $CalDAV->SyncEvents('Default', syncToken => '...');

=cut

sub SyncEvents {
  my ($Self, $calendarId, %Args) = @_;

  my ($Added, $Removed, $Errors, $SyncToken) = $Self->SyncEventLinks($calendarId, %Args);

  my @AllUrls = sort keys %$Added;

  my ($Events, $ThisErrors, $Links) = $Self->GetEventsMulti($calendarId, \@AllUrls, %Args);
  push @$Errors, @$ThisErrors;

  return wantarray ? ($Events, $Removed, $Errors, $SyncToken, $Links) : $Events;
}

=head2 $self->SyncEventLinks($calendarId, %Args)

Like GetEventLinks, but if you pass a syncToken argument, then it will
fetch changes since that token (obtained from an earlier GetCalendars
or SyncEvent* call).

In scalar context still just returns Added, in list context returns
Added, Removed, Errors and new token:

* Added: hash of href to etag - added or changed
* Removed: array of href
* Errors: array of descritive string
* NewToken: scalar opaque DAV:sync-token

e.g.

   my ($Added, $Removed, $Errors, $NewToken)
      = $CalDAV->SyncEventLinks('Default', syncToken => '...');

=cut

sub SyncEventLinks {
  my ($Self, $calendarId, %Args) = @_;

  confess "Need a calendarId" unless $calendarId;

  my $Response = $Self->Request(
    'REPORT',
    "$calendarId/",
    x('D:sync-collection', $Self->NS(),
      x('D:sync-token', ($Args{syncToken} ? ($Args{syncToken}) : ())),
      x('D:sync-level', 1),
      x('D:prop',
        x('D:getetag'),
      ),
    ),
  );

  my $NS_A = $Self->ns('A');
  my $NS_C = $Self->ns('C');
  my $NS_D = $Self->ns('D');

  my $SyncToken = $Response->{"{$NS_D}sync-token"}{content};
  confess "NO SYNC TOKEN RETURNED " . Dumper($Response) unless $SyncToken;

  my (%Added, @Removed, @Errors);
  foreach my $Response (@{$Response->{"{$NS_D}response"} || []}) {
    my $href = uri_unescape($Response->{"{$NS_D}href"}{content} // '');
    next unless $href;

    unless ($Response->{"{$NS_D}propstat"}) {
      push @Removed, $href;
      next;
    }

    foreach my $Propstat (@{$Response->{"{$NS_D}propstat"} || []}) {
      my $status = $Propstat->{"{$NS_D}status"}{content};
      if ($status =~ m/ 200 /) {
        my $etag = $Propstat->{"{$NS_D}prop"}{"{$NS_D}getetag"}{content};
        $Added{$href} = $etag;
      }
      else {
        push @Errors, "Odd status $status";
      }
    }
  }

  return (\%Added, \@Removed, \@Errors, $SyncToken);
}

=head2 $self->NewEvent($calendarId, $Args)

Create a new event in the named calendar.  If you don't specify 'uid' then
a UUID will be created.  You should only specify the UID if you need to for
syncing purposes - it's better to auto-generate otherwise.

Returns the href, but also updates 'uid' in $Args.

Also updates 'sequence'.

Special keys consumed from $Args (not stored in the event):

=over 4

=item _no_schedule

If true, sends C<Schedule-Reply: false> on the PUT request, suppressing
iTIP scheduling replies from the server (RFC 6638 section 8.1).

=back

e.g.

    my $href = $CalDAV->NewEvent('Default', $Args);
    my $newuid = $Args->{uid};

=cut

sub NewEvent {
  my ($Self, $calendarId, $Args) = @_;

  confess "Need a calendarId" unless $calendarId;

  confess "invalid event" unless ref($Args) eq 'HASH';

  my $UseEvent    = delete $Args->{_put_event_json};
  my $no_schedule = delete $Args->{_no_schedule};
  my @sched_header = $no_schedule ? ('Schedule-Reply' => 'false') : ();

  # calculate updated sequence numbers
  unless (exists $Args->{sequence}) {
    $Args->{sequence} = 1;
  }

  if ($Args->{exceptions}) {
    foreach my $recurrenceId (sort keys %{$Args->{exceptions}}) {
      my $val = $Args->{exceptions}{$recurrenceId};
      next unless $val;
      next if exists $val->{sequence};

      $val->{sequence} = $Args->{sequence};
    }
  }

  $Args->{uid} //= $Self->genuuid();
  my $uid = $Args->{uid};
  my $path = $uid;
  $path =~ tr/[a-zA-Z0-9\@\.\_\-]//cd;
  my $href = "$calendarId/$path.ics";

  if ($UseEvent) {
    $Self->Request(
      'PUT',
      $href,
      encode_json($Args),
      'Content-Type'  => 'application/event+json',
      @sched_header,
    );
  }
  else {
    my $VCalendar = $Self->_argsToVCalendar($Args);
    $Self->Request(
      'PUT',
      $href,
      $VCalendar->as_string(),
      'Content-Type'  => 'text/calendar',
      @sched_header,
    );
  }

  return $href;
}

=head2 $self->UpdateEvent($href, $Args)

Like NewEvent, but you only need to specify keys that you want to change,
and it takes the full href to the card instead of the containing calendar.

Accepts the same special keys as NewEvent (e.g. C<_no_schedule>).

=cut

sub UpdateEvent {
  my ($Self, $href, $Args) = @_;

  my $UseEvent    = delete $Args->{_put_event_json};
  my $no_schedule = delete $Args->{_no_schedule};
  my @sched_header = $no_schedule ? ('Schedule-Reply' => 'false') : ();

  my ($OldEvent, $NewEvent) = $Self->_updateEvent($href, $Args);

  if ($UseEvent) {
    $Self->Request(
      'PUT',
      $href,
      encode_json($NewEvent),
      'Content-Type'  => 'application/event+json',
      @sched_header,
    );
  }
  else {
    my $VCalendar = $Self->_argsToVCalendar($NewEvent);
    $Self->Request(
      'PUT',
      $href,
      $VCalendar->as_string(),
      'Content-Type'  => 'text/calendar',
      @sched_header,
    );
  }

  return 1;
}

sub _updateEvent {
  my ($Self, $href, $Args) = @_;

  my $OldEvent = $Self->GetEvent($href);

  confess "Error getting old event for $href"
    unless $OldEvent;

  # Merge patch onto old event (both are flat JSCalendar hashes)
  my %NewEvent = %$OldEvent;
  for my $key (keys %$Args) {
    if (defined $Args->{$key}) {
      $NewEvent{$key} = $Args->{$key};
    } else {
      delete $NewEvent{$key};
    }
  }

  # calculate updated sequence numbers
  unless (exists $Args->{sequence}) {
    $NewEvent{sequence} = ($OldEvent->{sequence} || 0) + 1;
  }

  if ($NewEvent{exceptions}) {
    foreach my $recurrenceId (sort keys %{$NewEvent{exceptions}}) {
      my $val = $NewEvent{exceptions}{$recurrenceId};
      next unless $val;
      next if exists $val->{sequence};

      my $old = $OldEvent->{exceptions}{$recurrenceId};
      my $sequence = $NewEvent{sequence};
      if ($old && exists $old->{sequence}) {
        $sequence = $old->{sequence} + 1 unless $sequence > $old->{sequence};
      }
      $val->{sequence} = $sequence if $sequence > $NewEvent{sequence};
    }
  }

  if ($NewEvent{recurrenceOverrides}) {
    foreach my $recurrenceId (sort keys %{$NewEvent{recurrenceOverrides}}) {
      my $val = $NewEvent{recurrenceOverrides}{$recurrenceId};
      next unless $val;
      next if exists $val->{sequence};

      my $old = ($OldEvent->{recurrenceOverrides} || {})->{$recurrenceId};
      my $sequence = $NewEvent{sequence};
      if ($old && exists $old->{sequence}) {
        $sequence = $old->{sequence} + 1 unless $sequence > $old->{sequence};
      }
      $val->{sequence} = $sequence if $sequence > $NewEvent{sequence};
    }
  }

  $NewEvent{href} = $href;

  return ($OldEvent, \%NewEvent);
}

=head2 $self->AnnotateEvent($href, $Args)

Instead of actually changing an event itself, use proppatch to
add or remove properties on the event.

=cut

sub AnnotateEvent {
  my ($Self, $href, $Args) = @_;

  my $OldEvent = $Self->GetEvent($href);

  confess "Error getting old event for $href"
    unless $OldEvent;

  my @Set;
  my @Remove;
  foreach my $key (sort keys %$Args) {
    my $name = ($key =~ m/:/ ? $key : "C:$key");
    if (defined $Args->{$key}) {
      push @Set, x($name, $Args->{$key});
    }
    else {
      push @Remove, x($name);
    }
  }

  my @Params;
  push @Params, x('D:set', x('D:prop', @Set)) if @Set;
  push @Params, x('D:remove', x('D:prop', @Remove)) if @Remove;
  return undef unless @Params;

  $Self->Request(
    'PROPPATCH',
    $href,
    x('D:propertyupdate', $Self->NS(), @Params),
  );

  return 1;
}

=head2 $self->MoveEvent($href, $newCalendarId)

Move an event into a new calendar.  Returns the new href.

=cut

sub MoveEvent {
  my ($Self, $href, $newCalendarId) = @_;

  my $OldEvent = $Self->GetEvent($href);

  return unless $OldEvent;

  my $dest = $href;
  $dest =~ s{.*/}{$newCalendarId/};
  return if $href eq $dest;

  $Self->Request(
    'MOVE',
    $href,
    undef,
    'Destination' => $Self->fullpath($dest),
  );

  warn "CAL: MoveEvent $Self->{user} ($href => $dest)\n";

  return $dest;
}

# ============================================================
# Conversion functions - delegated to Text::JSCalendar
# ============================================================

=head2 $NewEvent = Net::CalDAVTalk->NormaliseEvent($Event);

Doesn't change the original event, but removes any keys which are the same as their default value

=cut

sub NormaliseEvent {
  my ($class, $Event, $Root) = @_;
  return Text::JSCalendar->NormaliseEvent($Event, $Root);
}

=head2 Net::CalDAVTalk->CompareEvents($Event1, $Event2);

Returns true if the events are identical

=cut

sub CompareEvents {
  my ($class, $Event1, $Event2) = @_;
  return Text::JSCalendar->CompareEvents($Event1, $Event2);
}

sub vcalendarToEvents {
  my $Self = shift;
  return $Self->_jscal->vcalendarToEvents(@_);
}

sub _argsToVCalendar {
  my $Self = shift;
  return $Self->_jscal->_argsToVCalendar(@_);
}

sub eventsToVCalendar {
  my $Self = shift;
  return $Self->_jscal->eventsToVCalendar(@_);
}

# ============================================================
# Minimal helpers still used by GetFreeBusy/GetEventLinks
# ============================================================

sub _wireDate {
  return Text::JSCalendar::_wireDate(@_);
}

sub _makeDateObj {
  my $Self = shift;
  return $Self->_jscal->_makeDateObj(@_);
}

sub _make_duration {
  my $Self = shift;
  return $Self->_jscal->_make_duration(@_);
}

sub _hexkey {
  return Text::JSCalendar::_hexkey(@_);
}

sub _stripNonICal {
  my $Self = shift;
  my $Event = shift;

  delete $Event->{alerts};
  delete $Event->{attendees};
  delete $Event->{organizer};
  delete $Event->{participants};
  delete $Event->{organizerCalendarAddress};

  foreach my $exception (values %{$Event->{exceptions} || $Event->{recurrenceOverrides} || {}}) {
    next unless $exception;
    $Self->_stripNonICal($exception);
  }
}

=head2 $self->UpdateAddressSet($DisplayName, $EmailAddress)

Set the address set and display name for the calendar user (if supported)

=cut

sub UpdateAddressSet {
  my ($Self, $NewDisplayName, $NewAddressSet) = @_;

  my ($DisplayName, $AddressSet) = $Self->GetProps(\$Self->{principal}, 'D:displayname', [ 'C:calendar-user-address-set', 'D:href' ]);

  if (!$AddressSet || $AddressSet ne "mailto:" . $NewAddressSet ||
      !$DisplayName || $DisplayName ne $NewDisplayName) {
    $Self->Request(
      'PROPPATCH',
      "",
      x('D:propertyupdate', $Self->NS(),
        x('D:set',
          x('D:prop',
            x('D:displayname', $NewDisplayName),
            x('C:calendar-user-address-set', "mailto:" . $NewAddressSet),
          )
        )
      )
    );
    return 1;
  }

  return 0;
}

=head2 $self->GetICal($calendarId, $isFreeBusy)

Given a calender, fetch all the events and generate an ical format file
suitable for import into a client.

=cut

sub GetICal {
  my $Self = shift;
  my $calendarId = shift;
  my $isFreeBusy = shift;

  confess "Need a calendarId" unless $calendarId;

  my $Calendars = $Self->GetCalendars();
  foreach my $Cal (@$Calendars) {
    next unless $calendarId eq $Cal->{id};
    my ($Events, $Errors) = $isFreeBusy ?
                            $Self->GetFreeBusy($calendarId) :
                            $Self->GetEvents($calendarId);
    return undef if @$Errors;
    $Self->_stripNonICal($_) for @$Events;
    my $VCalendar = $Self->_argsToVCalendar($Events,
      method => 'PUBLISH',
      'x-wr-calname' => $Cal->{name},
      'x-wr-timezone' => $Cal->{timeZone},
      'x-apple-calendar-color' => $Cal->{color},
      # XXX - do we want to add our sync-token here or something?
    );
    return ($VCalendar->as_string(), $Cal);
  }
  return undef; # 404
}

=head1 AUTHOR

Bron Gondwana, C<< <brong at cpan.org> >>

=head1 BUGS

Please report any bugs or feature requests to C<bug-net-caldavtalk at rt.cpan.org>, or through
the web interface at L<http://rt.cpan.org/NoAuth/ReportBug.html?Queue=Net-CalDAVTalk>.  I will be notified, and then you'll
automatically be notified of progress on your bug as I make changes.




=head1 SUPPORT

You can find documentation for this module with the perldoc command.

    perldoc Net::CalDAVTalk


You can also look for information at:

=over 4

=item * RT: CPAN's request tracker (report bugs here)

L<http://rt.cpan.org/NoAuth/Bugs.html?Dist=Net-CalDAVTalk>

=item * AnnoCPAN: Annotated CPAN documentation

L<http://annocpan.org/dist/Net-CalDAVTalk>

=item * CPAN Ratings

L<http://cpanratings.perl.org/d/Net-CalDAVTalk>

=item * Search CPAN

L<http://search.cpan.org/dist/Net-CalDAVTalk/>

=back


=head1 ACKNOWLEDGEMENTS


=head1 LICENSE AND COPYRIGHT

Copyright 2015 FastMail Pty Ltd.

This program is free software; you can redistribute it and/or modify it
under the terms of the the Artistic License (2.0). You may obtain a
copy of the full license at:

L<http://www.perlfoundation.org/artistic_license_2_0>

Any use, modification, and distribution of the Standard or Modified
Versions is governed by this Artistic License. By using, modifying or
distributing the Package, you accept this license. Do not use, modify,
or distribute the Package, if you do not accept this license.

If your Modified Version has been derived from a Modified Version made
by someone other than you, you are nevertheless required to ensure that
your Modified Version complies with the requirements of this license.

This license does not grant you the right to use any trademark, service
mark, tradename, or logo of the Copyright Holder.

This license includes the non-exclusive, worldwide, free-of-charge
patent license to make, have made, use, offer to sell, sell, import and
otherwise transfer the Package with respect to any patent claims
licensable by the Copyright Holder that are necessarily infringed by the
Package. If you institute patent litigation (including a cross-claim or
counterclaim) against any party alleging that the Package constitutes
direct or contributory patent infringement, then this Artistic License
to you shall terminate on the date that such litigation is filed.

Disclaimer of Warranty: THE PACKAGE IS PROVIDED BY THE COPYRIGHT HOLDER
AND CONTRIBUTORS "AS IS' AND WITHOUT ANY EXPRESS OR IMPLIED WARRANTIES.
THE IMPLIED WARRANTIES OF MERCHANTABILITY, FITNESS FOR A PARTICULAR
PURPOSE, OR NON-INFRINGEMENT ARE DISCLAIMED TO THE EXTENT PERMITTED BY
YOUR LOCAL LAW. UNLESS REQUIRED BY LAW, NO COPYRIGHT HOLDER OR
CONTRIBUTOR WILL BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, OR
CONSEQUENTIAL DAMAGES ARISING IN ANY WAY OUT OF THE USE OF THE PACKAGE,
EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.


=cut

1; # End of Net::CalDAVTalk
