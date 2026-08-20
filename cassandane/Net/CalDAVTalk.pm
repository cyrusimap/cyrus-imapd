package Net::CalDAVTalk;

use 5.006;
use strict;
use warnings FATAL => 'all';

use Net::DAVTalk;
use base qw(Net::DAVTalk);

use Carp;
use Data::ICal;
use Data::ICal::Entry::Event;
use Data::ICal::TimeZone;
use Data::ICal::Entry::Alarm::Email;
use Data::ICal::Entry::Alarm::Display;
use DateTime::Format::ICal;
use DateTime::TimeZone;
use JSON::XS qw(encode_json);
use Net::CalDAVTalk::TimeZones;
use Text::VCardFast qw(vcard2hash);
use XML::Spice;
use MIME::Base64 qw(encode_base64);
use MIME::Types;
use Digest::SHA qw(sha1_hex);
use URI::Escape qw(uri_unescape);

our $BATCHSIZE = 100;

# monkey patch like a bandit
BEGIN {
  my @properties = Data::ICal::Entry::Alarm::optional_unique_properties();
  foreach my $want (qw(uid acknowledged)) {
    push @properties, $want unless grep { $_ eq $want } @properties;
  }
  no warnings 'redefine';
  *Data::ICal::Entry::Alarm::optional_unique_properties = sub { @properties };
}

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
  %WeekDayNames,
  %WeekDayNamesReverse,
  %DaysByName,
  %DaysByIndex,
  %ColourNames,
  @Frequencies,
  %RecurrenceProperties,
  %UTCLinks,
  %MustBeTopLevel,
  %EventKeys,
);

BEGIN {
  %WeekDayNames = (
    su => 'sunday',
    mo => 'monday',
    tu => 'tuesday',
    we => 'wednesday',
    th => 'thursday',
    fr => 'friday',
    sa => 'saturday',
  );
  %WeekDayNamesReverse = reverse %WeekDayNames;

  %DaysByName = (
    su => 0,
    mo => 1,
    tu => 2,
    we => 3,
    th => 4,
    fr => 5,
    sa => 6,
  );

  %DaysByIndex           = reverse %DaysByName;
  $DefaultCalendarColour = '#0252D4';
  $DefaultDisplayName    = 'Untitled Calendar';
  @Frequencies           = qw{yearly monthly weekly daily hourly minutely secondly};

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
      isAllDay             => [0, 'bool',      0, $JSON::false],
      start                => [0, 'localdate', 1, undef],
      timeZone             => [0, 'timezone',  0, undef],
      duration             => [0, 'duration',  0, undef],
      recurrenceRule       => [0, 'object',    0, undef],
      recurrenceOverrides  => [0, 'patch',     0, undef],
      status               => [0, 'string',    0, undef],
      showAsFree           => [0, 'bool',      0, undef],
      replyTo              => [0, 'object',    0, undef],
      participants         => [0, 'object',    0, undef],
      useDefaultAlerts     => [0, 'bool',      0, $JSON::false],
      alerts               => [0, 'object',    0, undef],
    },
    replyTo => {
      imip                 => [0, 'mailto',    0, undef],
      web                  => [0, 'href',      0, undef],
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
      firstDayOfWeek       => [0, 'string',    0, 'monday'],
      byDay                => [1, 'object',    0, undef],
      byDate               => [1, 'number',    0, undef],
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
      kind                 => [0, 'string',    0, 'unknown'],
      roles                => [1, 'string',    1, undef],
      locationId           => [0, 'string',    0, undef],
      scheduleStatus       => [0, 'string',    0, 'needs-action'],
      schedulePriority     => [0, 'string',    0, 'required'],
      scheduleRSVP         => [0, 'bool',      0, $JSON::false],
      scheduleUpdated      => [0, 'utcdate',   0, undef],
      memberOf             => [1, 'string',    0, undef],
    },
    alerts => {
      relativeTo           => [0, 'string',    0, 'before-start'],
      offset               => [0, 'duration',  1, undef],
      action               => [0, 'object',    1, undef],
    },
    action => {
      type                 => [0, 'string',    1, undef],
    },
  );

  %RecurrenceProperties = (
    bymonthday => {
      name   => 'byDate',
      max    => 31,
      signed => 1,
    },
    byyearday  => {
      name   => 'byYearDay',
      max    => 366,
      signed => 1,
    },
    byweekno   => {
      name   => 'byWeekNo',
      max    => 53,
      signed => 1,
    },
    byhour     => {
      name => 'byHour',
      max  => 23,
    },
    byminute   => {
      name => 'byMinute',
      max  => 59,
    },
    bysecond   => {
      name => 'bySecond',
      max  => 60,
    },
    bysetpos   => {
      name   => 'bySetPosition',
      max    => 366,
      signed => 1,
    },
  );

  %MustBeTopLevel = map { $_ => 1 } qw{
    uid
    relatedTo
    prodId
    isAllDay
    recurrenceRule
    recurrenceOverrides
    replyTo
    participantId
  };
  # not in tc-api / JMAP, but necessary for iMIP
  $MustBeTopLevel{method} = 1;

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

Version 0.12

=cut

our $VERSION = '0.12';


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

e.g.

    my $href = $CalDAV->NewEvent('Default', $Args);
    my $newuid = $Args->{uid};

=cut

sub NewEvent {
  my ($Self, $calendarId, $Args) = @_;

  confess "Need a calendarId" unless $calendarId;

  confess "invalid event" unless ref($Args) eq 'HASH';

  my $UseEvent = delete $Args->{_put_event_json};

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
    );
  }
  else {
    my $VCalendar = $Self->_argsToVCalendar($Args);
    $Self->Request(
      'PUT',
      $href,
      $VCalendar->as_string(),
      'Content-Type'  => 'text/calendar',
    );
  }

  return $href;
}

=head2 $self->UpdateEvent($href, $Args)

Like NewEvent, but you only need to specify keys that you want to change,
and it takes the full href to the card instead of the containing calendar.

=cut

sub UpdateEvent {
  my ($Self, $href, $Args) = @_;

  my $UseEvent = delete $Args->{_put_event_json};

  my ($OldEvent, $NewEvent) = $Self->_updateEvent($href, $Args);

  if ($UseEvent) {
    $Self->Request(
      'PUT',
      $href,
      encode_json($NewEvent),
      'Content-Type'  => 'application/event+json',
    );
  }
  else {
    my $VCalendar = $Self->_argsToVCalendar($NewEvent);
    $Self->Request(
      'PUT',
      $href,
      $VCalendar->as_string(),
      'Content-Type'  => 'text/calendar',
    );
  }

  return 1;
}

sub _updateEvent {
  my ($Self, $href, $Args) = @_;

  my $OldEvent = $Self->GetEvent($href);

  confess "Error getting old event for $href"
    unless $OldEvent;

  my %NewEvent;

  foreach my $Property (keys %EventKeys) {
    if (exists $Args->{$Property}) {
      if (defined $Args->{$Property}) {
        $NewEvent{$Property} = $Args->{$Property};
      }
    }
    elsif (exists $OldEvent->{$Property}) {
      $NewEvent{$Property} = $OldEvent->{$Property};
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
      $val->{sequence} = $sequence;
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

sub _BYDAY2byDay {
  my ($BYDAY) = @_;

  my ($Count, $Day) = $BYDAY =~ /^([-+]?\d+)?(\w\w)$/;

  unless ($Day) {
    confess 'Recurrence BYDAY-weekday not specified';
  }

  unless ($WeekDayNames{$Day}) {
    confess 'Invalid recurrence BYDAY-weekday';
  }

  if ($Count) {
    unless (($Count >= -53) and ($Count <= 53)) {
      confess 'Recurrence BYDAY-ordwk is out of range';
    }
  }

  return {
    day => $WeekDayNames{$Day},
    $Count ? (nthOfPeriod => int($Count)) : (),
  };
}

sub _byDay2BYDAY {
  my ($byDay) = @_;

  unless (defined $byDay) {
    confess 'Invalid recurrence byDay';
  }

  unless (ref $byDay eq 'HASH') {
    confess 'Recurrence byDay is not an object';
  }

  my $Day          = $WeekDayNamesReverse{$byDay->{day}};
  unless ($Day) {
    confess 'Recurrence byDay is not a known day';
  }
  my $Prefix = '';
  $Prefix = int($byDay->{nthOfPeriod}) if $byDay->{nthOfPeriod};

  return $Prefix . uc($Day);
}

sub _makeDateObj {
  my $Self = shift;
  my $DateStr = shift;
  my $TZStr = shift;
  my $TargetTz = shift;

  my ($Date, $HasTime) = _vDate($DateStr);

  # if it's all day, return it immediately
  return ($Date, 1) unless $HasTime;

  # Do the timezone manipulation as required
  $Date->set_time_zone($Self->tz($TZStr)) if $TZStr;
  $Date->set_time_zone($Self->tz($TargetTz)) if $TargetTz;

  return ($Date, 0);
}

sub _getDateObj {
  my $Self = shift;
  my $Calendar = shift;
  my $VItem = shift;
  my $TargetTz = shift;

  my $TimeZone = $Self->_getTimeZone($Calendar, $VItem);
  my ($Date, $IsAllDay) = $Self->_makeDateObj($VItem->{value}, $TimeZone, $TargetTz);

  return (wantarray ? ($Date, $TimeZone, $IsAllDay) : $Date);
}

sub _getDateObjMulti {
  my $Self = shift;
  my $Calendar = shift;
  my $VItem = shift;
  my $TargetTz = shift;

  my @Dates;

  my $TimeZone = $Self->_getTimeZone($Calendar, $VItem);
  foreach my $Value (split /,/, $VItem->{value}) {
    # XXX - handle $V2 sanely
    if (lc($VItem->{params}{value}[0] || '') eq 'period') {
      ($Value, my $V2) = split /\//, $Value;
    }
    my ($Date, $IsAllDay) = $Self->_makeDateObj($Value, $TimeZone, $TargetTz);
    push @Dates, $Date;
  }

  return @Dates;
}

# Exclude DTSTAMP from auto uid generation
sub _hexkey {
  my $VEvent = shift;
  my $updated = delete $VEvent->{properties}->{updated};
  my $d = Data::Dumper->new([$VEvent]);
  $d->Indent(0);
  $d->Sortkeys(1);
  my $Key = sha1_hex($d->Dump());
  $VEvent->{properties}->{updated} = $updated if defined $updated;
  return $Key;
}

sub _saneuid {
  my $uid = shift;
  return unless $uid;
  return if $uid =~ m/\s/;
  return if $uid =~ m/[\x7f-\xff]/;
  # any other sanity checks?
  return 1;
}

sub _makeParticipant {
  my ($Self, $Calendar, $Participants, $VAttendee, $role) = @_;

  my $id = $VAttendee->{value};
  return unless $id;
  $id =~ s/^mailto://i;
  return if $id eq '';

  $Participants->{$id} ||= {};

  # XXX - if present on one but not the other, take the "best" version
  $Participants->{$id}{name} = $VAttendee->{params}{"cn"}[0] // "";
  $Participants->{$id}{email} = $id;
  $Participants->{$id}{kind} = lc $VAttendee->{params}{"cutype"}[0]
    if $VAttendee->{params}{"cutype"};
  push @{$Participants->{$id}{roles}}, $role;
  # we don't support locationId yet
  if ($VAttendee->{params}{"partstat"}) {
    $Participants->{$id}{scheduleStatus} = lc($VAttendee->{params}{"partstat"}[0] // "needs-action");
  }
  if ($VAttendee->{params}{"role"}) {
    push @{$Participants->{$id}{roles}}, 'chair'
      if uc $VAttendee->{params}{"role"}[0] eq 'CHAIR';
    $Participants->{$id}{schedulePriority} = 'optional'
      if uc $VAttendee->{params}{"role"}[0] eq 'OPT-PARTICIPANT';
    $Participants->{$id}{schedulePriority} = 'non-participant'
      if uc $VAttendee->{params}{"role"}[0] eq 'NON-PARTICIPANT';
  }
  if ($VAttendee->{params}{"rsvp"}) {
    $Participants->{$id}{scheduleRSVP} = lc($VAttendee->{params}{"rsvp"}[0] // "") eq 'yes' ? $JSON::true : $JSON::false;
  }
  if (exists $VAttendee->{params}{"x-dtstamp"}) {
    my ($Date) = eval { $Self->_makeDateObj($VAttendee->{params}{"x-dtstamp"}[0], 'UTC', 'UTC') };
    $Participants->{$id}{"scheduleUpdated"} = $Date->iso8601() . 'Z' if $Date;
  }
  # memberOf is not supported

  if (exists $VAttendee->{params}{"x-sequence"}) {
    $Participants->{$id}{"x-sequence"} = $VAttendee->{params}{"x-sequence"}[0] // "";
  }
}

sub _make_duration {
  my ($Self, $dtdur, $IsAllDay) = @_;

  my ($w, $d, $H, $M, $S) = (
    $dtdur->weeks,
    $dtdur->days,
    $dtdur->hours,
    $dtdur->minutes,
    $dtdur->seconds,
  );

  return 'PT0S' unless ($w || $d || $H || $M || $S);

  my @bits = ('P');
  push @bits, ($w, 'W') if $w;
  push @bits, ($d, 'D') if $d;
  if (not $IsAllDay and ($H || $M || $S)) {
    push @bits, 'T';
    push @bits, ($H, 'H') if $H;
    push @bits, ($M, 'M') if $M;
    push @bits, ($S, 'S') if $S;
  }

  return join ('', @bits);
}

=head2 $NewEvent = Net::CalDAVTalk->NormaliseEvent($Event);

Doesn't change the original event, but removes any keys which are the same as their default value

=cut

sub NormaliseEvent {
  my ($class, $Event, $Root) = @_;

  $Root ||= '';

  my %Copy = %$Event;

  # XXX: patches need to be normalised as well...
  my $Spec = $EventKeys{$Root};
  foreach my $key (keys %$Event) {
    delete $Copy{$key} unless $Spec->{$key};
  }
  foreach my $key (sort keys %$Spec) {
    # remove if it's the default
    if ($Spec->{$key}[1] eq 'object') {
      my $Item = delete $Copy{$key};
      next unless $Item; # no object
      if ($Spec->{$key}[0]) {
        $Copy{$key} = [map { $class->NormaliseEvent($_, $key) } @$Item];
      }
      else {
        $Copy{$key} = $class->NormaliseEvent($Item, $key);
      }
    }
    elsif ($Spec->{$key}[1] eq 'bool') {
      delete $Copy{$key} if !!$Spec->{$key}[3] == !!$Copy{$key};
    }
    elsif ($Spec->{$key}[1] eq 'mailto') {
      $Copy{$key} = lc $Copy{$key} if $Copy{$key};
    }
    else {
      delete $Copy{$key} if _safeeq($Spec->{$key}[3], $Copy{$key});
    }
  }

  return \%Copy;
}

=head2 Net::CalDAVTalk->CompareEvents($Event1, $Event2);

Returns true if the events are identical

=cut

sub CompareEvents {
  my ($class, $Event1, $Event2) = @_;

  my $E1 = $class->NormaliseEvent($Event1);
  my $E2 = $class->NormaliseEvent($Event2);

  return _safeeq($E1, $E2);
}


sub _getEventsFromVCalendar {
  my ($Self, $VCalendar) = @_;

  my $CalendarData = eval { vcard2hash($VCalendar, multival => ['rrule'], only_one => 1) }
    or confess "Error parsing VCalendar data: $@\n\n$VCalendar";

  my @Events;

  foreach my $Calendar (@{$CalendarData->{objects} || []}) {
    next unless lc $Calendar->{type} eq 'vcalendar';

    my $method = $Calendar->{properties}{method}[0]{value};
    my $prodid = $Calendar->{properties}{prodid}[0]{value};

    foreach my $VEvent (@{$Calendar->{objects} || []}) {
      next unless lc $VEvent->{type} eq 'vevent';

      # parse simple component properties {{{

      my %Properties
        = map { $_ => $VEvent->{properties}{$_}[0] }
            keys %{$VEvent->{properties}};

      my $uid = $Properties{uid}{value};
      # Case: UID is badly broken or missing -
      # let's just calculate a UID based on the incoming data.  This
      # is the 'ICS sync url with no UIDs in it' case from BTS-3205,
      # http://mozorg.cdn.mozilla.net/media/caldata/DutchHolidays.ics
      $uid = _hexkey($VEvent) . '-syncauto' unless _saneuid($uid);

      my $ShowAsFree = (lc($Properties{transp}{value} || '')) eq 'transparent';

      # clean up whitespace on text fields
      foreach my $Property (qw{description location summary}) {
        next unless defined $Properties{$Property}{value};
        $Properties{$Property}{value} =~ s/^\s+//gs;
        $Properties{$Property}{value} =~ s/\s+$//gs;
      }

      my @description;
      push @description, $Properties{description}{value}
        if defined $Properties{description}{value};

      # }}}

      # parse time component properties {{{

      my ($IsAllDay, $Start, $StartTimeZone, $End, $EndTimeZone) = ('') x 5;

      confess "$uid: DTSTART not specified" unless defined $Properties{dtstart}{value};

      ($Start, $StartTimeZone, $IsAllDay) = $Self->_getDateObj($Calendar, $Properties{dtstart});

      if (defined $Properties{dtend}{value}) {
        if (defined $Properties{duration}{value}) {
          warn "$uid: DTEND and DURATION cannot both be set";
        }

        ($End, $EndTimeZone) = $Self->_getDateObj($Calendar, $Properties{dtend});
      }
      elsif (defined $Properties{duration}{value}) {
        my $Duration = DateTime::Format::ICal->parse_duration(uc $Properties{duration}{value});
        $End = $Start->clone()->add($Duration);
        $EndTimeZone = $StartTimeZone;
      }
      else {
        $End         = $Start->clone();
        $EndTimeZone = $StartTimeZone;
      }

      if (DateTime->compare($Start, $End) > 0) {
        # swap em!
        ($Start, $End) = ($End, $Start);
        ($StartTimeZone, $EndTimeZone) = ($EndTimeZone, $StartTimeZone);
      }

      if ($IsAllDay and $StartTimeZone) {
        warn "$uid: AllDay event with timezone $StartTimeZone specified";
      }

      # if one is set, make sure they are both set
      $StartTimeZone ||= $EndTimeZone;
      $EndTimeZone   ||= $StartTimeZone;

      # }}}

      my %Recurrence;

      if (exists $Properties{rrule}) {
        my %RRULE;

        foreach my $RRULE (@{$Properties{rrule}{values}}) {
          my ($Key,$Value) = split '=', $RRULE;
          next unless defined $Value;

          $RRULE{lc $Key} = $Value;
        }

        # parse simple recurrence properties {{{

        if (exists $RRULE{freq}) {
          my $freq = lc $RRULE{freq};
          unless (grep { $_ eq $freq } @Frequencies) {
            confess "$uid: Invalid recurrence FREQ ($RRULE{freq})";
          }

          $Recurrence{frequency} = $freq;
        }
        else {
          confess "$uid: Recurrence FREQ not specified";
        }

        if (exists $RRULE{interval}) {
          unless ($RRULE{interval} =~ /^\d+$/) {
            confess "$uid: Invalid recurrence INTERVAL ($RRULE{interval})";
          }
          my $interval = int $RRULE{interval};

          if ($interval == 0) {
            confess "$uid: Recurrence INTERVAL is out of range ($RRULE{interval})";
          }

          # default == 1, so don't set a key for it
          if ($interval > 1) {
            $Recurrence{interval} = $interval;
          }
        }

        if (exists $RRULE{rscale}) {
          $Recurrence{rscale} = lc $RRULE{rscale};
          $Recurrence{skip} = lc $RRULE{skip} if $RRULE{skip};
        }

        if (exists $RRULE{wkst}) {
          my $wkst = lc $RRULE{wkst};
          unless ($WeekDayNames{$wkst}) {
            confess "$uid: Invalid recurrence WKST ($RRULE{wkst})";
          }

          # default is Monday, so don't set a key for it
          if ($wkst ne 'mo') {
            $Recurrence{firstDayOfWeek} = $WeekDayNames{$wkst};
          }
        }

        if (exists $RRULE{byday}) {
          my @byDays;

          foreach my $BYDAY (split ',', $RRULE{byday}) {
            push @byDays, _BYDAY2byDay(lc $BYDAY);
          }

          $Recurrence{byDay} = \@byDays if @byDays;
        }

        if (exists $RRULE{bymonth}) {
          foreach my $BYMONTH (split ',', $RRULE{bymonth}) {
            unless ($BYMONTH =~ /^\d+L?$/) {
              confess "$uid: Invalid recurrence BYMONTH ($BYMONTH, $RRULE{bymonth})";
            }

            push @{$Recurrence{byMonth}}, "$BYMONTH";
          }
        }

        if (exists $RRULE{count}) {
          if (exists $RRULE{until}) {
            #confess "$uid: Recurrence COUNT and UNTIL cannot both be set";
            # seen in the wild: PRODID:-//dmfs.org//mimedir.icalendar//EN
            delete $RRULE{until};
          }

          unless ($RRULE{count} =~ /^\d+$/) {
            confess "$uid: Invalid recurrence COUNT ($RRULE{count})";
          }

          $Recurrence{count} = int $RRULE{count};
        }

        if (exists $RRULE{until}) {
          # rfc5545 3.3.10 - UNTIL must be in DTSTART timezone, but both
          # google and iCloud store it in Z, so we will too as per rfc2445.
          my ($Until, $IsAllDay) = $Self->_makeDateObj($RRULE{until}, $StartTimeZone, $StartTimeZone);
          $Recurrence{until} = $Until->iso8601();
        }

        # }}}

        # parse generic recurrence properties {{{

        foreach my $Property (keys %RecurrenceProperties) {
          if (defined $RRULE{$Property}) {
            foreach my $Value (split ',', $RRULE{$Property}) {
              my ($Valid, $Min) = $RecurrenceProperties{$Property}{signed}
                ? ('[-+]?[1-9]\d*', ($RecurrenceProperties{$Property}{max} * -1))
                : ('\d+', 0);

              unless ($Value =~ /^$Valid$/) {
                confess "$uid: Invalid recurrence $Property ($Value)";
              }

              unless (($Value >= $Min) and ($Value <= $RecurrenceProperties{$Property}{max})) {
                confess "$uid: Recurrence $Property is out of range ($Value)";
              }

              push @{$Recurrence{$RecurrenceProperties{$Property}{name}}}, int $Value;
            }
          }
        }

        # }}}
      }

      my %Overrides;
      if (exists $VEvent->{properties}{exdate}) {
        foreach my $Item (@{$VEvent->{properties}{exdate}}) {
          foreach my $Date ($Self->_getDateObjMulti($Calendar, $Item, $StartTimeZone)) {
            $Overrides{$Date->iso8601()} = $JSON::null;
          }
        }
      }

      if ($VEvent->{properties}{rdate}) {
        # rdate      = "RDATE" rdtparam ":" rdtval *("," rdtval) CRLF
        foreach my $Item (@{$VEvent->{properties}{rdate}}) {
          foreach my $Date ($Self->_getDateObjMulti($Calendar, $Item, $StartTimeZone)) {
            $Overrides{$Date->iso8601()} = {};
          }
        }
      }

      # parse alarms {{{

      my %Alerts;
      foreach my $VAlarm (@{$VEvent->{objects} || []}) {
        next unless lc $VAlarm->{type} eq 'valarm';

        my %AlarmProperties
          = map { $_ => $VAlarm->{properties}{$_}[0] }
              keys %{$VAlarm->{properties}};

        my $alarmuid = $AlarmProperties{uid}{value} || _hexkey($VAlarm) . '-alarmauto';

        my %Alert;

        my $AlarmAction = lc $AlarmProperties{action}{value};
        next unless $AlarmAction;

        my %Action;

        if ($AlarmAction eq 'display') {
          $Action{type} = 'display';
        }
        elsif ($AlarmAction eq 'email') {
          $Action{type} = 'email';

          $Action{to} = [
            map { my ($x) = $_->{value} =~ m/^(?:mailto:)?(.*)/i; { email => $x } }
            @{$VAlarm->{properties}{attendee} // []}
          ];
        }
        elsif ($AlarmAction eq 'uri') {
          $Action{type} = 'uri';
          $Action{uri} = $VAlarm->{properties}{uri} // [];
        }
        elsif ($AlarmAction eq 'audio') {
          # audio alerts aren't the same as popups, but for now...
          $Action{type} = 'display';
        }
        elsif ($AlarmAction eq 'none') {
          next;
        }
        else {
          warn "$uid: UNKNOWN VALARM ACTION $AlarmAction";
          next;
        }

        if ($AlarmProperties{acknowledged}) {
          my $date = $Self->_getDateObj($Calendar, $AlarmProperties{acknowledged}, 'UTC');
          $Action{acknowledged} = $date->iso8601() . 'Z';
        }

        my $Trigger = $AlarmProperties{trigger}{value}
          || next;

        my $Related = (lc ($AlarmProperties{trigger}{params}{related}[0] || '') eq 'end')
          ? 'end'
          : 'start';

        my $Duration;
        if ($Trigger =~ m/^[+-]?P/i) {
          $Duration = eval { DateTime::Format::ICal->parse_duration(uc $Trigger) }
            || next;

        } else {
          my $AlertDate = $Self->_getDateObj($Calendar, $AlarmProperties{trigger}, $StartTimeZone);
          $Duration = $AlertDate->subtract_datetime($Related eq 'end' ? $End : $Start);
        }

        if ($Duration->is_negative()) {
          $Duration = $Duration->inverse();
          $Alert{relativeTo} = "before-$Related";
        }
        else {
          $Alert{relativeTo} = "after-$Related";
        }

        $Alert{action} = \%Action;
        $Alert{offset} = $Self->_make_duration($Duration);

        $Alerts{$alarmuid} = \%Alert;
      }

      # }}}

      # parse attendees {{{

      my %Participants;
      for my $VOrganizer (@{$VEvent->{properties}{organizer} || []}) {
        $Self->_makeParticipant($Calendar, \%Participants, $VOrganizer, 'owner');
      }
      for my $VAttendee (@{$VEvent->{properties}{attendee} || []}) {
        $Self->_makeParticipant($Calendar, \%Participants, $VAttendee, 'attendee');
      }

      # }}}

      # parse attachments {{{

      my %Links;
      foreach my $Attach (@{$VEvent->{properties}{attach} || []}) {
        next unless $Attach->{value};
        next unless grep { $Attach->{value} =~ m{^$_://} } qw{http https ftp};

        my $uri = $Attach->{value};
        my $filename = $Attach->{params}{filename}[0];
        # XXX - mime guessing?
        my $mime = $Attach->{params}{fmttype}[0];
        if (not defined $mime) {
          $::MimeTypes ||= MIME::Types->new;
          my $MimeTypeObj = $::MimeTypes->mimeTypeOf($filename);
          $mime = $MimeTypeObj->type() if $MimeTypeObj;
        }

        my $size = $Attach->{params}{size}[0];

        $Links{$uri} = {
          href => $uri,
          rel => 'enclosure',
          defined $filename ? (title => $filename) : (),
          defined $mime ? (type => $mime) : (),
          defined $size ? (size => 0+$size) : (),
        };
      }
      foreach my $URL (@{$VEvent->{properties}{url} || []}) {
        my $uri = $URL->{value};
        next unless $uri;
        $Links{$uri} = { href => $uri };
      }

      # }}}

      # ============= Metadata
      my %Event = (uid => $uid);
      # no support for relatedTo yet
      $Event{prodId} = $prodid;
      if ($Properties{created}{value}) {
        # UTC item
        my $Date = eval { $Self->_getDateObj($Calendar, $Properties{created}, 'UTC') };
        $Event{created} = $Date->iso8601() . 'Z' if $Date;
      }
      if ($Properties{dtstamp}{value}) {
        # UTC item
        my $Date = eval { $Self->_getDateObj($Calendar, $Properties{dtstamp}, 'UTC') };
        $Event{updated} = $Date->iso8601() . 'Z' if $Date;
      }
      $Event{updated} ||= DateTime->now->iso8601();
      $Event{sequence} = int($Properties{sequence}{value}) if $Properties{sequence};
      $Event{method} = $method if $method;

      # ============= What
      $Event{title} = $Properties{summary}{value} if $Properties{summary};
      $Event{description} = join("\n", @description) if @description;
      # htmlDescription is not supported
      $Event{links} = \%Links if %Links;
      my $language;
      if ($Properties{description} and $Properties{description}{params}{language}) {
        $language = $Properties{description}{params}{language}[0];
      }
      if ($Properties{summary} and $Properties{summary}{params}{language}) {
        $language = $Properties{summary}{params}{language}[0];
      }
      $Event{locale} = $language if $language;
      # translations is not supported

      # ============= Where
      # XXX - support more structured representations from VEVENTs
      if ($Properties{location}{value}) {
        $Event{locations}{location} = { name => $Properties{location}{value} };
      }
      if (not $IsAllDay and $StartTimeZone and $StartTimeZone ne $EndTimeZone) {
        $Event{locations}{end} = { rel => 'end', timeZone => $EndTimeZone };
      }

      # ============= When
      $Event{isAllDay} = $IsAllDay ? $JSON::true : $JSON::false;
      $Event{start} = $Start->iso8601() if ref($Start);
      $Event{timeZone} = $StartTimeZone if not $IsAllDay;
      my $duration = $Self->_make_duration($End->subtract_datetime($Start), $IsAllDay);
      $Event{duration} = $duration if $duration;

      $Event{recurrenceRule} = \%Recurrence if %Recurrence;
      $Event{recurrenceOverrides} = \%Overrides if %Overrides;

      # ============= Scheduling
      if ($Properties{status}{value}) {
        $Event{status} = lc($Properties{status}{value}) if lc($Properties{status}{value}) ne 'confirmed';
      }
      if ($Properties{transp}{value}) {
        $Event{showAsFree} = $JSON::true if lc($Properties{transp}{value}) eq 'transparent';
      }
      foreach my $email (sort keys %Participants) { # later wins
        $Event{replyTo} = { imip => "mailto:$email" } if grep { $_ eq 'owner' } @{$Participants{$email}{roles}};
      }
      $Event{participants} = \%Participants if %Participants;

      # ============= Alerts
      # useDefaultAlerts is not supported
      $Event{alerts} = \%Alerts if %Alerts;

      if ($Properties{lastmodified}{value}) {
        # UTC item
        my $Date = eval { $Self->_getDateObj($Calendar, $Properties{lastmodified}, 'UTC') };
        $Event{lastModified} = $Date->iso8601() . 'Z';
      }
      if ($Properties{'recurrence-id'}{value}) {
        # in our system it's always in the timezone of the event, but iCloud
        # returns it in UTC despite the event having a timezone.  Super weird.
        # Anyway, we need to format it to the StartTimeZone of the parent
        # event if there is one, and we don't have that yet!
        $Event{_recurrenceObj} = $Self->_getDateObj($Calendar, $Properties{'recurrence-id'});
      }
      push @Events, \%Event;
    }
  }

  return \@Events;
}

sub _getTimeZone {
  my $Self = shift;
  my ($Calendar, $Element) = @_;

  if ($Element->{value} =~ m/Z$/) {
    return 'Etc/UTC';
  }

  my $TZID = $Element->{params}{tzid}[0];

  return undef unless $TZID;

  return $Self->{_tznamemap}{$TZID} if exists $Self->{_tznamemap}{$TZID};

  my %TzOffsets;

  foreach my $VTimeZone (@{$Calendar->{objects} || []}) {
    next unless lc $VTimeZone->{type} eq 'vtimezone';
    next unless ($VTimeZone->{properties}{tzid}[0]{value} || '') eq $TZID;

    foreach my $Observance (@{$VTimeZone->{objects} || []}) {
      next unless grep { (lc $Observance->{type} || '') eq $_ } qw{standard daylight};
      next unless defined $Observance->{properties}{tzoffsetto}[0]{value};

      $TzOffsets{lc $Observance->{type}}
        = $Observance->{properties}{tzoffsetto}[0]{value};
    }
  }

  return undef unless exists $TzOffsets{standard};

  my $TimeZone = Net::CalDAVTalk::TimeZones->GetTimeZone(
    TZID               => $TZID,
    Time               => $Element->{value},
    StandardTzOffsetTo => $TzOffsets{standard},
    ($TzOffsets{daylight}
      ? (DaylightTzOffsetTo => $TzOffsets{daylight})
      : ()),
  ) || undef;

  $Self->{_tznamemap}{$TZID} = $TimeZone;
  return $TimeZone;
}

sub _wireDate {
  # format: YYYY-MM-DDTHH:MM:SS Z?
  my $isoDate = shift;
  my $timeZone = shift || $FLOATING;
  confess "Invalid value '$isoDate' was not ISO8601" unless $isoDate =~ m/^(\d{4,})-(\d\d)-(\d\d)T(\d\d):(\d\d):(\d\d)(Z?)$/i;
  $timeZone = 'Etc/UTC' if $7;

  my $Date = DateTime->_new(
    year => $1,
    month => $2,
    day => $3,
    hour => $4,
    minute => $5,
    second => $6,
    time_zone => $timeZone,
    locale => $LOCALE,
  ) or confess "Invalid value '$isoDate'";

  return $Date;
}

sub _vDate {
  # format: :YYYYMMDDTHHMMSS (floating)
  # format: :YYYYMMDDTHHMMSSZ (UTC)
  # format: ;TZID=X/Y:YYMMDDTHHMMSS (zoned)
  # format: ;TYPE=DATE:YYYYMMDD (but we don't know about that)
  my $vDate = shift;

  if ($vDate =~ m/^(\d\d\d\d)(\d\d)(\d\d)T(\d\d)(\d\d)(\d\d)(\.\d+)?(Z?)$/i) {
    my $Date = DateTime->_new(
      year => $1,
      month => $2,
      day => $3,
      hour => $4,
      minute => $5,
      second => $6,
      # ignore milliseconds in $7
      time_zone => ($8 eq 'Z' ? $UTC : $FLOATING),
      locale => $LOCALE,
    ) or confess "Invalid value '$vDate' for DATETIME";

    return ($Date, 1);
  }

  if ($vDate =~ m/^(\d\d\d\d)(\d\d)(\d\d)$/) {
    # all day
    my $Date = DateTime->_new(
      year => $1,
      month => $2,
      day => $3,
      time_zone => $FLOATING,
      locale => $LOCALE,
    ) or confess "Invalid value '$vDate' for DATE";

    return ($Date, 0);
  }

  # we only support those two patterns
  confess "Date '$vDate' was neither a DATE or DATETIME value";
}

sub _makeVTime {
  my $Self = shift;
  my ($TimeZones, $wire, $tz, $IsAllDay) = @_;

  my $date = _wireDate($wire, $tz);

  return $Self->_makeVTimeObj($TimeZones, $date, $tz, $IsAllDay);
}

sub _makeVTimeObj {
  my $Self = shift;
  my ($TimeZones, $date, $tz, $IsAllDay) = @_;

  # all day?
  if ($IsAllDay) {
    return [$date->strftime('%Y%m%d'), { VALUE => 'DATE' }];
  }

  # floating?
  unless ($tz) {
    return [$date->strftime('%Y%m%dT%H%M%S')];
  }

  # UTC?
  if ($UTCLinks{$tz}) {
    return [$date->strftime('%Y%m%dT%H%M%SZ')];
  }

  my $zone = $Self->tz($tz);

  $TimeZones->{$zone->name()} = 1;

  return [$date->strftime('%Y%m%dT%H%M%S'), { TZID => $zone->name() }];
}

sub _makeZTime {
  my ($Self, $date) = @_;
  return $Self->_makeVTime({}, $date, 'UTC');
}

sub _makeLTime {
  my $Self = shift;
  my ($TimeZones, $ltime, $tz, $IsAllDay) = @_;

  my $date = _wireDate($ltime, $Self->tz($tz));

  return [$date->strftime('%Y%m%d'), { VALUE => 'DATE' }] if $IsAllDay;

  unless ($tz) {
    # floating
    return [$date->strftime('%Y%m%dT%H%M%S')];
  }

  if ($tz =~ m/UTC/i) {
    return [$date->strftime('%Y%m%dT%H%M%SZ')];
  }

  # XXX - factor this crap out
  $TimeZones->{$tz} = 1;

  # XXX - use our cache
  my $zone = $Self->tz($tz);

  return [$date->strftime('%Y%m%dT%H%M%S'), { TZID => $zone->name() }];
}

sub _argsToVEvents {
  my $Self = shift;
  my ($TimeZones, $Args, $recurrenceData) = @_;
  my @VEvents;

  my $VEvent = Data::ICal::Entry::Event->new();

  # required properties
  $VEvent->add_properties(
    uid      => $Args->{uid},
    sequence => ($Args->{sequence} || 0),
    transp   => ($Args->{showAsFree} ? 'TRANSPARENT' : 'OPAQUE'),
  );

  if ($recurrenceData) {
    my ($recurrenceId, $TopLevel) = @$recurrenceData;
    $VEvent->add_property('recurrence-id' => $Self->_makeLTime($TimeZones, $recurrenceId, $TopLevel->{timeZone}, $TopLevel->{isAllDay}));
  }

  # direct copy if properties exist
  foreach my $Property (qw{description title}) {
    my $Prop = $Args->{$Property} // '';
    next if $Prop eq '';
    my %lang;
    $lang{language} = $Args->{locale} if exists $Args->{locale};
    my $key = $Property;
    $key = 'summary' if $Property eq 'title';
    $VEvent->add_property($key => [$Prop, \%lang]);
  }

  # dates in UTC - stored in UTC
  $VEvent->add_property(created => $Self->_makeZTime($Args->{created})) if $Args->{created};
  $VEvent->add_property(dtstamp => $Self->_makeZTime($Args->{updated} || DateTime->now->iso8601()));

  # dates in localtime - zones based on location
  my $EndTimeZone;
  my $locations = $Args->{locations} || {};
  foreach my $id (sort keys %$locations) {
    if ($locations->{$id}{rel} and $locations->{id}{rel} eq 'end') {
      $EndTimeZone = $locations->{end}{timeZone};
    }
    if ($locations->{$id}{name}) {
      $VEvent->add_property(location => $locations->{$id}{name});
    }
  }

  my $StartTimeZone = $Args->{timeZone};
  my $Start = _wireDate($Args->{start}, $StartTimeZone);
  $VEvent->add_property(dtstart => $Self->_makeVTimeObj($TimeZones, $Start, $StartTimeZone, $Args->{isAllDay}));
  if ($Args->{duration}) {
    $EndTimeZone //= $StartTimeZone;
    my $Duration = eval { DateTime::Format::ICal->parse_duration($Args->{duration}) };
    my $End = $Start->clone()->add($Duration) if $Duration;
    $VEvent->add_property(dtend => $Self->_makeVTimeObj($TimeZones, $End, $EndTimeZone, $Args->{isAllDay}));
  }

  if ($Args->{recurrenceRule}) {
    my %Recurrence = $Self->_makeRecurrence($Args->{recurrenceRule}, $Args->{isAllDay}, $StartTimeZone);

    # RFC 2445 4.3.10 - FREQ is the first part of the RECUR value type.
    # RFC 5545 3.3.10 - FREQ should be first to ensure backward compatibility.
    my $rule = join(';',
      ('FREQ=' . delete($Recurrence{FREQ})),
      (map { "$_=$Recurrence{$_}" } keys %Recurrence),
    );
    $VEvent->add_property(rrule => $rule);
  }

  if ($Args->{recurrenceOverrides}) {
    foreach my $recurrenceId (sort keys %{$Args->{recurrenceOverrides}}) {
      my $val = $Args->{recurrenceOverrides}{$recurrenceId};
      if ($val) {
        if (keys %$val) {
          my $SubEvent = $Self->_maximise($Args, $val, $recurrenceId);
          push @VEvents, $Self->_argsToVEvents($TimeZones, $SubEvent, [$recurrenceId, $Args]);
        }
        else {
          $VEvent->add_property(rdate => $Self->_makeLTime($TimeZones, $recurrenceId, $StartTimeZone, $Args->{isAllDay}));
        }
      }
      else {
        $VEvent->add_property(exdate => $Self->_makeLTime($TimeZones, $recurrenceId, $StartTimeZone, $Args->{isAllDay}));
      }
    }
  }

  if ($Args->{alerts}) {
    for my $id (sort keys %{$Args->{alerts}}) {
      my $Alert = $Args->{alerts}{$id};

      my $Type          = $Alert->{action}{type} // '';
      my $Recipients    = $Alert->{action}{recipients} // [];
      my $Uri           = $Alert->{action}{uri} // '';
      my $Offset        = $Alert->{offset};
      my $Sign          = $Alert->{relativeTo} =~ m/before/ ? '-' : '';
      my $Loc1          = $Alert->{relativeTo} =~ m/end/ ? "ends" : "starts";
      my $Loc2          = $Alert->{relativeTo} =~ m/end/ ? "ended" : "started";
      my $Minutes       = DateTime::Format::ICal->parse_duration(uc $Offset)->in_units('minutes');

      my $VAlarm;

      if ($Type eq 'display') {
        $VAlarm = Data::ICal::Entry::Alarm::Display->new();
        $VAlarm->add_properties(
          description => (($Sign eq '-')
            ? "'$Args->{title}' $Loc1 in $Minutes minutes"
            : "'$Args->{title}' $Loc2 $Minutes minutes ago"),
        );
      }
      elsif ($Type eq 'email' || $Type eq 'uri') {
        my ($Summary, $Description);

        if ($Sign eq '-') {
          $Summary     = "Event alert: '$Args->{title}' $Loc1 in $Minutes minutes";
          $Description = "Your event '$Args->{title}' $Loc1 in $Minutes minutes";
        }
        else {
          $Summary     = "Event alert: '$Args->{title}' $Loc2 $Minutes minutes ago";
          $Description = "Your event '$Args->{title}' $Loc2 $Minutes minutes ago";
        }

        $VAlarm = Data::ICal::Entry::Alarm::Email->new();
        $VAlarm->add_properties(
          summary     => $Summary,
          description => join("\n",
            $Description,
            "",
            "Description:",
            $Args->{description},
            # XXX more
          ),
          (map { ( attendee => "MAILTO:$_" ) } @$Recipients), # XXX naive?
        );

        if ($Type eq 'uri') {
          $VAlarm->add_property("X-URI", $Uri);
        }
      }
      else {
        confess "Unknown alarm type $Type";
      }

      $VAlarm->add_property(uid => $id);
      $VAlarm->add_property(trigger => "${Sign}$Offset");
      $VAlarm->add_property(related => 'end') if $Alert->{relativeTo} =~ m/end/;

      if ($Alert->{action}{acknowledged}) {
        $VAlarm->add_property(acknowledged => $Self->_makeZTime($Alert->{action}{acknowledged}));
      }

      $VEvent->add_entry($VAlarm);
    }
  }

  my %namemap;
  if ($Args->{participants}) {
    foreach my $Address (sort keys %{$Args->{participants}}) {
      my $Attendee = $Args->{participants}{$Address};
      my $Email = $Attendee->{email} || $Address;
      my $Rsvp  = $Attendee->{rsvp};

      my %AttendeeProps;
      if ($Attendee->{"name"}) {
        $AttendeeProps{"CN"} = $Attendee->{"name"};
        $namemap{lc "mailto:$Email"}= $Attendee->{"name"};
      }

      next unless grep { $_ eq 'attendee' } @{$Attendee->{roles}};

      $AttendeeProps{"CUTYPE"}     = uc $Attendee->{"kind"} if defined $Attendee->{"kind"};
      $AttendeeProps{"RSVP"}       = uc $Attendee->{"scheduleRSVP"} if defined $Attendee->{"scheduleRSVP"};
      $AttendeeProps{"X-SEQUENCE"} = $Attendee->{"x-sequence"} if defined $Attendee->{"x-sequence"};
      $AttendeeProps{"X-DTSTAMP"}  = $Self->_makeZTime($Attendee->{"scheduleUpdated"}) if defined $Attendee->{"scheduleUpdated"};
      foreach my $prop (keys %AttendeeProps) {
        delete $AttendeeProps{$prop} if $AttendeeProps{$prop} eq '';
      }
      if (grep { $_ eq 'chair' } @{$Attendee->{roles}}) {
        $Attendee->{ROLE} = 'CHAIR';
      }
      elsif ($Attendee->{schedulePriority} and $Attendee->{schedulePriority} eq 'optional') {
        $Attendee->{ROLE} = 'OPT-PARTICIPANT';
      }
      elsif ($Attendee->{schedulePriority} and $Attendee->{schedulePriority} eq 'non-participant') {
        $Attendee->{ROLE} = 'NON-PARTICIPANT';
      }
      # default is REQ-PARTICIPANT

      $AttendeeProps{PARTSTAT} = uc $Attendee->{"scheduleStatus"} if $Attendee->{"scheduleStatus"};

      $VEvent->add_property(attendee => [ "MAILTO:$Email", \%AttendeeProps ]);
    }
  }
  if ($Args->{replyTo}) {
    if ($Args->{replyTo}{imip}) {
      my $CN = $namemap{lc $Args->{replyTo}{imip}};
      $VEvent->add_property(organizer => [ $Args->{replyTo}{imip}, $CN ? {CN => $CN} : () ]);
    }
  }

  if ($Args->{links}) {
    foreach my $uri (sort keys %{$Args->{links}}) {
      my $Attach = $Args->{links}{$uri};
      my $Url = $Attach->{href} || $uri;
      if ($Attach->{rel} && $Attach->{rel} eq 'enclosure') {
        my $FileName = $Attach->{title};
        my $Mime = $Attach->{type};
        my $Size = $Attach->{size};

        my %AttachProps;
        $AttachProps{FMTTYPE} = $Mime if defined $Mime;
        $AttachProps{SIZE} = $Size if defined $Size;
        $AttachProps{FILENAME} = $FileName if defined $FileName;
        $VEvent->add_property(attach => [ $Url, \%AttachProps ]);
      }
      # otherwise it's just a URL
      else {
        $VEvent->add_property(url => [ $Url ]);
      }
    }
  }

  # detect if this is a dummy top-level event and skip it
  unshift @VEvents, $VEvent unless ($Args->{replyTo} and not $Args->{participants});

  return @VEvents;
}

sub _argsToVCalendar {
  my $Self = shift;
  my $Item = shift;
  my %ExtraProp = @_;

  my $VCalendar = Data::ICal->new();
  my $havepid = 0;

  foreach my $extra (keys %ExtraProp) {
    $VCalendar->add_properties($extra => $ExtraProp{$extra});
  }
  $VCalendar->add_properties(calscale => 'GREGORIAN');

  my @VEvents;
  my %TimeZones;
  foreach my $Args (ref $Item eq 'ARRAY' ? @$Item : $Item) {
    if (not $havepid and $Args->{prodId}) {
      $VCalendar->add_properties('prodid' => $Args->{prodId});
      $havepid = 1;
    }
    # initialise timestamp if not given one
    $Args->{dtstamp} //= DateTime->now()->strftime('%Y-%m-%dT%H:%M:%S');
    push @VEvents, $Self->_argsToVEvents(\%TimeZones, $Args);
  }

  # add timezone parts first
  foreach my $Zone (sort keys %TimeZones) {
    my $VTimeZone = Net::CalDAVTalk::TimeZones->GetVTimeZone($Zone);
    next unless $VTimeZone;
    $VCalendar->add_entry($VTimeZone);
  }

  # then the events
  foreach my $VEvent (@VEvents) {
    $VCalendar->add_entry($VEvent);
  }

  return $VCalendar;
}

sub _makeRecurrence {
  my $Self = shift;
  my ($Args, $IsAllDay, $TZ) = @_;

  my %Recurrence;

  # validate simple recurrence properties {{{

  unless (ref($Args) eq 'HASH') {
    confess 'Invalid recurrence';
  }

  if ($Args->{frequency}) {
    unless (grep { $_ eq $Args->{frequency} } @Frequencies) {
      confess "Invalid recurrence frequency ($Args->{frequency})";
    }

    $Recurrence{FREQ} = uc($Args->{frequency});
  }
  else {
    confess 'Recurrence frequency not specified';
  }

  if (defined $Args->{interval}) {
    unless ($Args->{interval} =~ /^\d+$/) {
      confess "Invalid recurrence interval ($Args->{interval})";
    }

    if ($Args->{interval} == 0) {
      confess "Recurrence interval is out of range ($Args->{interval})";
    }

    if ($Args->{interval} > 1) {
      $Recurrence{INTERVAL} = $Args->{interval};
    }
  }

  if (defined $Args->{firstDayOfWeek}) {
    unless (exists $DaysByIndex{$Args->{firstDayOfWeek}}) {
      confess "Invalid recurrence firstDayOfWeek ($Args->{firstDayOfWeek})";
    }

    unless ($Args->{firstDayOfWeek} == 1){
      $Recurrence{WKST} = uc $DaysByIndex{$Args->{firstDayOfWeek}};
    }
  }

  if ($Args->{byDay}) {
    unless (ref($Args->{byDay}) eq 'ARRAY') {
      confess 'Invalid recurrence byDay';
    }

    unless (@{$Args->{byDay}}) {
      confess 'Recurrence byDay is empty';
    }

    $Recurrence{BYDAY} = join(',', map{ _byDay2BYDAY($_) } @{$Args->{byDay}});
  }

  if ($Args->{byMonth}) {
    unless (ref($Args->{byMonth}) eq 'ARRAY') {
      confess 'Invalid recurrence byMonth';
    }

    unless (@{$Args->{byMonth}}) {
      confess 'Recurrence byMonth is empty';
    }

    my @BYMONTHS;

    foreach my $byMonth (@{$Args->{byMonth}}) {
      unless ($byMonth =~ /^(\d+)L?$/i) {
        confess "Recurrence byMonth is not a number with optional L ($byMonth)";
      }
      my $monthNum = $1;
      unless ($monthNum >= 1 and $monthNum <= 13) {
        # not sure if 13 is OK
        confess "Recurrence byMonth is too high ($monthNum)";
      }

      push @BYMONTHS, $byMonth;
    }

    $Recurrence{BYMONTH} = join ',', @BYMONTHS;
  }

  if (defined $Args->{count}) {
    if (defined $Args->{until}) {
      confess 'Recurrence count and until cannot both be set';
    }

    unless ($Args->{count} =~ /^\d+$/) {
      confess "Invalid recurrence count ($Args->{count})";
    }

    $Recurrence{COUNT} = $Args->{count};
  }

  if ($Args->{until}) {
    my $Until = _wireDate($Args->{until}, $Self->tz($TZ));

    if ($IsAllDay) {
      $Recurrence{UNTIL} = $Until->strftime('%Y%m%d');
    }
    else {
      # API is in Localtime, but both iCloud and Google use 'Z' times as per
      # rfc2445, so we'll copy them for compatibility.
      $Until->set_time_zone($UTC);
      $Recurrence{UNTIL} = $Until->strftime('%Y%m%dT%H%M%SZ');
    }
  }

  # }}}

  # validate generic recurrence properties {{{

  foreach my $Property (keys %RecurrenceProperties) {
    my $Name = $RecurrenceProperties{$Property}{name}; 

    if ($Args->{$Name}) {
      unless (ref($Args->{$Name}) eq 'ARRAY') {
        confess "Invalid recurrence $Name";
      }

      unless (@{$Args->{$Name}}) {
        confess "Recurrence $Name is empty";
      }

      my @Values;

      foreach my $Value (@{$Args->{$Name}}) {
        my ($Valid, $Min) = $RecurrenceProperties{$Property}{signed}
          ? ('[-+]?[1-9]\d*', ($RecurrenceProperties{$Property}{max} * -1))
          : ('\d+', 0);

        unless ($Value =~ /^$Valid$/) {
          confess "Invalid recurrence $Name ($Value)";
        }

        unless (($Min <= $Value) and ($Value <= $RecurrenceProperties{$Property}{max})) {
          confess "Recurrence $Name is out of range ($Value)";
        }

        push @Values, $Value;
      }

      $Recurrence{uc $Property} = join ',', @Values;
    }
  }

  # }}}

  return %Recurrence;
}

=head2 $self->vcalendarToEvents($Data)

Convert a text vcalendar (either a single event or an entire ical file) into an array of events.

Returns an array (not arrayref) of Events in UID order.

e.g.

    foreach my $Event ($CalDAV->vcalendarToEvents($Data)) {
        # ...
    }

=cut

sub _insert_override {
  my $Event = shift;
  my $recurrenceId = shift;
  my $Recurrence = shift;

  my %override;
  my %oldkeys = map { $_ => 1 } keys %$Event;
  foreach my $Key (sort keys %$Recurrence) {
    delete $oldkeys{$Key};
    next if $MustBeTopLevel{$Key}; # XXX - check safeeq and die?
    if ($Key eq 'start') {
      # special case, it's the recurrence-id
      next if _safeeq($Recurrence->{start}, $recurrenceId);
      $override{start} = $Recurrence->{start};
      next;
    }
    next if _safeeq($Recurrence->{$Key}, $Event->{$Key});
    _add_override(\%override, _quotekey($Key), $Recurrence->{$Key}, $Event->{$Key});
  }

  foreach my $Key (sort keys %oldkeys) {
    next if $MustBeTopLevel{$Key};
    $override{$Key} = $JSON::null;
  }

  # in theory should never happen, but you could edit something back to be identical
  return unless %override;
  $Event->{recurrenceOverrides}{$recurrenceId} = \%override;
}

sub vcalendarToEvents {
  my $Self = shift;
  my $Data = shift;

  # Internal caches need to be invalidated on each item read! A bit evil really...
  delete $Self->{_tznamemap};

  my %map;
  my %exceptions;
  my $Events = $Self->_getEventsFromVCalendar($Data);

  foreach my $Event (@$Events) {
    my $uid = $Event->{uid};
    if ($Event->{_recurrenceObj}) {
      push @{$exceptions{$uid}}, $Event;
    }
    elsif ($map{$uid}) {
      # it looks like sometimes Google doesn't remember to put the Recurrence ID
      # on additional recurrences after the first one, which is going to screw up
      # pretty badly because if the date has changed, then we can't even notice
      # which recurrent it was SUPPOSED to be.  *sigh*.
      warn "DUPLICATE EVENT FOR $uid\n" . Dumper($map{$uid}, $Event);
      push @{$exceptions{$uid}}, $Event;
      $map{$uid}{_dirty} = 1;
    }
    else {
      $map{$uid} = $Event;
    }
  }

  foreach my $uid (keys %exceptions) {
    unless ($map{$uid}) {
      # create a synthetic top-level
      my $First = $exceptions{$uid}[0];
      $map{$uid} = {
        uid => $uid,
        # these two are required at top level, but may be different
        # in recurrences so aren't in MustBeTopLevel
        start => $First->{start},
        updated => $First->{updated},
      };
      $map{$uid}{timeZone} = $First->{timeZone} unless $First->{isAllDay};
      foreach my $key (keys %MustBeTopLevel) {
        $map{$uid}{$key} = $First->{$key} if exists $First->{$key};
      }
    }
    foreach my $SubEvent (@{$exceptions{$uid}}) {
      my $recurrenceId = $SubEvent->{start};
      if ($SubEvent->{_recurrenceObj}) {
        my $Date = delete $SubEvent->{_recurrenceObj};
        $Date->set_time_zone($map{$uid}{timeZone}) if $map{$uid}{timeZone};
        $recurrenceId = $Date->iso8601();
      }
      _insert_override($map{$uid}, $recurrenceId, $SubEvent);
    }
  }

  return map { $map{$_} } sort keys %map;
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

sub _quotekey {
  my $key = shift;
  $key =~ s/\~/~0/gs;
  $key =~ s/\//~1/gs;
  return $key;
}

sub _unquotekey {
  my $key = shift;
  $key =~ s/\~1/\//gs;
  $key =~ s/\~0/~/gs;
  return $key;
}

sub _add_override {
  my ($override, $prefix, $New, $Old) = @_;

  # basic case - it's not an object, so we just override
  if ($ENV{JMAP_ALWAYS_FULL} or ref($New) ne 'HASH' or ref($Old) or 'HASH') {
    $override->{$prefix} = $New;
    return;
  }

  # XXX - if too many, we could just abort...
  my %subover;
  my %oldkeys = map { $_ => 1 } keys %$Old;
  foreach my $Key (sort keys %$New) {
    delete $oldkeys{$Key};
    next if _safeeq($New->{$Key}, $Old->{$Key});
    _add_override(\%subover, "$prefix/" . _quotekey($Key), $New->{$Key}, $Old->{$Key});
  }
  foreach my $Key (sort keys %oldkeys) {
    $subover{"$prefix/" . _quotekey($Key)} = $JSON::null;
  }

  # which one is better?
  if (length(encode_json($New)) < length(encode_json(\%subover))) {
    $override->{$prefix} = $New; # cheaper to just encode the whole object
  }
  else {
    $override->{$_} = $subover{$_} for keys %subover;
  }
}

sub _apply_patch {
  my $path = shift;
  my $hash = shift;
  my $value = shift;

  return unless $path =~ s{^([^/]+)(/?)}{};
  return unless ref($hash) eq 'HASH';
  my $qkey = $1;
  my $slash = $2;
  my $key = _unquotekey($qkey);
  if ($slash) {
    _apply_patch($path, $hash->{$key}, $value);
  }
  elsif(defined $value) {
    $hash->{$key} = $value;
  }
  else {
    delete $hash->{$key};
  }
}

sub _maximise {
  my $Self = shift;
  my $Event = shift;
  my $Recurrence = shift;
  my $recurrenceId = shift;

  #warn "MAXIMIZING EVENT INTO RECURRENCE: " . Dumper($Event, $Recurrence);

  my $new = _deepcopy($Event);
  $new->{start} = $recurrenceId;
  delete $new->{recurrenceRule};
  delete $new->{recurrenceOverrides};

  foreach my $path (sort keys %$Recurrence) {
    my $value = $Recurrence->{$path};
    _apply_patch($path, $new, $value);
  }

  return $new;
}

sub _stripNonICal {
  my $Self = shift;
  my $Event = shift;

  delete $Event->{alerts};
  delete $Event->{attendees};
  delete $Event->{organizer};

  foreach my $exception (values %{$Event->{exceptions}}) {
    next unless $exception;
    $Self->_stripNonICal($exception);
  }
}

sub _safeeq {
  my ($a, $b) = @_;
  my $json = JSON::XS->new->canonical;
  return $json->encode([$a]) eq $json->encode([$b]);
}

sub _deepcopy {
  my $data = shift;
  my $json = JSON::XS->new->canonical;
  my $enc = $json->encode([$data]);
  my $copy = $json->decode($enc);
  return $copy->[0];
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
