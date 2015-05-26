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
use JSON;
use Net::CalDAVTalk::TimeZones;
use Text::VCardFast qw(vcard2hash);
use XML::Spice;
use MIME::Base64 qw(encode_base64);
use MIME::Types;
use Digest::SHA qw(sha1_hex);
use URI::Escape qw(uri_unescape);

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
  %DaysByName,
  %DaysByIndex,
  %ColourNames,
  @EventProperties,
  @Frequencies,
  %RecurrenceProperties,
  %UTCLinks,
);

BEGIN {
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
  @Frequencies           = qw{yearly monthly weekly daily hourly secondly};

  @EventProperties = qw{
    uid
    sequence
    created
    lastModified
    dtstamp
    summary
    description
    location
    showAsFree
    isAllDay
    utcStart
    startTimeZone
    utcEnd
    endTimeZone
    recurrence
    exceptions
    inclusions
    alerts
    attendees
    organiser
    attachments
  };

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

Net::CalDAVTalk - The great new Net::CalDAVTalk!

=head1 VERSION

Version 0.01

=cut

our $VERSION = '0.01';


=head1 SYNOPSIS

NOTE: documentation to follow - importing raw from FastMail repo first

Perhaps a little code snippet.

    use Net::CalDAVTalk;

    my $foo = Net::CalDAVTalk->new();
    ...

=head1 SUBROUTINES/METHODS

=head2 function1

=cut

# General methods

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

sub logger {
  my $Self = shift;

  if ($@) {
    $Self->{logger} = shift;
  }

  return $Self->{logger};
}

# Calendar methods

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
  my $colour = lc(shift || '');

  return $colour if $ColourNames{$colour};
  return $DefaultCalendarColour unless $colour =~ m/^(\#[a-f0-9]{3,8})$/;
  return uc($colour) if length($colour) == 7;

  # Optional digit is for transparency (RGBA)
  if ( $colour =~ m/^#(.)(.)(.).?$/ ) {
    return uc "#$1$1$2$2$3$3";
  }

  # Last two digits are for transparency (RGBA)
  if ( length($colour) == 9 ) {
    return uc(substr($colour,0,7));
  }

  return $DefaultCalendarColour;
}

sub GetPublicCalendars {
  my ($Class, $URL) = @_;

  $Class   = ref($Class) || $Class;
  my $Self = $Class->new(url => $URL);

  my $Response = $Self->Request(
    'GET',
    '',
  );

  my $CalendarData = eval { vcard2hash($Response->{content}, only_one => 1) }
    or confess "Error parsing VCalendar data: $@";

  my @Calendars;

  foreach my $CalendarData (@{$CalendarData->{objects} || []}) {
    next unless $CalendarData->{type} eq 'vcalendar';

    my %Calendar;

    foreach my $Property (keys %{$CalendarData->{properties} ||{}}) {
      $Calendar{$Property} = $CalendarData->{properties}{$Property}[0]{value};
    }

    push @Calendars, \%Calendar;
  }

  return \@Calendars;
}

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
    'D:sync-token',
    'D:supported-report-set',
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

      # XXX - temporary compat
      $Privileges{isReadOnly} = $Privileges{mayWrite} ? $JSON::false : $JSON::true;

      my @ShareWith;
      my $ace = $Propstat->{"{$NS_D}prop"}{"{$NS_D}acl"}{"{$NS_D}ace"};
      $ace = [] unless ($ace and ref($ace) eq 'ARRAY');
      foreach my $Acl (@$ace) {
        next if $Acl->{"{$NS_D}protected"};  # ignore admin ACLs
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
        colour     => _fixColour($Propstat->{"{$NS_D}prop"}{"{$NS_A}calendar-color"}{content}),
        isVisible  => $isVisible,
        precedence => int($Propstat->{"{$NS_D}prop"}{"{$NS_A}calendar-order"}{content} || 1),
        syncToken  => ($Propstat->{"{$NS_D}prop"}{"{$NS_D}sync-token"}{content} || ''),
        shareWith  => (@ShareWith ? \@ShareWith : $JSON::false),
        %Privileges,
      );


      push @Calendars, \%Cal;
    }
  }

  return \@Calendars;
}

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
  $Args->{name} //= '';

  my $calendarId = $Args->{id};

  my @Properties;

  push @Properties, x('D:displayname', $Args->{name});

  if (exists $Args->{isVisible}) {
    push @Properties, x('C:X-FM-isVisible', ($Args->{isVisible} ? 1 : 0));
  }

  if (exists $Args->{colour}) {
    push @Properties, x('A:calendar-color', _fixColour($Args->{colour}));
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

  if (defined $Calendar{colour}) {
    push @Params, x('A:calendar-color', _fixColour($Calendar{colour}));
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

sub GetEvents {
  my ($Self, $calendarId, %Args) = @_;

  # validate parameters {{{

  confess "Need a calendarId" unless $calendarId;

  my @Query;
  my $TopLevel = 'C:calendar-query';
  my $Filter;
  if ($Args{href}) {
    $TopLevel = 'C:calendar-multiget';
    $Filter = x('D:href', $Args{href});
  }
  elsif ($Args{AlwaysRange} || $Args{utcStart} || $Args{utcEnd}) {
    my $Start = _wireDate($Args{utcStart} || $BoT);
    my $End = _wireDate($Args{utcEnd} || $EoT);

    $Filter = x('C:filter',
      x('C:comp-filter', { name => 'VCALENDAR' },
        x('C:comp-filter', { name => 'VEVENT' },
          x('C:time-range', {
            start => $Start->strftime('%Y%m%dT000000Z'),
            end   => $End->strftime('%Y%m%dT000000Z'),
          }),
        ),
      ),
    );
  }
  else {
    $Filter = x('C:filter',
      x('C:comp-filter', { name => 'VCALENDAR' },
        x('C:comp-filter', { name => 'VEVENT' },
        ),
      ),
    );
  }
  my @Annotations;
  my $AnnotNames = $Args{Annotations} || [];
  foreach my $key (@$AnnotNames) {
    my $name = ($key =~ m/:/ ? $key : "C:$key");
    push @Annotations, x($name);
  }

  # }}}

  my $Response = $Self->Request(
    'REPORT',
    "$calendarId/",
    x($TopLevel, $Self->NS(),
      x('D:prop',
        x('C:calendar-data'),
        @Annotations,
      ),
      $Filter,
    ),
    Depth => 1,
  );

  return $Response if $Args{Raw};

  my (@Events, @Errors);

  my $NS_A = $Self->ns('A');
  my $NS_C = $Self->ns('C');
  my $NS_D = $Self->ns('D');
  foreach my $Response (@{$Response->{"{$NS_D}response"} || []}) {
    my $href = uri_unescape($Response->{"{$NS_D}href"}{content} // '');
    next unless $href;
    foreach my $Propstat (@{$Response->{"{$NS_D}propstat"} || []}) {
      my $Data = $Propstat->{"{$NS_D}prop"}{"{$NS_C}calendar-data"}{content};
      next unless $Data;

      my ($Event) = eval { $Self->vcalendarToEvents($Data) };

      if ($@) {
        push @Errors, $@;
        next;
      }
      next unless $Event;

      if ($Args{Full}) {
        $Event->{_raw} = $Data;
      }
      else {
        $Self->_minimise($Event);
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

  return wantarray ? (\@Events, \@Errors) : \@Events;
}

sub GetEvent {
  my ($Self, $href, %Args) = @_;

  # XXX - API
  my $calendarId = $href;
  $calendarId =~ s{/[^/]*$}{};

  my ($Events, $Errors) = $Self->GetEvents($calendarId, href => $Self->fullpath($href));

  die "Errors @$Errors" if @$Errors;
  die "Multiple items returned for $href" if @$Events > 1;

  return $Events->[0];
}

sub GetFreeBusy {
  my ($Self, $calendarId, %Args) = @_;

  # validate parameters {{{

  confess "Need a calendarId" unless $calendarId;

  my @Query;
  if ($Args{AlwaysRange} || $Args{utcStart} || $Args{utcEnd}) {
    my $Start = _wireDate($Args{utcStart} || $BoT);
    my $End = _wireDate($Args{utcEnd} || $EoT);

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
      my $NewEvent = {
        startTimeZone => 'Etc/UTC',
        endTimeZone => 'Etc/UTC',
        utcStart => $StartTime->iso8601(),
        utcEnd => $EndTime->iso8601(),
        summary => ($Args{name} // ''),
        isAllDay => ($IsAllDay ? 1 : 0), 
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

sub SyncEvents {
  my ($Self, $calendarId, %Args) = @_;

  confess "Need a calendarId" unless $calendarId;

  my @Annotations;
  my $AnnotNames = $Args{Annotations} || [];
  foreach my $key (@$AnnotNames) {
    my $name = ($key =~ m/:/ ? $key : "C:$key");
    push @Annotations, x($name);
  }

  my $Response = $Self->Request(
    'REPORT',
    "$calendarId/",
    x('D:sync-collection', $Self->NS(),
      x('D:sync-token', ($Args{syncToken} ? ($Args{syncToken}) : ())),
      x('D:sync-level', 1),
      x('D:prop',
        x('D:getetag'),
        x('C:calendar-data'),
        @Annotations,
      ),
    ),
  );

  my (@Events, @Removed, @Errors);

  my $NS_A = $Self->ns('A');
  my $NS_C = $Self->ns('C');
  my $NS_D = $Self->ns('D');
  foreach my $Response (@{$Response->{"{$NS_D}response"} || []}) {
    my $href = uri_unescape($Response->{"{$NS_D}href"}{content} // '');
    next unless $href;

    unless ($Response->{"{$NS_D}propstat"}) {
      push @Removed, $Self->shortpath($href);
      next;
    }

    foreach my $Propstat (@{$Response->{"{$NS_D}propstat"} || []}) {
      my $status = $Propstat->{"{$NS_D}status"}{content};
      if ($status =~ m/ 200 /) {
        my $Data = $Propstat->{"{$NS_D}prop"}{"{$NS_C}calendar-data"}{content};
        next unless $Data;

        my ($Event) = eval { $Self->vcalendarToEvents($Data) };

        if ($@) {
          push @Errors, $@;
          next;
        }
        next unless $Event;

        if ($Args{Full}) {
          $Event->{_raw} = $Data;
        }
        else {
          $Self->_minimise($Event);
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
      else {
        push @Errors, "Odd status $status";
      }
    }
  }

  return wantarray ? (\@Events, \@Removed, \@Errors) : \@Events;
}

sub NewEvent {
  my ($Self, $calendarId, $Args) = @_;

  confess "Need a calendarId" unless $calendarId;

  confess "invalid event" unless ref($Args) eq 'HASH';

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
  my $VCalendar = $Self->_argsToVCalendar($Args);

  my $uid = $Args->{uid};
  my $path = $uid;
  $path =~ tr/[a-zA-Z0-9\@\.\_\-]//cd;
  my $href = "$calendarId/$path.ics";

  $Self->Request(
    'PUT',
    $href,
    $VCalendar->as_string(),
    'Content-Type'  => 'text/calendar',
  );

  return $href;
}

sub UpdateEvent {
  my ($Self, $href, $Args) = @_;

  my ($OldEvent, $NewEvent) = $Self->_updateEvent($href, $Args);
  my $NewVCalendar          = $Self->_argsToVCalendar($NewEvent);

  $Self->Request(
    'PUT',
    $href,
    $NewVCalendar->as_string(),
    'Content-Type' => 'text/calendar',
  );

  return 1;
}

sub _updateEvent {
  my ($Self, $href, $Args) = @_;

  my $OldEvent = $Self->GetEvent($href);

  confess "Error getting old event for $href"
    unless $OldEvent;

  my %NewEvent;

  foreach my $Property (@EventProperties) {
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

  unless (exists $DaysByName{$Day}) {
    confess 'Invalid recurrence BYDAY-weekday';
  }

  if ($Count) {
    unless (($Count >= -53) and ($Count <= 53)) {
      confess 'Recurrence BYDAY-ordwk is out of range';
    }
  }

  return int($DaysByName{$Day} + ($Count ? (7 * $Count) : 0));
}

sub _byDay2BYDAY {
  my ($byDay) = @_;

  unless (defined $byDay) {
    confess 'Invalid recurrence byDay';
  }

  unless ($byDay =~ /^-?\d+$/) {
    confess 'Recurrence byDay is not a number';
  }

  my $Day          = $byDay % 7;
  my $SignedPrefix = ($byDay - $Day) / 7;

  unless (($SignedPrefix >= -53) and ($SignedPrefix <= 53)) {
    confess 'Recurrence byDay is out of range';
  }

  my $Prefix = ($SignedPrefix < 0 ? ($SignedPrefix * -1) : $SignedPrefix) % 54;

  if ($SignedPrefix < 0) {
    $Prefix *= -1;
  }

  return ($Prefix || '') . uc($DaysByIndex{$Day});
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
  $Date->set_time_zone($Self->tz($TZStr)) if ($TZStr);
  if ($TargetTz) {
    # XXX - skip if it's unchanged or already floating
    $Date->set_time_zone($Self->tz($TargetTz));
  }

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
    my ($Date, $IsAllDay) = $Self->_makeDateObj($Value, $TimeZone, $TargetTz);
    push @Dates, $Date;
  }

  return @Dates;
}

# Exclude DTSTAMP from auto uid generation
sub _hexkey {
  my $VEvent = shift;
  my $Dtstamp = delete $VEvent->{properties}->{dtstamp};
  my $d = Data::Dumper->new([$VEvent]);
  $d->Indent(0);
  $d->Sortkeys(1);
  my $Key = sha1_hex($d->Dump());
  $VEvent->{properties}->{dtstamp} = $Dtstamp if $Dtstamp;
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

sub _getEventsFromVCalendar {
  my ($Self, $VCalendar) = @_;

  my $CalendarData = eval { vcard2hash($VCalendar, multival => ['rrule'], only_one => 1) }
    or confess "Error parsing VCalendar data: $@\n\n$VCalendar";

  my @Events;

  foreach my $Calendar (@{$CalendarData->{objects} || []}) {
    next unless lc $Calendar->{type} eq 'vcalendar';

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
      push @description, map { $_->{value} } @{$VEvent->{properties}{url}}
        if $VEvent->{properties}{url};

      # }}}

      # parse time component properties {{{

      my ($IsAllDay, $Start, $StartTimeZone, $End, $EndTimeZone) = ('') x 5;

      if (defined $Properties{dtstart}{value}) {
        ($Start, $StartTimeZone, $IsAllDay) = $Self->_getDateObj($Calendar, $Properties{dtstart}, 'UTC');

        if (defined $Properties{dtend}{value}) {
          if (defined $Properties{duration}{value}) {
            confess "$uid: DTEND and DURATION cannot both be set";
          }

          ($End, $EndTimeZone) = $Self->_getDateObj($Calendar, $Properties{dtend}, 'UTC');

          if ($IsAllDay and $Start->iso8601() eq $End->iso8601()) {
            # make zero-length event longer
            $End->add(days => 1);
          }
        }
        elsif (defined $Properties{duration}{value}) {
          my $Duration = DateTime::Format::ICal->parse_duration(uc $Properties{duration}{value});
          $End = $Start->clone()->add($Duration);
          $EndTimeZone = $StartTimeZone;
        }
        elsif ($IsAllDay) {
          $End = $Start->clone()->add(days => 1);
        }
        else {
          $End         = $Start->clone();
          $EndTimeZone = $StartTimeZone;
        }

        if ($Start->iso8601() gt $End->iso8601()) {
          # swap em!
          ($Start, $End) = ($End, $Start);
          ($StartTimeZone, $EndTimeZone) = ($EndTimeZone, $StartTimeZone);
        }
      }
      elsif (not defined $Properties{'recurrence-id'}{value}) {
        confess "$uid: DTSTART not specified";
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
          use Data::Dumper;
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

        if (exists $RRULE{wkst}) {
          my $wkst = lc $RRULE{wkst};
          unless (defined $DaysByName{$wkst}) {
            confess "$uid: Invalid recurrence WKST ($RRULE{wkst})";
          }

          # default is Monday, so don't set a key for it
          if ($wkst ne 'mo') {
            $Recurrence{firstDayOfWeek} = int $DaysByName{$wkst};
          }
        }

        if (exists $RRULE{byday}) {
          my @byDays;

          foreach my $BYDAY (split ',', $RRULE{byday}) {
            push @byDays, _BYDAY2byDay(lc $BYDAY);
          }

          $Recurrence{byDay} = [sort { $a <=> $b } @byDays];
        }

        if (exists $RRULE{bymonth}) {
          foreach my $BYMONTH (split ',', $RRULE{bymonth}) {
            unless ($BYMONTH =~ /^\d+$/) {
              confess "$uid: Invalid recurrence BYMONTH ($BYMONTH, $RRULE{bymonth})";
            }

            unless (($BYMONTH >= 1) and ($BYMONTH <= 12)) {
              confess "$uid: Recurrence BYMONTH is out of range ($BYMONTH, $RRULE{bymonth})"; 
            }

            push @{$Recurrence{byMonth}}, ($BYMONTH - 1);
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

      my %Exceptions;
      if (exists $VEvent->{properties}{exdate}) {
        foreach my $Item (@{$VEvent->{properties}{exdate}}) {
          foreach my $Date ($Self->_getDateObjMulti($Calendar, $Item, $StartTimeZone)) {
            $Exceptions{$Date->iso8601()} = $JSON::null;
          }
        }
      }

      my @Inclusions;
      if ($VEvent->{properties}{rdate}) {
        # rdate      = "RDATE" rdtparam ":" rdtval *("," rdtval) CRLF
        my %Inclusions;
        foreach my $Item (@{$VEvent->{properties}{rdate}}) {
          foreach my $Date ($Self->_getDateObjMulti($Calendar, $Item, $StartTimeZone)) {
            $Inclusions{$Date->iso8601()} = $JSON::null;
          }
        }
        @Inclusions = sort keys %Inclusions;
      }

      # parse alarms {{{

      my @Alerts;
      foreach my $VAlarm (@{$VEvent->{objects} || []}) {
        next unless lc $VAlarm->{type} eq 'valarm';

        my %AlarmProperties
          = map { $_ => $VAlarm->{properties}{$_}[0] }
              keys %{$VAlarm->{properties}};

        my %Alert;

        my $Action = lc $AlarmProperties{action}{value};
        next unless $Action;

        if ($Action eq 'display') {
          $Alert{type} = 'alert';
        }
        elsif ($Action eq 'email') {
          $Alert{type} = 'email';

          $Alert{recipients} = [
            map { my ($x) = $_->{value} =~ m/^(?:mailto:)?(.*)/i; $x }
            @{$VAlarm->{properties}{attendee} // []}
          ];
        }
        elsif ($Action eq 'uri') {
          $Alert{type} = 'uri';
          $Alert{uri} = $VAlarm->{properties}{uri} // [];
        }
        elsif ($Action eq 'audio') {
          # audio alerts aren't the same as popups
          next;
        }
        elsif ($Action eq 'none') {
          next;
        }
        else {
          warn "$uid: UNKNOWN VALARM ACTION $Action";
          next;
        }

        my $Trigger = $AlarmProperties{trigger}{value}
          || next;

        my $Related = (lc ($AlarmProperties{trigger}{params}{related}[0] || '') eq 'end')
          ? 'end'
          : 'start';

        my $AlertDate;
        if ($Trigger =~ m/^[+-]?P/i) {
          my $Duration = eval { DateTime::Format::ICal->parse_duration(uc $Trigger) }
            || next;

          # Can't get seconds on all durations, so calculate real date,
          #  and then delta_ms against it
          my $RelDate = $Related eq 'start' ? $Start : $End;
          next unless ref $RelDate;

          $AlertDate = $RelDate->clone()->add($Duration);
        } else {
          $AlertDate = $Self->_getDateObj($Calendar, $AlarmProperties{trigger}, $StartTimeZone);
        }

        next unless ref $Start;
        $Alert{minutesBefore} = $AlertDate->delta_ms($Start)->in_units('minutes');

        if ($Start < $AlertDate) {
          # RFC and API are reverse signed
          $Alert{minutesBefore} *= -1;
        }

        push @Alerts, \%Alert;
      }

      # }}}

      # parse attendees {{{

      my @Attendees;
      for my $VAttendee (@{$VEvent->{properties}{attendee} || []}) {
        next unless $VAttendee->{value};
        $VAttendee->{value} =~ s/^mailto://i;

        my %Attendee;
        $Attendee{"name"}       = $VAttendee->{params}{"cn"}[0]         // "";
        $Attendee{"email"}      = $VAttendee->{value}                   // "";

        if (exists $VAttendee->{params}{"x-sequence"}) {
          $Attendee{"x-sequence"} = $VAttendee->{params}{"x-sequence"}[0] // "";
        }

        if (exists $VAttendee->{params}{"x-dtstamp"}) {
          $Attendee{"x-dtstamp"} = $VAttendee->{params}{"x-dtstamp"}[0]  // "";
        }

        $Attendee{rsvp} = {
          accepted  => "yes",
          declined  => "no",
          tentative => "maybe",
        }->{lc($VAttendee->{params}{partstat}[0] // "")} // "";

        push @Attendees, \%Attendee;
      }

      my $Organiser;
      for my $VOrganiser (@{$VEvent->{properties}{organizer} || []}) {
        next unless $VOrganiser->{value};
        $VOrganiser->{value} =~ s/^mailto://i;
        my %Organiser = (
          email => $VOrganiser->{value},
        );
        $Organiser{name} = $VOrganiser->{params}{cn}[0] // "";
        $Organiser = \%Organiser;
      }

      # }}}

      # parse attachments {{{

      my @Attachments;
      foreach my $Attach (@{$VEvent->{properties}{attach} || []}) {
        next unless $Attach->{value};
        next unless grep { $Attach->{value} =~ m{^$_://} } qw{http https ftp};

        my $url = $Attach->{value};
        my $filename = $Attach->{params}{filename}[0];
        if (not defined $filename and $url =~ m{/([^/]+)$}) {
          $filename = $1;
        }
        # XXX - mime guessing?
        my $mime = $Attach->{params}{fmttype}[0];
        if (not defined $mime) {
          $::MimeTypes ||= MIME::Types->new;
          my $MimeTypeObj = $::MimeTypes->mimeTypeOf($filename);
          $mime = $MimeTypeObj->type() if $MimeTypeObj;
        }

        my $size = $Attach->{params}{size}[0];

        push @Attachments, {
          url => $url,
          name => $filename,
          $mime ? (type => $mime) : (),
          $size ? (size => $size) : (),
        };
      }

      # }}}

      my %Event = (
        uid             => $uid,
        state           => '',
        sequence        => ($Properties{sequence}{value} || '0'),
        summary         => ($Properties{summary}{value} || ''),
        description     => join("\n", @description),
        location        => ($Properties{location}{value} || ''),
        showAsFree      => ($ShowAsFree ? $JSON::true : $JSON::false),
        isAllDay        => ($IsAllDay ? $JSON::true : $JSON::false),
        utcStart        => (ref($Start) ? $Start->iso8601() : $JSON::null),
        utcEnd          => (ref($End) ? $End->iso8601() : $JSON::null),
        startTimeZone   => ($IsAllDay ? $JSON::null : $StartTimeZone),
        endTimeZone     => ($IsAllDay ? $JSON::null : $EndTimeZone),
        recurrence      => (%Recurrence ? \%Recurrence : $JSON::null),
        exceptions      => (%Exceptions ? \%Exceptions : $JSON::null),
        inclusions      => (@Inclusions ? \@Inclusions : $JSON::null),
        organiser       => $Organiser,
        attendees       => (@Attendees ? \@Attendees : $JSON::null),
        alerts          => (@Alerts ? \@Alerts : $JSON::null),
        attachments     => (@Attachments ? \@Attachments : $JSON::null),
      );
      if ($Properties{dtstamp}{value}) {
        # UTC item
        my $Date = eval { $Self->_getDateObj($Calendar, $Properties{dtstamp}, 'UTC') };
        $Event{dtstamp} = $Date->iso8601() if $Date;
      }
      if ($Properties{created}{value}) {
        # UTC item
        my $Date = eval { $Self->_getDateObj($Calendar, $Properties{created}, 'UTC') };
        $Event{created} = $Date->iso8601() if $Date;
      }
      if ($Properties{lastmodified}{value}) {
        # UTC item
        my $Date = eval { $Self->_getDateObj($Calendar, $Properties{lastmodified}, 'UTC') };
        $Event{lastModified} = $Date->iso8601();
      }
      if ($Properties{'recurrence-id'}{value}) {
        # in our system it's always in the timezone of the event, but iCloud
        # returns it in UTC despite the event having a timezone.  Super weird.
        # Anyway, we need to format it to StartTimeZone to match everything else.
        my $Date = $Self->_getDateObj($Calendar, $Properties{'recurrence-id'}, $StartTimeZone);
        $Event{_recurrenceId} = $Date->iso8601();
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
  # format: YYYY-MM-DDTHH:MM:SS (no Z)
  my $isoDate = shift;
  my $timezone = shift || $FLOATING;
  confess "Invalid value '$isoDate' was not ISO8601" unless $isoDate =~ m/^(\d{4,})-(\d\d)-(\d\d)T(\d\d):(\d\d):(\d\d)$/i;

  my $Date = DateTime->_new(
    year => $1,
    month => $2,
    day => $3,
    hour => $4,
    minute => $5,
    second => $6,
    time_zone => $timezone,
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
  my ($TimeZones, $utc, $tz, $IsAllDay) = @_;

  my $date = _wireDate($utc, $UTC);

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

  eval {$date->set_time_zone($zone)}
    or confess "Invalid start timezone ($tz)";

  $TimeZones->{$zone->name()} = 1;

  return [$date->strftime('%Y%m%dT%H%M%S'), { TZID => $zone->name() }];
}

sub _makeZTime {
  my ($Self, $date) = @_;
  return $Self->_makeVTime({}, $date, 'UTC');
}

sub _makeLTime {
  my $Self = shift;
  my ($TimeZones, $ltime, $tz, $isAllDay) = @_;

  my $date = _wireDate($ltime, $Self->tz($tz));

  return [$date->strftime('%Y%m%d'), { VALUE => 'DATE' }] if $isAllDay;

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
  my ($TimeZones, $Args, $recurrenceId) = @_;
  my @SubVEvents;

  my $VEvent = Data::ICal::Entry::Event->new();

  # required properties
  $VEvent->add_properties(
    uid      => $Args->{uid},
    sequence => ($Args->{sequence} || 0),
    transp   => ($Args->{showAsFree} ? 'TRANSPARENT' : 'OPAQUE'),
  );

  if ($recurrenceId) {
    $VEvent->add_property('recurrence-id' => $Self->_makeLTime($TimeZones, $recurrenceId, $Args->{startTimeZone}, $Args->{isAllDay}));
  }

  # direct copy if properties exist
  foreach my $Property (qw{summary description location}) {
    my $Prop = $Args->{$Property} // '';
    next if $Prop eq '';
    $VEvent->add_property($Property => $Prop);
  }

  # dates in UTC - stored in UTC
  $VEvent->add_property(dtstamp => $Self->_makeZTime($Args->{dtstamp}));
  $VEvent->add_property(created => $Self->_makeZTime($Args->{created})) if $Args->{created};
  $VEvent->add_property('last-modified' => $Self->_makeZTime($Args->{lastModified})) if $Args->{lastModified};

  # dates in UTC - stored in localtime
  my $StartTimeZone = $Args->{startTimeZone};
  my $EndTimeZone   = $Args->{endTimeZone};

  # if one is set, make sure they are both set
  $StartTimeZone ||= $EndTimeZone;
  $EndTimeZone   ||= $StartTimeZone;

  if ($Args->{utcStart}) {

    $VEvent->add_property(dtstart => $Self->_makeVTime($TimeZones, $Args->{utcStart}, $StartTimeZone, $Args->{isAllDay}));

    if ($Args->{utcEnd}) {
      $VEvent->add_property(dtend => $Self->_makeVTime($TimeZones, $Args->{utcEnd}, $EndTimeZone, $Args->{isAllDay}));

      if ($Args->{utcStart} gt $Args->{utcEnd}) {
        confess "Start date is later than end date ($Args->{utcStart}, $Args->{utcEnd})";
      }
    }
  }
  elsif (not $recurrenceId) {
    confess "no utcStart for event $Args->{id}";
  }

  if ($Args->{recurrence}) {
    my %Recurrence = $Self->_makeRecurrence($Args->{recurrence}, $Args->{isAllDay}, $StartTimeZone);

    # RFC 2445 4.3.10 - FREQ is the first part of the RECUR value type.
    # RFC 5545 3.3.10 - FREQ should be first to ensure backward compatibility.
    my $rule = join(';',
      ('FREQ=' . delete($Recurrence{FREQ})),
      (map { "$_=$Recurrence{$_}" } keys %Recurrence),
    );
    $VEvent->add_property(rrule => $rule);
  }

  if ($Args->{exceptions}) {
    foreach my $recurrenceId (sort keys %{$Args->{exceptions}}) {
      my $val = $Args->{exceptions}{$recurrenceId};
      if ($val) {
        $Self->_maximise($Args, $val, $recurrenceId);
        $val->{uid} = $Args->{uid}; # make sure this one is set
        push @SubVEvents, $Self->_argsToVEvents($TimeZones, $val, $recurrenceId);
      }
      else {
        $VEvent->add_property(exdate => $Self->_makeLTime($TimeZones, $recurrenceId, $StartTimeZone, $Args->{isAllDay}));
      }
    }
  }

  if ($Args->{inclusions}) {
    foreach my $date (sort @{$Args->{inclusions}}) {
      $VEvent->add_property(rdate => $Self->_makeLTime($TimeZones, $date, $StartTimeZone, $Args->{isAllDay}));
    }
  }

  if ($Args->{alerts}) {
    for my $Alert (@{$Args->{alerts}}) {
      my $Type          = $Alert->{type} // '';
      my $Recipients    = $Alert->{recipients} // [];
      my $Uri           = $Alert->{uri} // '';
      my $MinutesBefore = $Alert->{minutesBefore} // 15;
      my $Sign          = ($MinutesBefore >= 0) ? '-' : '';
      $MinutesBefore    = abs($MinutesBefore);

      my $VAlarm;

      if ($Type eq 'alert') {
        $VAlarm = Data::ICal::Entry::Alarm::Display->new();
        $VAlarm->add_properties(
          description => (($Sign eq '-')
            ? "'$Args->{summary}' starts in $MinutesBefore minutes"
            : "'$Args->{summary}' started $MinutesBefore minutes ago"),
        );
      }
      elsif ($Type eq 'email' || $Type eq 'uri') {
        my ($Summary, $Description);

        if ($Sign eq '-') {
          $Summary     = "Event alert: '$Args->{summary}' starts in $MinutesBefore minutes";
          $Description = "Your event '$Args->{summary}' starts in $MinutesBefore minutes";
        }
        else {
          $Summary     = "Event alert: '$Args->{summary}' started $MinutesBefore minutes ago";
          $Description = "Your event '$Args->{summary}' started $MinutesBefore minutes ago";
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

      $VAlarm->add_property(trigger => "${Sign}PT".$MinutesBefore."M");
      $VEvent->add_entry($VAlarm);
    }
  }

  if ($Args->{attendees}) {
    for my $Attendee (@{$Args->{attendees}}) {
      my $Email = $Attendee->{email};
      my $Rsvp  = $Attendee->{rsvp};

      my %AttendeeProps;
      $AttendeeProps{"CN"}         = $Attendee->{"name"}       if defined $Attendee->{"name"};
      $AttendeeProps{"RSVP"}       = "TRUE";
      $AttendeeProps{"X-SEQUENCE"} = $Attendee->{"x-sequence"} if defined $Attendee->{"x-sequence"};
      $AttendeeProps{"X-DTSTAMP"}  = $Attendee->{"x-dtstamp"}  if defined $Attendee->{"x-dtstamp"};
      foreach my $prop (keys %AttendeeProps) {
        delete $AttendeeProps{$prop} if $AttendeeProps{$prop} eq '';
      }

      $AttendeeProps{PARTSTAT} = {
        yes   => "ACCEPTED",
        no    => "DECLINED",
        maybe => "TENTATIVE",
      }->{$Rsvp} // "NEEDS-ACTION";

      $VEvent->add_property(attendee => [ "MAILTO:$Email", \%AttendeeProps ]);
    }
  }

  if ($Args->{organiser}) {
    my $Email = $Args->{organiser}{email};
    my $Name = $Args->{organiser}{name};

    my %OrganiserProps;
    $OrganiserProps{CN} = $Name if $Name;

    $VEvent->add_property(organizer => [ "MAILTO:$Email", \%OrganiserProps ]);
  }

  if ($Args->{attachments}) {
    foreach my $Attach (@{$Args->{attachments}}) {
      my $Url = $Attach->{url};
      my $FileName = $Attach->{name};
      my $Mime = $Attach->{type};
      my $Size = $Attach->{size};

      my %AttachProps;
      $AttachProps{FMTTYPE} = $Mime if defined $Mime;
      $AttachProps{SIZE} = $Size if defined $Size;
      $AttachProps{NAME} = $FileName if defined $FileName;
      $VEvent->add_property(attach => [ $Url, \%AttachProps ]);
    }
  }

  return ($VEvent, @SubVEvents);
}

sub _argsToVCalendar {
  my $Self = shift;
  my $Item = shift;
  my %ExtraProp = @_;

  my $VCalendar = Data::ICal->new();

  foreach my $extra (keys %ExtraProp) {
    $VCalendar->add_properties($extra => $ExtraProp{$extra});
  }
  $VCalendar->add_properties(calscale => 'GREGORIAN');

  my @VEvents;
  my %TimeZones;
  foreach my $Args (ref $Item eq 'ARRAY' ? @$Item : $Item) {
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
      unless ($byMonth =~ /^\d+$/) {
        confess "Recurrence byMonth is not a number ($byMonth)";
      }

      unless (($byMonth >= 0) and ($byMonth <= 11)) {
        confess "Recurrence byMonth is out of range ($byMonth)";
      }

      push @BYMONTHS, $byMonth + 1;
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
    my $recurrenceId = delete $Event->{'_recurrenceId'};
    if ($recurrenceId) {
      # never in sub records
      delete $Event->{recurrence};
      delete $Event->{exceptions};
      delete $Event->{inclusions};
      $exceptions{$uid}{$recurrenceId} = $Event;
    }
    else {
      if ($map{$uid}) {
        # it looks like sometimes Google doesn't remember to put the Recurrence ID
        # on additional recurrences after the first one, which is going to screw up
        # pretty badly because if the date has changed, then we can't even notice
        # which recurrent it was SUPPOSED to be.  *sigh*.
        warn "DUPLICATE EVENT FOR $uid\n" . Dumper($map{$uid}, $Event);
        $map{$uid}{_dirty} = 1;
      }
      else {
        $map{$uid} = $Event;
      }
    }
  }

  foreach my $uid (keys %exceptions) {
    foreach my $recur (sort keys %{$exceptions{$uid}}) {
      if ($map{$uid}) {
        $map{$uid}{exceptions}{$recur} = $exceptions{$uid}{$recur};
      }
      else {
        # event with ONLY exceptions.  WTF.  The RFC says it's OK though, RFC 4791
        # section 4.1
        #                                          [...] It is possible for a
        # calendar object resource to just contain components that represent
        # "overridden" instances (ones that modify the behavior of a regular
        # instance, and thus include a RECURRENCE-ID property) without also
        # including the "master" recurring component (the one that defines the
        # recurrence "set" and does not contain any RECURRENCE-ID property).
        $map{$uid} = $exceptions{$uid}{$recur};
      }
    }
  }

  return map { $map{$_} } sort keys %map;
}

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
      'x-apple-calendar-color' => $Cal->{colour},
      # XXX - do we want to add our sync-token here or something?
    );
    return ($VCalendar->as_string(), $Cal);
  }
  return undef; # 404
}

sub _minimise {
  my $Self = shift;
  my $Event = shift;

  confess unless ref($Event) eq 'HASH';
  delete $Event->{dtstamp};
  delete $Event->{created};

  foreach my $Key (keys %$Event) {
    delete $Event->{$Key} if $Key =~ m/^_/;
  }

  foreach my $recurrenceId (sort keys %{$Event->{exceptions}}) {
    my $Recurrence = $Event->{exceptions}{$recurrenceId};
    next unless $Recurrence; # EXDATE

    delete $Recurrence->{sequence};
    delete $Recurrence->{dtstamp};
    delete $Recurrence->{created};

    # check if time range is identical (keep timezone until after we've done this)
    if ($Recurrence->{utcStart}) {
      my $tz = $Recurrence->{startTimeZone} // $Event->{startTimeZone};
      my $uDate = _wireDate($recurrenceId, $Self->tz($tz));
      $uDate->set_time_zone($UTC);
      if ($uDate->iso8601() eq $Recurrence->{utcStart}) {
        delete $Recurrence->{utcStart};

        if ($Recurrence->{utcEnd}) {
          die Data::Dumper::Dumper($Event) unless $Event->{utcStart};
          my $start = _wireDate($Event->{utcStart}, $UTC);
          my $end = _wireDate($Event->{utcEnd}, $UTC);
          my $diff = $end->subtract_datetime($start);
          $uDate->add_duration($diff);
          if ($uDate->iso8601() eq $Recurrence->{utcEnd}) {
            delete $Recurrence->{utcEnd};
          }
        }
      }
    }

    # dupelim
    foreach my $Key (keys %$Recurrence) {
      delete $Recurrence->{$Key} if $Key =~ m/^_/;
      delete $Recurrence->{$Key} if safeeq($Event->{$Key}, $Recurrence->{$Key});
    }

    # no point sending if it's entirely empty
    delete $Event->{exceptions}{$recurrenceId} unless keys %$Recurrence;
  }

  return $Event;
}

sub _maximise {
  my $Self = shift;
  my $Event = shift;
  my $Recurrence = shift;
  my $recurrenceId = shift;

  #warn "MAXIMIZING EVENT INTO RECURRENCE: " . Dumper($Event, $Recurrence);

  # time is a special case - if it's set on the event, it MUST be the
  # actual recurrence's start and end time, not the original start and
  # end time.  We wind up doing date maths.  Yay.
  unless (exists $Recurrence->{utcStart}) {
    my $tz = $Recurrence->{startTimeZone} // $Event->{startTimeZone};
    my $uDate = _wireDate($recurrenceId, $Self->tz($tz));
    $uDate->set_time_zone($UTC);
    $Recurrence->{utcStart} = $uDate->iso8601();
  }

  unless (exists $Recurrence->{utcEnd}) {
    my $start = _wireDate($Event->{utcStart}, $UTC);
    my $end = _wireDate($Event->{utcEnd}, $UTC);
    # length of the parent event
    my $diff = $end->subtract_datetime($start);
    # add to the recurrence ID time to see when the event would have ended
    my $tz = $Recurrence->{startTimeZone} // $Event->{startTimeZone};
    my $uDate = _wireDate($recurrenceId, $Self->tz($tz));
    $uDate->set_time_zone($UTC);
    $uDate->add_duration($diff);
    $Recurrence->{utcEnd} = $uDate->iso8601();
  }

  foreach my $key (sort keys %$Event) {
    next if defined $Recurrence->{$key};

    # these items can only ever exist on the parent
    next if $key eq 'recurrence';
    next if $key eq 'exceptions';
    next if $key eq 'inclusions';

    # otherwise copy the key from the main event into the recurrence
    $Recurrence->{$key} = $Event->{$key}; # XXX - deepclone?
  }
}

sub _stripNonICal {
  my $Self = shift;
  my $Event = shift;

  delete $Event->{alerts};
  delete $Event->{attendees};
  delete $Event->{organiser};

  foreach my $exception (values %{$Event->{exceptions}}) {
    next unless $exception;
    $Self->_stripNonICal($exception);
  }
}

sub safeeq {
  my ($a, $b) = @_;
  return 1 if (not defined $a and not defined $b);
  return 0 if (not defined $a  or not defined $b);
  return ($a eq $b) if (not ref ($a) and not ref($b));
  return 0 if (not ref ($a) or not ref($b));
  my $json = JSON::XS->new->canonical;
  return $json->encode($a) eq $json->encode($b);
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

Copyright 2015 Bron Gondwana.

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
