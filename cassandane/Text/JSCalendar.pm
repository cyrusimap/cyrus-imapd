#/usr/bin/perl -cw
use strict;
use warnings FATAL => 'all';
package Text::JSCalendar;

use Carp;
use Data::ICal;
use Data::ICal::Entry::Event;
use Data::ICal::TimeZone;
use Data::ICal::Entry::Alarm::Email;
use Data::ICal::Entry::Alarm::Display;
use DateTime::Format::ICal;
use DateTime::TimeZone;
use JSON::XS qw(encode_json);
use Text::JSCalendar::TimeZones;
use Text::VCardFast qw(vcard2hash);
use XML::Spice;
use MIME::Base64 qw(encode_base64);
use MIME::Types;
use Digest::SHA qw(sha1_hex);
use URI::Escape qw(uri_unescape);
use Data::Dumper;
use JSON;

use Text::JSCalendar::TimeZones;

# monkey patch like a bandit
BEGIN {
  my @alarm_properties = Data::ICal::Entry::Alarm::optional_unique_properties();
  foreach my $want (qw(uid acknowledged)) {
    push @alarm_properties, $want unless grep { $_ eq $want } @alarm_properties;
  }
  no warnings 'redefine';
  *Data::ICal::Entry::Alarm::optional_unique_properties = sub { @alarm_properties };

  # Suppress warnings for properties not known to Data::ICal::Entry::Event
  my $orig_warn = $SIG{__WARN__};
  $SIG{__WARN__} = sub {
    return if $_[0] =~ /^Unknown property for Data::ICal::Entry::/;
    if ($orig_warn) { $orig_warn->(@_) }
    else { warn @_ }
  };
}

our $UTC = DateTime::TimeZone::UTC->new();
our $FLOATING = DateTime::TimeZone::Floating->new();
our $LOCALE = DateTime::Locale->load('en_US');

my (
  %ValidDay,
  %ValidFrequency,
  %EventKeys,
  %ColorNames,
  %RecurrenceProperties,
  %UTCLinks,
  %MustBeTopLevel,
);

BEGIN {
  %ValidDay = map { $_ => 1 } qw(su mo tu we th fr sa);
  %ValidFrequency = map { $_ => 1 } qw(yearly monthly weekly daily hourly minutely secondly);

  %EventKeys = (
    '' => {
      uid                  => [0, 'string',    1, undef],
      relatedTo            => [2, 'keywords',  0, undef],
      keywords             => [0, 'keywords',  0, undef],
      categories           => [0, 'keywords',  0, undef],
      prodId               => [0, 'string',    0, undef],
      created              => [0, 'utcdate',   0, undef],
      updated              => [0, 'utcdate',   1, undef],
      sequence             => [0, 'number',    0, 0],
      method               => [0, 'string',    0, undef],
      title                => [0, 'string',    0, ''],
      description          => [0, 'string',    0, ''],
      descriptionContentType => [0, 'string',  0, undef],
      links                => [2, 'object',    0, undef],
      locale               => [0, 'string',    0, undef],
      localizations        => [0, 'patch',     0, undef],
      locations            => [2, 'object',    0, undef],
      virtualLocations     => [2, 'object',    0, undef],
      color                => [0, 'string',    0, undef],
      showWithoutTime      => [0, 'bool',      0, $JSON::false],
      isAllDay             => [0, 'bool',      0, $JSON::false],
      start                => [0, 'localdate', 1, undef],
      timeZone             => [0, 'timezone',  0, undef],
      endTimeZone          => [0, 'timezone',  0, undef],
      duration             => [0, 'duration',  0, undef],
      recurrenceRule       => [0, 'object',    0, undef],
      recurrenceOverrides  => [2, 'patch',     0, undef],
      recurrenceId         => [0, 'localdate', 0, undef],
      recurrenceIdTimeZone => [0, 'timezone',  0, undef],
      status               => [0, 'string',    0, undef],
      freeBusyStatus       => [0, 'string',    0, 'busy'],
      privacy              => [0, 'string',    0, 'public'],
      priority             => [0, 'number',    0, 0],
      replyTo              => [0, 'object',    0, undef],
      organizerCalendarAddress => [0, 'string', 0, undef],
      participants         => [2, 'object',    0, undef],
      useDefaultAlerts     => [0, 'bool',      0, $JSON::false],
      alerts               => [2, 'object',    0, undef],
      excluded             => [0, 'bool',      0, $JSON::false],
      lastModified         => [0, 'utcdate',   0, undef],
      # Task-specific properties
      due                  => [0, 'localdate', 0, undef],
      estimatedDuration    => [0, 'duration',  0, undef],
      percentComplete      => [0, 'number',    0, undef],
      progress             => [0, 'string',    0, undef],
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
      locationTypes        => [0, 'keywords',  0, undef],
      links                => [2, 'object',    0, undef],
      uri                  => [0, 'string',    0, undef],
    },
    virtualLocations => {
      name                 => [0, 'string',    0, ''],
      uri                  => [0, 'string',    1, undef],
      features             => [0, 'keywords',  0, undef],
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
      calendarAddress      => [0, 'string',    0, undef],
      sendTo               => [0, 'object',    0, undef],
      kind                 => [0, 'string',    0, 'unknown'],
      roles                => [1, 'string',    1, undef],
      locationId           => [0, 'string',    0, undef],
      participationStatus  => [0, 'string',    0, 'needs-action'],
      attendance           => [0, 'string',    0, 'required'],
      expectReply          => [0, 'bool',      0, $JSON::false],
      scheduleAgent        => [0, 'string',    0, undef],
      scheduleSequence     => [0, 'number',    0, 0],
      scheduleUpdated      => [0, 'utcdate',   0, undef],
      progress             => [0, 'string',    0, undef],
      delegatedFrom        => [0, 'keywords',  0, undef],
      delegatedTo          => [0, 'keywords',  0, undef],
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
    showWithoutTime
    recurrenceRule
    recurrenceOverrides
    replyTo
    organizerCalendarAddress
    participantId
    method
  };

  # Color names defined in CSS Color Module Level 3
  # http://www.w3.org/TR/css3-color/

  %ColorNames
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

Text::JSCalendar

=head1 VERSION

Version 0.02

=cut

our $VERSION = '0.03';

=head1 SYNOPSIS

This module implements a perl mapping between iCalendar:

    https://tools.ietf.org/html/rfc5545

and JSCalendar:

    https://datatracker.ietf.org/doc/draft-ietf-calext-jscalendar/

=head1 SUBROUTINES/METHODS

=cut

sub new {
  my $class = shift;
  return bless {@_}, ref($class) || $class;
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

sub color {
  my $Self = shift;
  my $color = shift;
  return _fixColor($color);
}

sub _fixColor {
  my $color = lc(shift || '');

  return $color if $ColorNames{$color};
  confess("unparseable color: $color") unless $color =~ m/^\s*(\#[a-f0-9]{3,8})\s*$/;
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

  confess("invalid color") unless $color =~ m/^\s*(\#[a-f0-9]{3,8})\s*$/;
}

sub _BYDAY2byDay {
  my ($BYDAY) = @_;

  my ($Count, $Day) = $BYDAY =~ /^([-+]?\d+)?(\w\w)$/;

  unless ($Day) {
    confess 'Recurrence BYDAY-weekday not specified';
  }

  unless ($ValidDay{lc $Day}) {
    confess 'Invalid recurrence BYDAY-weekday';
  }

  if ($Count) {
    unless (($Count >= -53) and ($Count <= 53)) {
      confess 'Recurrence BYDAY-ordwk is out of range';
    }
  }

  return {
    day => lc $Day,
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

  my $Day = $byDay->{day};
  unless ($Day and $ValidDay{lc $Day}) {
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
  my $extra = shift || '';
  my $updated = delete $VEvent->{properties}->{updated};
  my $d = Data::Dumper->new([$VEvent]);
  $d->Indent(0);
  $d->Sortkeys(1);
  my $Key = sha1_hex($d->Dump() . $extra);
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

  my $email = $VAttendee->{value};
  return unless $email;
  $email =~ s/^mailto://i;
  return if $email eq '';
  my $id = sha1_hex(lc $email);

  $Participants->{$id} ||= {};

  # XXX - if present on one but not the other, take the "best" version
  $Participants->{$id}{name} = $VAttendee->{params}{"cn"}[0] // "";
  $Participants->{$id}{email} = $VAttendee->{params}{"email"}[0] // $email;
  $Participants->{$id}{sendTo} = { "imip" => "mailto:$email" };
  $Participants->{$id}{kind} = lc $VAttendee->{params}{"cutype"}[0]
    if $VAttendee->{params}{"cutype"};
  push @{$Participants->{$id}{roles}}, $role
    unless grep { $_ eq $role } @{$Participants->{$id}{roles} || []};
  # we don't support locationId yet
  if ($VAttendee->{params}{"partstat"}) {
    $Participants->{$id}{participationStatus} = lc($VAttendee->{params}{"partstat"}[0] // "needs-action");
  }
  if ($VAttendee->{params}{"role"}) {
    my $ical_role = uc($VAttendee->{params}{"role"}[0] || '');
    if ($ical_role eq 'CHAIR' && !grep { $_ eq 'chair' } @{$Participants->{$id}{roles} || []}) {
      push @{$Participants->{$id}{roles}}, 'chair';
    }

    if ($ical_role eq 'OWNER' && !grep { $_ eq 'owner' } @{$Participants->{$id}{roles} || []}) {
      push @{$Participants->{$id}{roles}}, 'owner';
    }

    $Participants->{$id}{attendance} = 'optional'
      if $ical_role eq 'OPT-PARTICIPANT';

    $Participants->{$id}{attendance} = 'none'
      if $ical_role eq 'NON-PARTICIPANT';
  }
  if ($VAttendee->{params}{"rsvp"}) {
    $Participants->{$id}{expectReply} = lc($VAttendee->{params}{"rsvp"}[0] // "") eq 'yes' ? $JSON::true : $JSON::false;
  }
  if (exists $VAttendee->{params}{"x-dtstamp"}) {
    my ($Date) = eval { $Self->_makeDateObj($VAttendee->{params}{"x-dtstamp"}[0], 'UTC', 'UTC') };
    $Participants->{$id}{"scheduleUpdated"} = $Date->iso8601() . 'Z' if $Date;
  }
  # memberOf is not supported

  if (exists $VAttendee->{params}{"x-sequence"}) {
    $Participants->{$id}{scheduleSequence} = $VAttendee->{params}{"x-sequence"}[0] // "";
  }

  if ($VAttendee->{params}{"schedule-agent"}) {
    $Participants->{$id}{scheduleAgent} = lc($VAttendee->{params}{"schedule-agent"}[0]);
  }

  if ($VAttendee->{params}{"delegated-from"}) {
    my %df;
    for my $uri (@{$VAttendee->{params}{"delegated-from"}}) {
      $df{$uri} = $JSON::true;
    }
    $Participants->{$id}{delegatedFrom} = \%df if %df;
  }

  if ($VAttendee->{params}{"delegated-to"}) {
    my %dt;
    for my $uri (@{$VAttendee->{params}{"delegated-to"}}) {
      $dt{$uri} = $JSON::true;
    }
    $Participants->{$id}{delegatedTo} = \%dt if %dt;
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
    if ($Spec->{$key}[0] == 2) {
      # idmap of type
      my $Item = delete $Copy{$key};
      next unless ref($Item) eq 'HASH';
      next unless keys %$Item;
      my %new;
      foreach my $id (keys %$Item) {
        if ($Spec->{$key}[1] eq 'object') {
          next unless ref($Item->{$id}) eq 'HASH';
          $new{$id} = $class->NormaliseEvent($Item->{$id}, $key);
        }
        elsif ($Spec->{$key}[1] eq 'patch') {
          next unless ref($Item->{$id}) eq 'HASH';
          # XXX - handle keys?  Tricky
          $new{$id} = $class->NormaliseEvent($Item->{$id}, $key);
        }
        else {
          $new{$id} = $Item->{$id};
        }
      }
      $Copy{$key} = \%new;
    }
    elsif ($Spec->{$key}[0] == 1) {
      my $Item = delete $Copy{$key};
      next unless ref($Item) eq 'ARRAY';
      next unless @$Item;
      my @new;
      foreach my $one (@$Item) {
        if ($Spec->{$key}[1] eq 'object') {
          next unless ref($one) eq 'HASH';
          push @new, $class->NormaliseEvent($one, $key);
        }
        elsif ($Spec->{$key}[1] eq 'patch') {
          next unless ref($one) eq 'HASH';
          # XXX - handle keys?  Tricky
          push @new, $class->NormaliseEvent($one, $key);
        }
        else {
          push @new, $one;
        }
      }
      $Copy{$key} = \@new;
    }
    else {
      if ($Spec->{$key}[1] eq 'object') {
        next unless ref($Copy{$key}) eq 'HASH';
        $Copy{$key} = $class->NormaliseEvent($Copy{$key}, $key);
      }
      elsif ($Spec->{$key}[1] eq 'bool') {
        next if ref($Copy{$key});
        delete $Copy{$key} if !!$Spec->{$key}[3] == !!$Copy{$key};
      }
      elsif ($Spec->{$key}[1] eq 'mailto') {
        next if ref($Copy{$key});
        $Copy{$key} = lc $Copy{$key} if $Copy{$key};
      }
      else {
        next if ref($Copy{$key});
        delete $Copy{$key} if _safeeq($Spec->{$key}[3], $Copy{$key});
      }
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
      next unless lc $VEvent->{type} eq 'vevent' || lc $VEvent->{type} eq 'vtodo';
      my $is_task = lc $VEvent->{type} eq 'vtodo';

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
          unless ($ValidFrequency{$freq}) {
            confess "$uid: Invalid recurrence FREQ ($freq)";
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
          unless ($ValidDay{$wkst}) {
            confess "$uid: Invalid recurrence WKST ($wkst)";
          }

          # default is Monday, so don't set a key for it
          if ($wkst ne 'mo') {
            $Recurrence{firstDayOfWeek} = $wkst;
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
            $Overrides{$Date->iso8601()} = { excluded => $JSON::true }; # 4.3.3
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
      my $hasDefaultAlarm = 0;
      foreach my $VAlarm (@{$VEvent->{objects} || []}) {
        next unless lc $VAlarm->{type} eq 'valarm';

        my %AlarmProperties
          = map { $_ => $VAlarm->{properties}{$_}[0] }
              keys %{$VAlarm->{properties}};

        # X-APPLE-DEFAULT-ALARM:TRUE -> useDefaultAlerts
        if (lc($AlarmProperties{'x-apple-default-alarm'}{value} // '') eq 'true') {
          $hasDefaultAlarm = 1;
        }

        my $alarmuid = $AlarmProperties{uid}{value}
                    || $AlarmProperties{'x-wr-alarmuid'}{value}
                    || _hexkey($VAlarm, $uid) . '-alarmauto';

        my %Alert;

        my $AlarmAction = lc $AlarmProperties{action}{value};
        next unless $AlarmAction;

        if ($AlarmAction eq 'display') {
          $Alert{action} = 'display';
        }
        elsif ($AlarmAction eq 'email') {
          $Alert{action} = 'email';
        }
        elsif ($AlarmAction eq 'audio') {
          # audio alerts aren't the same as popups, but for now...
          $Alert{action} = 'display';
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
          $Alert{acknowledged} = $date->iso8601() . 'Z';
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

        my $uri;
        my $encoding = lc($Attach->{params}{encoding}[0] || '');
        if ($encoding eq 'base64' || $encoding eq 'b') {
          # Binary ATTACH - convert to data: URI
          my $mime = $Attach->{params}{fmttype}[0] || 'application/octet-stream';
          $uri = "data:$mime;base64," . $Attach->{value};
        }
        elsif (grep { $Attach->{value} =~ m{^$_://} } qw{http https ftp data}) {
          $uri = $Attach->{value};
        }
        else {
          next;
        }

        my $filename = $Attach->{params}{filename}[0];
        my $mime = $Attach->{params}{fmttype}[0];
        if (not defined $mime and $filename) {
          $::MimeTypes ||= MIME::Types->new;
          my $MimeTypeObj = $::MimeTypes->mimeTypeOf($filename);
          $mime = $MimeTypeObj->type() if $MimeTypeObj;
        }

        my $size = $Attach->{params}{size}[0];

        $Links{sha1_hex(lc $uri)} = {
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
        $Links{sha1_hex(lc $uri)} = { href => $uri };
      }
      # IMAGE -> links with rel='icon'
      foreach my $Image (@{$VEvent->{properties}{image} || []}) {
        my $uri = $Image->{value};
        next unless $uri;
        my $id = sha1_hex(lc $uri);
        $Links{$id} = {
          href => $uri,
          rel => 'icon',
          defined $Image->{params}{fmttype}[0] ? (type => $Image->{params}{fmttype}[0]) : (),
          defined $Image->{params}{label}[0] ? (title => $Image->{params}{label}[0]) : (),
        };
      }

      # }}}

      # parse CONFERENCE -> virtualLocations {{{

      my %VirtualLocations;
      foreach my $Conference (@{$VEvent->{properties}{conference} || []}) {
        next unless $Conference->{value};
        my $id = $Conference->{params}{'x-jmap-id'}[0] || sha1_hex($Conference->{value});
        my %vloc = (uri => $Conference->{value});
        if ($Conference->{params}{label}) {
          $vloc{name} = $Conference->{params}{label}[0];
        }
        if ($Conference->{params}{feature}) {
          my @features = map { lc $_ } map { split /,/ } @{$Conference->{params}{feature}};
          $vloc{features} = { map { $_ => $JSON::true } @features };
        }
        $VirtualLocations{$id} = \%vloc;
      }

      # }}}

      # Parse keywords {{{

      my %keywords;
      foreach my $Categories (@{$VEvent->{properties}{categories} || []}) {
        my $val = $Categories->{value};
        $keywords{$_} = $JSON::true for split ',', $val;
      }
      delete $keywords{''}; # just in case it was created by leading or trailing ,

      # }}}

      # Parse relations {{{

      my %relations;
      foreach my $Relation (@{$VEvent->{properties}{'related-to'} || []}) {
        my $reltype = $Relation->{params}{reltype}[0] || 'parent';
        $reltype = lc $reltype if grep { $_ eq lc $reltype } qw(first next parent child);
        $relations{$Relation->{value}}{relation}{$reltype} = $JSON::true;
      }

      # }}}

      my %Event = ();

      # ==============================================================
      # 4.1 Metadata

      # 4.1.1 @type (JSCalendar bis uses capitalized names)
      $Event{'@type'} = $is_task ? 'Task' : 'Event';

      # 4.1.2 uid
      $Event{uid} = "$uid";

      # 4.1.3 relatedTo
      $Event{relatedTo} = \%relations if %relations;

      # 4.1.4 prodId
      $Event{prodId} = $prodid if defined $prodid;

      # 4.1.5 created
      if ($Properties{created}{value}) {
        # UTC item
        my $Date = eval { $Self->_getDateObj($Calendar, $Properties{created}, 'UTC') };
        $Event{created} = $Date->iso8601() . 'Z' if $Date;
      }

      # 4.1.6 updated
      if ($Properties{dtstamp}{value}) {
        # UTC item
        my $Date = eval { $Self->_getDateObj($Calendar, $Properties{dtstamp}, 'UTC') };
        $Event{updated} = $Date->iso8601() . 'Z' if $Date;
      }
      if (not $Event{updated} and $Properties{'last-modified'}{value}) {
        # UTC item
        my $Date = eval { $Self->_getDateObj($Calendar, $Properties{'last-modified'}, 'UTC') };
        $Event{updated} = $Date->iso8601() . 'Z' if $Date;
      }
      $Event{updated} ||= DateTime->now->iso8601();

      # 4.1.7 sequence
      $Event{sequence} = int($Properties{sequence}{value}) if $Properties{sequence};

      # 4.1.8 method
      $Event{method} = $method if $method;

      # ==============================================================
      # 4.2 What and where

      # 4.2.1 title
      $Event{title} = $Properties{summary}{value}
        if ($Properties{summary} and defined $Properties{summary}{value});

      # 4.2.2 description
      # STYLED-DESCRIPTION overrides DESCRIPTION if present
      if ($Properties{'styled-description'}{value}) {
        $Event{description} = $Properties{'styled-description'}{value};
        $Event{descriptionContentType} = $Properties{'styled-description'}{params}{fmttype}[0] // 'text/html';
      }
      elsif (@description) {
        $Event{description} = join("\n", @description);
      }

      # 4.2.4 locations
      if ($Properties{location}{value}) {
        $Event{locations}{location} = { name => $Properties{location}{value} };
      }
      # X-APPLE-STRUCTURED-LOCATION -> location with coordinates, name, description
      # Check for Apple structured locations first; if present, skip plain GEO
      my $has_apple_location = scalar @{$VEvent->{properties}{'x-apple-structured-location'} || []};

      # GEO -> separate location with coordinates (only if no Apple structured location)
      if (!$has_apple_location && $Properties{geo}{value}) {
        my ($lat, $lon) = split /;/, $Properties{geo}{value};
        if (defined $lat && defined $lon) {
          my $coords = "geo:$lat,$lon";
          my $locid = $Event{locations} ? 'geo' : 'location';
          $Event{locations}{$locid} = { coordinates => $coords };
        }
      }

      for my $ASL (@{$VEvent->{properties}{'x-apple-structured-location'} || []}) {
        next unless $ASL->{value};
        my %loc;
        if ($ASL->{value} =~ m{^geo:([-\d.]+),([-\d.]+)}) {
          $loc{coordinates} = $ASL->{value};
        }
        my $title = $ASL->{params}{'x-title'}[0];
        $loc{name} = $title if defined $title && $title ne '';
        my $address = $ASL->{params}{'x-address'}[0];
        $loc{description} = $address if defined $address && $address ne '';
        if (%loc) {
          my $locid = sha1_hex($ASL->{value} || 'apple-location');
          $Event{locations}{$locid} = \%loc;
        }
      }

      # endTimeZone (replaces old locations[end] hack)
      if (not $IsAllDay and $StartTimeZone and $StartTimeZone ne $EndTimeZone) {
        $Event{endTimeZone} = $EndTimeZone;
      }

      # 4.2.5 virtualLocations
      $Event{virtualLocations} = \%VirtualLocations if %VirtualLocations;

      # 4.2.6 links
      $Event{links} = \%Links if %Links;

      # 4.2.7 locale
      my $language;
      if ($Properties{description} and $Properties{description}{params}{language}) {
        $language = $Properties{description}{params}{language}[0];
      }
      if ($Properties{summary} and $Properties{summary}{params}{language}) {
        $language = $Properties{summary}{params}{language}[0];
      }
      $Event{locale} = $language if $language;

      # 4.2.8 keywords
      $Event{keywords} = \%keywords if %keywords;

      # 4.2.9 categories is not supported

      # 4.2.10 color
      $Event{color} = _fixColor($Properties{color}{value}) if $Properties{color};

      # ==============================================================
      # 4.3 Recurrence properties

      # 4.3.1 recurrenceRule
      $Event{recurrenceRule} = \%Recurrence if %Recurrence;

      # 4.3.2 recurrenceOverrides
      $Event{recurrenceOverrides} = \%Overrides if %Overrides;

      # ... special case for recurrence overrides when processing the child ...
      if ($Properties{'recurrence-id'}{value}) {
        # in our system it's always in the timezone of the event, but iCloud
        # returns it in UTC despite the event having a timezone.  Super weird.
        # Anyway, we need to format it to the StartTimeZone of the parent
        # event if there is one, and we don't have that yet!
        $Event{_recurrenceObj} = $Self->_getDateObj($Calendar, $Properties{'recurrence-id'});
      }

      # ==============================================================
      # 4.4 Sharing and scheduling properties

      # 4.4.1 priority
      if ($Properties{priority}{value}) {
        # default is '0', so truth test is sufficient!
        $Event{priority} = int($Properties{priority}{value});
      }

      # 4.4.2 freeBusyStatus
      if ($Properties{transp}{value}) {
        $Event{freeBusyStatus} = 'free' if lc($Properties{transp}{value}) eq 'transparent';
      }

      # 4.4.3 privacy (from CLASS property)
      if ($Properties{class}{value}) {
        my $cls = lc($Properties{class}{value});
        if ($cls eq 'private') { $Event{privacy} = 'private' }
        elsif ($cls eq 'confidential') { $Event{privacy} = 'confidential' }
      }

      # 4.4.4 replyTo + organizerCalendarAddress
      foreach my $partid (sort keys %Participants) { # later wins
        next unless grep { $_ eq 'owner' } @{$Participants{$partid}{roles}};
        $Event{replyTo} = $Participants{$partid}{sendTo};
        if ($Participants{$partid}{sendTo}{imip}) {
          $Event{organizerCalendarAddress} = $Participants{$partid}{sendTo}{imip};
        }
      }

      # 4.4.5 participants
      $Event{participants} = \%Participants if %Participants;

      # ==============================================================
      # 4.5 Alerts

      # 4.5.1 useDefaultAlerts is not supported

      # 4.5.2 alerts
      $Event{alerts} = \%Alerts if %Alerts;
      $Event{useDefaultAlerts} = $JSON::true if $hasDefaultAlarm;

      # ==============================================================
      # 4.6 Multilingual properties

      # 4.6.1 localisations is not supported

      if ($Properties{lastmodified}{value}) {
        # UTC item
        my $Date = eval { $Self->_getDateObj($Calendar, $Properties{lastmodified}, 'UTC') };
        $Event{lastModified} = $Date->iso8601() . 'Z';
      }


      # ==============================================================
      # 5.1 JSEvent specific properties

      # 5.1.1 start
      $Event{start} = $Start->iso8601() if ref($Start);

      # 5.1.2 timeZone
      $Event{timeZone} = $StartTimeZone if not $IsAllDay;

      # 5.1.3 duration
      my $duration = $Self->_make_duration($End->subtract_datetime($Start), $IsAllDay);
      $Event{duration} = $duration if $duration;

      # 5.1.4 showWithoutTime (replaces isAllDay)
      $Event{showWithoutTime} = $IsAllDay ? $JSON::true : $JSON::false;
      $Event{isAllDay} = $IsAllDay ? $JSON::true : $JSON::false;
      # SHOW-WITHOUT-TIME property (for DATE-TIME events shown as all-day)
      if (!$IsAllDay && $Properties{'show-without-time'}{value}) {
        my $swt = lc($Properties{'show-without-time'}{value});
        $Event{showWithoutTime} = $JSON::true if $swt eq 'true' || $swt eq 'yes';
      }

      # 5.1.5 status
      if ($Properties{status}{value}) {
        $Event{status} = lc($Properties{status}{value}) if lc($Properties{status}{value}) ne 'confirmed';
      }

      # Task-specific properties (VTODO)
      if ($is_task) {
        if ($Properties{due}{value}) {
          my ($Due, $DueTz) = $Self->_getDateObj($Calendar, $Properties{due});
          $Event{due} = $Due->iso8601();
        }
        if (defined $Properties{'percent-complete'}{value}) {
          $Event{percentComplete} = int($Properties{'percent-complete'}{value});
        }
        if ($Properties{'estimated-duration'}{value}) {
          $Event{estimatedDuration} = uc $Properties{'estimated-duration'}{value};
        }
        if ($Properties{completed}{value}) {
          $Event{progress} = 'completed';
        }
        elsif (lc($Properties{status}{value} || '') eq 'in-process') {
          $Event{progress} = 'in-process';
        }
        elsif (lc($Properties{status}{value} || '') eq 'cancelled') {
          $Event{progress} = 'cancelled';
        }
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

  my $TimeZone = Text::JSCalendar::TimeZones->GetTimeZone(
    TZID               => $TZID,
    Time               => $Element->{value},
    (exists $TzOffsets{standard}
      ? (StandardTzOffsetTo => $TzOffsets{standard})
      : ()),
    (exists $TzOffsets{daylight}
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

  my $type = $Args->{'@type'} || '';
  my $is_task = $type eq 'jstask' || $type eq 'Task';
  my $VEvent;
  if ($is_task) {
    eval { require Data::ICal::Entry::Todo };
    $VEvent = Data::ICal::Entry::Todo->new();
  } else {
    $VEvent = Data::ICal::Entry::Event->new();
  }

  # required properties
  my $transp = 'OPAQUE';
  if (defined $Args->{freeBusyStatus}) {
    $transp = 'TRANSPARENT' if $Args->{freeBusyStatus} eq 'free';
  }
  $VEvent->add_properties(
    uid      => $Args->{uid},
    sequence => ($Args->{sequence} || 0),
    ($is_task ? () : (transp => $transp)),
  );

  if ($recurrenceData) {
    my ($recurrenceId, $TopLevel) = @$recurrenceData;
    $VEvent->add_property('recurrence-id' => $Self->_makeLTime($TimeZones, $recurrenceId, $TopLevel->{timeZone}, $TopLevel->{isAllDay}));
  }

  # direct copy if properties exist
  if (defined $Args->{title} && $Args->{title} ne '') {
    my %lang;
    $lang{language} = $Args->{locale} if exists $Args->{locale};
    $VEvent->add_property(summary => [$Args->{title}, \%lang]);
  }
  if (defined $Args->{description} && $Args->{description} ne '') {
    my %lang;
    $lang{language} = $Args->{locale} if exists $Args->{locale};
    if ($Args->{descriptionContentType} && $Args->{descriptionContentType} ne 'text/plain') {
      # STYLED-DESCRIPTION for non-plain content types
      $VEvent->add_property('styled-description' => [$Args->{description}, { FMTTYPE => $Args->{descriptionContentType}, %lang }]);
    }
    else {
      $VEvent->add_property(description => [$Args->{description}, \%lang]);
    }
  }

  if ($Args->{status} and $Args->{status} ne 'confirmed') {
    $VEvent->add_property('status', uc($Args->{status}));
  }

  # privacy -> CLASS
  if ($Args->{privacy} && $Args->{privacy} ne 'public') {
    $VEvent->add_property('class' => uc($Args->{privacy}));
  }

  # priority
  if ($Args->{priority} && $Args->{priority} > 0) {
    $VEvent->add_property('priority' => $Args->{priority});
  }

  # color
  if ($Args->{color}) {
    $VEvent->add_property('color' => $Args->{color});
  }

  # dates in UTC - stored in UTC
  $VEvent->add_property(created => $Self->_makeZTime($Args->{created})) if $Args->{created};
  $VEvent->add_property(dtstamp => $Self->_makeZTime($Args->{updated} || DateTime->now->iso8601()));

  # dates in localtime - zones based on location
  my $EndTimeZone = $Args->{endTimeZone};
  my $locations = $Args->{locations} || {};
  foreach my $id (sort keys %$locations) {
    # Backward compat: also check locations[end] hack
    if (!$EndTimeZone && $locations->{$id}{rel} && $locations->{$id}{rel} eq 'end') {
      $EndTimeZone = $locations->{$id}{timeZone};
    }
    if ($locations->{$id}{name} && !$locations->{$id}{coordinates}) {
      # Only emit LOCATION if this entry doesn't also have coordinates
      # (coordinates with name go into X-APPLE-STRUCTURED-LOCATION with X-TITLE)
      $VEvent->add_property(location => $locations->{$id}{name});
    }
    # GEO from coordinates
    if ($locations->{$id}{coordinates} && $locations->{$id}{coordinates} =~ m{^geo:([-\d.]+),([-\d.]+)}) {
      my ($lat, $lon) = ($1, $2);
      my $has_apple_meta = $locations->{$id}{name} || $locations->{$id}{description};
      if ($has_apple_meta) {
        # Emit X-APPLE-STRUCTURED-LOCATION (which implies GEO)
        my %asl_params = (VALUE => 'URI');
        $asl_params{'X-TITLE'} = $locations->{$id}{name} if $locations->{$id}{name};
        $asl_params{'X-ADDRESS'} = $locations->{$id}{description} if $locations->{$id}{description};
        $VEvent->add_property('x-apple-structured-location' => [$locations->{$id}{coordinates}, \%asl_params]);
      }
      else {
        # Plain GEO without Apple metadata
        $VEvent->add_property('geo' => "$lat;$lon");
      }
    }
  }

  # lastModified
  if ($Args->{lastModified}) {
    $VEvent->add_property('last-modified' => $Self->_makeZTime($Args->{lastModified}));
  }

  my $StartTimeZone = $Args->{timeZone};
  my $IsAllDay = $Args->{showWithoutTime} // $Args->{isAllDay};
  my $Start = _wireDate($Args->{start}, $StartTimeZone);
  $VEvent->add_property(dtstart => $Self->_makeVTimeObj($TimeZones, $Start, $StartTimeZone, $IsAllDay));

  # SHOW-WITHOUT-TIME for DATE-TIME events displayed as all-day
  if ($Args->{showWithoutTime} && !$IsAllDay) {
    $VEvent->add_property('show-without-time' => 'TRUE');
  }

  if ($Args->{duration}) {
    $EndTimeZone //= $StartTimeZone;
    my $Duration = eval { DateTime::Format::ICal->parse_duration($Args->{duration}) };
    my $End = $Start->clone()->add($Duration) if $Duration;
    $End->set_time_zone($EndTimeZone) if $EndTimeZone;
    $VEvent->add_property(dtend => $Self->_makeVTimeObj($TimeZones, $End, $EndTimeZone, $IsAllDay));
  }

  if ($Args->{recurrenceRule}) {
    my %Recurrence = $Self->_makeRecurrence($Args->{recurrenceRule}, $IsAllDay, $StartTimeZone);

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
      if ($val->{excluded}) {
        $VEvent->add_property(exdate => $Self->_makeLTime($TimeZones, $recurrenceId, $StartTimeZone, $IsAllDay));
      }
      elsif (keys %$val) {
        my $SubEvent = $Self->_maximise($Args, $val, $recurrenceId);
        push @VEvents, $Self->_argsToVEvents($TimeZones, $SubEvent, [$recurrenceId, $Args]);
      }
      else {
        $VEvent->add_property(rdate => $Self->_makeLTime($TimeZones, $recurrenceId, $StartTimeZone, $IsAllDay));
      }
    }
  }

  if ($Args->{alerts}) {
    for my $id (sort keys %{$Args->{alerts}}) {
      my $Alert = $Args->{alerts}{$id};

      my $Type          = $Alert->{action} // '';
      my $Offset        = $Alert->{offset};
      my $Relative      = $Alert->{relativeTo} // 'before-start';
      my $Sign          = $Relative =~ m/before/ ? '-' : '';
      my $Loc1          = $Relative =~ m/end/ ? "ends" : "starts";
      my $Loc2          = $Relative =~ m/end/ ? "ended" : "started";
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
      elsif ($Type eq 'email') {
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
          attendee    => 'mailto:',  # XXX - name?
          description => join("\n",
            $Description,
            "",
            "Description:",
            ($Args->{description} // ''),
            # XXX more
          ),
        );
          #(map { ( attendee => "MAILTO:$_" ) } @$Recipients), # XXX naive?
      }
      else {
        confess "Unknown alarm type $Type";
      }

      $VAlarm->add_property(uid => $id);
      $VAlarm->add_property(trigger => "${Sign}$Offset");
      $VAlarm->add_property(related => 'end') if $Relative =~ m/end/;

      if ($Alert->{acknowledged}) {
        $VAlarm->add_property(acknowledged => $Self->_makeZTime($Alert->{acknowledged}));
      }

      $VEvent->add_entry($VAlarm);
    }
  }

  my %namemap;
  if ($Args->{participants}) {
    foreach my $partid (sort keys %{$Args->{participants}}) {
      my $Attendee = $Args->{participants}{$partid};
      my $Email = $Attendee->{email};
      my $Rsvp  = $Attendee->{rsvp};

      my %AttendeeProps;
      if ($Attendee->{"name"}) {
        $AttendeeProps{"CN"} = $Attendee->{"name"};
        $namemap{lc "mailto:$Email"}= $Attendee->{"name"};
      }

      next unless grep { $_ eq 'attendee' } @{$Attendee->{roles}};

      $AttendeeProps{"CUTYPE"}     = uc $Attendee->{"kind"} if defined $Attendee->{"kind"};
      $AttendeeProps{"RSVP"}       = "TRUE" if $Attendee->{"expectReply"};
      $AttendeeProps{"X-SEQUENCE"} = $Attendee->{"scheduleSequence"} if defined $Attendee->{"scheduleSequence"};
      $AttendeeProps{"X-DTSTAMP"}  = $Self->_makeZTime($Attendee->{"scheduleUpdated"}) if defined $Attendee->{"scheduleUpdated"};
      foreach my $prop (keys %AttendeeProps) {
        delete $AttendeeProps{$prop} if $AttendeeProps{$prop} eq '';
      }
      if (grep { $_ eq 'owner' } @{$Attendee->{roles}}) {
        $AttendeeProps{ROLE} = 'OWNER';
      }
      elsif (grep { $_ eq 'chair' } @{$Attendee->{roles}}) {
        $AttendeeProps{ROLE} = 'CHAIR';
      }
      elsif ($Attendee->{attendance} and $Attendee->{attendance} eq 'optional') {
        $AttendeeProps{ROLE} = 'OPT-PARTICIPANT';
      }
      elsif ($Attendee->{attendance} and $Attendee->{attendance} eq 'none') {
        $AttendeeProps{ROLE} = 'NON-PARTICIPANT';
      }
      # default is REQ-PARTICIPANT
      $AttendeeProps{"SCHEDULE-AGENT"} = uc($Attendee->{scheduleAgent}) if $Attendee->{scheduleAgent};
      if ($Attendee->{delegatedFrom} && ref($Attendee->{delegatedFrom}) eq 'HASH') {
        $AttendeeProps{"DELEGATED-FROM"} = join(',', sort keys %{$Attendee->{delegatedFrom}});
      }
      if ($Attendee->{delegatedTo} && ref($Attendee->{delegatedTo}) eq 'HASH') {
        $AttendeeProps{"DELEGATED-TO"} = join(',', sort keys %{$Attendee->{delegatedTo}});
      }

      $AttendeeProps{PARTSTAT} = uc $Attendee->{"participationStatus"} if $Attendee->{"participationStatus"};

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

  if ($Args->{relatedTo}) {
    foreach my $uid (keys %{$Args->{relatedTo}}) {
      my $relation = $Args->{relatedTo}{$uid}{relation};
      foreach my $key (keys %$relation) {
        $key = uc($key) if grep { $_ eq $key } qw(first next parent child);
        my %Props;
        $Props{RELTYPE} = $key unless $key eq 'PARENT';
        $VEvent->add_property('RELATED-TO' => [ $uid, \%Props ]);
      }
    }
  }

  if ($Args->{keywords}) {
    my @items = sort keys %{$Args->{keywords}};
    $VEvent->add_property('CATEGORIES', join(',', @items));
  }

  # virtualLocations -> CONFERENCE
  if ($Args->{virtualLocations}) {
    foreach my $id (sort keys %{$Args->{virtualLocations}}) {
      my $vloc = $Args->{virtualLocations}{$id};
      next unless $vloc->{uri};
      my %params = ('VALUE' => 'URI');
      $params{'X-JMAP-ID'} = $id;
      if ($vloc->{features} && ref($vloc->{features}) eq 'HASH') {
        my @feats = sort keys %{$vloc->{features}};
        $params{FEATURE} = join(',', map { uc $_ } @feats) if @feats;
      }
      $params{LABEL} = $vloc->{name} if defined $vloc->{name} && $vloc->{name} ne '';
      $VEvent->add_property(conference => [$vloc->{uri}, \%params]);
    }
  }

  # Task-specific properties (VTODO)
  if ($is_task) {
    if ($Args->{due}) {
      $VEvent->add_property(due => $Self->_makeLTime($TimeZones, $Args->{due}, $StartTimeZone, $IsAllDay));
    }
    if (defined $Args->{percentComplete}) {
      $VEvent->add_property('percent-complete' => $Args->{percentComplete});
    }
    if ($Args->{estimatedDuration}) {
      $VEvent->add_property('estimated-duration' => $Args->{estimatedDuration});
    }
    if ($Args->{progress} && $Args->{progress} eq 'completed') {
      $VEvent->add_property(completed => $Self->_makeZTime($Args->{updated} || DateTime->now->iso8601()));
    }
  }

  # detect if this is a dummy top-level event and skip it
  unshift @VEvents, $VEvent unless ($Args->{replyTo} and not $Args->{participants});

  return @VEvents;
}

=head2 $self->eventsToVCalendar(@Events)

Convert a set of events (one or multiple) into an ical file)

Returns a string

e.g.

print $jscal->eventsToVCalendar(@Events);

=cut

sub eventsToVCalendar {
  my $Self = shift;
  my $VCalendar = $Self->_argsToVCalendar(\@_);
  return $VCalendar->as_string();
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
    push @VEvents, $Self->_argsToVEvents(\%TimeZones, $Args);
  }

  # add timezone parts first
  foreach my $Zone (sort keys %TimeZones) {
    my $VTimeZone = Text::JSCalendar::TimeZones->GetVTimeZone($Zone);
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
    unless ($ValidFrequency{$Args->{frequency}}) {
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
    unless ($ValidDay{$Args->{firstDayOfWeek}}) {
      confess "Invalid recurrence firstDayOfWeek ($Args->{firstDayOfWeek})";
    }

    unless ($Args->{firstDayOfWeek} eq 'mo') {
      $Recurrence{WKST} = uc $Args->{firstDayOfWeek};
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

  if ($Args->{rscale}) {
    $Recurrence{RSCALE} = uc $Args->{rscale};
    $Recurrence{SKIP} = uc $Args->{skip} if exists $Args->{skip};
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
  delete $Event->{participants};
  delete $Event->{replyTo};

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

=head1 LICENSE AND COPYRIGHT

Copyright 2019 FastMail Pty Ltd.

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

1; # End of Text::JSCalendar
