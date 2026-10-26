# SPDX-License-Identifier: BSD-3-Clause-CMU
# See COPYING file at the root of the distribution for more details.

package Cassandane::Util::ICalendar;
use v5.28.0;
use warnings;
use experimental 'signatures';
use base qw(Exporter);

use Carp ();
use Text::VCardFast ();

our @EXPORT = qw(&ical2hash &hash2ical);

=head1 NAME

Cassandane::Util::ICalendar - parse and serialize iCalendar data

=head1 SYNOPSIS

    my $vcalendar = ical2hash($caldav_response->{content});
    my ($vevent) = grep { $_->{type} eq 'vevent' } $vcalendar->{objects}->@*;
    say $vevent->{properties}{summary}[0]{value};

    my $ical = hash2ical($vcalendar);

=head1 DESCRIPTION

A component is a hashref in the shape L<Text::VCardFast> produces: C<type> is
the lowercased component name, C<properties> maps each lowercased property name
to an arrayref of property instances, and C<objects> is an arrayref of
subcomponents.  A property instance has a C<value>, and optionally C<params>,
mapping lowercased parameter names to arrayrefs of values.

=head2 ical2hash

    my $component = ical2hash($ical);

Parse C<$ical> and return its first top-level component, usually a VCALENDAR.
You get TEXT values with their backslash escapes decoded; all other values come
back exactly as written.

=cut

sub ical2hash ($ical)
{
    my $parsed = Text::VCardFast::vcard2hash($ical, only_one => 1);
    my $component = $parsed && $parsed->{objects}[0];

    Carp::confess("can't parse iCalendar data:\n$ical") unless $component;
    return $component;
}

=head2 hash2ical

    my $ical = hash2ical($component);

Serialize C<$component> to iCalendar, with CRLF line endings.  VERSION comes
first, as some clients require, and the other properties follow sorted by
name, so serializing an unchanged parse gives the same bytes every time.

=cut

# Text::VCardFast::hash2vcard can't do this: it backslash-escapes every value
# as vCard TEXT, which corrupts RRULE, EXDATE, GEO and the like.  These are the
# properties whose values aren't TEXT and may contain a comma or semicolon;
# any other property is TEXT or can't contain either.  -- claude, 2026-10-26
my %NOT_TEXT = map { $_ => 1 } qw(
    attach attendee exdate exrule freebusy geo image organizer rdate
    request-status rrule source tzurl url
);

sub hash2ical ($component)
{
    return join q{}, map { "$_\r\n" } _component_lines($component);
}

sub _component_lines ($component)
{
    my $type = uc $component->{type};
    my $properties = $component->{properties} // {};

    my @lines = ("BEGIN:$type");

    my @names = sort { ($b eq q{version}) <=> ($a eq q{version}) || $a cmp $b }
        keys %$properties;

    for my $name (@names) {
        for my $prop ($properties->{$name}->@*) {
            push @lines, Text::VCardFast::foldline(_property_line($name, $prop));
        }
    }

    push @lines, _component_lines($_) for ($component->{objects} // [])->@*;
    push @lines, "END:$type";

    return @lines;
}

sub _property_line ($name, $prop)
{
    my $line = uc $name;

    my $params = $prop->{params} // {};
    for my $param (sort keys %$params) {
        my @values = map {; _param_value($_) } $params->{$param}->@*;
        $line .= ';' . uc($param) . '=' . join q{,}, @values;
    }

    my $value = $prop->{value} // q{};
    unless ($NOT_TEXT{$name}) {
        $value =~ s/([\\;,])/\\$1/g;
        $value =~ s/\r?\n/\\n/g;
    }

    return "$line:$value";
}

sub _param_value ($value)
{
    # RFC 6868 caret encoding
    $value =~ s/\^/^^/g;
    $value =~ s/\r?\n/^n/g;
    $value =~ s/"/^'/g;

    return $value =~ /[:;,]/ ? qq{"$value"} : $value;
}

1;
