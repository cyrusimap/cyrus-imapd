use v5.28.0;
package Cassandane::TestEntity::DataType::CalendarEvent;

=head1 NAME

Cassandane::TestEntity::DataType::CalendarEvent - the CalendarEvent entity datatype

=head1 FACTORY METHODS

=cut

package Cassandane::TestEntity::Factory::CalendarEvent {
    use Moo;

    use Data::GUID ();
    use DateTime ();

=head2 create

The create method will provide sensible defaults, as usual.  An event that says
nothing about when it happens becomes an hour long event in UTC that starts now,
and one that names no calendar lands in the user's default calendar.

=cut

    sub fill_in_creation_defaults {
        my ($self, $prop) = @_;

        state $i = 1;
        $prop->{title} //= 'Event #' . $i++;

        # Now, rather than a date written into this file, so that no test
        # depends on how far the current date has drifted from that literal.
        $prop->{start} //= DateTime->now(time_zone => 'UTC')
                                   ->strftime('%Y-%m-%dT%H:%M:%S');
        $prop->{duration} //= 'PT1H';
        $prop->{timeZone} //= 'Etc/UTC';

        $prop->{uid}     //= Data::GUID->new->as_string;
        $prop->{version} //= '2.0';

        $prop->{calendarIds} //= {
            $self->user->calendars->default->id => JSON::true(),
        };

        return;
    }

    use Cassandane::TestEntity::AutoSetup;

    no Moo;
}

=head1 INSTANCE METHODS

=cut

package Cassandane::TestEntity::Instance::CalendarEvent {
    use Moo;

    # The properties here are those of a JSCalendar bis Event, plus the ones the
    # JMAP Calendars specification adds, in the order of the property table in
    # imap/jmap_props/calendar_event.gperf.
    use Cassandane::TestEntity::AutoSetup properties => [ qw(
        calendarIds
        uid relatedTo prodId created updated sequence method version
        title description descriptionContentType
        locations virtualLocations mainLocationId links
        locale keywords categories color
        recurrenceId recurrenceIdTimeZone recurrenceRule recurrenceOverrides
        excluded excludedRecurrenceRules
        priority freeBusyStatus privacy
        organizerCalendarAddress participants sentBy
        useDefaultAlerts alerts localizations
        start timeZone endTimeZone duration showWithoutTime status
        isDraft isOrigin baseEventId
        mayInviteSelf mayInviteOthers hideAttendees
    ) ];

    no Moo;
}

1;
