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
    use JSON ();

=head2 create

The create method provide sensible defaults, as usual.

=cut

    sub fill_in_creation_defaults {
        my ($self, $prop) = @_;

        state $i = 1;
        $prop->{title} //= 'Event #' . $i++;

        my $show_without_time = $prop->{showWithoutTime};

        unless ($show_without_time || exists $prop->{timeZone}) {
            $prop->{timeZone} = 'Etc/UTC';
        }

        unless (exists $prop->{start}) {
            my $now = DateTime->now(
                time_zone => $prop->{timeZone} // 'Etc/UTC',
            );
            $now->truncate(to => 'day') if $show_without_time;
            $prop->{start} = $now->strftime('%Y-%m-%dT%H:%M:%S');
        }

        unless (exists $prop->{duration}) {
            $prop->{duration} = $show_without_time ? 'P1D' : 'PT1H';
        }

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

    use Cassandane::TestEntity::AutoSetup properties => [ qw(
        alerts
        baseEventId
        blobId
        calendarIds
        categories
        color
        created
        description
        descriptionContentType
        duration
        endTimeZone
        freeBusyStatus
        hideAttendees
        isDraft
        isOrigin
        keywords
        links
        locale
        locations
        mainLocationId
        mayInviteOthers
        mayInviteSelf
        method
        organizerCalendarAddress
        participants
        priority
        privacy
        prodId
        recurrenceId
        recurrenceIdTimeZone
        recurrenceOverrides
        recurrenceRule
        relatedTo
        scheduleSequence
        scheduleUpdated
        sentBy
        sequence
        showWithoutTime
        start
        status
        timeZone
        title
        uid
        updated
        useDefaultAlerts
        utcEnd
        utcStart
        version
        virtualLocations
    ) ];

    no Moo;
}

1;
