use v5.28.0;
package Cassandane::TestEntity::DataType::Calendar;

=head1 NAME

Cassandane::TestEntity::DataType::Calendar - the Calendar entity datatype

=cut

package Cassandane::TestEntity::Factory::Calendar {
    use Moo;

    sub fill_in_creation_defaults {
        my ($self, $prop) = @_;

        state $i = 1;
        $prop->{name} //= 'Calendar #' . $i++;

        return;
    }

=head2 default

    my $cal = $user->calendars->default;

This acts like C<< ->get >>, returning an address book instance, but finds and
returns the address book with id C<Default>.  Later, this should look for a
true C<isDefault> property.

=cut

    sub default {
        my ($self) = @_;
        my $dt = $self->datatype;

        my $jmap = $self->user->entity_jmap;

        my $res = $jmap->request([[ "Calendar/get", {} ]]);

        my $get = $res->single_sentence('Calendar/get');

        my @objs = $get->arguments->{list}->@*;
        @objs > 0 || Carp::confess("user has no Calendars");

        my ($default, @extra) = grep {; $_->{isDefault} } @objs;
        $default || Carp::confess("user has no default Calendar");
        @extra && Carp::confess("user has more than one default Calendar");

        $self->instance_class->new({
            id  => "$default->{id}",
            factory    => $self,
            properties => $default,
        })
    }

    use Cassandane::TestEntity::AutoSetup;

    no Moo;
}

=head1 INSTANCE METHODS

=cut

package Cassandane::TestEntity::Instance::Calendar {
    use Moo;

    use JSON ();

    use Cassandane::TestEntity::AutoSetup properties => [ qw(
        name
    ) ];

    with 'Cassandane::TestEntity::Role::ShareableInstance';

=head2 create_event

    my $event = $cal->create_event({ ... });

This method creates a CalendarEvent instance that's in C<< $cal >> and no other
calendars.

=cut

    sub create_event {
        my ($self, $prop) = @_;
        $prop //= {};

        $self->user->calendarevents->create({
            %$prop,
            calendarIds => { $self->id => JSON::true() },
        });
    }

    no Moo;
}

1;
