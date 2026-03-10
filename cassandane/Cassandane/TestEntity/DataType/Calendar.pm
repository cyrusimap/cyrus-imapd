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

        return $self->get('Default');
    }

    use Cassandane::TestEntity::AutoSetup;

    no Moo;
}

=head1 INSTANCE METHODS

=cut

package Cassandane::TestEntity::Instance::Calendar {
    use Moo;

    use Cassandane::TestEntity::AutoSetup properties => [ qw(
        name
    ) ];

    with 'Cassandane::TestEntity::Role::ShareableInstance';

    no Moo;
}

1;
