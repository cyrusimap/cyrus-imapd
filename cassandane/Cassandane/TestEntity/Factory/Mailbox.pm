package Cassandane::TestEntity::Factory::Mailbox;
use Moo;

use feature 'state';

sub fill_in_creation_defaults {
    my ($self, $prop) = @_;

    state $i = 1;
    $prop->{name} //= 'Mailbox #' . $i++;

    return;
}

sub inbox {
    my ($self) = @_;
    my $dt = $self->datatype;

    my $jmap = $self->user->entity_jmap;
    local $jmap->{CreatedIds}; # do not pollute the client for later use

    my $res = $jmap->CallMethods([
        [ "$dt/query", { filter => { role => 'inbox' } }, 'a' ],
        [ "$dt/get", {
            '#ids' => {
                resultOf => 'a',
                name     => "$dt/query",
                path     => '/ids'
            },
        }, 'b' ],
    ]);

    unless ($res->[1][0] eq "$dt/get" && $res->[1][1]{list}->@*) {
        Carp::confess("failed to get $dt object for inbox role");
    }

    $self->instance_class->new({
        factory    => $self,
        properties => $res->[1][1]{list}[0],
    })
}

use Cassandane::TestEntity::AutoSetup;

no Moo;
1;
