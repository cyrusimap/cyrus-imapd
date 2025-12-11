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

    my $res = $jmap->request([
        [ "$dt/query", { filter => { role => 'inbox' } }, "a" ],
        [ "$dt/get", {
            '#ids' => {
                resultOf => 'a',
                name     => "$dt/query",
                path     => '/ids'
            },
        } ],
    ]);

    my $get = $res->sentence(1);

    unless ($get->name eq "$dt/get"
        &&  $get->arguments->{list}->@* == 1
    ) {
        Carp::confess("failed to get $dt object for inbox role");
    }

    my $props = $get->arguments->{list}[0];
    my $id    = delete $props->{id};
    $self->instance_class->new({
        id  => $id,
        factory    => $self,
        properties => $props,
    })
}

use Cassandane::TestEntity::AutoSetup;

no Moo;
1;
