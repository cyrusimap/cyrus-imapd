package Cassandane::TestEntity::Role::Factory;
use Moo::Role;

requires 'datatype'; # Email, Mailbox, etc.

requires 'instance_class';

has user => (
    is => 'ro',
    required => 1,
    handles => [qw(tester test_instance)],
    weak_ref => 1,
);

sub _get_properties {
    my ($self, $id) = @_;
    my $dt = $self->datatype;

    my $jmap = $self->user->entity_jmap;
    local $jmap->{CreatedIds}; # do not pollute the client for later use

    my ($res) = $jmap->CallMethods([[
        "$dt/get",
        { ids => [ "$id" ] },
        'FactoryGet',
    ]]);

    unless ($res->[0][0] eq "$dt/get") {
        Carp::confess("failed to get properties of $dt object with id $id")
    }

    my $props = $res->[0][1]{list}[0];
    delete $props->{id};

    return $props;
}

sub get {
    my ($self, $id) = @_;

    my $props = $self->_get_properties($id);

    $self->instance_class->new({
        id  => $id,
        factory    => $self,
        properties => $props,
    })
}

sub fill_in_creation_defaults {
    my ($self, $hashref) = @_;
    # ...
}

sub create {
    my ($self, $prop) = @_;
    $prop //= {};

    my $dt = $self->datatype;

    my $jmap = $self->user->entity_jmap;
    local $jmap->{CreatedIds}; # do not pollute the client for later use

    $self->fill_in_creation_defaults($prop);

    my ($res) = $jmap->CallMethods([[
        "$dt/set",
        { create => { toCreate => $prop } },
        'FactorySetCreate',
    ]]);

    unless ($res->[0][0] eq "$dt/set") {
        Carp::confess("failed to complete $dt/set call")
    }

    unless ($res->[0][1]{created}{toCreate}) {
        Carp::confess("failed to create $dt object")
    }

    $self->get($res->[0][1]{created}{toCreate}{id});
}

sub _update {
    my ($self, $instance, $update) = @_;
    my $dt = $self->datatype;
    my $id = $instance->id;

    my $jmap = $self->user->entity_jmap;
    local $jmap->{CreatedIds}; # do not pollute the client for later use

    my ($res) = $jmap->CallMethods([[
        "$dt/set",
        { update => { $id => $update } },
        'FactorySetUpdate',
    ]]);

    unless ($res->[0][0] eq "$dt/set") {
        Carp::confess("failed to complete $dt/set call")
    }

    if ($res->[0][1]{notUpdated}{$id}) {
        Carp::confess("failed to update $dt object")
    }

    $instance->clear_properties;

    return;
}

no Moo::Role;
1;
