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

sub get {
    my ($self, $id) = @_;
    my $dt = $self->datatype;

    my $jmap = $self->user->jmap;
    delete $jmap->{CreatedIds};

    my ($res) = $jmap->CallMethods([[
        "$dt/get",
        { ids => [ "$id" ] },
        'FactoryGet',
    ]]);

    unless ($res->[0][0] eq "$dt/get") {
        Carp::confess("failed to get $dt object with id $id")
    }

    $self->instance_class->new({
        factory    => $self,
        properties => $res->[0][1]{list}[0],
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

    my $jmap = $self->user->jmap;
    delete $jmap->{CreatedIds};

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

    my $jmap = $self->user->jmap;
    delete $jmap->{CreatedIds};

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

    my %newprops = {
        %$update,
        ( $res->[0][1]{updated}{$id} // {} )->%*,
    };

    $instance->properties->@{ keys %newprops } = values %newprops;

    return;
}

no Moo::Role;
1;
