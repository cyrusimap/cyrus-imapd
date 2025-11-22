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

    my $jmap = $self->user->jmaptester;

    my $res = $jmap->request([
        [ "$dt/get", { ids => [ "$id" ] }, 'FactoryGet' ]
    ]);

    my $get = $res->single_sentence("$dt/get");

    $self->instance_class->new({
        factory    => $self,
        properties => $get->arguments->{list}[0],
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

    my $jmap = $self->user->jmaptester;

    $self->fill_in_creation_defaults($prop);

    my $res = $jmap->request([[
        "$dt/set",
        { create => { toCreate => $prop } },
        'FactorySetCreate',
    ]]);

    my $set = $res->single_sentence("$dt/set")->as_set;
    my $id  = $set->created_id('toCreate');

    unless (defined $id) {
        Carp::confess("failed to create $dt object")
    }

    $self->get($id);
}

sub _update {
    my ($self, $instance, $update) = @_;
    my $dt = $self->datatype;
    my $id = $instance->id;

    my $jmap = $self->user->jmaptester;

    my $res = $jmap->request([[
        "$dt/set",
        { update => { $id => $update } },
        'FactorySetUpdate',
    ]]);

    my $set = $res->single_sentence("$dt/set")->as_set->assert_no_errors;

    my %newprops = {
        %$update,
        ( $set->arguments->{updated}{$id} // {} )->%*,
    };

    $instance->properties->@{ keys %newprops } = values %newprops;

    return;
}

no Moo::Role;
1;
