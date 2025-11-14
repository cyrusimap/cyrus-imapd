package Cassandane::TestEntity::AutoSetup;
use v5.20.0;
use warnings;

use Carp ();
use Sub::Install ();

sub import {
    my ($self, %arg) = @_;
    my $into = caller();

    my ($i_or_f, $final) = $into =~ /\ACassandane::TestEntity::(Instance|Factory)::(\w+)\z/;

    $i_or_f || Carp::confess("weirdly-formatted package name $into");
    $final  || Carp::confess("couldn't figure out datatype from $into");

    my $type = lc $i_or_f;
    my $datatype = $final;

    if ($type eq 'factory') {
        $self->_setup_factory_class($into, $datatype, \%arg);
        return;
    }

    if ($type eq 'instance') {
        $self->_setup_instance_class($into, $datatype, \%arg);
        return;
    }

    Carp::confess("unreachable code");
}

sub _setup_factory_class {
    my ($self, $class, $datatype, $arg) = @_;

    %$arg && Carp::confess("unknown arguments passed to TestEntity autosetup");

    my $instance_class;

    if ($class->can('instance_class')) {
        $instance_class = $class->instance_class;
    } else {
        $instance_class = "Cassandane::TestEntity::Instance::$datatype";
        Sub::Install::install_sub({
            into => $class,
            as   => 'instance_class',
            code => sub { $instance_class },
        });
    }

    unless ($class->can('datatype')) {
        Sub::Install::install_sub({
            into => $class,
            as   => 'datatype',
            code => sub { $datatype },
        });
    }

    eval "require $instance_class; 1"
        || die "Failed to load $instance_class: $@";

    # Avert your eyes, this is nasty.
    $class->can('with')->('Cassandane::TestEntity::Role::Factory');
}

sub _setup_instance_class {
    my ($self, $class, $datatype, $arg) = @_;

    my $properties = delete($arg->{properties}) // [];

    %$arg && Carp::confess("unknown arguments passed to TestEntity autosetup");

    my $instance_class;

    unless ($class->can('datatype')) {
        Sub::Install::install_sub({
            into => $class,
            as   => 'datatype',
            code => sub { $datatype },
        });
    }

    if ($class->can('datatype_properties')) {
        @$properties && Carp::croak("provided autosetup properties and datatype_properties method");
    } else {
        Sub::Install::install_sub({
            into => $class,
            as   => 'datatype_properties',
            code => sub { @$properties },
        });
    }

    # Avert your eyes, this is also nasty.
    $class->can('with')->('Cassandane::TestEntity::Role::Instance');

    $class->initialize_accessors;
}

1;
