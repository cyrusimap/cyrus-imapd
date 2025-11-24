package Cassandane::TestEntity::Role::ShareableInstance;
use Moo::Role;

use Sub::Install ();

# $mailbox->share_with($user => [ qw( mayFoo mayBar ) ], $user2 => ...)
#
# This sets the exact bits for the given users, leaving other users intact.
# That means that if you want to turn on mayFoo and mayBar for a single user,
# you must do it in one share_with call.  A second call would *replace*, not
# *union* permissions.
sub share_with {
    my ($self, @input) = @_;

    @input % 2 && Carp::confess("odd size input to ->share_with -- it must be pairs!");

    my %to_update;
    while (my ($target, $bits) = splice @input, 0, 2) {
        my $ident = ref $target ? $target->username : $target;
        my @bits  = ref $bits   ? @$bits : $bits; # the BITS! 🍟

        $to_update{"shareWith/$ident"} = { map {; $_ => JSON::true() } @bits };
    }

    $self->factory->_update($self => \%to_update);
    return;
}

sub unshare_entirely {
    my ($self) = @_;

    $self->factory->_update($self => { shareWith => {} });
    return;
}

no Moo::Role;
1;
