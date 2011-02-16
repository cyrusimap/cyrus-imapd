#!/usr/bin/perl

use strict;
use warnings;
package Cassandane::Cyrus::Simple;
use base qw(Test::Unit::TestCase);
use DateTime;
use Cassandane::Generator;
use Cassandane::MessageStoreFactory;
use Cassandane::CyrusInstance;

my $verbose = 1;

sub new
{
    my $class = shift;
    my $self = $class->SUPER::new(@_);

    $self->{instance} = Cassandane::CyrusInstance->new();
    $self->{instance}->add_service('imap');
    # Connection information for the IMAP server
    $self->{store_params} = $self->{instance}->service_params('imap');

    $self->{gen} = Cassandane::Generator->new();

    return $self;
}

sub set_up
{
    my ($self) = @_;

    $self->{instance}->start();
    $self->{store} =
	Cassandane::MessageStoreFactory->create(%{$self->{store_params}});

    $self->{expected} = {};
}

sub tear_down
{
    my ($self) = @_;

    $self->{store}->disconnect()
	if defined $self->{store};
    $self->{store} = undef;
    $self->{instance}->stop();
}

sub make_message
{
    my ($self, $subject, @attrs) = @_;

    $self->{store}->write_begin();
    my $msg = $self->{gen}->generate(subject => $subject, @attrs);
    $self->{store}->write_message($msg);
    $self->{store}->write_end();

    return $msg;
}

sub check_messages
{
    my ($self, %params) = @_;
    my $actual = {};
    my $expected = $self->{expected};
    my $store = $params{store} || $self->{store};

    printf "check_messages: %s\n", join(' ',%params) if $verbose;

    $store->read_begin();
    while (my $msg = $store->read_message())
    {
	my $subj = $msg->get_header('subject');
	$self->assert(!defined $actual->{$subj});
	$actual->{$subj} = $msg;
    }
    $store->read_end();

    $self->assert(scalar keys %$actual == scalar keys %$expected);

    foreach my $expmsg (values %$expected)
    {
	my $subj = $expmsg->get_header('subject');
	my $actmsg = $actual->{$subj};

	$self->assert(defined $actmsg);

	$self->assert(defined $actmsg->get_header('x-cassandane-unique'));

	$self->assert($actmsg->get_header('x-cassandane-unique') eq
		      $expmsg->get_header('x-cassandane-unique'));
    }

    return $actual;
}

#
# Test APPEND of messages to IMAP
#
sub test_append
{
    my ($self) = @_;

    printf "generating message A\n" if $verbose;
    $self->{expected}->{A} = $self->make_message("Message A");
    $self->check_messages();

    printf "generating message B\n" if $verbose;
    $self->{expected}->{B} = $self->make_message("Message B");
    $self->check_messages();

    printf "generating message C\n" if $verbose;
    $self->{expected}->{C} = $self->make_message("Message C");
    $self->check_messages();

    printf "generating message D\n" if $verbose;
    $self->{expected}->{D} = $self->make_message("Message D");
    $self->check_messages();
}

1;
