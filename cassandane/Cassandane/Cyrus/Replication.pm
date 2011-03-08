#!/usr/bin/perl

use strict;
use warnings;
package Cassandane::Cyrus::Replication;
use base qw(Test::Unit::TestCase);
use DateTime;
use Cassandane::Util::Log;
use Cassandane::Generator;
use Cassandane::Instance;
use Cassandane::Service;
use Cassandane::Config;

sub new
{
    my $class = shift;
    my $self = $class->SUPER::new(@_);

    my $port = Cassandane::Service->alloc_port();
    my $conf = Cassandane::Config->default()->clone();
    $conf->set(
	# sync_client will find the port in the config
	sync_port => $port,
	# tell sync_client how to login
	sync_authname => 'repluser',
	sync_password => 'replpass',
	sync_realm => 'internal',
	sasl_mech_list => 'PLAIN',
	# Ensure sync_server gives sync_client enough privileges
	admins => 'admin repluser',
    );


    $self->{master} = Cassandane::Instance->new(config => $conf);
    $self->{master}->add_service('imap');

    $self->{replica} = Cassandane::Instance->new(config => $conf);
    $self->{replica}->add_service('imap');
    $self->{replica}->add_service('sync', port => $port);

    $self->{gen} = Cassandane::Generator->new();

    return $self;
}

sub set_up
{
    my ($self) = @_;

    $self->{master}->start();
    $self->{master_store} =
	$self->{master}->get_service('imap')->create_store();

    $self->{replica}->start();
    $self->{replica_store} =
	$self->{replica}->get_service('imap')->create_store();

    $self->{expected} = {};
}

sub tear_down
{
    my ($self) = @_;

    $self->{master_store}->disconnect()
	if defined $self->{master_store};
    $self->{master_store} = undef;

    $self->{replica_store}->disconnect()
	if defined $self->{replica_store};
    $self->{replica_store} = undef;

    $self->{master}->stop();
    $self->{replica}->stop();
}

sub make_message
{
    my ($self, $subject, %params) = @_;

    my $store = $params{store} || $self->{master_store};
    delete $params{store};

    $store->write_begin();
    my $msg = $self->{gen}->generate(subject => $subject, %params);
    $store->write_message($msg);
    $store->write_end();

    return $msg;
}

sub check_messages
{
    my ($self, $store, $expected) = @_;
    my $actual = {};

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

sub run_replication
{
    my ($self) = @_;

    my $params =
	$self->{replica}->get_service('sync')->store_params();

    # TODO: need a timeout!!

    my $code = $self->{master}->run_utility('sync_client',
	'-v',			# verbose
	'-S', $params->{host},	# hostname to connect to
	'-u', 'cassandane',	# replicate the Cassandane user
	);
    $self->assert($code == 0);
}

#
# Test replication of messages APPENDed to the master
#
sub test_append
{
    my ($self) = @_;

    # Use INBOX because we know it exists at both ends.
    $self->{master_store}->set_folder('INBOX');
    $self->{replica_store}->set_folder('INBOX');

    xlog "generating messages A..D";
    my $expected;
    $expected->{A} = $self->make_message("Message A");
    $expected->{B} = $self->make_message("Message B");
    $expected->{C} = $self->make_message("Message C");
    $expected->{D} = $self->make_message("Message D");

    xlog "Before replication, the master should have all four messages";
    $self->check_messages($self->{master_store}, $expected);
    xlog "Before replication, the replica should have no messages";
    $self->check_messages($self->{replica_store}, {});

    $self->run_replication();

    xlog "After replication, the master should still have all four messages";
    $self->check_messages($self->{master_store}, $expected);
    xlog "After replication, the replica should now have all four messages";
    $self->check_messages($self->{replica_store}, $expected);
}

1;
