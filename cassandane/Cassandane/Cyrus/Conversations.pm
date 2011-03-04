#!/usr/bin/perl

use strict;
use warnings;
package Cassandane::Cyrus::Conversations;
use base qw(Test::Unit::TestCase);
use DateTime;
use URI::Escape;
use Digest::SHA1 qw(sha1_hex);
use Cassandane::Generator;
use Cassandane::Util::Log;
use Cassandane::Util::DateTime qw(to_iso8601 from_iso8601
				  from_rfc822
				  to_rfc3501 from_rfc3501);
use Cassandane::MessageStoreFactory;
use Cassandane::Instance;

sub new
{
    my $class = shift;
    my $self = $class->SUPER::new(@_);

    my $config = Cassandane::Config->default()->clone();
    $config->set(conversations => 'on');
    $self->{instance} = Cassandane::Instance->new(config => $config);
    $self->{instance}->add_service('imap');
    # Connection information for the IMAP server
    $self->{store_params} = $self->{instance}->service_params('imap');

#     $self->{replica_params} =
#     {
# 	%{$self->{store_params}},
# 	host => 'slott01'
#     };

    $self->{gen} = Cassandane::Generator->new();

    return $self;
}

sub set_up
{
    my ($self) = @_;

    $self->{instance}->start();
    $self->{store} =
	Cassandane::MessageStoreFactory->create(%{$self->{store_params}});
    $self->{store}->set_fetch_attributes('uid', 'cid');

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

# Calculate a CID from a message - this is the CID that the
# first message in a new conversation will be assigned.
sub calc_cid
{
    my ($msg) = @_;
    return substr(sha1_hex($msg->as_string()), 0, 16);
}

# The resulting CID when a clash happens is supposed to be
# the MAXIMUM of all the CIDs.  Here we use the fact that
# CIDs are expressed in a form where lexical order is the
# same as numeric order.
sub choose_cid
{
    my (@cids) = @_;
    @cids = sort { $b cmp $a } @cids;
    return $cids[0];
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

    xlog "check_messages: " . join(' ',%params);

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

	$self->assert(defined $actmsg->get_attribute('cid'));

	my $cid = (defined $params{cid} ? $params{cid} : calc_cid($actmsg));

	$self->assert($actmsg->get_attribute('cid') eq $cid);

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

    # check IMAP server has the XCONVERSATIONS capability
    $self->assert($self->{store}->get_client()->capability()->{xconversations});

    xlog "removing folder";
    $self->{store}->remove();

    xlog "generating message A";
    $self->{expected}->{A} = $self->make_message("Message A");
    $self->check_messages();

    xlog "generating message B";
    $self->{expected}->{B} = $self->make_message("Message B");
    $self->check_messages();

    xlog "generating message C";
    $self->{expected}->{C} = $self->make_message("Message C");
    my $actual = $self->check_messages();

    xlog "generating message D";
    $self->{expected}->{D} = $self->make_message("Message D");
    $self->check_messages();
}


#
# Test APPEND of messages to IMAP which results in a CID clash.
#
sub test_append_clash
{
    my ($self) = @_;

    # check IMAP server has the XCONVERSATIONS capability
    $self->assert($self->{store}->get_client()->capability()->{xconversations});

    xlog "removing folder";
    $self->{store}->remove();

    xlog "generating message A";
    $self->{expected}->{A} = $self->make_message("Message A");
    $self->check_messages();

    xlog "generating message B";
    $self->{expected}->{B} = $self->make_message("Message B");
    my $actual = $self->check_messages();

    xlog "generating message C";
    $self->{expected}->{C} = $self->make_message(
				 "Message C",
				 references =>
				       $self->{expected}->{A}->get_header('message-id') .  ", " .
				       $self->{expected}->{B}->get_header('message-id'),
				 );
    $self->check_messages(cid => choose_cid(
					calc_cid($actual->{'Message A'}),
					calc_cid($actual->{'Message B'})
				    ));
}

#
# Test APPEND of messages to IMAP which results in multiple CID clashes.
#
sub test_double_clash
{
    my ($self) = @_;

    # check IMAP server has the XCONVERSATIONS capability
    $self->assert($self->{store}->get_client()->capability()->{xconversations});

    xlog "removing folder";
    $self->{store}->remove();

    xlog "generating message A";
    $self->{expected}->{A} = $self->make_message("Message A");
    $self->check_messages();

    xlog "generating message B";
    $self->{expected}->{B} = $self->make_message("Message B");
    $self->check_messages();

    xlog "generating message C";
    $self->{expected}->{C} = $self->make_message("Message C");
    my $actual = $self->check_messages();

    xlog "generating message D";
    $self->{expected}->{D} = $self->make_message(
				 "Message D",
				 references =>
				       $self->{expected}->{A}->get_header('message-id') .  ", " .
				       $self->{expected}->{B}->get_header('message-id') .  ", " .
				       $self->{expected}->{C}->get_header('message-id'),
				 );
    $self->check_messages(cid => choose_cid(
					calc_cid($actual->{'Message A'}),
					calc_cid($actual->{'Message B'}),
					calc_cid($actual->{'Message C'})
				    ));
}

# #
# # Test that a CID clash resolved on the master is replicated
# #
# sub test_replication_clash
# {
#     my ($self) = @_;
# 
#     my $replica =
# 	Cassandane::MessageStoreFactory->create(%{$self->{replica_params}});
#     $replica->set_fetch_attributes('uid', 'cid');
# 
#     #
#     # Double check that we're connected to the servers
#     # we wanted to be connected to.
#     #
#     $self->assert($self->{store_params}->{host} ne $self->{replica_params}->{host});
#     $self->assert($self->{store}->get_server_name() eq $self->{store_params}->{host});
#     $self->assert($replica->get_server_name() eq $self->{replica_params}->{host});
# 
#     # check IMAP server has the XCONVERSATIONS capability
#     $self->assert($self->{store}->get_client()->capability()->{xconversations});
#     $self->assert($replica->get_client()->capability()->{xconversations});
# 
#     # let the rolling replication catch up
#     sleep(3);
# 
#     xlog "removing folder";
#     $self->{store}->remove();
# 
#     xlog "generating message A";
#     $self->{expected}->{A} = $self->make_message("Message A");
#     sleep(3);   # let the replication catch up
#     $self->check_messages();
#     $self->check_messages(store => $replica);
# 
#     xlog "generating message B";
#     $self->{expected}->{B} = $self->make_message("Message B");
#     sleep(3);   # let the replication catch up
#     $self->check_messages();
#     $self->check_messages(store => $replica);
# 
#     xlog "generating message C";
#     $self->{expected}->{C} = $self->make_message("Message C");
#     sleep(3);   # let the replication catch up
#     my $actual = $self->check_messages();
#     $self->check_messages(store => $replica);
# 
#     xlog "generating message D";
#     $self->{expected}->{D} = $self->make_message("Message D",
# 				 references =>
# 				       $self->{expected}->{A}->get_header('message-id') .  ", " .
# 				       $self->{expected}->{B}->get_header('message-id') .  ", " .
# 				       $self->{expected}->{C}->get_header('message-id')
# 				 );
#     sleep(3);   # let the replication catch up
#     my $ElCid = choose_cid(
# 		    calc_cid($actual->{'Message A'}),
# 		    calc_cid($actual->{'Message B'}),
# 		    calc_cid($actual->{'Message C'})
# 		);
#     $self->check_messages(cid => $ElCid);
#     $self->check_messages(store => $replica, cid => $ElCid);
# }

1;
