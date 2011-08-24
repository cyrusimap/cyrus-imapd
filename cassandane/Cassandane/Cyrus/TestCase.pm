#!/usr/bin/perl
#
#  Copyright (c) 2011 Opera Software Australia Pty. Ltd.  All rights
#  reserved.
#
#  Redistribution and use in source and binary forms, with or without
#  modification, are permitted provided that the following conditions
#  are met:
#
#  1. Redistributions of source code must retain the above copyright
#     notice, this list of conditions and the following disclaimer.
#
#  2. Redistributions in binary form must reproduce the above copyright
#     notice, this list of conditions and the following disclaimer in
#     the documentation and/or other materials provided with the
#     distribution.
#
#  3. The name "Opera Software Australia" must not be used to
#     endorse or promote products derived from this software without
#     prior written permission. For permission or any legal
#     details, please contact
# 	Opera Software Australia Pty. Ltd.
# 	Level 50, 120 Collins St
# 	Melbourne 3000
# 	Victoria
# 	Australia
#
#  4. Redistributions of any form whatsoever must retain the following
#     acknowledgment:
#     "This product includes software developed by Opera Software
#     Australia Pty. Ltd."
#
#  OPERA SOFTWARE AUSTRALIA DISCLAIMS ALL WARRANTIES WITH REGARD TO
#  THIS SOFTWARE, INCLUDING ALL IMPLIED WARRANTIES OF MERCHANTABILITY
#  AND FITNESS, IN NO EVENT SHALL OPERA SOFTWARE AUSTRALIA BE LIABLE
#  FOR ANY SPECIAL, INDIRECT OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES
#  WHATSOEVER RESULTING FROM LOSS OF USE, DATA OR PROFITS, WHETHER IN
#  AN ACTION OF CONTRACT, NEGLIGENCE OR OTHER TORTIOUS ACTION, ARISING
#  OUT OF OR IN CONNECTION WITH THE USE OR PERFORMANCE OF THIS SOFTWARE.
#

use strict;
use warnings;
package Cassandane::Cyrus::TestCase;
use base qw(Cassandane::Unit::TestCase);
use Cassandane::Util::Log;
use Cassandane::Generator;
use Cassandane::MessageStoreFactory;
use Cassandane::Instance;

sub new
{
    my ($class, $params, @args) = @_;

    my $want = {
	instance => 1,
	imapd => 1,
	store => 1,
	adminstore => 0,
	gen => 1,
    };
    map {
	$want->{$_} = $params->{$_}
	    if defined $params->{$_};
    } keys %$want;

    my %instance_params;
    foreach my $p (qw(config))
    {
	$instance_params{$p} = $params->{$p}
	    if defined $params->{$p};
    }

    my $self = $class->SUPER::new(@args);
    $self->{_want} = $want;

    if ($want->{instance})
    {
	$self->{instance} = Cassandane::Instance->new(%instance_params);
	$self->{instance}->add_service('imap')
	    if ($want->{imapd});
    }

    if ($want->{gen})
    {
	$self->{gen} = Cassandane::Generator->new();
    }

    return $self;
}

sub set_up
{
    my ($self) = @_;

    my $inst = $self->{instance};
    return unless defined $inst;
    $inst->start();

    my $svc = $inst->get_service('imap');
    return unless defined $svc;

    $self->{store} = $svc->create_store()
	if ($self->{_want}->{store});
    $self->{adminstore} = $svc->create_store(username => 'admin')
	if ($self->{_want}->{adminstore});
}

sub tear_down
{
    my ($self) = @_;

    if (defined $self->{store})
    {
	$self->{store}->disconnect();
	$self->{store} = undef;
    }
    if (defined $self->{adminstore})
    {
	$self->{adminstore}->disconnect();
	$self->{adminstore} = undef;
    }
    if (defined $self->{instance})
    {
	$self->{instance}->stop();
	$self->{instance} = undef;
    }
}

# TODO: provide a way to do this in the same instance
# which would be more efficient
sub restart_with_config
{
    my ($self, %nv) = @_;

    my $conf = $self->{instance}->{config}->clone();
    $conf->set(%nv);

    $self->tear_down();
    $self->{instance} = Cassandane::Instance->new(config => $conf);
    $self->{instance}->add_service('imap');
    $self->set_up();
}

sub _save_message
{
    my ($self, $msg, $store) = @_;

    $store ||= $self->{store};

    $store->write_begin();
    $store->write_message($msg);
    $store->write_end();
}

sub make_message
{
    my ($self, $subject, %attrs) = @_;

    my $store = $attrs{store};	# may be undef
    delete $attrs{store};

    my $msg = $self->{gen}->generate(subject => $subject, %attrs);
    $self->_save_message($msg, $store);

    return $msg;
}

sub check_messages
{
    my ($self, $expected, %params) = @_;
    my $actual = {};
    my $store = $params{store} || $self->{store};

    xlog "check_messages: " . join(' ', %params);

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

	$self->assert_not_null($actmsg);

	xlog "checking guid";
	$self->assert_str_equals($expmsg->get_guid(),
			         $actmsg->get_guid());

	# Check required headers
	foreach my $h (qw(x-cassandane-unique))
	{
	    xlog "checking $h";
	    $self->assert_not_null($actmsg->get_header($h));
	    $self->assert_str_equals($expmsg->get_header($h),
				     $actmsg->get_header($h));
	}

	# if there were optional headers we wished to check, do it here

	# check optional string attributes
	foreach my $a (qw(id uid cid))
	{
	    next unless defined $expmsg->get_attribute($a);
	    xlog "checking $a";
	    $self->assert_str_equals($expmsg->get_attribute($a),
				     $actmsg->get_attribute($a));
	}

	# check optional structured attributes
	foreach my $a (qw(flags))
	{
	    next unless defined $expmsg->get_attribute($a);
	    xlog "checking $a";
	    $self->assert_deep_equals($expmsg->get_attribute($a),
				      $actmsg->get_attribute($a));
	}

	# check annotations
	foreach my $ea ($expmsg->list_annotations())
	{
	    xlog "checking annotation ($ea->{entry} $ea->{attrib})";
	    $self->assert_not_null($actmsg->get_annotation($ea));
	    $self->assert_str_equals($expmsg->get_annotation($ea),
				     $actmsg->get_annotation($ea));
	}
    }

    return $actual;
}

1;
