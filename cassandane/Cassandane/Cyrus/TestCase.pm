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

package Cassandane::Cyrus::TestCase;
use strict;
use warnings;
use attributes;
use Scalar::Util qw(refaddr);

use lib '.';
use base qw(Cassandane::Unit::TestCase);
use Cassandane::Util::Log;
use Cassandane::Util::Words;
use Cassandane::Generator;
use Cassandane::MessageStoreFactory;
use Cassandane::Instance;
use Cassandane::PortManager;

my @stores = qw(store adminstore
		replica_store replica_adminstore
		frontend_store frontend_adminstore);
my %magic_handlers;

# This code for storing function attributes is from
# http://stackoverflow.com/questions/987059/how-do-perl-method-attributes-work

my %attrs; # package variable to store attribute lists by coderef address

sub MODIFY_CODE_ATTRIBUTES
{
    my ($package, $subref, @attrs) = @_;
    $attrs{refaddr $subref} = \@attrs;
    return;
}

sub FETCH_CODE_ATTRIBUTES
{
    my ($package, $subref) = @_;
    my $attrs = $attrs{refaddr $subref} || [];
    return @$attrs;
}

sub new
{
    my ($class, $params, @args) = @_;

    my $want = {
	instance => 1,
	replica => 0,
	murder => 0,
	start_instances => 1,
	services => [ 'imap' ],
	store => 1,
	adminstore => 0,
	gen => 1,
	deliver => 0,
    };
    map {
	$want->{$_} = delete $params->{$_}
	    if defined $params->{$_};

    } keys %$want;
    $want->{folder} = delete $params->{folder}
	if defined $params->{folder};

    my $instance_params = {};
    foreach my $p (qw(config))
    {
	$instance_params->{$p} = delete $params->{$p}
	    if defined $params->{$p};
    }

    # should have consumed all of the $params hash; if
    # not something is awry.
    my $leftovers = join(' ', keys %$params);
    die "Unexpected configuration parameters: $leftovers"
	if length($leftovers);

    my $self = $class->SUPER::new(@args);
    $self->{_name} = $args[0] || 'unknown';
    $self->{_want} = $want;
    $self->{_instance_params} = $instance_params;

    return $self;
}

# will magically cause some special actions to be taken during test
# setup.  This used to be a horrible hack to enable a replica instance
# if the test name contained the word "replication", but now it's more
# general.  The handler function is called near the start of set_up(),
# before Cyrus instances are created, and can call want() to add to the
# set of features wanted by this test, or config_set() to set additional
# imapd.conf variables for all instances.
sub magic
{
    my ($name, $handler) = @_;
    $name = lc($name);
    die "Magic \"$name\" registered twice"
	if defined $magic_handlers{$name};
    $magic_handlers{$name} = $handler;
}

sub _who_wants_it
{
    my ($self) = @_;
    return $self->{_current_magic}
	if defined $self->{_current_magic} ;
    return "Test " . $self->{_name};
}

sub want
{
    my ($self, $name, $value) = @_;
    $value = 1 if !defined $value;
    $self->{_want}->{$name} = $value;
    xlog $self->_who_wants_it() .  " wants $name = $value";
}

sub config_set
{
    my ($self, %pairs) = @_;
    $self->{_config}->set(%pairs);
    while (my ($n, $v) = each %pairs)
    {
	xlog $self->_who_wants_it() . " sets config $n = $v";
    }
}

magic(ReverseACLs => sub {
    shift->config_set(reverseacls => 1);
});
magic(replication => sub { shift->want('replica'); });
magic(murder => sub { shift->want('murder'); });
magic(AnnotationAllowUndefined => sub {
    shift->config_set(annotation_allow_undefined => 1);
});
magic(ImmediateDelete => sub {
    shift->config_set(delete_mode => 'immediate');
});
magic(DelayedDelete => sub {
    shift->config_set(delete_mode => 'delayed');
});
magic(UnixHierarchySep => sub {
    shift->config_set(unixhierarchysep => 'yes');
});
magic(ImmediateExpunge => sub {
    shift->config_set(expunge_mode => 'immediate');
});
magic(DefaultExpunge => sub {
    shift->config_set(expunge_mode => 'default');
});
magic(DelayedExpunge => sub {
    shift->config_set(expunge_mode => 'delayed');
});
magic(VirtDomains => sub {
    shift->config_set(virtdomains => 'userid');
});
magic(AltNamespace => sub {
    shift->config_set(altnamespace => 'yes');
});
magic(CrossDomains => sub {
    shift->config_set(crossdomains => 'yes');
});
magic(Conversations => sub {
    shift->config_set(conversations => 'yes');
});
magic(Admin => sub {
    shift->want('adminstore');
});
magic(AllowMoves => sub {
    shift->config_set('allowusermoves' => 'yes');
});
magic(DisconnectOnVanished => sub {
    shift->config_set('disconnect_on_vanished_mailbox' => 'yes');
});
magic(NoStartInstances => sub {
    shift->want('start_instances' => 0);
});
magic(MagicPlus => sub {
    shift->config_set('imapmagicplus' => 'yes');
});
magic(FastMailSharing => sub {
    shift->config_set('fastmailsharing' => 'true');
});



# Run any magic handlers indicated by the test name or attributes
sub _run_magic
{
    my ($self) = @_;

    my %seen;

    foreach my $m (split(/_/, $self->{_name}))
    {
	next if $seen{$m};
	next unless defined $magic_handlers{$m};
	$self->{_current_magic} = "Magic word $m in name";
	$magic_handlers{$m}->($self);
	$self->{_current_magic} = undef;
	$seen{$m} = 1;
    }

    my $sub = $self->can($self->{_name});
    if (defined $sub) {
	foreach my $a (attributes::get($sub))
	{
	    my $m = lc($a);
	    # ignore min/max version attribution here
	    next if $a =~ m/^(?:min|max)_version_/;
	    die "Unknown attribute $a"
		unless defined $magic_handlers{$m};
	    next if $seen{$m};
	    $self->{_current_magic} = "Magic attribute $a";
	    $magic_handlers{$m}->($self);
	    $self->{_current_magic} = undef;
	    $seen{$m} = 1;
	}
    }
}

sub _create_instances
{
    my ($self) = @_;
    my $sync_port;
    my $mupdate_port;
    my $backend_imapd_port;

    $self->{_config} = $self->{_instance_params}->{config} || Cassandane::Config->default();
    $self->{_config} = $self->{_config}->clone();

    $self->_run_magic();

    my $want = $self->{_want};
    my %instance_params = %{$self->{_instance_params}};

    my $cassini = Cassandane::Cassini->instance();

    if ($want->{instance})
    {
	my $conf = $self->{_config}->clone();

	if ($want->{replica})
	{
	    $sync_port = Cassandane::PortManager::alloc();
	    $conf->set(
		# sync_client will find the port in the config
		sync_port => $sync_port,
		# tell sync_client how to login
		sync_authname => 'repluser',
		sync_password => 'replpass',
		sasl_mech_list => 'PLAIN',
		# Ensure sync_server gives sync_client enough privileges
		admins => 'admin repluser',
	    );
	}

	if ($want->{murder})
	{
	    $mupdate_port = Cassandane::PortManager::alloc();
	    $backend_imapd_port = Cassandane::PortManager::alloc();

	    $conf->set(
		servername => "localhost:$backend_imapd_port",
		mupdate_server => "localhost:$mupdate_port",
		# XXX documentation says to use mupdate_port, but
		# XXX this doesn't work -- need to embed port number in
		# XXX mupdate_server setting instead.
		#mupdate_port => $mupdate_port,
		mupdate_username => 'mupduser',
		mupdate_authname => 'mupduser',
		mupdate_password => 'mupdpass',
		proxyservers => 'mailproxy',
		lmtp_admins => 'mailproxy',
		sasl_mech_list => 'PLAIN',
	    );
	}

	my $sub = $self->{_name};
	if ($sub =~ s/^test_/config_/ && $self->can($sub))
	{
	    die 'Use of config_<testname> subs is not supported anymore';
	}

	$instance_params{config} = $conf;

	$instance_params{description} = "main instance for test $self->{_name}";
	$self->{instance} = Cassandane::Instance->new(%instance_params);
	$self->{instance}->add_services(@{$want->{services}});
	$self->{instance}->_setup_for_deliver()
	    if ($want->{deliver});

	if ($want->{replica})
	{
	    my $cyrus_replica_prefix = $cassini->val('cyrus replica', 'prefix');
	    if (defined $cyrus_replica_prefix and -d $cyrus_replica_prefix) {
		xlog "replica instance: using [cyrus replica] configuration";
		$instance_params{installation} = 'replica';
	    }

	    $instance_params{description} = "replica instance for test $self->{_name}";
	    $self->{replica} = Cassandane::Instance->new(%instance_params,
							 setup_mailbox => 0);
	    my ($v) = Cassandane::Instance->get_version($instance_params{installation});
	    if ($v < 3) {
		$self->{replica}->add_service(name => 'sync',
					      port => $sync_port,
					      argv => ['sync_server']);
	    }
	    else {
		$self->{replica}->add_service(name => 'sync', port => $sync_port);
	    }
	    $self->{replica}->add_services(@{$want->{services}});
	    $self->{replica}->_setup_for_deliver()
		if ($want->{deliver});
	}

	if ($want->{murder})
	{
	    # set up a front end on which we also run the mupdate master
	    my $frontend_conf = $self->{_config}->clone();
	    $frontend_conf->set(
		mupdate_server => "localhost:$mupdate_port",
		# XXX documentation says to use mupdate_port, but
		# XXX this doesn't work -- need to embed port number in
		# XXX mupdate_server setting instead.
		#mupdate_port => $mupdate_port,
		mupdate_username => 'mupduser',
		mupdate_authname => 'mupduser',
		mupdate_password => 'mupdpass',
		serverlist => "localhost:$backend_imapd_port",
		admins => 'admin mupduser',
		proxy_authname => 'mailproxy',
		proxy_password => 'mailproxy',
		sasl_mech_list => 'PLAIN',
	    );

	    my $cyrus_murder_prefix = $cassini->val('cyrus murder', 'prefix');
	    if (defined $cyrus_murder_prefix and -d $cyrus_murder_prefix) {
		xlog "murder instance: using [cyrus murder] configuration";
		$instance_params{installation} = 'murder';
	    }

	    $instance_params{description} = "murder frontend for test $self->{_name}";
	    $instance_params{config} = $frontend_conf;
	    $self->{frontend} = Cassandane::Instance->new(%instance_params,
							  setup_mailbox => 0);
	    $self->{frontend}->add_service(name => 'mupdate',
					   port => $mupdate_port,
					   argv => ['mupdate', '-m'],
					   prefork => 1);
	    $self->{frontend}->add_services(@{$want->{services}});

	    # arrange for the backend to push to mupdate on startup
	    $self->{instance}->add_start(name => 'mupdatepush',
					 argv => ['ctl_mboxlist', '-m']);

	    # arrange for the backend imapd to run on a known port
	    $self->{instance}->remove_service('imap');
	    $self->{instance}->add_service(name => 'imap',
					   port => $backend_imapd_port);
	}
    }

    if ($want->{gen})
    {
	$self->{gen} = Cassandane::Generator->new();
    }
}

sub set_up
{
    my ($self) = @_;

    xlog "---------- BEGIN $self->{_name} ----------";

    $self->_create_instances();
    $self->_start_instances()
	if $self->{_want}->{start_instances};
    xlog "Calling test function";
}

sub _start_instances
{
    my ($self) = @_;

    $self->{frontend}->start()
	if (defined $self->{frontend});
    $self->{instance}->start()
	if (defined $self->{instance});
    $self->{replica}->start()
	if (defined $self->{replica});

    $self->{store} = undef;
    $self->{adminstore} = undef;
    $self->{master_store} = undef;
    $self->{master_adminstore} = undef;
    $self->{replica_store} = undef;
    $self->{replica_adminstore} = undef;
    $self->{frontend_store} = undef;
    $self->{frontend_adminstore} = undef;
    $self->{backend_store} = undef;
    $self->{backend_adminstore} = undef;

    # Run the replication engine to create the user mailbox
    # in the replica.  Doing it this way avoids issues with
    # mismatched mailbox uniqueids.
    $self->run_replication()
	if (defined $self->{replica});

    my %store_params;
    $store_params{folder} = $self->{_want}->{folder}
	if defined $self->{_want}->{folder};

    my %adminstore_params = ( %store_params, username => 'admin' );
    # The admin stores need an extra parameter to force their
    # default folder because otherwise they will default to 'INBOX'
    # which refers to user.admin not user.cassandane
    $adminstore_params{folder} ||= 'INBOX';
    $adminstore_params{folder} = 'user.cassandane'
	if ($adminstore_params{folder} =~ m/^inbox$/i);

    if (defined $self->{instance})
    {
	my $svc = $self->{instance}->get_service('imap');
	if (defined $svc)
	{
	    $self->{store} = $svc->create_store(%store_params)
		if ($self->{_want}->{store});
	    $self->{adminstore} = $svc->create_store(%adminstore_params)
		if ($self->{_want}->{adminstore});
	}
    }
    if (defined $self->{replica})
    {
	# aliases for the master's store(s)
	$self->{master_store} = $self->{store};
	$self->{master_adminstore} = $self->{adminstore};

	my $svc = $self->{replica}->get_service('imap');
	if (defined $svc)
	{
	    $self->{replica_store} = $svc->create_store(%store_params)
		if ($self->{_want}->{store});
	    $self->{replica_adminstore} = $svc->create_store(%adminstore_params)
		if ($self->{_want}->{adminstore});
	}
    }
    if (defined $self->{frontend})
    {
	# aliases for the backend store(s)
	$self->{backend_store} = $self->{store};
	$self->{backend_adminstore} = $self->{adminstore};

	my $svc = $self->{frontend}->get_service('imap');
	if (defined $svc)
	{
	    $self->{frontend_store} = $svc->create_store(%store_params)
		if ($self->{_want}->{store});
	    $self->{frontend_adminstore} = $svc->create_store(%adminstore_params)
		if ($self->{_want}->{adminstore});
	}
    }
}

sub tear_down
{
    my ($self) = @_;

    xlog "Beginning tear_down";

    foreach my $s (@stores)
    {
	if (defined $self->{$s})
	{
	    $self->{$s}->disconnect();
	    $self->{$s} = undef;
	}
    }
    $self->{master_store} = undef;
    $self->{master_adminstore} = undef;
    $self->{backend_store} = undef;
    $self->{backend_adminstore} = undef;

    if (defined $self->{instance})
    {
	$self->{instance}->stop();
	$self->{instance}->cleanup();
	$self->{instance} = undef;
    }
    if (defined $self->{replica})
    {
	$self->{replica}->stop();
	$self->{replica}->cleanup();
	$self->{replica} = undef;
    }
    if (defined $self->{frontend})
    {
	$self->{frontend}->stop();
	$self->{frontend}->cleanup();
	$self->{frontend} = undef;
    }
    xlog "---------- END $self->{_name} ----------";
}

sub post_tear_down
{
    my ($self) = @_;

    die "Found some stray processes"
	if (Cassandane::Daemon::kill_processes_on_ports(
		    Cassandane::PortManager::free_all()));
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
    $msg->remove_headers('subject') if !defined $subject;
    $self->_save_message($msg, $store);

    return $msg;
}

sub make_random_data
{
    my ($self, $kb, %params) = @_;
    my $data = '';
    $params{minreps} = 10
	unless defined $params{minreps};
    $params{maxreps} = 100
	unless defined $params{maxreps};
    $params{separators} = ' '
	unless defined $params{separators};
    my $sepidx = 0;
    while (!defined $kb || length($data) < 1024*$kb)
    {
	my $word = random_word();
	my $count = $params{minreps} +
		    rand($params{maxreps} - $params{minreps});
	while ($count > 0)
	{
	    my $sep = substr($params{separators},
			     $sepidx % length($params{separators}), 1);
	    $sepidx++;
	    $data .= $sep . $word;
	    $count--;
	}
	last unless defined $kb;
    }
    return $data;
}

sub check_messages
{
    my ($self, $expected, %params) = @_;
    my $actual = $params{actual};
    my $check_guid = $params{check_guid};
    $check_guid = 1 unless defined $check_guid;
    my $keyed_on = $params{keyed_on} || 'subject';

    xlog "check_messages: " . join(' ', %params);

    if (!defined $actual)
    {
	my $store = $params{store} || $self->{store};
	$actual = {};
	$store->read_begin();
	while (my $msg = $store->read_message())
	{
	    my $key = $msg->$keyed_on();
	    $self->assert(!defined $actual->{$key});
	    $actual->{$key} = $msg;
	}
	$store->read_end();
    }

    $self->assert_num_equals(scalar keys %$expected, scalar keys %$actual);

    foreach my $expmsg (values %$expected)
    {
	my $key = $expmsg->$keyed_on();
	xlog "message \"$key\"";
	my $actmsg = $actual->{$key};

	$self->assert_not_null($actmsg);

	if ($check_guid)
	{
	    xlog "checking guid";
	    $self->assert_str_equals($expmsg->get_guid(),
				     $actmsg->get_guid());
	}

	# Check required headers
	foreach my $h (qw(x-cassandane-unique))
	{
	    xlog "checking header $h";
	    $self->assert_not_null($actmsg->get_header($h));
	    $self->assert_str_equals($expmsg->get_header($h),
				     $actmsg->get_header($h));
	}

	# if there were optional headers we wished to check, do it here

	# check optional string attributes
	foreach my $a (qw(id uid cid))
	{
	    next unless defined $expmsg->get_attribute($a);
	    xlog "checking attribute $a";
	    $self->assert_str_equals($expmsg->get_attribute($a),
				     $actmsg->get_attribute($a));
	}

	# check optional structured attributes
	foreach my $a (qw(flags modseq))
	{
	    next unless defined $expmsg->get_attribute($a);
	    xlog "checking attribute $a";
	    $self->assert_deep_equals($expmsg->get_attribute($a),
				      $actmsg->get_attribute($a));
	}

	# check annotations
	foreach my $ea ($expmsg->list_annotations())
	{
	    xlog "checking annotation ($ea->{entry} $ea->{attrib})";
	    $self->assert($actmsg->has_annotation($ea));
	    my $expval = $expmsg->get_annotation($ea);
	    my $actval = $actmsg->get_annotation($ea);
	    if (defined $expval)
	    {
		$self->assert_not_null($actval);
		$self->assert_str_equals($expval, $actval);
	    }
	    else
	    {
		$self->assert_null($actval);
	    }
	}
    }

    return $actual;
}

sub _disconnect_all
{
    my ($self) = @_;

    foreach my $s (@stores)
    {
	$self->{$s}->disconnect()
	    if defined $self->{$s};
    }
}

sub _reconnect_all
{
    my ($self) = @_;

    foreach my $s (@stores)
    {
	if (defined $self->{$s})
	{
	    $self->{$s}->connect();
	    $self->{$s}->_select();
	}
    }
}

sub run_replication
{
    my ($self, %opts) = @_;

    # Parse options from caller
    my $server = $self->{replica}->get_service('sync')->store_params()->{host};
    $server = delete $opts{server} if exists $opts{server};
    # $server might be undef at this point
    my $channel = delete $opts{channel};
    my $inputfile = delete $opts{inputfile};

    # mode options
    my $nmodes = 0;
    my $user = delete $opts{user};
    my $rolling = delete $opts{rolling};
    my $mailbox = delete $opts{mailbox};
    my $meta = delete $opts{meta};
    $nmodes++ if $user;
    $nmodes++ if $rolling;
    $nmodes++ if $mailbox;
    $nmodes++ if $meta;

    # pass through run_command options
    my $handlers = delete $opts{handlers};
    my $redirects = delete $opts{redirects};

    # historical default for Cassandane tests is user mode
    $user = 'cassandane' if ($nmodes == 0);
    die "Too many mode options" if ($nmodes > 1);

    die "Unrecognised options: " . join(' ', keys %opts) if (scalar %opts);

    xlog "running replication";

    # Disconnect during replication to ensure no imapd
    # is locking the mailbox, which gives us a spurious
    # error which is ignored in real world scenarios.
    $self->_disconnect_all();

    # build sync_client command line
    my @cmd = ('sync_client', '-v', '-v');
    push(@cmd, '-S', $server) if defined $server;
    push(@cmd, '-n', $channel) if defined $channel;
    push(@cmd, '-f', $inputfile) if defined $inputfile;
    push(@cmd, '-u', $user) if defined $user;
    push(@cmd, '-R') if defined $rolling;
    push(@cmd, '-m') if defined $mailbox;
    push(@cmd, '-s') if defined $meta;
    push(@cmd, $mailbox) if defined $mailbox;

    my %run_options;
    $run_options{cyrus} = 1;
    $run_options{handlers} = $handlers if defined $handlers;
    $run_options{redirects} = $redirects if defined $redirects;
    $self->{instance}->run_command(\%run_options, @cmd);

    $self->_reconnect_all();
}

sub run_delayed_expunge
{
    my ($self) = @_;

    xlog "Performing delayed expunge";

    $self->_disconnect_all();

    my @cmd = ( 'cyr_expire', '-E', '1', '-X', '0', '-D', '0' );
    push(@cmd, '-v')
	if get_verbose;
    $self->{instance}->run_command({ cyrus => 1 }, @cmd);

    $self->_reconnect_all();
}


1;
