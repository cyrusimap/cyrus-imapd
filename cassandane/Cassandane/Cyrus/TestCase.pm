#!/usr/bin/perl
#
#  Copyright (c) 2011-2017 FastMail Pty Ltd. All rights reserved.
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
#  3. The name "Fastmail Pty Ltd" must not be used to
#     endorse or promote products derived from this software without
#     prior written permission. For permission or any legal
#     details, please contact
#      FastMail Pty Ltd
#      PO Box 234
#      Collins St West 8007
#      Victoria
#      Australia
#
#  4. Redistributions of any form whatsoever must retain the following
#     acknowledgment:
#     "This product includes software developed by Fastmail Pty. Ltd."
#
#  FASTMAIL PTY LTD DISCLAIMS ALL WARRANTIES WITH REGARD TO THIS SOFTWARE,
#  INCLUDING ALL IMPLIED WARRANTIES OF MERCHANTABILITY  AND FITNESS, IN NO
#  EVENT SHALL OPERA SOFTWARE AUSTRALIA BE LIABLE FOR ANY SPECIAL, INDIRECT
#  OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES WHATSOEVER RESULTING FROM LOSS OF
#  USE, DATA OR PROFITS, WHETHER IN AN ACTION OF CONTRACT, NEGLIGENCE OR OTHER
#  TORTIOUS ACTION, ARISING OUT OF OR IN CONNECTION WITH THE USE OR PERFORMANCE
#  OF THIS SOFTWARE.
#

package Cassandane::Cyrus::TestCase;
use strict;
use warnings;
use attributes;
use Data::Dumper;
use Scalar::Util qw(refaddr);
use List::Util qw(uniq);

use lib '.';
use base qw(Cassandane::Unit::TestCase);
use Cassandane::Util::Log;
use Cassandane::Util::Words;
use Cassandane::Generator;
use Cassandane::MessageStoreFactory;
use Cassandane::Instance;
use Cassandane::PortManager;
use Cyrus::CheckReplication;

my @stores = qw(store adminstore
                replica_store replica_adminstore
                frontend_store frontend_adminstore
                backend2_store backend2_adminstore);
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
        backups => 0,
        start_instances => 1,
        services => [ 'imap' ],
        store => 1,
        adminstore => 0,
        gen => 1,
        deliver => 0,
        jmap => 0,
        install_certificates => 0,
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

# return an id for use by xlog
sub id
{
    my ($self) = @_;
    return $self->{_name}; # XXX something cleverer?
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

sub want_services
{
    my ($self, @services) = @_;

    @{$self->{_want}->{services}} = uniq(@{$self->{_want}->{services}},
                                         @services);
    xlog $self->_who_wants_it() . " wants services " . join(', ', @services);

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
magic(RightNow => sub {
    shift->config_set(sync_rightnow_channel => '""');
});
magic(SyncLog => sub {
    shift->config_set(sync_log => 1);
});
magic(Replication => sub { shift->want('replica'); });
magic(CSyncReplication => sub {
    my ($self) = @_;
    $self->want('csyncreplica');
    $self->config_set('sync_try_imap' => 0);
});
magic(Murder => sub { shift->want('murder'); });
magic(Backups => sub { shift->want('backups'); });
magic(AnnotationAllowUndefined => sub {
    shift->config_set(annotation_allow_undefined => 1);
});
magic(AllowDeleted => sub {
    shift->config_set(allowdeleted => 1);
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
magic(SemidelayedExpunge => sub {
    my $semidelayed = 'semidelayed';
    my ($maj, $min) = Cassandane::Instance->get_version();
    if ($maj < 3 || ($maj == 3 && $min < 1)) {
        # this value used to be called 'default' in 3.0 and earlier
        $semidelayed = 'default';
    }
    shift->config_set(expunge_mode => $semidelayed);
});
magic(DelayedExpunge => sub {
    shift->config_set(expunge_mode => 'delayed');
});
magic(VirtDomains => sub {
    shift->config_set(virtdomains => 'userid');
});
magic(NoVirtDomains => sub {
    shift->config_set(virtdomains => 'off');
});
magic(AltNamespace => sub {
    shift->config_set(altnamespace => 'yes');
});
magic(NoAltNamespace => sub {
    shift->config_set(altnamespace => 'no');
});
magic(NoMailboxLegacyDirs => sub {
    shift->config_set(mailbox_legacy_dirs => 'no');
});
magic(MailboxLegacyDirs => sub {
    shift->config_set(mailbox_legacy_dirs => 'yes');
});
magic(CrossDomains => sub {
    shift->config_set(crossdomains => 'yes');
});
magic(Conversations => sub {
    shift->config_set(conversations => 'yes');
});
magic(ConversationsQuota => sub {
    # this setting is new in 3.3.0 -- any test using this magic
    # also needs :min_version_3_3
    shift->config_set(quota_use_conversations => 'yes');
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
    # If you use this magic, you must call
    # $self->_start_instances() and optionally $self->_jmap_setup()
    # yourself from your test function once you're ready for Cyrus
    # to be started!
    # If any test function in your suite uses this magic, then
    # your suite's set_up function cannot assume Cyrus is running!
    shift->want('start_instances' => 0);
});
magic(MagicPlus => sub {
    shift->config_set('imapmagicplus' => 'yes');
});
magic(FastMailSharing => sub {
    shift->config_set('fastmailsharing' => 'true');
});
magic(Partition2 => sub {
    shift->config_set('partition-p2' => '@basedir@/data-p2');
});
magic(FastMailEvent => sub {
    shift->config_set(
        event_content_inclusion_mode => 'standard',
        event_content_size => 1,  # just the first byte
        event_exclude_specialuse => '\\Junk',
        event_extra_params => 'modseq vnd.fastmail.clientId service uidnext vnd.fastmail.sessionId vnd.cmu.envelope vnd.fastmail.convUnseen vnd.fastmail.convExists vnd.fastmail.cid vnd.cmu.mbtype vnd.cmu.davFilename vnd.cmu.davUid vnd.cmu.mailboxACL vnd.fastmail.counters messages vnd.cmu.unseenMessages flagNames',
        event_groups => 'mailbox message flags calendar applepushservice',
    );
});
magic(NoMunge8Bit => sub {
    shift->config_set(munge8bit => 'no');
});
magic(RFC2047_UTF8 => sub {
    shift->config_set(rfc2047_utf8 => 'yes');
});
magic(JMAPSearchDBLegacy => sub {
    # XXX Needed for JMAPEmail.email_query_..._legacy (3.1-3.4).
    # XXX Don't use in newer tests, and remove this someday when 3.4 is
    # XXX obsolete.
    shift->config_set('jmap_emailsearch_db_path' =>
                      '@basedir@/search/jmap_emailsearch.db');
});
magic(JMAPQueryCacheMaxAge1s => sub {
    shift->config_set('jmap_querycache_max_age' => '1s');
});
magic(JMAPNoHasAttachment => sub {
    shift->config_set('jmap_set_has_attachment' => 'no');
});
magic(JMAPExtensions => sub {
    shift->config_set('jmap_nonstandard_extensions' => 'yes');
});
magic(SearchAttachmentExtractor => sub {
    my $port = Cassandane::PortManager::alloc();
    shift->config_set('search_attachment_extractor_url' =>
        "http://localhost:$port/extractor");
});
magic(SearchLanguage => sub {
    my $self = shift;
    $self->config_set('search_index_language' => 'yes');
});
magic(SieveUTF8Fileinto => sub {
    shift->config_set('sieve_utf8fileinto' => 'yes');
});
magic(SearchSetForceScanMode => sub {
    shift->config_set(search_queryscan => '1');
});
magic(SearchFuzzyAlways => sub {
    shift->config_set(search_fuzzy_always => '1');
});
magic(SearchEngineSquat => sub {
    shift->config_set(search_engine => 'squat');
});
magic(SearchNormalizationMax20000 => sub {
    shift->config_set(search_normalisation_max => 20000);
});
magic(SearchMaxtime1Sec => sub {
    shift->config_set(search_maxtime => 1);
});
magic(SearchMaxSize4k => sub {
    shift->config_set(search_maxsize => 4);
});
magic(TLS => sub {
    # XXX Here be dragons.  Check existing tests that use this magic
    # XXX for some of the hoops you may still need to jump through!
    my $self = shift;
    $self->config_set(tls_server_cert => '@basedir@/conf/certs/cert.pem');
    $self->config_set(tls_server_key => '@basedir@/conf/certs/key.pem');
    $self->want('install_certificates');
    $self->want_services('imaps');
});
magic(LowEmailLimits => sub {
    # these settings are new in 3.3.0 -- any test using this magic
    # also needs :min_version_3_3
    shift->config_set(
        conversations_max_guidrecords => 10,
        conversations_max_guidexists => 5,
        conversations_max_guidinfolder => 2,
    );
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
            # ignore feature test attribution here
            next if $a =~ m/^needs_/;
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
    my $frontend_imapd_port;
    my $backend1_imapd_port;
    my $backend2_imapd_port;
    my $backupd_port;

    $self->{_config} = $self->{_instance_params}->{config} || Cassandane::Config->default();
    $self->{_config} = $self->{_config}->clone();

    $self->_run_magic();

    my $want = $self->{_want};
    my %instance_params = %{$self->{_instance_params}};

    my $cassini = Cassandane::Cassini->instance();

    if ($want->{instance})
    {
        my $conf = $self->{_config}->clone();

        if ($want->{replica} || $want->{csyncreplica})
        {
            $sync_port = Cassandane::PortManager::alloc();
            $conf->set(
                # sync_client will find the port in the config
                sync_host => 'localhost',
                sync_port => $sync_port,
                # tell sync_client how to login
                sync_authname => 'repluser',
                sync_password => 'replpass',
            );
        }

        if ($want->{murder})
        {
            $mupdate_port = Cassandane::PortManager::alloc();
            $backend1_imapd_port = Cassandane::PortManager::alloc();

            $conf->set(
                servername => "localhost:$backend1_imapd_port",
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
                proxy_authname => 'mailproxy',
                proxy_password => 'mailproxy',
            );
        }

        if ($want->{backups})
        {
            $backupd_port = Cassandane::PortManager::alloc();
            $conf->set(
                backup_sync_host => "localhost",
                backup_sync_port => $backupd_port,
                backup_sync_authname => 'repluser',
                backup_sync_password => 'repluser',
                backup_sync_try_imap => 'no',
                xbackup_enabled => 'yes',
            );
        }

        my $sub = $self->{_name};
        if ($sub =~ s/^test_/config_/ && $self->can($sub))
        {
            die 'Use of config_<testname> subs is not supported anymore';
        }

        $instance_params{config} = $conf;
        $instance_params{install_certificates} = $want->{install_certificates};

        $instance_params{description} = "main instance for test $self->{_name}";
        $self->{instance} = Cassandane::Instance->new(%instance_params);
        $self->{instance}->add_services(@{$want->{services}});
        $self->{instance}->_setup_for_deliver()
            if ($want->{deliver});

        if ($want->{replica} || $want->{csyncreplica})
        {
            my %replica_params = %instance_params;
            $replica_params{config} = $conf->clone();
            $replica_params{config}->set(sync_rightnow_channel => undef);
            my $cyrus_replica_prefix = $cassini->val('cyrus replica', 'prefix');
            if (defined $cyrus_replica_prefix and -d $cyrus_replica_prefix) {
                xlog $self, "replica instance: using [cyrus replica] configuration";
                $replica_params{installation} = 'replica';
            }

            $replica_params{description} = "replica instance for test $self->{_name}";
            $self->{replica} = Cassandane::Instance->new(%replica_params,
                                                         setup_mailbox => 0);
            my ($v) = Cassandane::Instance->get_version($replica_params{installation});
            if ($v < 3 || $want->{csyncreplica}) {
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
            $frontend_imapd_port = Cassandane::PortManager::alloc();
            $backend2_imapd_port = Cassandane::PortManager::alloc();

            # set up a front end on which we also run the mupdate master
            my $frontend_conf = $self->{_config}->clone();
            $frontend_conf->set(
                servername => "localhost:$frontend_imapd_port",
                mupdate_server => "localhost:$mupdate_port",
                # XXX documentation says to use mupdate_port, but
                # XXX this doesn't work -- need to embed port number in
                # XXX mupdate_server setting instead.
                #mupdate_port => $mupdate_port,
                mupdate_username => 'mupduser',
                mupdate_authname => 'mupduser',
                mupdate_password => 'mupdpass',
                serverlist =>
                    "localhost:$backend1_imapd_port localhost:$backend2_imapd_port",
                proxy_authname => 'mailproxy',
                proxy_password => 'mailproxy',
            );

            my $cyrus_murder_prefix = $cassini->val('cyrus murder', 'prefix');
            if (defined $cyrus_murder_prefix and -d $cyrus_murder_prefix) {
                xlog $self, "murder instance: using [cyrus murder] configuration";
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
            $self->{frontend}->_setup_for_deliver()
                if ($want->{deliver});

            # arrange for frontend imapd to run on a known port
            $self->{frontend}->remove_service('imap');
            $self->{frontend}->add_service(name => 'imap',
                                           port => $frontend_imapd_port);

            # arrange for backend1 to push to mupdate on startup
            $self->{instance}->add_start(name => 'mupdatepush',
                                         argv => ['ctl_mboxlist', '-m']);

            # arrange for backend1 imapd to run on a known port
            $self->{instance}->remove_service('imap');
            $self->{instance}->add_service(name => 'imap',
                                           port => $backend1_imapd_port);


            # set up a second backend
            my $backend2_conf = $self->{_config}->clone();
            $backend2_conf->set(
                servername => "localhost:$backend2_imapd_port",
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
                proxy_authname => 'mailproxy',
                proxy_password => 'mailproxy',
            );

            $instance_params{description} = "murder backend2 for test $self->{_name}";
            $instance_params{config} = $backend2_conf;
            $self->{backend2} = Cassandane::Instance->new(%instance_params,
                                                          setup_mailbox => 0); # XXX ?
            $self->{backend2}->add_services(@{$want->{services}});

            # arrange for backend2 to push to mupdate on startup
            $self->{backend2}->add_start(name => 'mupdatepush',
                                         argv => ['ctl_mboxlist', '-m']);

            # arrange for backend2 imap to run on a known port
            $self->{backend2}->remove_service('imap');
            $self->{backend2}->add_service(name => 'imap',
                                           port => $backend2_imapd_port);

            $self->{backend2}->_setup_for_deliver()
                if ($want->{deliver});
        }

        if ($want->{backups})
        {
            # set up a backup server
            my $backup_conf = $self->{_config}->clone();
            $backup_conf->set(
                temp_path => '@basedir@/tmp',
                backup_keep_previous => 'yes',
                'backuppartition-default' => '@basedir@/data/backup',
            );

            my $cyrus_backup_prefix = $cassini->val('cyrus backup', 'prefix');
            if (defined $cyrus_backup_prefix and -d $cyrus_backup_prefix) {
                xlog $self, "backup instance: using [cyrus backup] configuration";
                $instance_params{installation} = 'backup';
            }

            $instance_params{description} = "backup server for test $self->{_name}";
            $instance_params{config} = $backup_conf;

            $self->{backups} = Cassandane::Instance->new(%instance_params,
                                                         setup_mailbox => 0);
            $self->{backups}->add_service(name => 'backup',
                                          port => $backupd_port,
                                          argv => ['backupd']);
        }
    }

    if ($want->{gen})
    {
        $self->{gen} = Cassandane::Generator->new();
    }
}

sub _jmap_setup
{
    my ($self) = @_;

    require Mail::JMAPTalk;
    require Net::CalDAVTalk;
    require Net::CardDAVTalk;

    my $service = $self->{instance}->get_service("http");
    $ENV{DEBUGJMAP} = 1;
    eval {
        $self->{carddav} = Net::CardDAVTalk->new(
            user => 'cassandane',
            password => 'pass',
            host => $service->host(),
            port => $service->port(),
            scheme => 'http',
            url => '/',
            expandurl => 1,
        );
        $self->{caldav} = Net::CalDAVTalk->new(
            user => 'cassandane',
            password => 'pass',
            host => $service->host(),
            port => $service->port(),
            scheme => 'http',
            url => '/',
            expandurl => 1,
        );
        $self->{caldav}->UpdateAddressSet("Test User", "cassandane\@example.com");
        $self->{jmap} = Mail::JMAPTalk->new(
            user => 'cassandane',
            password => 'pass',
            host => $service->host(),
            port => $service->port(),
            scheme => 'http',
            url => '/jmap/',
        );
    };
    if ($@) {
        my $e = $@;
        $self->tear_down();
        die $e;
    }

    xlog $self, "JMAP setup complete!";
}

sub set_up
{
    my ($self) = @_;

    xlog "---------- BEGIN $self->{_name} ----------";

    $self->_create_instances();
    if ($self->{_want}->{start_instances}) {
        $self->_start_instances();
        $self->_jmap_setup()
            if $self->{_want}->{jmap};
    }
    else {
        xlog $self, "Instances not started due to :NoStartInstances magic!";
        xlog $self, "JMAP not setup due to :NoStartInstances magic!"
            if $self->{_want}->{jmap};
    }
    xlog $self, "Calling test function";
}

sub _start_instances
{
    my ($self) = @_;

    $self->{frontend}->start()
        if (defined $self->{frontend});
    $self->{instance}->start()
        if (defined $self->{instance});
    $self->{backend2}->start()
        if (defined $self->{backend2});
    $self->{replica}->start()
        if (defined $self->{replica});
    $self->{backups}->start()
        if (defined $self->{backups});

    $self->{store} = undef;
    $self->{adminstore} = undef;
    $self->{master_store} = undef;
    $self->{master_adminstore} = undef;
    $self->{replica_store} = undef;
    $self->{replica_adminstore} = undef;
    $self->{frontend_store} = undef;
    $self->{frontend_adminstore} = undef;
    $self->{backend1_store} = undef;
    $self->{backend1_adminstore} = undef;
    $self->{backend2_store} = undef;
    $self->{backend2_adminstore} = undef;

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
        # aliases for first backend store
        $self->{backend1_store} = $self->{store};
        $self->{backend1_adminstore} = $self->{adminstore};

        my $svc = $self->{frontend}->get_service('imap');
        if (defined $svc)
        {
            $self->{frontend_store} = $svc->create_store(%store_params)
                if ($self->{_want}->{store});
            $self->{frontend_adminstore} = $svc->create_store(%adminstore_params)
                if ($self->{_want}->{adminstore});
        }
    }
    if (defined $self->{backend2})
    {
        my $svc = $self->{backend2}->get_service('imap');
        if (defined $svc)
        {
            $self->{backend2_store} = $svc->create_store(%store_params)
                if ($self->{_want}->{store});
            $self->{backend2_adminstore} = $svc->create_store(%adminstore_params)
                if ($self->{_want}->{adminstore});
        }
    }
}

sub tear_down
{
    my ($self) = @_;

    xlog $self, "Beginning tear_down";

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
    $self->{backend1_store} = undef;
    $self->{backend1_adminstore} = undef;

    if (defined $self->{instance})
    {
        $self->{instance}->stop();
        $self->{instance}->cleanup();
        $self->{instance} = undef;
    }
    if (defined $self->{backups})
    {
        $self->{backups}->stop();
        $self->{backups}->cleanup();
        $self->{backups} = undef;
    }
    if (defined $self->{backend2})
    {
        $self->{backend2}->stop();
        $self->{backend2}->cleanup();
        $self->{backend2} = undef;
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
        if (Cassandane::GenericDaemon::kill_processes_on_ports(
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

    my $store = $attrs{store};  # may be undef
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

    xlog $self, "check_messages: " . join(' ', %params);

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
        xlog $self, "message \"$key\"";
        my $actmsg = $actual->{$key};

        $self->assert_not_null($actmsg);

        if ($check_guid)
        {
            xlog $self, "checking guid";
            $self->assert_str_equals($expmsg->get_guid(),
                                     $actmsg->get_guid());
        }

        # Check required headers
        foreach my $h (qw(x-cassandane-unique))
        {
            xlog $self, "checking header $h";
            $self->assert_not_null($actmsg->get_header($h));
            $self->assert_str_equals($expmsg->get_header($h),
                                     $actmsg->get_header($h));
        }

        # if there were optional headers we wished to check, do it here

        # check optional string attributes
        foreach my $a (qw(id uid cid))
        {
            next unless defined $expmsg->get_attribute($a);
            xlog $self, "checking attribute $a";
            $self->assert_str_equals($expmsg->get_attribute($a),
                                     $actmsg->get_attribute($a));
        }

        # check optional structured attributes
        foreach my $a (qw(modseq))
        {
            next unless defined $expmsg->get_attribute($a);
            xlog $self, "checking attribute $a";
            $self->assert_deep_equals($expmsg->get_attribute($a),
                                      $actmsg->get_attribute($a));
        }

        # check optional order-agnostic attributes
        foreach my $a (qw(flags))
        {
            next unless defined $expmsg->get_attribute($a);
            xlog $self, "checking attribute $a";

            my $exp = $expmsg->get_attribute($a);
            my $act = $actmsg->get_attribute($a);

            if (ref $exp eq 'ARRAY') {
                $exp = [ sort @{$exp} ];
            }
            if (ref $act eq 'ARRAY') {
                $act = [ sort @{$act} ];
            }

            $self->assert_deep_equals($exp, $act);
        }

        # check annotations
        foreach my $ea ($expmsg->list_annotations())
        {
            xlog $self, "checking annotation ($ea->{entry} $ea->{attrib})";
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
    my $nosyncback = delete $opts{nosyncback};
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

    xlog $self, "running replication";

    # Disconnect during replication to ensure no imapd
    # is locking the mailbox, which gives us a spurious
    # error which is ignored in real world scenarios.
    $self->_disconnect_all();

    # build sync_client command line
    my @cmd = ('sync_client', '-v', '-v', '-o');
    push(@cmd, '-S', $server) if defined $server;
    push(@cmd, '-n', $channel) if defined $channel;
    push(@cmd, '-f', $inputfile) if defined $inputfile;
    push(@cmd, '-R') if defined $rolling;
    push(@cmd, '-s') if defined $meta;
    push(@cmd, '-O') if defined $nosyncback;
    push(@cmd, '-u', $user) if defined $user;
    push(@cmd, '-m', $mailbox) if defined $mailbox;

    my %run_options;
    $run_options{cyrus} = 1;
    $run_options{handlers} = $handlers if defined $handlers;
    $run_options{redirects} = $redirects if defined $redirects;
    $self->{instance}->run_command(\%run_options, @cmd);

    $self->_reconnect_all();
}

sub check_replication {
    my ($self, $user) = @_;

    # get store connections as the user

    my $mastersvc = $self->{instance}->get_service('imap');
    my $masterstore = $mastersvc->create_store(username => $user);

    my $replicasvc = $self->{replica}->get_service('imap');
    my $replicastore = $replicasvc->create_store(username => $user);

    my $CR = Cyrus::CheckReplication->new(
        IMAPs1 => $masterstore->get_client(),
        IMAPs2 => $replicastore->get_client(),
        CyrusName => $user,
        SleepTime => 0,
        Repeats => 1,
        CheckConversations => 1,
        CheckAnnotations => 1,
        CheckMetadata => 1,
    );
    $CR->CheckUserReplication(2);
    if ($CR->HasError()) {
        my @Messages = $CR->GetMessages();
        $self->assert(0, "GOT ERRORS " . join(', ', @Messages));
    }
}

sub run_delayed_expunge
{
    my ($self) = @_;

    xlog $self, "Performing delayed expunge";

    $self->_disconnect_all();

    my @cmd = ( 'cyr_expire', '-E', '1', '-X', '0', '-D', '0' );
    push(@cmd, '-v')
        if get_verbose;
    $self->{instance}->run_command({ cyrus => 1 }, @cmd);

    $self->_reconnect_all();
}

sub check_conversations
{
    my ($self) = @_;
    my $filename = $self->{instance}{basedir} . "/ctl_conversationsdb.out";
    $self->{instance}->run_command({
        cyrus => 1,
        redirects => {stdout => $filename},
    }, 'ctl_conversationsdb', '-A', '-r', '-v');

    local $/;
    open FH, '<', $filename
        or die "Cannot open $filename for reading: $!";
    my $str = <FH>;
    close(FH);

    xlog $self, "RESULT: $str";
    $self->assert_matches(qr/is OK/, $str);
    $self->assert_does_not_match(qr/is BROKEN/, $str);
}

1;
