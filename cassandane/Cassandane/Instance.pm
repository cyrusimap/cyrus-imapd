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

package Cassandane::Instance;
use strict;
use warnings;
use Config;
use Data::Dumper;
use Errno qw(ENOENT);
use File::Copy;
use File::Path qw(mkpath rmtree remove_tree);
use File::Find qw(find);
use File::Basename;
use File::stat;
use JSON;
use POSIX qw(geteuid :signal_h :sys_wait_h :errno_h);
use DateTime;
use BSD::Resource;
use Cwd qw(abs_path getcwd);
use AnyEvent;
use AnyEvent::Handle;
use AnyEvent::Socket;
use AnyEvent::Util;
use JSON;
use HTTP::Daemon;
use DBI;
use Time::HiRes qw(usleep);
use List::Util qw(uniqstr);

use lib '.';
use Cassandane::Util::DateTime qw(to_iso8601);
use Cassandane::Util::Log;
use Cassandane::Util::Slurp;
use Cassandane::Util::Wait;
use Cassandane::Mboxname;
use Cassandane::Config;
use Cassandane::Service;
use Cassandane::ServiceFactory;
use Cassandane::GenericListener;
use Cassandane::MasterStart;
use Cassandane::MasterEvent;
use Cassandane::MasterDaemon;
use Cassandane::Cassini;
use Cassandane::PortManager;
use Cassandane::BuildInfo;

use lib '../perl/imap';
require Cyrus::DList;

my $__cached_rootdir;
my $stamp;
my $next_unique = 1;

sub new
{
    my $class = shift;
    my %params = @_;

    my $cassini = Cassandane::Cassini->instance();

    my $self = {
        name => undef,
        buildinfo => undef,
        basedir => undef,
        installation => 'default',
        cyrus_prefix => undef,
        cyrus_destdir => undef,
        config => Cassandane::Config->default()->clone(),
        starts => [],
        services => {},
        events => [],
        daemons => {},
        generic_listeners => {},
        re_use_dir => 0,
        setup_mailbox => 1,
        persistent => 0,
        authdaemon => 1,
        _children => {},
        _stopped => 0,
        description => 'unknown',
        _shutdowncallbacks => [],
        _started => 0,
        _pwcheck => $cassini->val('cassandane', 'pwcheck', 'alwaystrue'),
        install_certificates => 0,
        _pid => $$,
        smtpdaemon => 0,
        lsan_suppressions => "",
    };

    $self->{name} = $params{name}
        if defined $params{name};
    $self->{basedir} = $params{basedir}
        if defined $params{basedir};
    $self->{installation} = $params{installation}
        if defined $params{installation};
    $self->{cyrus_prefix} = $cassini->val("cyrus $self->{installation}",
                                          'prefix', '/usr/cyrus');
    $self->{cyrus_prefix} = $params{cyrus_prefix}
        if defined $params{cyrus_prefix};
    $self->{cyrus_destdir} = $cassini->val("cyrus $self->{installation}",
                                          'destdir', '');
    $self->{cyrus_destdir} = $params{cyrus_destdir}
        if defined $params{cyrus_destdir};
    $self->{config} = $params{config}->clone()
        if defined $params{config};
    $self->{re_use_dir} = $params{re_use_dir}
        if defined $params{re_use_dir};
    $self->{setup_mailbox} = $params{setup_mailbox}
        if defined $params{setup_mailbox};
    $self->{persistent} = $params{persistent}
        if defined $params{persistent};
    $self->{authdaemon} = $params{authdaemon}
        if defined $params{authdaemon};
    $self->{description} = $params{description}
        if defined $params{description};
    $self->{pwcheck} = $params{pwcheck}
        if defined $params{pwcheck};
    $self->{install_certificates} = $params{install_certificates}
        if defined $params{install_certificates};
    $self->{smtpdaemon} = $params{smtpdaemon}
        if defined $params{smtpdaemon};
    $self->{lsan_suppressions} = $params{lsan_suppressions}
        if defined $params{lsan_suppressions};
    $self->{mailbox_version} = $params{mailbox_version}
        if defined $params{mailbox_version};
    $self->{old_jmap_ids} = $params{old_jmap_ids}
        if defined $params{old_jmap_ids};

    # XXX - get testcase name from caller, to apply even finer
    # configuration from cassini ?
    return bless $self, $class;
}

# return an id for use by xlog
sub id
{
    my ($self) = @_;
    return $self->{name}; # XXX something cleverer?
}

# Class method! Need to be able to interrogate the Cyrus version
# being tested without actually instantiating a Cassandane::Instance.
# This also means we have to do a few things here the direct way,
# rather than using helper methods...
my %cached_version = ();
my %cached_sversion = ();
sub get_version
{
    my ($class, $installation) = @_;
    $installation = 'default' if not defined $installation;

    if (exists $cached_version{$installation}) {
        return @{$cached_version{$installation}} if wantarray;
        return $cached_sversion{$installation};
    }

    my $cassini = Cassandane::Cassini->instance();

    # Need to check the named-installation directory AND the
    # default installation directory, before falling back to the
    # default-default
    # Usually Cassandane::Cyrus::TestCase only initialises an Instance
    # object with a non-default installation if that installation actually
    # exists, but this is a class method, not an object method, so we
    # don't have that protection and have to DIY.
    my ($cyrus_prefix, $cyrus_destdir, $cyrus_master);

    INSTALLATION: foreach my $i (uniqstr($installation, 'default')) {
        $cyrus_prefix = $cassini->val("cyrus $i", 'prefix',
                                      $i eq 'default' ? '/usr/cyrus' : undef);

        # no prefix? non-default installation isn't configured, skip it
        next INSTALLATION if not defined $cyrus_prefix;

        $cyrus_destdir = $cassini->val("cyrus $i", 'destdir', q{});

        foreach my $d (qw( bin sbin libexec libexec/cyrus-imapd lib cyrus/bin ))
        {
            my $try = "$cyrus_destdir$cyrus_prefix/$d/master";
            if (-x $try) {
                $cyrus_master = $try;
                last INSTALLATION;
            }
        }
    }

    die "unable to locate master binary" if not defined $cyrus_master;

    my $version;
    {
        open my $fh, '-|', "$cyrus_master -V"
            or die "unable to execute '$cyrus_master -V': $!";
        local $/;
        $version = <$fh>;
        close $fh;
    }

    if (not $version) {
        # Cyrus version might be too old for 'master -V'
        # Try to squirrel a version out of libcyrus pkgconfig file
        open my $fh, '<', "$cyrus_destdir$cyrus_prefix/lib/pkgconfig/libcyrus.pc";
        while (<$fh>) {
            $version = $_ if m/^Version:/;
        }
        close $fh;
    }

    #cyrus-imapd 3.0.0-beta3-114-g5fa1dbc-dirty
    if ($version =~ m/^cyrus-imapd (\d+)\.(\d+).(\d+)(?:-(.*))?$/) {
        my ($maj, $min, $rev, $extra) = ($1, $2, $3, $4);
        my $pluscommits = 0;
        if (defined $extra && $extra =~ m/(\d+)-g[a-fA-F0-9]+(?:-dirty)?$/) {
            $pluscommits = $1;
        }
        $cached_version{$installation} = [ 0 + $maj,
                                           0 + $min,
                                           0 + $rev,
                                           0 + $pluscommits,
                                           $extra ];
    }
    elsif ($version =~ m/^Version: (\d+)\.(\d+).(\d+)(?:-(.*))?$/) {
        my ($maj, $min, $rev, $extra) = ($1, $2, $3, $4);
        my $pluscommits;
        if ($extra =~ m/(\d+)-g[a-fA-F0-9]+(?:-dirty)?$/) {
            $pluscommits = $1;
        }
        $cached_version{$installation} = [ 0 + $maj,
                                           0 + $min,
                                           0 + $rev,
                                           0 + $pluscommits,
                                           $extra ];
    }
    else {
        $cached_version{$installation} = [0, 0, 0, 0, q{}];
    }

    $cached_sversion{$installation} = join q{.},
                                           @{$cached_version{$installation}}[0..2];
    $cached_sversion{$installation} .= "-$cached_version{$installation}->[4]"
        if $cached_version{$installation}->[4];

    return @{$cached_version{$installation}} if wantarray;
    return $cached_sversion{$installation};
}

sub _rootdir
{
    if (!defined $__cached_rootdir)
    {
        my $cassini = Cassandane::Cassini->instance();
        $__cached_rootdir =
            $cassini->val('cassandane', 'rootdir', '/var/tmp/cass');
    }
    return $__cached_rootdir;
}

sub _make_instance_info
{
    my ($name, $basedir) = @_;

    die "Need either a name or a basename"
        if !defined $name && !defined $basedir;
    $name ||= basename($basedir);
    $basedir ||= _rootdir() . '/' . $name;

    my $sb = stat($basedir);
    die "Cannot stat $basedir: $!" if !defined $sb && $! != ENOENT;

    return {
        name => $name,
        basedir => $basedir,
        ctime => ($sb ? $sb->ctime : undef),
    };
}

sub _make_unique_instance_info
{
    # This must be kept in sync with cleanup_leftovers, which expects
    # to be able to recognise instance directories by name for cleanup.
    if (!defined $stamp)
    {
        $stamp = to_iso8601(DateTime->now);
        $stamp =~ s/.*T(\d+)Z/$1/;

        my $workerid = $ENV{TEST_UNIT_WORKER_ID};
        die "Invalid TEST_UNIT_WORKER_ID - code not run in Worker context"
            if (defined($workerid) && $workerid eq 'invalid');
        $stamp .= sprintf("%02X", $workerid) if defined $workerid;
    }

    my $rootdir = _rootdir();

    my $name;
    my $basedir;
    for (;;)
    {
        $name = sprintf("%s%02X", $stamp, $next_unique);
        $next_unique++;
        $basedir = "$rootdir/$name";
        last if mkdir($basedir);
        die "Cannot create $basedir: $!" if ($! != EEXIST);
    }
    return _make_instance_info($name, $basedir);
}

sub list
{
    my $rootdir = _rootdir();
    opendir ROOT, $rootdir
        or die "Cannot open $rootdir for reading: $!";
    my @instances;
    while ($_ = readdir(ROOT))
    {
        next unless m/^[0-9]+[A-Z]?$/;
        push(@instances, _make_instance_info($_));
    }
    closedir ROOT;
    return @instances;
}

sub exists
{
    my ($name) = @_;
    return if ( ! -d _rootdir() . '/' . $name );
    return _make_instance_info($name);
}

sub _init_basedir_and_name
{
    my ($self) = @_;

    my $info;
    my $which = (defined $self->{name} ? 1 : 0) |
                (defined $self->{basedir} ? 2 : 0);
    if ($which == 0)
    {
        # have neither name nor basedir
        # usual first time case for test instances
        $info = _make_unique_instance_info();
    }
    else
    {
        # have name but not basedir
        # usual first time case for start-instance.pl
        # or basedir but not name, which doesn't happen
        $info = _make_instance_info($self->{name}, $self->{basedir});
    }
    $self->{name} = $info->{name};
    $self->{basedir} = $info->{basedir};
}

sub get_basedir
{
    my ($self) = @_;

    return $self->{basedir} if $self->{basedir};

    $self->_init_basedir_and_name();

    return $self->{basedir};
}

# Remove on-disk traces of any previous instances
sub cleanup_leftovers
{
    my $rootdir = _rootdir();

    return if (!-d $rootdir);
    opendir ROOT, $rootdir
        or die "Cannot open directory $rootdir for reading: $!";
    my @dirs;
    while (my $e = readdir(ROOT))
    {
        # This must be kept in sync with _make_unique_instance_info,
        # which is what names and creates these directories.
        my $basedirpat = qr{
            \d{6}               # UTC timestamp as HHMMSS
            (?:[0-9A-F]{2,})?   # optional worker ID as 2+ hex digits
            [0-9A-F]{2,}        # unique number as 2+ hex digits
        }ax;

        push(@dirs, $e) if $e =~ m/$basedirpat/;
    }
    closedir ROOT;

    map
    {
        if (get_verbose) {
            xlog "Cleaning up old basedir $rootdir/$_";
        }
        rmtree "$rootdir/$_";
    } @dirs;
}

sub add_service
{
    my ($self, %params) = @_;

    my $name = $params{name};
    die "Missing parameter 'name'"
        unless defined $name;
    die "Already have a service named \"$name\""
        if defined $self->{services}->{$name};

    # Add a hardcoded recover START if we're doing an actual IMAP test.
    if ($name =~ m/imap/)
    {
        $self->add_recover();
    }

    my $srv = Cassandane::ServiceFactory->create(instance => $self, %params);
    $self->{services}->{$name} = $srv;
    return $srv;
}

sub add_services
{
    my ($self, @names) = @_;
    map { $self->add_service(name => $_); } @names;
}

sub get_service
{
    my ($self, $name) = @_;
    return $self->{services}->{$name};
}

sub remove_service
{
    my ($self, $name) = @_;
    delete $self->{services}->{$name};
}

sub add_start
{
    my ($self, %params) = @_;
    push(@{$self->{starts}}, Cassandane::MasterStart->new(%params));
}

sub remove_start
{
    my ($self, $name) = @_;
    $self->{starts} = [ grep { $_->{name} ne $name } @{$self->{starts}} ];
}

sub add_recover
{
    my ($self) = @_;

    if (!grep { $_->{name} eq 'recover'; } @{$self->{starts}})
    {
        $self->add_start(name => 'recover',
                         argv => [ qw(ctl_cyrusdb -r) ]);
    }
}

sub add_event
{
    my ($self, %params) = @_;
    push(@{$self->{events}}, Cassandane::MasterEvent->new(%params));
}

sub add_daemon
{
    my ($self, %params) = @_;

    my $name = $params{name};
    die "Missing parameter 'name'"
        unless defined $name;
    die "Already have a daemon named \"$name\""
        if defined $self->{daemons}->{$name};

    $self->{daemons}->{$name} = Cassandane::MasterDaemon->new(%params);
}

sub add_generic_listener
{
    my ($self, %params) = @_;

    my $name = delete $params{name};
    die "Missing parameter 'name'"
        unless defined $name;
    die "Already have a generic listener named \"$name\""
        if defined $self->{generic_listeners}->{$name};

    $params{config} //= $self->{config};

    my $listener = Cassandane::GenericListener->new(
        name => $name,
        %params
    );

    $self->{generic_listeners}->{$name} = $listener;
    return $listener;
}

sub set_config
{
    my ($self, $conf) = @_;

    $self->{config} = $conf;
}

sub _find_binary
{
    my ($self, $name) = @_;

    my $cassini = Cassandane::Cassini->instance();
    my $name_override = $cassini->val("cyrus $self->{installation}", $name);
    $name = $name_override if defined $name_override;

    return $name if $name =~ m/^\//;

    my $base = $self->{cyrus_destdir} . $self->{cyrus_prefix};

    if ($name =~ m/xapian-.*$/) {
        my $lib = `ldd $base/libexec/imapd` || die "can't ldd imapd";
        $lib =~ m{(/\S+)/lib/libxapian-([0-9.]+)\.so};
        return "$1/bin/$name-$2";
    }

    foreach (qw( bin sbin libexec libexec/cyrus-imapd lib cyrus/bin ))
    {
        my $dir = "$base/$_";
        if (opendir my $dh, $dir)
        {
            if (grep { $_ eq $name } readdir $dh) {
                xlog "Found binary $name in $dir";
                closedir $dh;
                return "$dir/$name";
            }
            closedir $dh;
        }
        else
        {
            xlog "Couldn't opendir $dir: $!" if $! != ENOENT;
            next;
        }
    }

    die "Couldn't locate $name under $base";
}

sub _valgrind_setup
{
    my ($self, $name) = @_;

    my @cmd;

    my $cassini = Cassandane::Cassini->instance();

    my $arguments = '-q --tool=memcheck --leak-check=full --run-libc-freeres=no';
    my $valgrind_logdir = $self->{basedir} . '/vglogs';
    my $valgrind_suppressions =
        abs_path($cassini->val('valgrind', 'suppression', 'vg.supp'));
    mkpath $valgrind_logdir
        unless ( -d $valgrind_logdir );
    push(@cmd,
        $cassini->val('valgrind', 'binary', '/usr/bin/valgrind'),
        "--log-file=$valgrind_logdir/$name.%p",
        "--suppressions=$valgrind_suppressions",
        "--gen-suppressions=all",
        split(/\s+/, $cassini->val('valgrind', 'arguments', $arguments))
    );

    return @cmd;
}

sub _binary
{
    my ($self, $name) = @_;

    my @cmd;
    my $valground = 0;

    my $cassini = Cassandane::Cassini->instance();

    if ($cassini->bool_val('valgrind', 'enabled') &&
        !($name =~ m/xapian.*$/) &&
        !($name =~ m/\.pl$/) &&
        !($name =~ m/^\//))
    {
        push @cmd, $self->_valgrind_setup($name);
        $valground = 1;
    }

    my $bin = $self->_find_binary($name);
    push(@cmd, $bin);

    if (!$valground && $cassini->bool_val('gdb', $name))
    {
        xlog "Will run binary $name under gdb due to cassandane.ini";
        xlog "Look in syslog for helpful instructions from gdbtramp";
        push(@cmd, '-D');
    }

    return @cmd;
}

sub _imapd_conf
{
    my ($self, $prefix) = @_;

    my $fname = $prefix ? "$prefix-imapd.conf" : 'imapd.conf';

    return $self->{basedir} . "/conf/$fname";
}

sub _master_conf
{
    my ($self) = @_;

    return $self->{basedir} . '/conf/cyrus.conf';
}

sub _pid_file
{
    my ($self, $name) = @_;

    $name ||= 'master';

    if ($name eq 'master') {
        my $pidfile = $self->{config}->get('master_pid_file');
        return $self->{config}->substitute($pidfile) if $pidfile;
    }

    return $self->{basedir} . "/run/$name.pid";
}

sub _list_pid_files
{
    my ($self) = @_;

    my $rundir = $self->{basedir} . "/run";
    if (!opendir(RUNDIR, $rundir)) {
        return if $!{ENOENT}; # no run dir? never started
        die "Cannot open run directory $rundir: $!";
    }

    my @pidfiles;
    while ($_ = readdir(RUNDIR))
    {
        my ($name) = m/^([^.].*)\.pid$/;
        push(@pidfiles, $name) if defined $name;
    }

    closedir(RUNDIR);

    @pidfiles = sort { $a cmp $b } @pidfiles;
    @pidfiles = ( 'master', grep { $_ ne 'master' } @pidfiles );

    return @pidfiles;
}

sub _build_skeleton
{
    my ($self) = @_;

    my @subdirs =
    (
        'conf',
        'conf/certs',
        'conf/cores',
        'conf/sieve',
        'conf/socket',
        'conf/proc',
        'conf/log',
        'conf/log/admin',
        'conf/log/cassandane',
        'conf/log/user2',
        'conf/log/foo',
        'conf/log/mailproxy',
        'conf/log/mupduser',
        'conf/log/postman',
        'conf/log/repluser',
        'conf/log/smtpclient.sendmail',
        'conf/log/smtpclient.host',
        'lock',
        'data',
        'meta',
        'run',
        'smtpd',
        'tmp',
    );
    foreach my $sd (@subdirs)
    {
        my $d = $self->{basedir} . '/' . $sd;
        mkpath $d
            or die "Cannot make path $d: $!";
    }
}

sub _generate_imapd_conf
{
    my ($self, $config, $prefix) = @_;

    # Be very careful about setting $config options in this
    # function.  Anything that is set here cannot be varied
    # per test!

    if (defined $self->{services}->{http}) {
        my $davhost = $self->{services}->{http}->host;
        if (defined $self->{services}->{http}->port) {
            $davhost .= ':' . $self->{services}->{http}->port;
        }
        $config->set(
            webdav_attachments_baseurl => "http://$davhost"
        );
    }

    my ($cyrus_major_version, $cyrus_minor_version) =
        Cassandane::Instance->get_version($self->{installation});

    $config->set_variables(
        name => $self->{name},
        basedir => $self->{basedir},
        cyrus_prefix => $self->{cyrus_prefix},
        prefix => getcwd(),
    );
    $config->set(
        sasl_pwcheck_method => 'saslauthd',
        sasl_saslauthd_path => "$self->{basedir}/run/mux",
        notifysocket => "dlist:$self->{basedir}/run/notify",
        event_notifier => 'pusher',
    );
    if ($cyrus_major_version >= 3) {
        $config->set_bits('event_groups', 'mailbox message flags calendar');
    }
    else {
        $config->set_bits('event_groups', 'mailbox message flags');
    }
    if ($self->{buildinfo}->get('search', 'xapian')) {
        my %xapian_defaults = (
            search_engine => 'xapian',
            search_index_headers => 'no',
            search_batchsize => '8192',
            defaultsearchtier => 't1',
            't1searchpartition-default' => "$self->{basedir}/search",
            't2searchpartition-default' => "$self->{basedir}/search2",
            't3searchpartition-default' => "$self->{basedir}/search3",
        );
        while (my ($k, $v) = each %xapian_defaults) {
            if (not defined $config->get($k)) {
                $config->set($k => $v);
            }
        }
    }

    $config->generate($self->_imapd_conf($prefix));
}

sub _emit_master_entry
{
    my ($self, $entry) = @_;

    my $params = $entry->master_params();
    my $name = delete $params->{name};
    my $config = delete $params->{config};

    # if this master entry has its own confix, it will have a prefixed name
    my $imapd_conf = $self->_imapd_conf($config ? $name : undef);

    # Convert ->{argv} to ->{cmd}
    my $argv = delete $params->{argv};
    die "No argv argument"
        unless defined $argv;
    # do not alter original argv
    my @args = @$argv;
    my $bin = shift @args;
    $params->{cmd} = join(' ',
        $self->_binary($bin),
        '-C', $imapd_conf,
        @args
    );

    print MASTER "    $name";
    while (my ($k, $v) = each %$params)
    {
        $v = "\"$v\""
            if ($v =~ m/\s/);
        print MASTER " $k=$v";
    }
    print MASTER "\n";
}

sub _generate_master_conf
{
    my ($self) = @_;

    my $filename = $self->_master_conf();
    open MASTER,'>',$filename
        or die "Cannot open $filename for writing: $!";

    if (scalar @{$self->{starts}})
    {
        print MASTER "START {\n";
        map { $self->_emit_master_entry($_); } @{$self->{starts}};
        print MASTER "}\n";
    }

    if (scalar %{$self->{services}})
    {
        print MASTER "SERVICES {\n";
        map { $self->_emit_master_entry($_); } values %{$self->{services}};
        print MASTER "}\n";
    }

    if (scalar @{$self->{events}})
    {
        print MASTER "EVENTS {\n";
        map { $self->_emit_master_entry($_); } @{$self->{events}};
        print MASTER "}\n";
    }

    if (scalar %{$self->{daemons}})
    {
        print MASTER "DAEMON {\n";
        $self->_emit_master_entry($_) for values %{$self->{daemons}};
        print MASTER "}\n";
    }

    close MASTER;
}

sub _add_services_from_cyrus_conf
{
    my ($self) = @_;

    my $filename = $self->_master_conf();
    open MASTER,'<',$filename
        or die "Cannot open $filename for reading: $!";

    my $in;
    while (<MASTER>)
    {
        chomp;
        s/\s*#.*//;             # strip comments
        next if m/^\s*$/;       # skip empty lines
        my ($m) = m/^(START|SERVICES|EVENTS|DAEMON)\s*{/;
        if ($m)
        {
            $in = $m;
            next;
        }
        if ($in && m/^\s*}\s*$/)
        {
            $in = undef;
            next;
        }
        next if !defined $in;

        my ($name, $rem) = m/^\s*([a-zA-Z0-9]+)\s+(.*)$/;
        $_ = $rem;
        my %params;
        while (length $_)
        {
            my ($k, $rem2) = m/^([a-zA-Z0-9]+)=(.*)/;
            die "Bad parameter name" if !defined $k;
            $_ = $rem2;

            my ($v, $rem3) = m/^"([^"]*)"(.*)/;
            if (!defined $v)
            {
                ($v, $rem3) = m/^(\S*)(.*)/;
            }
            die "Bad parameter value" if !defined $v;
            $_ = $rem3;

            if ($k eq 'listen')
            {
                my $aa = Cassandane::GenericListener::parse_address($v);
                $params{host} = $aa->{host};
                $params{port} = $aa->{port};
            }
            elsif ($k eq 'cmd')
            {
                $params{argv} = [ split(/\s+/, $v) ];
            }
            else
            {
                $params{$k} = $v;
            }
            s/^\s+//;
        }
        if ($in eq 'SERVICES')
        {
            $self->add_service(instance => $self, name => $name, %params);
        }
    }

    close MASTER;
}

sub _fix_ownership
{
    my ($self, $path) = @_;

    $path ||= $self->{basedir};

    return if geteuid() != 0;
    my $uid = getpwnam('cyrus');
    my $gid = getgrnam('root');

    find(sub { chown($uid, $gid, $File::Find::name) }, $path);
}

sub _read_pid_file
{
    my ($self, $name) = @_;
    my $file = $self->_pid_file($name);
    my $pid;

    open PID,'<',$file
        or return undef;
    while(<PID>)
    {
        chomp;
        ($pid) = m/^(\d+)$/;
        last;
    }
    close PID;

    return undef unless defined $pid;
    return undef unless $pid > 1;
    return undef unless kill(0, $pid) > 0;
    return $pid;
}

sub _start_master
{
    my ($self) = @_;

    # First check that nothing is listening on any of the ports
    # we expect to be able to use.  That would indicate a failure
    # of test containment - i.e. we failed to shut something down
    # earlier.  Or it might indicate that someone is trying to run
    # a second set of Cassandane tests on this machine, which is
    # also going to fail miserably.  In any case we want to know.
    foreach my $srv (values %{$self->{services}},
                     values %{$self->{generic_listeners}})
    {
        die "Some process is already listening on " . $srv->address()
            if $srv->is_listening();
    }

    # Now start the master process.
    my @cmd =
    (
        'master',
        # The following is added automatically by _fork_command:
        # '-C', $self->_imapd_conf(),
        '-l', '255',
        '-d',
        '-M', $self->_master_conf(),
    );
    if (get_verbose) {
        my $logfile = $self->{basedir} . '/conf/master.log';
        xlog "_start_master: logging to $logfile";
        push(@cmd, '-L', $logfile);
    }
    # Start master daemon
    $self->run_command({ cyrus => 1 }, @cmd);

    # wait until the pidfile exists and contains a PID
    # that we can verify is still alive.
    xlog "_start_master: waiting for PID file";
    timed_wait(sub { $self->_read_pid_file() },
                description => "the master PID file to exist");
    xlog "_start_master: PID file present and correct";

    # Start any other defined listeners
    foreach my $listener (values %{$self->{generic_listeners}})
    {
        $self->run_command({ cyrus => 0 }, $listener->get_argv());
    }

    # Wait until all the defined services are reported as listening.
    # That doesn't mean they're ready to use but it means that at least
    # a client will be able to connect(), although the first response
    # might be a bit slow.
    xlog "_start_master: PID waiting for services";
    foreach my $srv (values %{$self->{services}},
                     values %{$self->{generic_listeners}})
    {
        timed_wait(sub
                {
                    $self->is_running()
                        or die "Master no longer running";
                    $srv->is_listening();
                },
                description => $srv->address() . " to be in LISTEN state");
    }
    timed_wait(sub { -e "$self->{basedir}/master.ready" },
               description => "master.ready file exists"
    );
    xlog "_start_master: all services listening";
}

sub _start_notifyd
{
    my ($self) = @_;

    my $basedir = $self->{basedir};

    my $notifypid = fork();
    unless ($notifypid) {
        $SIG{TERM} = sub { POSIX::_exit(0) };

        POSIX::close( $_ ) for 3 .. 1024; ## Arbitrary upper bound

        # child;
        $0 = "cassandane notifyd: $basedir";
        notifyd("$basedir/run");
        POSIX::_exit(0);
    }

    xlog "started notifyd for $basedir as $notifypid";
    push @{$self->{_shutdowncallbacks}}, sub {
        local *__ANON__ = "kill_notifyd";
        my $self = shift;
        xlog "killing notifyd $notifypid";
        kill(15, $notifypid);
        waitpid($notifypid, 0);
    };
}

#
# Create a user, with a home folder
#
# Argument 'user' may be of the form 'user' or 'user@domain'.
# Following that are optional named parameters
#
#   subdirs         array of strings, lists folders
#                   to be created, relative to the new
#                   home folder
#
# Returns void, or dies if something went wrong
#
sub create_user
{
    my ($self, $user, %params) = @_;

    my $mb = Cassandane::Mboxname->new(config => $self->{config}, username => $user);

    xlog "create user $user";

    my $srv = $self->get_service('imap');
    return
        unless defined $srv;

    my $adminstore = $srv->create_store(username => 'admin');
    my $adminclient = $adminstore->get_client();

    my @mboxes = ( $mb->to_external() );
    foreach my $subdir ($params{subdirs} ? @{$params{subdirs}} : ())
    {
        if (ref $subdir eq 'Cassandane::Mboxname') {
            push(@mboxes, $subdir->to_external());
        }
        else {
            push(@mboxes, $mb->make_child($subdir)->to_external());
        }
    }

    my @mb_version;
    my $old_jmap_ids;

    if (my $version = $params{mailbox_version} // $self->{mailbox_version}) {
        unless ($version =~ /\A[0-9]+\z/) {
            require Carp;
            Carp::confess("Invalid mailbox_version '$version'");
        }

        if ($version <= 19) {
            $old_jmap_ids = 1;
        }

        push @mb_version, [ 'VERSION', $version ];
    }

    foreach my $mb (@mboxes)
    {
        $adminclient->create($mb, @mb_version)
            or die "Cannot create $mb: $@";
        $adminclient->setacl($mb, admin => 'lrswipkxtecdan')
            or die "Cannot setacl for $mb: $@";
        $adminclient->setacl($mb, $user => 'lrswipkxtecdn')
            or die "Cannot setacl for $mb: $@";
        $adminclient->setacl($mb, anyone => 'p')
            or die "Cannot setacl for $mb: $@";
    }

    if ($old_jmap_ids || $params{old_jmap_ids} || $self->{old_jmap_ids}) {
        xlog $self, "Disable compactids";

        $self->run_command(
            { cyrus => 1 },
            'ctl_conversationsdb', '-I', 'off', $user
        );
    } else {
        # XXX: This should be removed when "on" is the default...
        xlog $self, "Enable compactids";

        $self->run_command(
            { cyrus => 1 },
            'ctl_conversationsdb', '-I', 'on', $user
        );
    }
}

sub set_smtpd {
    my ($self, $data) = @_;
    my $basedir = $self->{basedir};
    if ($data) {
        open(FH, ">$basedir/conf/smtpd.json");
        print FH encode_json($data);
        close(FH);
    }
    else {
        unlink("$basedir/conf/smtpd.json");
    }
}

sub _start_smtpd
{
    my ($self) = @_;

    return if not $self->{smtpdaemon};

    my $smtp_host = $self->{config}->get('smtp_host');
    die "smtp_host requested but not configured"
        if not $smtp_host or $smtp_host eq 'bogus:0';

    my ($host, $port) = split /:/, $smtp_host;

    my $smtppid = $self->run_command({
            cyrus => 0,
            background => 1,
        },
        abs_path('utils/fakesmtpd'),
        '-h', $host,
        '-p', $port,
    );

    # give the child a moment to actually start up
    sleep 1;

    # and then make sure it did!
    my $waitstatus = waitpid($smtppid, WNOHANG);
    if ($waitstatus == 0) {
        xlog "started fakesmtpd as $smtppid";
        push @{$self->{_shutdowncallbacks}}, sub {
            local *__ANON__ = "kill_smtpd";
            my $self = shift;
            xlog "killing fakesmtpd $smtppid";
            kill(15, $smtppid);
            $self->reap_command($smtppid);
        };
    }
    else {
        # child process already exited, something has gone wrong
        Cassandane::PortManager::free($port);
        die "fakesmtpd with pid=$smtppid failed to start";
    }
}

sub start_httpd {
    my ($self, $handler, $port) = @_;

    my $basedir = $self->{basedir};

    my $host = 'localhost';
    $port ||= Cassandane::PortManager::alloc($host);

    my $httpdpid = fork();
    unless ($httpdpid) {
        # Child process.
        # XXX This child still has the whole test's process space
        # XXX still mapped, and when it exits, all our destructors
        # XXX will be called, leaving the test in who knows what
        # XXX state...
        $SIG{TERM} = sub { exit 0; };

        POSIX::close( $_ ) for 3 .. 1024; ## Arbitrary upper bound

        $0 = "cassandane httpd: $basedir";

        my $httpd = HTTP::Daemon->new(
            LocalAddr => $host,
            LocalPort => $port,
            ReuseAddr => 1, # Reuse ports left in TIME_WAIT
        ) || die;
        while (my $conn = $httpd->accept) {
            while (my $req = $conn->get_request) {
                $handler->($conn, $req);
            }
            $conn->close;
            undef($conn);
        }

        exit 0; # Never reached
    }

    # Parent process.
    $self->{httpdhost} = $host . ':' . $port;

    xlog "started httpd as $httpdpid";
    push @{$self->{_shutdowncallbacks}}, sub {
        local *__ANON__ = "kill_httpd";
        my $self = shift;
        xlog "killing httpd $httpdpid";
        kill(15, $httpdpid);
        waitpid($httpdpid, 0);
    };

    return $port;
}

sub start
{
    my ($self, %params) = @_;

    my $created = 0;

    $self->_init_basedir_and_name();
    xlog "start $self->{description}: basedir $self->{basedir}";

    my $lsan_suppressions = $params{lsan_suppressions} || $self->{lsan_suppressions};

    if ($lsan_suppressions) {
        my $current = $ENV{LSAN_OPTIONS} // "";

        $ENV{LSAN_OPTIONS} = "$current:suppressions=$lsan_suppressions";

        xlog "running with LSAN_OPTIONS=$ENV{LSAN_OPTIONS}";
    }

    # arrange for fakesmtpd to be started by Cassandane if we need it
    # XXX should make it a Cyrus waitdaemon instead like fakesaslauthd
    if ($self->{smtpdaemon}) {
        my ($maj, $min) =
            Cassandane::Instance->get_version($self->{installation});

        if ($maj > 3 || ($maj == 3 && $min >= 1)) {
            my $host = '127.0.0.1';
            my $port = Cassandane::PortManager::alloc($host);

            $self->{config}->set(
                smtp_host => "$host:$port",
            );
        }
        else {
            die "smtpdaemon requested but Cyrus $maj.$min is too old";
        }
    }

    # arrange for fakesaslauthd to be started by master
    my $fakesaslauthd_socket = "$self->{basedir}/run/mux";
    my $fakesaslauthd_isdaemon = 1;
    if ($self->{authdaemon}) {
        my ($maj, $min) = Cassandane::Instance->get_version(
                            $self->{installation});
        if ($maj < 3 || ($maj == 3 && $min < 4)) {
            $self->add_start(
                name => 'fakesaslauthd',
                argv => [
                    abs_path('utils/fakesaslauthd'),
                    '-p', $fakesaslauthd_socket,
                ],
            );
            $fakesaslauthd_isdaemon = 0;
        }
        elsif (not exists $self->{daemons}->{fakesaslauthd}) {
            $self->add_daemon(
                name => 'fakesaslauthd',
                argv => [
                    abs_path('utils/fakesaslauthd'),
                    '-p', $fakesaslauthd_socket,
                ],
                wait => 'y',
            );
        }
    }

    $self->{buildinfo} = Cassandane::BuildInfo->new($self->{cyrus_destdir},
                                                    $self->{cyrus_prefix});

    if (!$self->{re_use_dir} || ! -d $self->{basedir})
    {
        $created = 1;
        rmtree $self->{basedir};
        $self->_build_skeleton();
        # TODO: system("echo 1 >/proc/sys/kernel/core_uses_pid");
        # TODO: system("echo 1 >/proc/sys/fs/suid_dumpable");

        # the main imapd.conf
        $self->_generate_imapd_conf($self->{config});

        # individual prefix-imapd.conf for master entries that want one
        foreach my $me (values %{$self->{services}},
                        values %{$self->{daemons}},
                        @{$self->{starts}},
                        @{$self->{events}})
        {
            if ($me->{config}) {
                $self->_generate_imapd_conf($me->{config}, $me->{name});
            }
        }

        $self->_generate_master_conf();
        $self->install_certificates() if $self->{install_certificates};
        $self->_fix_ownership();
    }
    elsif (!scalar $self->{services})
    {
        $self->_add_services_from_cyrus_conf();
        # XXX START, EVENTS, DAEMON entries will be missed here if reusing
        # XXX the directory.  Does it matter?  Maybe not, since the master
        # XXX conf already contains them, so they'll still run, just
        # XXX cassandane won't know about it.
    }
    $self->setup_syslog_replacement();
    $self->_start_smtpd() if $self->{smtpdaemon};
    $self->_start_notifyd();
    $self->_uncompress_berkeley_crud();
    $self->_start_master();
    $self->{_stopped} = 0;
    $self->{_started} = 1;

    # give fakesaslauthd a moment (but not more than 2s) to set up its
    # socket before anything starts trying to connect to services
    if ($self->{authdaemon} && !$fakesaslauthd_isdaemon) {
        my $tries = 0;
        while (not -S $fakesaslauthd_socket && $tries < 2_000_000) {
            $tries += usleep(10_000); # 10ms as us
        }
        die "fakesaslauthd socket $fakesaslauthd_socket not ready after 2s!"
            if not -S $fakesaslauthd_socket;
    }

    if ($created && $self->{setup_mailbox})
    {
        $self->create_user("cassandane");
    }

    xlog "started $self->{description}: cyrus version "
        . Cassandane::Instance->get_version($self->{installation});
}

sub _compress_berkeley_crud
{
    my ($self) = @_;

    my @files;
    my $dbdir = $self->{basedir} . "/conf/db";
    if ( -d $dbdir )
    {
        opendir DBDIR, $dbdir
            or return "Cannot open directory $dbdir: $!";
        while (my $e = readdir DBDIR)
        {
            push(@files, "$dbdir/$e")
                if ($e =~ m/^__db\.\d+$/);
        }
        closedir DBDIR;
    }

    if (scalar @files)
    {
        xlog "Compressing Berkeley environment files: " . join(' ', @files);
        system('/bin/bzip2', @files);
    }

    return;
}

sub _uncompress_berkeley_crud
{
    my ($self) = @_;

    my @files;
    my $dbdir = $self->{basedir} . "/conf/db";
    if ( -d $dbdir )
    {
        opendir DBDIR, $dbdir
            or die "Cannot open directory $dbdir: $!";
        while (my $e = readdir DBDIR)
        {
            push(@files, "$dbdir/$e")
                if ($e =~ m/^__db\.\d+\.bz2$/);
        }
        closedir DBDIR;
    }

    if (scalar @files)
    {
        xlog "Uncompressing Berkeley environment files: " . join(' ', @files);
        system('/bin/bunzip2', @files);
    }
}

sub _check_valgrind_logs
{
    my ($self) = @_;

    return unless Cassandane::Cassini->instance()->bool_val('valgrind', 'enabled');

    my $valgrind_logdir = $self->{basedir} . '/vglogs';

    return unless -d $valgrind_logdir;
    opendir VGLOGS, $valgrind_logdir
        or return "Cannot open directory $valgrind_logdir for reading: $!";

    my @nzlogs;
    while ($_ = readdir VGLOGS)
    {
        next if m/^\./;
        next if m/\.core\./;
        my $log = "$valgrind_logdir/$_";
        next if -z $log;
        push(@nzlogs, $_);

        if (open VG, "<$log") {
            xlog "Valgrind errors from file $log";
            while (<VG>) {
                chomp;
                xlog "$_";
            }
            close VG;
        }
        else {
            xlog "Cannot open Valgrind log $log for reading: $!";
        }

    }
    closedir VGLOGS;

    return "Found Valgrind errors, see log for details"
        if scalar @nzlogs;

    return;
}

sub _sanitizer_log_dir()
{
    my ($self, $sanitizer) = @_;

    my $san_logdir = $self->{basedir} . "/${sanitizer}logs/";
    mkpath $san_logdir
        unless ( -d $san_logdir );

    return $san_logdir;
}

sub _check_sanitizer_logs
{
    my ($self, $sanitizer) = @_;

    my $san_logdir = $self->_sanitizer_log_dir($sanitizer);

    opendir my $dirfh, $san_logdir
        or return "Cannot open directory $san_logdir for reading: $!";

    my @nzlogs;
    while ($_ = readdir $dirfh)
    {
        next if m/^\./;
        next if m/\.core\./;
        my $log = "$san_logdir/$_";
        next if -z $log;

        if (open my $fh, '<', $log) {
            xlog "$sanitizer errors from file $log";

            # First pass, see if it's only suppressions output. If so, ignore.
            # be strict so as to avoid false negatives. We can adjust in the
            # future if this becomes an annoyance. We expect suppressions
            # look like the following (for lsan at least...)
            #
            # -----------------------------------------------------
            # Suppressions used:
            #   count      bytes template
            #      10       2120 libcrypto.so
            #       2       1856 libssl.so
            # -----------------------------------------------------

            my $has_errors;

            my (
                $have_open_delim,
                $have_header,
                $have_columns,
                $have_closing_delim
            );

            while (<$fh>) {
                # Ignore whitespace
                next if /^\s*$/;

                if (! $have_open_delim) {
                    if (! /^---+$/) {
                        $has_errors = 1;
                        last;
                    }

                    $have_open_delim = 1;
                    next;
                }

                if (! $have_header) {
                    if (! /^Suppressions used:/) {
                        $has_errors = 1;
                        last;
                    }

                    $have_header = 1;
                    next;
                }

                if (! $have_columns) {
                    if (! /^\s+count\s+bytes\s+template/) {
                        $has_errors = 1;
                        last;
                    }

                    $have_columns = 1;
                    next;
                }

                if (/^---+$/ && ! $have_closing_delim) {
                    $have_closing_delim = 1;
                    next;
                }

                if (! $have_closing_delim) {
                    next if /^\s+\d+\s+\d+\w+/;
                }

                # Didn't get our closing delim and doesn't look like a
                # suppression? Uh-oh, probably a real error
                $has_errors = 1;
                last;
            }

            seek $fh, 0, 0;

            push(@nzlogs, $_) if $has_errors;

            while (<$fh>) {
                chomp;
                xlog "$_";
            }
            close $fh;
        }
        else {
            xlog "Cannot open $sanitizer log $log for reading: $!";

            # Adding this in forces errors
            push(@nzlogs, $_);
        }

    }
    closedir $dirfh;

    return "Found $sanitizer errors, see log for details"
        if scalar @nzlogs;

    return;
}

# The 'file' program seems to consistently misreport cores
# so we apply a heuristic that seems to work
sub _detect_core_program
{
    my ($core) = @_;
    my $lines = 0;
    my $prog;

    my $bindir_pattern = qr{
        \/
        (?:bin|sbin|libexec)
        \/
    }x;

    open STRINGS, '-|', ('strings', '-a', $core)
        or die "Cannot run strings on $core: $!";
    while (<STRINGS>)
    {
        chomp;
        if (m/$bindir_pattern/)
        {
            $prog = $_;
            last;
        }
        $lines++;
        last if ($lines > 10);
    }
    close STRINGS;

    return $prog;
}

sub find_cores
{
    my ($self) = @_;
    my $coredir = $self->{basedir} . '/conf/cores';

    my $cassini = Cassandane::Cassini->instance();
    my $core_pattern = $cassini->get_core_pattern();

    my @cores;

    return unless -d $coredir;
    opendir CORES, $coredir
        or return "Cannot open directory $coredir for reading: $!";
    while ($_ = readdir CORES)
    {
        next if m/^\./;
        next unless m/$core_pattern/;
        my $core = "$coredir/$_";
        next if -z $core;
        chmod(0644, $core);
        push @cores, $core;

        my $prog = _detect_core_program($core);

        xlog "Found core file $core";
        if (defined $prog) {
           xlog "   from program $prog";
           my ($bin) = $prog =~ m/^(\S+)/; # binary only
           xlog "   debug: sudo gdb $bin $core";
        }
    }
    closedir CORES;

    return @cores;
}

sub _check_cores
{
    my ($self) = @_;
    my $coredir = $self->{basedir} . '/conf/cores';

    return "Core files found in $coredir" if scalar $self->find_cores();
}

sub _check_mupdate
{
    my ($self) = @_;

    my $mupdate_server = $self->{config}->get('mupdate_server');
    return if not $mupdate_server; # not in a murder

    my $serverlist = $self->{config}->get('serverlist');
    return if $serverlist; # don't sync mboxlist on frontends

    # Run ctl_mboxlist -m to sync backend mailboxes with mupdate.
    #
    # You typically run this from START, and we do, but at test start
    # there's no mailboxes yet, so there's nothing to sync, and if
    # something is broken it probably won't be detected.
    my $basedir = $self->{basedir};
    eval {
        $self->run_command({
                redirects => { stdout => "$basedir/ctl_mboxlist.out",
                               stderr => "$basedir/ctl_mboxlist.err",
                             },
                cyrus => 1,
            }, 'ctl_mboxlist', '-m');
    };
    if ($@) {
        my @err = slurp_file("$basedir/ctl_mboxlist.err");
        chomp for @err;
        xlog "ctl_mboxlist -m failed: " . Dumper \@err;
        return "unable to sync local mailboxes with mupdate";
    }
}

sub _check_sanity
{
    my ($self) = @_;

    # We added this check during 3.5 development... older versions
    # probably fail these checks.  If we backport fixes we can decrement
    # this version check.
    my ($maj, $min) = Cassandane::Instance->get_version($self->{installation});
    if ($maj < 3 || ($maj == 3 && $min < 5)) {
        return;
    }

    my $basedir = $self->{basedir};
    my $found = 0;
    eval {
        $self->run_command({redirects => {stdout => "$basedir/quota.out", stderr => "$basedir/quota.err"}, cyrus => 1}, 'quota', '-f', '-q');
    };
    if ($@) {
        xlog "quota -f failed, $@";
        $found = 1;
    }
    eval {
        $self->run_command({redirects => {stdout => "$basedir/reconstruct.out", stderr => "$basedir/reconstruct.err"}, cyrus => 1}, 'reconstruct', '-q', '-G');
    };
    if ($@) {
        xlog "reconstruct failed, $@";
        $found = 1;
    }
    for my $file ("quota.out", "quota.err", "reconstruct.out", "reconstruct.err") {
        next unless open(FH, "<$basedir/$file");
        while (<FH>) {
            next unless $_;
            $found = 1;
            xlog "INCONSISTENCY FOUND: $file $_";
        }
    }

    return "INCONSISTENCIES FOUND IN SPOOL" if $found;

    return;
}

sub _check_syslog
{
    my ($self, $pattern) = @_;

    if (defined $pattern) {
        # pattern is optional but must be a regex if present
        die "getsyslog: pattern is not a regular expression"
            if lc ref($pattern) ne 'regexp';
    }

    my @lines = $self->getsyslog();
    my @errors = grep {
        m/ERROR|TRACELOG|Unknown code ____/ || ($pattern && m/$pattern/)
    } @lines;

    @errors = grep { not m/DBERROR.*skipstamp/ } @errors;

    $self->xlog("syslog error: $_") for @errors;

    return "Errors found in syslog" if @errors;

    return;
}

# Stop a given PID.  Returns 1 if the process died
# gracefully (i.e. soon after receiving SIGTERM)
# or wasn't even running beforehand.
sub _stop_pid
{
    my ($pid, $reaper) = @_;

    # Try to be nice, but leave open the option of not being nice should
    # that be necessary.  The signals we send are:
    #
    # SIGTERM - The standard Cyrus graceful shutdown signal, should
    #           be handled and propagated by master.
    # SIGILL - Not handled by master; kernel's default action is to
    #          dump a core.  We use this to try to get a core when
    #          something is wrong with master.
    # SIGKILL - Hmm, something went wrong with our cunning SIGILL plan,
    #           let's take off and nuke it from orbit.  We just don't
    #           want to leave processes around cluttering up the place.
    #
    my @sigs = ( SIGTERM, SIGILL, SIGKILL );
    my %signame = (
        SIGTERM, "TERM",
        SIGILL,  "ILL",
        SIGKILL, "KILL",
    );
    my $r = 1;

    foreach my $sig (@sigs)
    {
        xlog "_stop_pid: sending signal $signame{$sig} to $pid";
        kill($sig, $pid) or xlog "Can't send signal $signame{$sig} to pid $pid: $!";
        eval {
            timed_wait(sub {
                eval { $reaper->() if (defined $reaper) };
                return (kill(0, $pid) == 0);
            });
        };
        last unless $@;
        # Timed out -- No More Mr Nice Guy
        xlog "_stop_pid: failed to shut down pid $pid with signal $signame{$sig}";
        $r = 0;
    }
    return $r;
}

sub send_sighup
{
    my ($self) = @_;

    return if (!$self->{_started});
    return if ($self->{_stopped});
    xlog "sighup";

    my $pid = $self->_read_pid_file('master') or return;
    kill(SIGHUP, $pid) or die "Can't send signal SIGHUP to pid $pid: $!";
    return 1;
}

#
# n.b. If you are stopping the instance intending to restart it again later,
# you must set:
#     $instance->{'re_use_dir'} => 1
# before restarting, otherwise it will wipe and re-initialise its basedir
# during startup, probably ruining whatever you were trying to do.  It
# will still use the same directory name though, so it won't be obvious
# from the logs that this is happening!
#
sub stop
{
    my ($self, %params) = @_;

    $self->_init_basedir_and_name();

    return if ($self->{_stopped} || !$self->{_started});
    $self->{_stopped} = 1;

    my @errors;

    push @errors, $self->_check_sanity();
    push @errors, $self->_check_mupdate();

    xlog "stop $self->{description}: basedir $self->{basedir}";

    foreach my $name ($self->_list_pid_files())
    {
        my $pid = $self->_read_pid_file($name);
        next if (!defined $pid);
        _stop_pid($pid)
            or push @errors, "Cannot shut down $name pid $pid";
    }
    # Note: no need to reap this daemon which is not our child anymore

    foreach my $item (@{$self->{_shutdowncallbacks}}) {
        eval {
            $item->($self);
        };
        if ($@) {
            push @errors, "some shutdown callback died: $@";
        }
    }
    $self->{_shutdowncallbacks} = [];

    # n.b. still need this for testing 2.5
    push @errors, $self->_compress_berkeley_crud();

    push @errors, $self->_check_valgrind_logs();
    push @errors, $self->_check_sanitizer_logs("asan");
    push @errors, $self->_check_sanitizer_logs("ubsan");
    push @errors, $self->_check_cores();
    push @errors, $self->_check_syslog() unless $params{no_check_syslog};
    push @errors, "master ready file still exists" if -e "$self->{basedir}/master.ready";

    # filter out empty errors (shouldn't be any, but just in case)
    @errors = grep { $_ } @errors;

    foreach my $e (@errors) {
        xlog "$self->{description}: $e";
    }

    return @errors;
}

sub DESTROY
{
    my ($self) = @_;

    if ($$ != $self->{_pid}) {
        xlog "ignoring DESTROY from bad caller: $$";
        return;
    }

    if (defined $self->{basedir} &&
        !$self->{persistent} &&
        !$self->{_stopped})
    {
        # clean up any dangling master and daemon process
        foreach my $name ($self->_list_pid_files())
        {
            my $pid = $self->_read_pid_file($name);
            next if (!defined $pid);
            _stop_pid($pid);
        }

        foreach my $item (@{$self->{_shutdowncallbacks}}) {
            $item->($self);
        }
        $self->{_shutdowncallbacks} = [];
    }
}

sub is_running
{
    my ($self) = @_;

    my $pid = $self->_read_pid_file();
    return 0 unless defined $pid;
    return kill(0, $pid);
}

sub _setup_for_deliver
{
    my ($self) = @_;

    $self->add_service(name => 'lmtp',
                       argv => ['lmtpd', '-a'],
                       port => '@basedir@/conf/socket/lmtp');
}

sub deliver
{
    my ($self, $msg, %params) = @_;
    my $str = $msg->as_string();
    my @cmd = ( 'deliver' );

    my $folder = $params{folder};
    if (defined $folder)
    {
        $folder =~ s/^inbox.//i;
        push(@cmd, '-m', $folder);
    }

    my @users;
    if (defined $params{users})
    {
        push(@users, @{$params{users}});
    }
    elsif (defined $params{user})
    {
        push(@users, $params{user})
    }
    else
    {
        push(@users, 'cassandane');
    }
    push(@cmd, @users);

    my $ret = 0;

    $self->run_command({
        cyrus => 1,
        redirects => {
            stdin => \$str
        },
        handlers => {
            exited_abnormally => sub { (undef, $ret) = @_; },
        },
    }, @cmd);

    return $ret;
}

# Runs a command with the given arguments.  The first argument is an
# options hash:
#
# background  whether to start the command in the background; you need
#           to give returned arguments to reap_command afterwards
#
# cyrus     whether it is a cyrus utility; if so, instance path is
#           automatically prepended to the given command name
#
# handlers  hash of coderefs to be called when various events
#           are detected.  Default is to 'die' on any event
#           except exiting with code 0.  The events are:
#
#   exited_normally($child)
#   exited_abnormally($child, $code)
#   signaled($child, $sig)
#
# redirects  hash for I/O redirections
#     stdin     feed stdin from; handles SCALAR data or filename,
#                   /dev/null by default
#     stdout    feed stdout to; /dev/null by default (or is unmolested
#                   if xlog is in verbose mode)
#     stderr    feed stderr to; /dev/null by default (or is unmolested
#                   if xlog is in verbose mode)
#
# workingdir  path to launch the command from
#
sub run_command
{
    my ($self, @args) = @_;

    my $options = {};
    if (ref($args[0]) eq 'HASH') {
        $options = shift(@args);
    }

    my $basedir = $self->{basedir};

    my ($stdout, $stderr);

    my $redirs = $options->{redirects} // {};

    if ($redirs->{stdout} && (ref($redirs->{stdout}) // '') eq 'SCALAR') {
        $stdout = $redirs->{stdout};

        my $i = 0;

        while (1) {
            $redirs->{stdout} = "$basedir/$args[0].$i.stdout";
            last if ! -e $redirs->{stdout};

            $i++;
        }
    }

    if ($redirs->{stderr} && (ref($redirs->{stderr}) // '') eq 'SCALAR') {
        $stderr = $redirs->{stderr};

        my $i = 0;

        while (1) {
            $redirs->{stderr} = "$basedir/$args[0].$i.stderr";
            last if ! -e $redirs->{stderr};

            $i++;
        }
    }

    if ($options->{background} && ($stdout || $stderr)) {
        require Carp;
        Carp::confess("background doesn't work with SCALAR stdout/stderr!");
    }



    # Always set these. If they weren't compiled in they won't be used.
    local $ENV{ASAN_OPTIONS} = ($ENV{ASAN_OPTIONS} // "")
        . ":log_path=" . $self->_sanitizer_log_dir("asan") . "asan";

    local $ENV{UBSAN_OPTIONS} = ($ENV{UBSAN_OPTIONS} // "")
        . ":log_path=" . $self->_sanitizer_log_dir("ubsan") . "ubsan";

    my ($pid, $got_exit) = $self->_fork_command($options, @args);

    return $pid
        if ($options->{background});

    my $ret;

    if (defined $got_exit) {
        # Child already reaped, pass it on
        $? = $got_exit;

        $ret = $self->_handle_wait_status($pid);
    } else {
        $ret = $self->reap_command($pid);
    }

    # Copy stdout/stderr into SCALAR refs if requested
    if ($stdout) {
        $$stdout = slurp_file($redirs->{stdout});

        if (get_verbose()) {
            xlog $self, "stdout: $$stdout";
        }
    }

    if ($stderr) {
        $$stderr = slurp_file($redirs->{stderr});

        if (get_verbose()) {
            xlog $self, "stderr: $$stderr";
        }
    }

    return $ret;
}

# Like above, but automatically redirects stdout/stderr to scalar refs, then
# returns an object that includes 'status', 'stdout', and 'stderr' to easily
# inspect the results
sub run_command_capture
{
    my ($self, @args) = @_;

    my $options = {};
    if (ref($args[0]) eq 'HASH') {
        $options = shift(@args);
    }

    if ($options->{redirects}
        && ($options->{redirects}{stdout} || $options->{redirects}{stderr})
    ) {
        require Carp;
        Carp::confess("run_command_capture() can't be used with custom stdout/stderr redirects!");
    }

    if ($options->{background}) {
        require Carp;
        Carp::confess("run_command_capture() can't be used with background mode!");
    }

    my ($stdout, $stderr);

    $options->{redirects}{stdout} = \$stdout;
    $options->{redirects}{stderr} = \$stderr;

    my $res = $self->run_command($options, @args);

    return Cassandane::Instance::RunCommandOut->new({
        status => $res,
        stdout => $stdout,
        stderr => $stderr,
    });
}

{
    package Cassandane::Instance::RunCommandOut;

    sub new {
        my ($class, $ref) = @_;

        bless $ref, $class;
    }

    sub status { shift->{status} }

    sub stdout {
        my $stdout = shift->{stdout};

        return $stdout // "";
    }

    sub stderr {
        my $stderr = shift->{stderr};

        return $stderr // "";
    }
}

sub reap_command
{
    my ($self, $pid) = @_;

    # parent process...wait for child
    my $child = waitpid($pid, 0);
    # and deal with it's exit status
    return $self->_handle_wait_status($pid)
        if $child == $pid;
    return undef;
}

# returns the command's exit status, or -1 if something went wrong
sub stop_command
{
    my ($self, $pid) = @_;
    my $child;

    # it's our child, so we must reap it, otherwise it'll never
    # completely exit.  but if it ignores the first sigterm, a normal
    # waitpid will block forever, so we need to be WNOHANG here
    my $r = _stop_pid($pid, sub { $child = waitpid($pid, WNOHANG); });
    return -1 if $r != 1;

    if ($child == $pid) {
        return $self->_handle_wait_status($pid)
    }
    else {
        return -1;
    }
}

my %default_command_handlers = (
    signaled => sub
    {
        my ($child, $sig) = @_;
        my $desc = _describe_child($child);
        die "child process $desc terminated by signal $sig";
    },
    exited_normally => sub
    {
        my ($child) = @_;
        return 0;
    },
    exited_abnormally => sub
    {
        my ($child, $code) = @_;
        my $desc = _describe_child($child);
        die "child process $desc exited with code $code";
    },
);

sub _add_child
{
    my ($self, $binary, $pid, $handlers) = @_;
    my $key = $pid;

    $handlers ||= \%default_command_handlers;

    my $child = {
        binary => $binary,
        pid => $pid,
        handlers => { %default_command_handlers, %$handlers },
    };
    $self->{_children}->{$key} = $child;
    return $child;
}

sub _describe_child
{
    my ($child) = @_;
    return "unknown" unless $child;
    return "(binary $child->{binary} pid $child->{pid})";
}

sub _cyrus_perl_search_path
{
    my ($self) = @_;
    my @inc = (
        substr($Config{installvendorlib}, length($Config{vendorprefix})),
        substr($Config{installvendorarch}, length($Config{vendorprefix})),
        substr($Config{installsitelib}, length($Config{siteprefix})),
        substr($Config{installsitearch}, length($Config{siteprefix}))
    );
    return map { $self->{cyrus_destdir} . $self->{cyrus_prefix} . $_; } @inc;
}

#
# Starts a new process to run a program.
#
# Returns launched $pid; you must call _handle_wait_status() to
#          decode $?.  Dies on errors.
#
sub _fork_command
{
    my ($self, $options, $binary, @argv) = @_;

    die "No binary specified"
        unless defined $binary;

    my %redirects;
    if (defined($options->{redirects})) {
        %redirects = %{$options->{redirects}};
    }
    # stdin is null, stdout is null or unmolested
    $redirects{stdin} = '/dev/null'
        unless(defined($redirects{stdin}));
    $redirects{stdout} = '/dev/null'
        unless(get_verbose || defined($redirects{stdout}));
    $redirects{stderr} = '/dev/null'
        unless(get_verbose || defined($redirects{stderr}));

    my @cmd = ();
    if ($options->{cyrus})
    {
        push(@cmd, $self->_binary($binary), '-C', $self->_imapd_conf());
    }
    elsif ($binary =~ m/xapian.*$/) {
        push(@cmd, $self->_binary($binary));
    }
    else {
        push(@cmd, $binary);
    }
    push(@cmd, @argv);

    xlog "Running: " . join(' ', map { "\"$_\"" } @cmd);

    if (defined($redirects{stdin}) && (ref($redirects{stdin}) eq 'SCALAR'))
    {
        my $fh;
        my $data = $redirects{stdin};
        $redirects{stdin} = undef;
        # Use the fork()ing form of open()
        my $pid = open $fh,'|-';
        die "Cannot fork: $!"
            if !defined $pid;
        if ($pid)
        {
            xlog "child pid=$pid";
            # parent process
            $self->_add_child($binary, $pid, $options->{handlers});
            print $fh ${$data};
            close ($fh);
            return ($pid, $?);
        }
    }
    else
    {
        # No capturing - just plain fork()
        my $pid = fork();
        die "Cannot fork: $!"
            if !defined $pid;
        if ($pid)
        {
            # parent process
            xlog "child pid=$pid";
            $self->_add_child($binary, $pid, $options->{handlers});
            return ($pid, undef);
        }
    }

    # child process

    my $cassroot = getcwd();
    $ENV{CASSANDANE_CYRUS_DESTDIR} = $self->{cyrus_destdir};
    $ENV{CASSANDANE_CYRUS_PREFIX} = $self->{cyrus_prefix};
    $ENV{CASSANDANE_PREFIX} = $cassroot;
    $ENV{CASSANDANE_BASEDIR} = $self->{basedir};
    $ENV{CASSANDANE_VERBOSE} = 1 if get_verbose();
    $ENV{PERL5LIB} = join(':', ($cassroot, $self->_cyrus_perl_search_path()));
    if ($self->{have_syslog_replacement}) {
        $ENV{CASSANDANE_SYSLOG_FNAME} = abs_path($self->{syslog_fname});
        $ENV{LD_PRELOAD} = abs_path('utils/syslog.so')
    }
    $ENV{PKG_CONFIG_PATH} = $self->{cyrus_destdir}
                          . $self->{cyrus_prefix}
                          . "/lib/pkgconfig";

#     xlog "\$PERL5LIB is"; map { xlog "    $_"; } split(/:/, $ENV{PERL5LIB});

    # Set up the runtime linker path to find the Cyrus shared libraries
    #
    # TODO: on some platforms we need lib64/ not lib/ but it's not
    # entirely clear how to detect that - we could use readelf -d
    # on an executable to discover what it thinks it's RPATH ought
    # to be, then prepend destdir to that.
    $ENV{LD_LIBRARY_PATH} = join(':', (
            $self->{cyrus_destdir} . $self->{cyrus_prefix} . "/lib",
            split(/:/, $ENV{LD_LIBRARY_PATH} || "")
    ));
#     xlog "\$LD_LIBRARY_PATH is"; map { xlog "    $_"; } split(/:/, $ENV{LD_LIBRARY_PATH});

    my $cd = $options->{workingdir};
    $cd = $self->{basedir} . '/conf/cores'
        unless defined($cd);
    chdir($cd)
        or die "Cannot cd to $cd: $!";

    # ulimit -c ...
    my $cassini = Cassandane::Cassini->instance();
    my $coresizelimit = 0 + $cassini->val("cyrus $self->{installation}",
                                          'coresizelimit', '100');
    if ($coresizelimit <= 0) {
        $coresizelimit = RLIM_INFINITY;
    }
    else {
        # convert megabytes to bytes
        $coresizelimit *= (1024 * 1024);
    }
    xlog "setting core size limit to $coresizelimit";
    setrlimit(RLIMIT_CORE, $coresizelimit, $coresizelimit);

    # let's log our rlimits, might be useful for diagnosing weirdnesses
    if (get_verbose() >= 4) {
        my $limits = get_rlimits();
        foreach my $name (keys %{$limits}) {
            $limits->{$name} = [ getrlimit($limits->{$name}) ];
        }
        xlog "rlimits: " . Dumper $limits;
    }

    # TODO: do any setuid, umask, or environment futzing here

    # implement redirects
    if (defined $redirects{stdin})
    {
        open STDIN,'<',$redirects{stdin}
            or die "Cannot redirect STDIN from $redirects{stdin}: $!";
    }
    if (defined $redirects{stdout})
    {
        open STDOUT,'>',$redirects{stdout}
            or die "Cannot redirect STDOUT to $redirects{stdout}: $!";
    }
    if (defined $redirects{stderr})
    {
        open STDERR,'>',$redirects{stderr}
            or die "Cannot redirect STDERR to $redirects{stderr}: $!";
    }

    # exec in a block by itself shushes the "Statement unlikely to be reached"
    # warning, which is generated when exec is followed by something other
    # than die
    { exec @cmd; }

    # If exec failed, then this process is still a clone of a Worker.  If we
    # die here it would report a test failure, then loop around and try to
    # run the next test!  And if we exit here, it would deconstruct the real
    # Worker's memory space out from under it.  Need to use POSIX::_exit
    # to bypass all that and have the child process actually exit.
    xlog "Cannot run $binary: $!";
    POSIX::_exit(71); # EX_OSERR
}

sub _handle_wait_status
{
    my ($self, $key) = @_;
    my $status = $?;

    my $child = delete $self->{_children}->{$key};

    if (WIFSIGNALED($status))
    {
        my $sig = WTERMSIG($status);
        return $child->{handlers}->{signaled}->($child, $sig);
    }
    elsif (WIFEXITED($status))
    {
        my $code = WEXITSTATUS($status);
        return $child->{handlers}->{exited_abnormally}->($child, $code)
            if $code != 0;
    }
    else
    {
        die "WTF? Cannot decode wait status $status";
    }
    return $child->{handlers}->{exited_normally}->($child);
}

sub describe
{
    my ($self) = @_;

    print "Cyrus instance\n";
    printf "    name: %s\n", $self->{name};
    printf "    imapd.conf: %s\n", $self->_imapd_conf();
    printf "    services:\n";
    foreach my $srv (values %{$self->{services}})
    {
        printf "        ";
        $srv->describe();
    }
    printf "    generic listeners:\n";
    foreach my $listener (values %{$self->{generic_listeners}})
    {
        printf "        ";
        $listener->describe();
    }
}

sub _quota_Z_file
{
    my ($self, $mboxname) = @_;
    return $self->{basedir} . '/conf/quota-sync/' . $mboxname;
}

sub quota_Z_go
{
    my ($self, $mboxname) = @_;
    my $filename = $self->_quota_Z_file($mboxname);

    xlog "Allowing quota -Z to proceed for $mboxname";

    my $dir = dirname($filename);
    mkpath $dir
        unless ( -d $dir );

    my $fd = POSIX::creat($filename, 0600);
    POSIX::close($fd);
}

sub quota_Z_wait
{
    my ($self, $mboxname) = @_;
    my $filename = $self->_quota_Z_file($mboxname);

    timed_wait(sub { return (! -f $filename); },
                description => "quota -Z to be finished with $mboxname");
}

#
# Unpacks file.  Handles tar, gz, and bz2.
#
sub unpackfile
{
    my ($self, $src, $dst) = @_;

    if (!defined($dst)) {
        # unpack in base directory
        $dst = $self->{basedir};
    }
    elsif ($dst !~ /^\//) {
        # unpack relatively to base directory
        $dst = $self->{basedir} . '/' . $dst;
    }
    # else: absolute path given

    my $options = {};
    my @cmd = ();

    my $file = [split(/\./, (split(/\//, $src))[-1])];
    if (grep { $_ eq 'tar' } @$file) {
        push(@cmd, 'tar', '-x', '-f', $src, '-C', $dst);
    }
    elsif ($file->[-1] eq 'gz') {
        $options->{redirects} = {
            stdout => "$dst/" . join('.', splice(@$file, 0, -1))
        };
        push(@cmd, 'gunzip', '-c', $src);
    }
    elsif ($file->[-1] eq 'bz2') {
        $options->{redirects} = {
            stdout => "$dst/" . join('.', splice(@$file, 0, -1))
        };
        push(@cmd, 'bunzip2', '-c', $src);
    }
    else {
        # we don't handle this combination
        die "Unhandled packed file $src";
    }

    return $self->run_command($options, @cmd);
}

sub folder_to_directory
{
    my ($self, $folder) = @_;

    $folder =~ s/^inbox\./user.cassandane./i;
    $folder =~ s/^inbox$/user.cassandane/i;

    my $data = eval { $self->run_mbpath($folder) };
    return unless $data;
    my $dir = $data->{data};
    return undef unless -d $dir;
    return $dir;
}

sub folder_to_deleted_directories
{
    my ($self, $folder) = @_;

    $folder =~ s/^inbox\./user.cassandane./i;
    $folder =~ s/^inbox$/user.cassandane/i;

    # ideally we'd have a command-line way to do this, but imap works too
    my $srv = $self->get_service('imap');
    my $adminstore = $srv->create_store(username => 'admin');
    my $adminclient = $adminstore->get_client();
    my @folders = $adminclient->list('', "DELETED.$folder.%");

    my @res;
    for my $item (@folders) {
      next if grep { lc $_ eq '\\noselect' } @{$item->[0]};
      my $mailbox = $item->[2];
      my $data = eval { $self->run_mbpath($mailbox) };
      my $dir = $data->{data};
      next unless -d $dir;
      push @res, $dir;
    }

    return @res;
}

sub notifyd
{
    my $dir = shift;

    $0 = "cassandane notifyd $dir";

    my @EVENTS;
    tcp_server("unix/", "$dir/notify", sub {
        my $fh = shift;
        my $Handle = AnyEvent::Handle->new(
            fh => $fh,
        );
        $Handle->push_read('Cyrus::DList' => 1, sub {
            my $dlist = $_[1];
            my $event = $dlist->as_perl();
            #xlog "GOT EVENT: " . encode_json($event);
            push @EVENTS, $event;
            $Handle->push_write('Cyrus::DList' => scalar(Cyrus::DList->new_kvlist("OK")), 1);
            $Handle->push_shutdown();
        });
    });

    tcp_server("unix/", "$dir/getnotify", sub {
        my $fh = shift;
        my $Handle = AnyEvent::Handle->new(
            fh => $fh,
        );
        #xlog "REPLYING EVENTS: " . scalar(@EVENTS);
        $Handle->push_write(json => \@EVENTS);
        $Handle->push_shutdown();
        @EVENTS = ();
    });

    my $cv = AnyEvent->condvar();

    $SIG{TERM} = sub { $cv->send() };

    $cv->recv();
}

sub getnotify
{
    my ($self) = @_;

    my $basedir = $self->{basedir};
    my $path = "$basedir/run/getnotify";

    my $data = eval {
        my $sock = IO::Socket::UNIX->new(
            Type => SOCK_STREAM(),
            Peer => $path,
        ) || die "Connection failed $!";
        my $line = $sock->getline();
        my $json = decode_json($line);
        if (get_verbose) {
            use Data::Dumper;
            warn "NOTIFY " . Dumper($json);
        }
        return $json;
    };
    if ($@) {
        my $data = `ls -la $basedir/run; whoami; lsof -n | grep notify`;
        xlog "Failed $@ ($data)";
    }

    return $data;
}

sub setup_syslog_replacement
{
    my ($self) = @_;

    if (not(-e 'utils/syslog.so') || not(-e 'utils/syslog_probe')) {
        xlog "utils/syslog.so not found (do you need to run 'make'?)";
        xlog "tests will not examine syslog output";
        $self->{have_syslog_replacement} = 0;
        return;
    }

    # Can't reliably replace syslog when source fortification is in play,
    # and syslog_probe can't reliably detect whether the replacement has
    # worked or not in this case, so just turn syslog replacement off if
    # we detect source fortification
    if ($self->{buildinfo}->get('version', 'FORTIFY_LEVEL')) {
        xlog "Cyrus was built with -D_FORTIFY_SOURCE";
        xlog "tests will not examine syslog output";
        $self->{have_syslog_replacement} = 0;
        return;
    }

    $self->{syslog_fname} = "$self->{basedir}/conf/log/syslog";
    $self->{have_syslog_replacement} = 1;

    # if the syslog file already exists, remember how large it is
    # so we can seek past existing content without missing the
    # startup content!
    my $syslog_start = 0;
    $syslog_start = -s $self->{syslog_fname} if -e $self->{syslog_fname};

    # check that we can syslog a message and find it again
    my $syslog_probe = abs_path('utils/syslog_probe');
    $self->run_command($syslog_probe, $self->{name});

    $self->{_syslogfh} = IO::File->new($self->{syslog_fname}, 'r');

    if ($self->{_syslogfh}) {
        $self->{_syslogfh}->seek($syslog_start, 0);
        $self->{_syslogfh}->blocking(0);

        if (not scalar $self->getsyslog(qr/\bthe magic word\b/)) {
            xlog "didn't find the magic word when probing syslog";
            xlog "tests will not examine syslog output";

            $self->{have_syslog_replacement} = 0;
            undef $self->{_syslogfh};
        }
    }
    else {
        xlog "couldn't read $self->{syslog_fname} when probing syslog";
        xlog "tests will not examine syslog output";

        $self->{have_syslog_replacement} = 0;
    }
}

# n.b. This only gives you syslog lines if we were able to successfully
# inject our syslog replacement.
# If you need to make sure an error WASN'T logged, it'll do approximately
# the right thing.
# But if you need to make sure an error WAS logged, first make sure that
# $instance->{have_syslog_replacement} is true, otherwise you will always
# fail on systems where the syslog replacement doesn't work.
sub getsyslog
{
    my ($self, $pattern) = @_;

    if (defined $pattern) {
        # pattern is optional but must be a regex if present
        die "getsyslog: pattern is not a regular expression"
            if lc ref($pattern) ne 'regexp';
    }
    my $logname = $self->{name};
    my @lines;

    if ($self->{have_syslog_replacement} && $self->{_syslogfh}) {
        # https://github.com/Perl/perl5/issues/21240
        # eof status is no longer cleared automatically in newer perls
        if ($self->{_syslogfh}->eof()) {
            $self->{_syslogfh}->clearerr();
        }
        if ($self->{_syslogfh}->error()) {
            die "error reading $self->{syslog_fname}";
        }

        # hopefully unobtrusively, let busy log finish writing
        usleep(100_000); # 100ms (0.1s) as us
        @lines = grep { m/$logname/ } $self->{_syslogfh}->getlines();

        if (defined $pattern) {
            @lines = grep { m/$pattern/ } @lines;
        }

        chomp for @lines;
    }

    return @lines;
}

sub _get_sqldb
{
    my $dbfile = shift;
    my $dbh = DBI->connect("dbi:SQLite:$dbfile", undef, undef);
    my @tables = map { s/"//gs; s/^main\.//; $_ } $dbh->tables();
    my %res;
    foreach my $table (@tables) {
        $res{$table} = $dbh->selectall_arrayref("SELECT * FROM $table", { Slice => {} });
    }
    return \%res;
}

sub getalarmdb
{
    my $self = shift;
    my $file = "$self->{basedir}/conf/caldav_alarm.sqlite3";
    return [] unless -e $file;
    my $data = _get_sqldb($file);
    return $data->{events} || die "NO EVENTS IN CALDAV ALARM DB";
}

sub getdavdb
{
    my $self = shift;
    my $user = shift;
    my $file = $self->get_conf_user_file($user, 'dav');
    return unless -e $file;
    return _get_sqldb($file);
}

sub get_sieve_script_dir
{
    my ($self, $cyrusname) = @_;

    if ($cyrusname) {
        my $data = eval { $self->run_mbpath('-u', $cyrusname) };
        return $data->{user}{sieve} if $data;
    }

    $cyrusname //= '';

    my $sieved = "$self->{basedir}/conf/sieve";

    my ($user, $domain) = split '@', $cyrusname;

    if ($domain) {
        my $dhash = substr($domain, 0, 1);
        $sieved .= "/domain/$dhash/$domain";
    }

    if ($user ne '')
    {
        my $uhash = substr($user, 0, 1);
        $sieved .= "/$uhash/$user/";
    }
    else
    {
        # shared folder
        $sieved .= '/global/';
    }

    return $sieved;
}

sub get_conf_user_file
{
    my ($self, $cyrusname, $ext) = @_;

    my $data = eval { $self->run_mbpath('-u', $cyrusname) };
    return $data->{user}{$ext} if $data;
}

sub install_sieve_script
{
    my ($self, $script, %params) = @_;

    my $user = (exists $params{username} ? $params{username} : 'cassandane');
    my $name = $params{name} || 'test1';
    my $sieved = $self->get_sieve_script_dir($user);

    xlog "Installing sieve script $name in $sieved";

    -d $sieved or mkpath $sieved
        or die "Cannot make path $sieved: $!";
    die "Path does not exist: $sieved" if not -d $sieved;

    open(FH, '>', "$sieved/$name.script")
        or die "Cannot open $sieved/$name.script for writing: $!";
    print FH $script;
    close(FH);

    $self->run_command({ cyrus => 1 },
                         "sievec",
                         "$sieved/$name.script",
                         "$sieved/$name.bc");
    die "File does not exist: $sieved/$name.bc" if not -f "$sieved/$name.bc";

    -e "$sieved/defaultbc" || symlink("$name.bc", "$sieved/defaultbc")
        or die "Cannot symlink $name.bc to $sieved/defaultbc";
    die "Symlink does not exist: $sieved/defaultbc" if not -l "$sieved/defaultbc";

    xlog "Sieve script installed successfully";
}

sub install_old_mailbox
{
    my ($self, $user, $version) = @_;

    my $data_file = abs_path("data/old-mailboxes/version$version.tar.gz");
    die "Old mailbox data does not exist: $data_file" if not -f $data_file;

    xlog "installing version $version mailbox for user $user";

    my $dest_dir = "data/user/$user";

    $self->unpackfile($data_file, $dest_dir);
    $self->run_command({ cyrus => 1 }, 'reconstruct', '-f', "user.$user");

    xlog "installed version $version mailbox for user $user: user.$user.version$version";

    return "user.$user.version$version";
}

sub install_certificates
{
    my ($self) = @_;

    my $cert_file = abs_path("data/certs/cert.pem");
    my $key_file = abs_path("data/certs/key.pem");
    my $cacert_file = abs_path("data/certs/cacert.pem");

    my $destdir = $self->get_basedir() . "/conf/certs";
    xlog "installing certificate files to $destdir ...";
    foreach my $f ($cert_file, $key_file, $cacert_file) {
        copy($f, $destdir)
            or die "cannot install $f to $destdir: $!";
    }

    $destdir = $self->get_basedir() . "/conf/certs/http_jwt";
    my $jwt_file = abs_path("data/certs/http_jwt/jwt.pem");
    xlog "installing JSON Web Token key file ...";
    copy($jwt_file, $destdir)
        or die "cannot install $jwt_file to $destdir: $!";
}

sub get_servername
{
    my ($self) = @_;

    return $self->{config}->get('servername');
}

sub run_mbpath
{
    my ($self, @args) = @_;
    my ($maj, $min) = Cassandane::Instance->get_version($self->{installation});
    my $basedir = $self->get_basedir();
    if ($maj < 3 || $maj == 3 && $min <= 4) {
        my $folder = pop @args;
        my $domain = '';
        if ($folder =~ s/\@([^@]+)$//) {
            $domain = $1;
        }

        # support -u $user, including users with dots
        if (@args and $args[0] eq '-u') {
            $folder =~ s/\./\^/g;
            $folder = "user.$folder";
        }

        # translate to path
        $folder =~ s/\./\//g;
        my $user = '';
        if ($folder =~ m{user/([^/]+)}) {
            $user = $1;
        }

        my $dhash = substr($domain, 0, 1);
        my $uhash = substr($user, 0, 1);

        my $dotuser = $user;
        $dotuser =~ s/\^/\./g;

        # XXX - hashing smarts?
        my $upath = '';
        $upath .= "domain/$dhash/$domain/" if $domain;
        $upath .= "user/$uhash/$dotuser";
        my $spath = '';
        # fricking sieve, always different
        $spath .= "domain/$dhash/$domain/" if $domain;
        $spath .= "$uhash/$dotuser";
        my $xpath = '';
        # et tu xapian
        $xpath .= "domain/$dhash/$domain/" if $domain;
        $xpath .= "$uhash/user/$dotuser";

        my $res = {
            data => "$basedir/data/$folder",
            archive => "$basedir/archive/$folder",
            meta => "$basedir/meta/$folder",
            # skip mbname, we're not using it
            user => {
                (map { $_ => "$basedir/conf/$upath.$_" } qw(conversations counters dav seen sub xapianactive)),
                sieve => "$basedir/conf/sieve/$spath",
            },
            xapian => {
                t1 => "$basedir/search/$xpath",
                t2 => "$basedir/search2/$xpath",
                t3 => "$basedir/search3/$xpath",
            },
        };
        return $res;
    }

    my $filename = "$basedir/cyr_info.out";
    $self->run_command({
        cyrus => 1,
        redirects => {
            stdout => $filename,
        },
    }, 'mbpath', '-j', @args);

    return decode_json(slurp_file($filename));
}

sub _mkastring
{
    my $string = shift;
    return '{' . length($string) . '+}' . "\r\n" . $string;
}

sub run_dbcommand_cb
{
    my ($self, $linecb, $dbname, $engine, @items) = @_;

    if (@items > 1) {
        unshift @items, ['BEGIN'];
        push @items, ['COMMIT'];
    }

    my $input = '';
    foreach my $item (@items) {
        $input .= $item->[0];
        for (1..2) {
            $input .= ' ' . _mkastring($item->[$_]) if defined $item->[$_];
        }
        $input .= "\r\n";
    }

    my $basedir = $self->{basedir};
    my $res = $self->run_command({
       redirects => {
           stdin => \$input,
           stdout => "$basedir/run_dbcommand.out",
       },
       cyrus => 1,
       handlers => {
           exited_normally => sub { return 'ok'; },
           exited_abnormally => sub { return 'failure'; },
       },
    }, 'cyr_dbtool', $dbname, $engine, 'batch');
    return $res unless $res eq 'ok';

    my $needbytes = 0;
    my $buf = '';

    # The output of `cyr_dbtool` is in theory one logical line at a time.
    #  However each logical line can have IMAP literals in them. In that
    #  case, you get a real line that ends with "{nbytes+}\r\n" and you then
    #  have to read that many bytes of data (including possibly \r's and
    #  \n's as well). This function potentially reads multiple real lines
    #  in $line to gather up a single logical line in $buf, and then parses
    #  that.
    # It could be made simpler and more efficient by tokenising the line as
    #  it goes, but it was extracted from an original codebase which processed
    #  the entire response buffer from `cyr_dbtool` as a single giant string.
    open(FH, "<$basedir/run_dbcommand.out");
    LINE: while (defined(my $line = <FH>)) {
        $buf .= $line;

        # inside a literal, that's all we need
        if ($needbytes) {
            my $len = length($line);
            if ($len <= $needbytes) {
                $needbytes -= $len;
                next LINE;
            }
            substr($line, 0, $needbytes, '');
            $needbytes = 0;
        }

        # does this line include a literal, process it now
        if ($line =~ m/\{(\d+)\+?\}\r?\n$/s) {
            $needbytes = $1;
            next LINE;
        }

        # we have a line!

        my @array;
        my $pos = 0;
        my $length = length($buf);
        while ($pos < $length) {
            my $chr = substr($buf, $pos, 1);

            if ($chr eq ' ') {
                $pos++;
                next;
            }

            if ($chr eq "\n") {
                $pos++;
                next;
            }

            if ($chr eq '{') {
                my $end = index($buf, '}', $pos);
                die "Missing }" if $end < 0;
                my $len = substr($buf, $pos + 1, $end - $pos - 1);
                $len =~ s/\+//;
                $pos = $end+1;
                my $chr = substr($buf, $pos++, 1);
                $chr = substr($buf, $pos++, 1) if $chr eq "\r";
                die "BOGUS LITERAL" unless $chr eq "\n";
                push @array, substr($buf, $pos, $len);
                $pos += $len;
                next;
            }

            if ($chr eq '"') {
                my $end = index($buf, '"', $pos+1);
                die "Missing quote" if $end < 0;
                push @array, substr($buf, $pos + 1, $end - $pos - 1);
                $pos = $end + 1;
                next;
            }

            my $space = index($buf, ' ', $pos);
            my $endline = index($buf, "\n", $pos);

            if ($space < 0) {
                push @array, substr($buf, $pos, $endline - $pos);
                $pos = $endline;
                next;
            }

            if ($endline < 0) {
                push @array, substr($buf, $pos, $space - $pos);
                $pos = $space;
                next;
            }

            if ($endline < $space) {
                push @array, substr($buf, $pos, $endline - $pos);
                $pos = $endline;
                next;
            }

            if ($space < $endline) {
                push @array, substr($buf, $pos, $space - $pos);
                $pos = $space;
                next;
            }

            die "shouldn't get here";
        }

        $linecb->(@array);

        $buf = '';
    }
    close(FH);

    return 'ok';
}

sub run_dbcommand
{
    my ($self, $dbname, $engine, @items) = @_;
    my @array;
    $self->run_dbcommand_cb(sub { push @array, @_ }, $dbname, $engine, @items);
    return @array;
}

sub read_mailboxes_db
{
    my ($self, $params) = @_;

    # run ctl_mboxlist -d to dump mailboxes.db to a file
    my $outfile = $params->{outfile}
                  || $self->get_basedir() . "/$$-ctl_mboxlist.out";
    $self->run_command({
        cyrus => 1,
        redirects => {
            stdout => $outfile,
        },
    }, 'ctl_mboxlist', '-d');

    return JSON::decode_json(slurp_file($outfile));
}

sub run_cyr_info
{
    my ($self, @args) = @_;

    my $filename = $self->{basedir} . "/cyr_info.out";

    $self->run_command({
            cyrus => 1,
            redirects => { stdout => $filename },
        },
        'cyr_info',
        # we get -C for free
        '-M', $self->_master_conf(),
        @args
    );

    open RESULTS, '<', $filename
        or die "Cannot open $filename for reading: $!";
    my @res = readline(RESULTS);
    close RESULTS;

    if ($args[0] eq 'proc') {
        # if we see any of our fake daemons, no we didn't
        my @fakedaemons = qw(fakesaslauthd fakeldapd);
        my $pattern = q{\b(?:} . join(q{|}, @fakedaemons) . q{)\b};
        my $re = qr{$pattern};
        @res = grep { $_ !~ m/$re/ } @res;
    }

    return @res;
}

sub make_folder_intermediate
{
    my ($self, $uniqueid) = @_;
    my $value;

    # stop service while tinkering
    $self->stop();
    $self->{re_use_dir} = 1;

    my $basedir = $self->get_basedir();
    my $mailboxes_db = "$basedir/conf/mailboxes.db";
    my $format = $self->{config}->get('mboxlist_db');

    my $I_key = "I$uniqueid";
    (undef, $value) = $self->run_dbcommand($mailboxes_db, $format,
                                           [ 'SHOW', $I_key ]);
    my $I = Cyrus::DList->parse_string($value)->as_perl;

    my $N_key = 'N' . $I->{N};
    (undef, $value) = $self->run_dbcommand($mailboxes_db, $format,
                                           [ 'SHOW', $N_key ]);
    my $N = Cyrus::DList->parse_string($value)->as_perl;

    # make sure it's something we can convert
    die "must be MBTYPE_EMAIL" if $I->{T} ne 'e';
    die "must be MBTYPE_EMAIL" if $N->{T} ne 'e';

    # fiddle mailboxes.db records to say its intermediate
    $I->{T} = q{i};
    my $new_I = Cyrus::DList->new_perl('', $I);
    $self->run_dbcommand($mailboxes_db, $format,
                         [ 'SET', $I_key, $new_I->as_string() ]);
    $N->{T} = q{i};
    my $new_N = Cyrus::DList->new_perl('', $N);
    $self->run_dbcommand($mailboxes_db, $format,
                         [ 'SET', $N_key, $new_N->as_string() ]);

    # fiddle filesystem stuff
    my ($a, $b) = (substr($uniqueid, 0, 1), substr($uniqueid, 1, 1));
    my $data = "$basedir/data/uuid/$a/$b/$uniqueid";
    my $lock = "$basedir/conf/lock/$uniqueid.lock";
    remove_tree($data, $lock, { safe => 1 });

    # bring service back up
    $self->getsyslog();
    $self->start();
}

1;
