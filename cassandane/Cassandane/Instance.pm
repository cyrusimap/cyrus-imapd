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

package Cassandane::Instance;
use strict;
use warnings;
use File::Path qw(mkpath rmtree);
use File::Find qw(find);
use File::Basename;
use POSIX qw(geteuid :signal_h :sys_wait_h);
use DateTime;
use BSD::Resource;
use Cwd qw(abs_path getcwd);
use Cassandane::Util::DateTime qw(to_iso8601);
use Cassandane::Util::Log;
use Cassandane::Util::Wait;
use Cassandane::Config;
use Cassandane::Service;
use Cassandane::ServiceFactory;
use Cassandane::Cassini;

my $rootdir;
my $stamp;
my $next_unique = 1;
my %defaults =
(
    valgrind => 0,
);

sub new
{
    my $class = shift;
    my %params = @_;

    my $cassini = Cassandane::Cassini->instance();
    $rootdir = $cassini->val('cassandane', 'rootdir', '/var/tmp/cass')
	unless defined $rootdir;

    my $self = {
	name => undef,
	basedir => undef,
	installation => 'default',
	cyrus_prefix => undef,
	config => Cassandane::Config->default()->clone(),
	starts => [],
	services => {},
	events => [],
	re_use_dir => 0,
	setup_mailbox => 1,
	persistent => 0,
	valgrind => $defaults{valgrind},
	_children => {},
	_stopped => 0,
	description => 'unknown',
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
    $self->{config} = $params{config}->clone()
	if defined $params{config};
    $self->{re_use_dir} = $params{re_use_dir}
	if defined $params{re_use_dir};
    $self->{setup_mailbox} = $params{setup_mailbox}
	if defined $params{setup_mailbox};
    $self->{valgrind} = $params{valgrind}
	if defined $params{valgrind};
    $self->{persistent} = $params{persistent}
	if defined $params{persistent};
    $self->{description} = $params{description}
	if defined $params{description};

    # XXX - get testcase name from caller, to apply even finer
    # configuration from cassini ?

    if (!defined $stamp)
    {
	$stamp = to_iso8601(DateTime->now);
	$stamp =~ s/.*T(\d+)Z/$1/;
    }

    if (!defined $self->{name})
    {
	for (;;)
	{
	    $self->{name} = $stamp . $next_unique;
	    $next_unique++;
	    last unless -d "$rootdir/$self->{name}";
	}
    }
    $self->{basedir} = $rootdir . '/' . $self->{name}
	unless defined $self->{basedir};
    $self->{config}->set_variables(
		name => $self->{name},
		basedir => $self->{basedir},
		cyrus_prefix => $self->{cyrus_prefix},
		prefix => getcwd(),
	    );

    bless $self, $class;
    xlog "$self->{description}: basedir $self->{basedir}";
    return $self;
}

sub set_defaults
{
    my ($class, %params) = @_;

    foreach my $p (qw(valgrind))
    {
	$defaults{$p} = $params{$p}
	    if defined $params{$p};
    }
}

sub cleanup_leftovers
{
    my $cassini = Cassandane::Cassini->instance();
    $rootdir = $cassini->val('cassandane', 'rootdir', '/var/tmp/cass')
	unless defined $rootdir;

    return if (!-d $rootdir);
    opendir ROOT, $rootdir
	or die "Cannot open directory $rootdir for reading: $!";
    my @dirs;
    while (my $e = readdir(ROOT))
    {
	push(@dirs, $_) if ($e =~ m/^[0-9]{7,}$/);
    }
    closedir ROOT;

    map
    {
	xlog "Cleaning up old basedir $rootdir/$_";
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
	if (!grep { $_->{name} eq 'recover'; } @{$self->{starts}})
	{
	    $self->add_start(name => 'recover',
			     argv => [ qw(ctl_cyrusdb -r) ]);
	}
    }

    my $srv = Cassandane::ServiceFactory->create(%params);
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

sub add_start
{
    my ($self, %params) = @_;
    push(@{$self->{starts}}, Cassandane::MasterStart->new(%params));
}

sub add_event
{
    my ($self, %params) = @_;
    push(@{$self->{events}}, Cassandane::MasterEvent->new(%params));
}

sub _binary
{
    my ($self, $name) = @_;

    my @cmd;
    my $valground = 0;

    if ($self->{valgrind} &&
        !($name =~ m/\.pl$/) &&
	!($name =~ m/^\//))
    {
	my $valgrind_logdir = $self->{basedir} . '/vglogs';
	my $valgrind_suppressions = abs_path('vg.supp');
	mkpath $valgrind_logdir
	    unless ( -d $valgrind_logdir );
	push(@cmd,
	    '/usr/bin/valgrind',
	    '-q',
	    "--log-file=$valgrind_logdir/$name.%p",
	    "--suppressions=$valgrind_suppressions",
	    '--tool=memcheck',
	    '--leak-check=full'
	);
	$valground = 1;
    }

    my $bin = $name;
    $bin = $self->{cyrus_prefix} . '/bin/' . $bin
	unless $bin =~ m/^\//;
    push(@cmd, $bin);

    my $cassini = Cassandane::Cassini->instance();
    if (!$valground && $cassini->val('gdb', $name, 'no') =~ m/^yes$/i)
    {
	xlog "Will run binary $name under gdb due to cassandane.ini";
	xlog "Look in syslog for helpful instructions from gdbtramp";
	push(@cmd, '-D');
    }

    return @cmd;
}

sub _imapd_conf
{
    my ($self) = @_;

    return $self->{basedir} . '/conf/imapd.conf';
}

sub _master_conf
{
    my ($self) = @_;

    return $self->{basedir} . '/conf/cyrus.conf';
}

sub _pid_file
{
    my ($self) = @_;

    return $self->{basedir} . '/run/cyrus.pid';
}

sub _build_skeleton
{
    my ($self) = @_;

    my @subdirs =
    (
	'conf',
	'conf/cores',
	'conf/db',
	'conf/sieve',
	'conf/socket',
	'conf/proc',
	'conf/log',
	'conf/log/admin',
	'conf/log/cassandane',
	'lock',
	'data',
	'meta',
	'run',
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
    my ($self) = @_;

    $self->{config}->generate($self->_imapd_conf());
}

sub _emit_master_entry
{
    my ($self, $entry) = @_;

    my $params = $entry->master_params();
    my $name = delete $params->{name};

    # Convert ->{argv} to ->{cmd}
    my $argv = delete $params->{argv};
    die "No argv argument"
	unless defined $argv;
    my $bin = shift @$argv;
    $params->{cmd} = join(' ',
	$self->_binary($bin),
	'-C', $self->_imapd_conf(),
	@$argv
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
    my $conf = $self->_imapd_conf();
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
    my ($self, $file) = @_;
    my $pid;

    return undef if ( ! -f $file );

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
    foreach my $srv (values %{$self->{services}})
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
	'-p', $self->_pid_file(),
	'-d',
	'-M', $self->_master_conf(),
    );
    if (get_verbose) {
	my $logfile = $self->{basedir} . '/conf/master.log';
	xlog "_start_master: logging to $logfile";
	push(@cmd, '-L', $logfile);
    }
    unlink $self->_pid_file();
    # Start master daemon
    $self->run_command({ cyrus => 1 }, @cmd);

    # wait until the pidfile exists and contains a PID
    # that we can verify is still alive.
    xlog "_start_master: waiting for PID file";
    timed_wait(sub { $self->_read_pid_file($self->_pid_file()) },
	        description => "the master PID file to exist");
    xlog "_start_master: PID file present and correct";

    # Wait until all the defined services are reported as listening.
    # That doesn't mean they're ready to use but it means that at least
    # a client will be able to connect(), although the first response
    # might be a bit slow.
    xlog "_start_master: PID waiting for services";
    foreach my $srv (values %{$self->{services}})
    {
	timed_wait(sub
		{
		    $self->is_running()
			or die "Master no longer running";
		    $srv->is_listening();
		},
	        description => $srv->address() . " to be in LISTEN state");
    }
    xlog "_start_master: all services listening";
}

sub create_user
{
    my ($self, $user, %params) = @_;

    xlog "create user $user";
    my $srv = $self->get_service('imap');
    die "No IMAP service in create_user"
	unless defined $srv;

    my $adminstore = $srv->create_store(username => 'admin');
    my $adminclient = $adminstore->get_client();

    my @mboxes = ( "user.$user" );
    map { push(@mboxes, "user.$user.$_"); } @{$params{subdirs}}
	if ($params{subdirs});

    foreach my $mb (@mboxes)
    {
	$adminclient->create($mb)
	    or die "Cannot create $mb: $@";
	$adminclient->setacl($mb, admin => 'lrswipkxtecda')
	    or die "Cannot setacl for $mb: $@";
	$adminclient->setacl($mb, $user => 'lrswipkxtecd')
	    or die "Cannot setacl for $mb: $@";
	$adminclient->setacl($mb, anyone => 'p')
	    or die "Cannot setacl for $mb: $@";
    }
}

sub start
{
    my ($self) = @_;

    my $created = 0;

    xlog "start";
    if (!$self->{re_use_dir} || ! -d $self->{basedir})
    {
	$created = 1;
	rmtree $self->{basedir};
	$self->_build_skeleton();
	# TODO: system("echo 1 >/proc/sys/kernel/core_uses_pid");
	# TODO: system("echo 1 >/proc/sys/fs/suid_dumpable");
	$self->_generate_imapd_conf();
	$self->_generate_master_conf();
	$self->_fix_ownership();
    }
    $self->_start_master();
    $self->{_stopped} = 0;

    if ($created && $self->{setup_mailbox} && defined $self->get_service('imap'))
    {
	$self->create_user("cassandane");
    }
}

sub _check_valgrind_logs
{
    my ($self) = @_;

    return unless $self->{valgrind};

    my $valgrind_logdir = $self->{basedir} . '/vglogs';
    my $nerrs = 0;

    return unless -d $valgrind_logdir;
    opendir VGLOGS, $valgrind_logdir
	or die "Cannot open directory $valgrind_logdir for reading: $!";
    while (my $_ = readdir VGLOGS)
    {
	next if m/^\./;
	next if m/\.core\./;
	my $log = "$valgrind_logdir/$_";
	next if -z $log;
	$nerrs++;

	xlog "Valgrind errors from file $log";
	open VG, "<$log"
	    or die "Cannot open Valgrind log $log for reading: $!";
	while (<VG>) {
	    chomp;
	    xlog "$_";
	}
	close VG;

    }
    closedir VGLOGS;

    die "Valgrind found errors" if $nerrs;
}

sub _check_cores
{
    my ($self) = @_;

    my $coredir = $self->{basedir} . '/conf/cores';
    my $ncores = 0;

    return unless -d $coredir;
    opendir CORES, $coredir
	or die "Cannot open directory $coredir for reading: $!";
    while (my $_ = readdir CORES)
    {
	next if m/^\./;
	next unless m/^core(\.\d+)?$/;
	my $core = "$coredir/$_";
	next if -z $core;
	$ncores++;

	xlog "Found core file $core";
    }
    closedir CORES;

    die "Core files found in $coredir" if $ncores;
}

# Stop a given PID.  Returns 1 if the process died
# gracefully (i.e. soon after receiving SIGQUIT)
# or wasn't even running beforehand.
sub _stop_pid
{
    my ($pid) = @_;

    # Try to be nice, but leave open the option of not being nice should
    # that be necessary.  The signals we send are:
    #
    # SIGQUIT - The standard Cyrus graceful shutdown signal, should
    #           be handled and propagated by master.
    # SIGILL - Not handled by master; kernel's default action is to
    #	       dump a core.  We use this to try to get a core when
    #	       something is wrong with master.
    # SIGKILL - Hmm, something went wrong with our cunning SIGILL plan,
    #           let's take off and nuke it from orbit.  We just don't
    #           want to leave processes around cluttering up the place.
    #
    my @sigs = ( SIGQUIT, SIGILL, SIGKILL );
    my $r = 1;

    foreach my $sig (@sigs)
    {
	xlog "_stop_pid: sending signal $sig to $pid";
	kill($sig, $pid);
	eval {
	    timed_wait(sub { kill(0, $pid) == 0 });
	};
	last unless $@;
	# Timed out -- No More Mr Nice Guy
	xlog "_stop_pid: failed to shut down pid $pid with signal $sig";
	$r = 0;
    }
    return $r;
}

sub stop
{
    my ($self) = @_;

    return if ($self->{_stopped});
    $self->{_stopped} = 1;

    xlog "stop";

    my $pid = $self->_read_pid_file($self->_pid_file());
    if (defined $pid)
    {
	_stop_pid($pid)
	    or die "Cannot shut down master pid $pid";
    }
    # Note: no need to reap this daemon which is not our child anymore

    $self->_check_valgrind_logs();
    $self->_check_cores();

#     return if ($self->{persistent});
#     rmtree $self->{basedir};
}

sub DESTROY
{
    my ($self) = @_;

    if (!$self->{persistent} && !$self->{_stopped})
    {
	my $pid = $self->_read_pid_file($self->_pid_file());
	if (defined $pid)
	{
	    # clean up any dangling master process
	    _stop_pid($pid);
	}
    }
}

sub is_running
{
    my ($self) = @_;

    my $pid = $self->_read_pid_file($self->_pid_file());
    return 0 unless defined $pid;
    return kill(0, $pid);
}

sub _setup_for_deliver
{
    my ($self) = @_;

    $self->add_service(name => 'lmtp',
		       argv => ['lmtpd', '-a'],
		       port => $self->{basedir} . '/conf/socket/lmtp');
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
    push(@users, @{$params{users}}) if (defined $params{users});
    push(@users, $params{user}) if (defined $params{user});
    push(@users, 'cassandane') if !scalar(@users);
    push(@cmd, @users);

    $self->run_command({
	cyrus => 1,
	redirects => {
	    stdin => \$str
	}
    }, @cmd);
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
#	    are detected.  Default is to 'die' on any event
#	    except exiting with code 0.  The events are:
#
#   exited_normally($child)
#   exited_abnormally($child, $code)
#   signaled($child, $sig)
#
# redirects  hash for I/O redirections
#     stdin     feed stdin from; handles SCALAR data or filename,
#		    /dev/null by default
#     stdout    feed stdout to; /dev/null by default (or is unmolested
#		    if xlog is in verbose mode)
#     stderr    feed stderr to; /dev/null by default (or is unmolested
#		    if xlog is in verbose mode)
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

    my $pid = $self->_fork_command($options, @args);

    return $pid
	if ($options->{background});

    return $self->reap_command($pid);
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

sub stop_command
{
    my ($self, $pid) = @_;
    _stop_pid($pid);
    $self->reap_command($pid);
}

sub stop_command_pidfile
{
    my ($self, $pidfile) = @_;
    my $pid = $self->_read_pid_file($pidfile);
    $self->stop_command($pid)
	if (defined $pid);
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
    my ($self, $binary, $pid, $handlers, $fh) = @_;
    my $key = $fh || $pid;

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

#
# Starts a new process to run a program.
#
# Returns launched $pid; you must call _handle_wait_status() to
#	   decode $?.  Dies on errors.
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
	    # parent process
	    $self->_add_child($binary, $pid, $options->{handlers}, $fh);
	    print $fh ${$data};
	    close ($fh);
	    return $pid;
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
	    $self->_add_child($binary, $pid, $options->{handlers}, undef);
	    return $pid;
	}
    }

    # child process

    $ENV{CASSANDANE_CYRUS_PREFIX} = $self->{cyrus_prefix};
    $ENV{CASSANDANE_PREFIX} = getcwd();
    $ENV{CASSANDANE_BASEDIR} = $self->{basedir};
    $ENV{CASSANDANE_VERBOSE} = 1 if get_verbose();

    my $cd = $options->{workingdir};
    $cd = $self->{basedir} . '/conf/cores'
	unless defined($cd);
    chdir($cd)
	or die "Cannot cd to $cd: $!";

    # ulimit -c 102400
    setrlimit(RLIMIT_CORE, 102400*1024, 102400*1024);

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

    exec @cmd;
    die "Cannot run $binary: $!";
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
sub unpack
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

1;
