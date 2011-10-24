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
use Time::HiRes qw(sleep gettimeofday tv_interval);
use DateTime;
use BSD::Resource;
use Cwd qw(abs_path getcwd);
use Cassandane::Util::DateTime qw(to_iso8601);
use Cassandane::Util::Log;
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
	services => {},
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

sub add_service
{
    my ($self, $name, %params) = @_;

    die "Already have a service named \"$name\""
	if defined $self->{services}->{$name};

    my $srv = Cassandane::ServiceFactory->create($name, %params);
    $self->{services}->{$name} = $srv;
    return $srv;
}

sub add_services
{
    my ($self, @names) = @_;
    foreach my $n (@names)
    {
	$self->add_service($n);
    }
}

sub get_service
{
    my ($self, $name) = @_;
    return $self->{services}->{$name};
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

sub _generate_master_conf
{
    my ($self) = @_;

    my $filename = $self->_master_conf();
    open MASTER,'>',$filename
	or die "Cannot open $filename for writing: $!";
    print MASTER "SERVICES {\n";

    foreach my $srv (values %{$self->{services}})
    {
	my $mp = $srv->master_params();

	# Fix up {cmd}
	my $bin = shift @{$mp->{cmd}};
	$mp->{cmd} = join(' ',
	    $self->_binary($bin),
	    '-C', $self->_imapd_conf(),
	    @{$mp->{cmd}}
	);

	print MASTER "    $srv->{name}";
	while (my ($k, $v) = each %$mp)
	{
	    $v = "\"$v\""
		if ($v =~ m/\s/);
	    print MASTER " $k=$v";
	}
	print MASTER "\n";
    }

    print MASTER "}\n";
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

sub _timed_wait
{
    my ($condition, %p) = @_;
    $p{delay} = 0.010		# 10 millisec
	unless defined $p{delay};
    $p{maxwait} = 20.0
	unless defined $p{maxwait};
    $p{description} = 'unknown condition'
	unless defined $p{description};

    my $start = [gettimeofday()];
    my $delayed = 0;
    while ( ! $condition->() )
    {
	die "Timed out waiting for " . $p{description}
	    if (tv_interval($start, [gettimeofday()]) > $p{maxwait});
	sleep($p{delay});
	$delayed = 1;
	$p{delay} *= 1.5;	# backoff
    }

    xlog "_timed_wait: waited " .
	tv_interval($start, [gettimeofday()]) .
	" sec for " .
	$p{description}
	if ($delayed);
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
    unlink $self->_pid_file();
    # Start master daemon
    $self->run_command({ cyrus => 1 }, @cmd);

    # wait until the pidfile exists and contains a PID
    # that we can verify is still alive.
    xlog "_start_master: waiting for PID file";
    _timed_wait(sub { $self->_read_pid_file($self->_pid_file()) },
	        description => "the master PID file to exist");
    xlog "_start_master: PID file present and correct";

    # Wait until all the defined services are reported as listening.
    # That doesn't mean they're ready to use but it means that at least
    # a client will be able to connect(), although the first response
    # might be a bit slow.
    xlog "_start_master: PID waiting for services";
    foreach my $srv (values %{$self->{services}})
    {
	next unless $srv->{port} =~ m/^\d+$/;
	_timed_wait(sub { $srv->is_listening() },
	        description => $srv->address() . " to be in LISTEN state");
    }
    xlog "_start_master: all services listening";
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
	my $owner = "cassandane";

	xlog "create user $owner";
	my $adminstore = $self->get_service('imap')->create_store(username => 'admin');
	my $adminclient = $adminstore->get_client();
	$adminclient->create("user.$owner");
	$adminclient->setacl("user.$owner", admin => 'lrswipkxtecda');
	$adminclient->setacl("user.$owner", $owner => 'lrswipkxtecd');
	$adminclient->setacl("user.$owner", anyone => 'p');
    }
}

sub _stop_pid
{
    my ($pid) = @_;

    # try to be nice
    xlog "_stop_pid: sending SIGQUIT to $pid";
    kill(SIGQUIT, $pid);
    eval {
	_timed_wait(sub { kill(0, $pid) == 0 });
    };
    if ($@)
    {
	# Timed out -- No More Mr Nice Guy
	xlog "_stop_pid: sending SIGTERM to $pid";
	kill(SIGTERM, $pid);
    }
}

sub stop
{
    my ($self) = @_;

    return if ($self->{persistent});
    return if ($self->{_stopped});
    $self->{_stopped} = 1;

    xlog "stop";

    my $pid = $self->_read_pid_file($self->_pid_file());
    _stop_pid($pid) if defined $pid;
    # Note: no need to reap this daemon which is not our child anymore

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
	    xlog "cleaning up $pid";
	    kill(SIGKILL, $pid);
	}
    }
}

sub _setup_for_deliver
{
    my ($self) = @_;

    $self->add_service('lmtp',
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
	    $self->{_children}->{$fh} = "(binary $binary pid $pid)";
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
	    $self->{_children}->{$pid} = "(binary $binary pid $pid)";
	    return $pid;
	}
    }

    # child process

    $ENV{CASSANDANE_CYRUS_PREFIX} = $self->{cyrus_prefix};
    $ENV{CASSANDANE_PREFIX} = getcwd();
    $ENV{CASSANDANE_BASEDIR} = $self->{basedir};

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

    my $desc = $self->{_children}->{$key} || "unknown";
    delete $self->{_children}->{$key};

    if (WIFSIGNALED($status))
    {
	my $sig = WTERMSIG($status);
	die "child process $desc terminated by signal $sig";
    }
    elsif (WIFEXITED($status))
    {
	my $code = WEXITSTATUS($status);
	die "child process $desc exited with code $code"
	    if $code != 0;
    }
    else
    {
	die "WTF? Cannot decode wait status $status";
    }
    return 0;
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

    _timed_wait(sub { return (! -f $filename); },
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
