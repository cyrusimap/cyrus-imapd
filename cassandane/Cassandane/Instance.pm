#!/usr/bin/perl

package Cassandane::Instance;
use strict;
use warnings;
use File::Path qw(mkpath rmtree);
use File::Find qw(find);
use POSIX qw(geteuid :signal_h);
use Time::HiRes qw(sleep gettimeofday);
use DateTime;
use Cassandane::Util::DateTime qw(to_iso8601);
use Cassandane::Util::Log;
use Cassandane::Config;

my $rootdir = '/var/tmp/cassandane';

sub new
{
    my $class = shift;
    my %params = @_;
    my $self = {
	name => undef,
	basedir => undef,
	cyrus_prefix => '/usr/cyrus',
	config => Cassandane::Config->default()->clone(),
	services => {},
    };

    $self->{name} = $params{name}
	if defined $params{name};
    $self->{basedir} = $params{basedir}
	if defined $params{basedir};
    $self->{cyrus_prefix} = $params{cyrus_prefix}
	if defined $params{cyrus_prefix};
    $self->{config} = $params{config}
	if defined $params{config};

    $self->{name} = 'cass' . to_iso8601(DateTime->now)
	unless defined $self->{name};
    $self->{basedir} = $rootdir . '/' . $self->{name}
	unless defined $self->{basedir};

    bless $self, $class;
    xlog "basedir $self->{basedir}";
    return $self;
}

sub add_service
{
    my ($self, $name, %params) = @_;

    die "Already have a service named \"$name\""
	if defined $self->{services}->{$name};

    my $srv =
    {
	name => $name,
	binary => 'imapd',
	host => '127.0.0.1',
	port => 9143,
    };
    $srv->{binary} = $params{binary}
	if defined $params{binary};
    $srv->{host} = $params{host}
	if defined $params{host};
    $srv->{port} = $params{port}
	if defined $params{port};
    $self->{services}->{$name} = $srv;
}

sub service_params
{
    my ($self, $name) = @_;

    my $srv = $self->{services}->{$name};
    die "No such service \"$name\""
	unless defined $srv;

    die "Can only handle imapd for now"
	unless $srv->{binary} eq "imapd";

    return
    {
	type => 'imap',
	host => $srv->{host},
	port => $srv->{port},
	folder => 'inbox.CassandaneTestFolder',
	username => 'cassandane',
	password => 'testpw',
	verbose => get_verbose,
    };
}

sub _service_is_listening
{
    my ($self, $srv) = @_;

    # hardcoded for TCP4
    die "Sorry, the host argument \"$srv->{host}\" must be a numeric IP address"
	unless ($srv->{host} =~ m/^\d+\.\d+\.\d+\.\d+$/);
    die "Sorry, the port argument \"$srv->{port}\" must be a numeric TCP port"
	unless ($srv->{port} =~ m/^\d+$/);

    my @cmd = (
	'netstat',
	'-l',		# listening ports only
	'-n',		# numeric output
	'-Ainet',	# AF_INET only
	);

    open NETSTAT,'-|',@cmd
	or die "Cannot run netstat to check for port $srv->{port}: $!";
    #     # netstat -ln -Ainet
    #     Active Internet connections (only servers)
    #     Proto Recv-Q Send-Q Local Address           Foreign Address State
    #     tcp        0      0 0.0.0.0:56686           0.0.0.0:* LISTEN
    my $found;
    while (<NETSTAT>)
    {
	chomp;
	my @a = split;
	next unless scalar(@a) == 6;
	next unless $a[0] eq 'tcp';
	next unless $a[5] eq 'LISTEN';
	next unless $a[3] eq "$srv->{host}:$srv->{port}";
	$found = 1;
	last;
    }
    close NETSTAT;

    xlog "_service_is_listening: service $srv->{name} is " .
	 "listening on port $srv->{port}"
	if ($found);

    return $found;
}

sub _binary
{
    my ($self, $name) = @_;

    # TODO: stick in valgrind here.  That's why we return
    # a list rather than a scalar.
    return ( $self->{cyrus_prefix} . '/bin/' . $name );
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
	'lock',
	'data',
	'meta',
	'run',
	'log'
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
    my ($self, $filename) = @_;
    my $conf = $self->{config}->clone();

    $conf->set(
	    servername => $self->{name},
	    syslog_prefix => $self->{name},
	    configdirectory => $self->{basedir} . '/conf',
	    sievedir => $self->{basedir} . '/conf/sieve',
	    defaultpartition => 'default',
	    'partition-default' => $self->{basedir} . '/data',
	    sasl_mech_list => 'PLAIN LOGIN DIGEST-MD5',
	    allowplaintext => 'yes',
	    sasl_pwcheck_method => 'alwaystrue',
	);
    $conf->generate($self->_imapd_conf());
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
	print MASTER '    ' . $srv->{name};
	print MASTER ' cmd="' . $self->_binary($srv->{binary}) . ' -C ' .  $self->_imapd_conf() . '"';
	print MASTER ' listen="' . $srv->{host} . ':' . $srv->{port} .  '"';
	print MASTER "\n";
    }

    print MASTER "}\n";
    close MASTER;
}

sub _fix_ownership
{
    my ($self) = @_;

    return if geteuid() != 0;
    my $uid = getpwnam('cyrus');
    my $gid = getgrnam('root');
    find(sub { chown($uid, $gid, $File::Find::name) }, $self->{basedir});
}

sub _setup_mboxlist
{
    my ($self) = @_;
    my @cmd =
    (
	$self->_binary('ctl_mboxlist'),
	'-C', $self->_imapd_conf(),
	'-u',
    );

    my $owner = 'cassandane';	    # or name@realm
    my $mboxname = "user.$owner";   # or realm!user.owner.whatever
    my $partition = 'default';

    # Construct the default ACL
    my $userperms = 'lrswipkxtecd';
    my @aclbits =
    (
	$owner, $userperms,
	'admin', $userperms . 'a',
	'anyone', 'p',
    );
    my $acl = join("\t", @aclbits);

    open MBOXLIST,'|-',@cmd
	or die "Cannot run ctl_mboxlist to set up mboxlist.db: $!";
    # type 0 is a local mailbox
    # Note the trailing TAB is very important
    printf MBOXLIST "%s\t0 %s %s\t\n",
	    $mboxname,
	    $partition,
	    $acl;
    close MBOXLIST;
}

sub _reconstruct
{
    my ($self) = @_;
    my $owner = 'cassandane';	    # or name@realm
    my $mboxname = "user.$owner";   # or realm!user.owner.whatever
    my @cmd =
    (
	$self->_binary('reconstruct'),
	'-C', $self->_imapd_conf(),
	$mboxname
    );
    system(@cmd);
}

sub _timed_wait
{
    my ($condition, %p) = @_;
    $p{delay} = 0.010		# 10 millisec
	unless defined $p{delay};
    $p{maxwait} = 3.0
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
    }

    xlog "_timed_wait: waited " .
	tv_interval($start, [gettimeofday()]) .
	" sec for " .
	$p{description}
	if ($delayed);
}

sub _read_pid_file
{
    my ($self) = @_;
    my $file = $self->_pid_file();
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
	die "Some process is already listening on $srv->{host}:$srv->{port}"
	    if $self->_service_is_listening($srv);
    }

    # Now start the master process.
    my @cmd =
    (
	$self->_binary('master'),
	'-l', '255',
	'-p', $self->_pid_file(),
	'-d',
	'-C', $self->_imapd_conf(),
	'-M', $self->_master_conf(),
    );
    unlink $self->_pid_file();
    system(@cmd);

    # wait until the pidfile exists and contains a PID
    # that we can verify is still alive.
    xlog "_start_master: waiting for PID file";
    _timed_wait(sub { $self->_read_pid_file() },
	        description => "the master PID file to exist");
    xlog "_start_master: PID file present and correct";

    # Wait until all the defined services are reported as listening.
    # That doesn't mean they're ready to use but it means that at least
    # a client will be able to connect(), although the first response
    # might be a bit slow.
    xlog "_start_master: PID waiting for services";
    foreach my $srv (values %{$self->{services}})
    {
	_timed_wait(sub { $self->_service_is_listening($srv) },
	        description => "port $srv->{port} to be in LISTEN state");
    }
    xlog "_start_master: all services listening";
}

sub start
{
    my ($self) = @_;

    xlog "start";
    rmtree $self->{basedir};
    $self->_build_skeleton();
    # TODO: system("echo 1 >/proc/sys/kernel/core_uses_pid");
    $self->_generate_imapd_conf();
    $self->_generate_master_conf();
    $self->_fix_ownership();
    $self->_setup_mboxlist();
    $self->_reconstruct();
    $self->_start_master();
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

    xlog "stop";

    my $pid = $self->_read_pid_file();
    _stop_pid($pid) if defined $pid;

#     rmtree $self->{basedir};
}

1;
