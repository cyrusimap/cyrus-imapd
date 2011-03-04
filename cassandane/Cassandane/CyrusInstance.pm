#!/usr/bin/perl

package Cassandane::CyrusInstance;
use strict;
use warnings;
use File::Path qw(mkpath rmtree);
use File::Find qw(find);
use POSIX qw(geteuid);
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
	print MASTER ' cmd="' . $srv->{binary} . ' -C ' .  $self->_imapd_conf() . '"';
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
	$self->{cyrus_prefix} . '/bin/ctl_mboxlist',
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
	$self->{cyrus_prefix} . '/bin/reconstruct',
	'-C', $self->_imapd_conf(),
	$mboxname
    );
    system(@cmd);
}

sub _start_master
{
    my ($self) = @_;
    my @cmd =
    (
	$self->{cyrus_prefix} . '/bin/master',
	'-l', '255',
	'-p', $self->{basedir} . '/run/cyrus.pid',
	'-d',
	'-C', $self->_imapd_conf(),
	'-M', $self->_master_conf(),
    );
    system(@cmd);
    sleep(3);
    # TODO: check for the pid file etc
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

sub stop
{
    my ($self) = @_;

    xlog "stop";
# TODO: shut down the master and any other processes
#     rmtree $self->{basedir};
}

1;
