#!/usr/bin/perl

package Cassandane::Service;
use strict;
use warnings;
use Cassandane::Util::Log;
use Cassandane::MessageStoreFactory;

my $next_port = 9100;
sub alloc_port
{
    my ($class) = @_;

    my $port = $next_port;
    $next_port++;
    return $port;
}

sub new
{
    my $class = shift;
    my $name = shift;
    my %params = @_;

    die "No name specified"
	unless defined $name;

    my $self =
    {
	name => $name,
	binary => undef,
	host => '127.0.0.1',
	port => undef,
    };

    $self->{binary} = $params{binary}
	if defined $params{binary};
    $self->{host} = $params{host}
	if defined $params{host};
    $self->{port} = $params{port}
	if defined $params{port};

    $self->{port} = Cassandane::Service->alloc_port()
	unless defined $self->{port};
    die "No binary specified"
	unless defined $self->{binary};

    bless $self, $class;
    return $self;
}

# Return a hash of parameters suitable for passing
# to MessageStoreFactory::create.
sub store_params
{
    my ($self) = @_;

    return
    {
	type => 'unknown',
	host => $self->{host},
	port => $self->{port},
	verbose => get_verbose,
    };
}

sub create_store
{
    my ($self) = @_;
    return Cassandane::MessageStoreFactory->create(%{$self->store_params()});
}

sub address
{
    my ($self) = @_;
    return "$self->{host}:$self->{port}";
}

sub is_listening
{
    my ($self) = @_;

    # hardcoded for TCP4
    die "Sorry, the host argument \"$self->{host}\" must be a numeric IP address"
	unless ($self->{host} =~ m/^\d+\.\d+\.\d+\.\d+$/);
    die "Sorry, the port argument \"$self->{port}\" must be a numeric TCP port"
	unless ($self->{port} =~ m/^\d+$/);

    my @cmd = (
	'netstat',
	'-l',		# listening ports only
	'-n',		# numeric output
	'-Ainet',	# AF_INET only
	);

    open NETSTAT,'-|',@cmd
	or die "Cannot run netstat to check for port $self->{port}: $!";
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
	next unless $a[3] eq $self->address();
	$found = 1;
	last;
    }
    close NETSTAT;

    xlog "is_listening: service $self->{name} is " .
	 "listening on " . $self->address()
	if ($found);

    return $found;
}

1;
