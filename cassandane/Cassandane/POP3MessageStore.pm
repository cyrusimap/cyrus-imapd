#!/usr/bin/perl

package Cassandane::POP3MessageStore;
use strict;
use warnings;
use Net::POP3;
# use Cassandane::Util::DateTime qw(to_rfc822);
# use Data::Dumper;

# TODO: isa Cassandane::MessageStore

sub new
{
    my $class = shift;
    my %params = @_;
    my $self = {
	host => 'localhost',
	port => 110,
	folder => 'INBOX',
	username => undef,
	password => undef,
	verbose => 0,
	client => undef,
	# state for streaming read
	next_id => undef,
	last_id => undef,
    };

    $self->{host} = $params{host}
	if defined $params{host};
    $self->{port} = 0 + $params{port}
	if defined $params{port};
    $self->{folder} = $params{folder}
	if defined $params{folder};
    $self->{username} = $params{username}
	if defined $params{username};
    $self->{password} = $params{password}
	if defined $params{password};
    $self->{verbose} = 0 + $params{verbose}
	if defined $params{verbose};

    bless $self, $class;
    return $self;
}

sub _connect
{
    my ($self) = @_;

    # if already successfully connected, do nothing
    return
	if (defined $self->{client});

    # printf STDERR "_connect: creating POP3 object\n";
    my %opts;
    $opts{Debug} = $self->{verbose}
	if $self->{verbose};
    my $client = Net::POP3->new("$self->{host}:$self->{port}", %opts)
	or die "Cannot create Net::POP3 object";

    my ($uu, $ud) = split(/@/, $self->{username});

    $ud = (defined $ud ? "\@$ud" : "");

    my $ff = $self->{folder};
    if ($ff =~ m/^inbox$/i)
    {
	$ff = '';
    }
    elsif ($ff =~ m/^inbox\./i)
    {
	$ff =~ s/^inbox\./+/i;
    }
    else
    {
	$ff = "+$ff";
    }

    my $pop3_username = "$uu$ff$ud";
    # printf STDERR "_connect: pop3_username=\"%s\"\n", $pop3_username;
    # printf STDERR "_connect: password=\"%s\"\n", $self->{password};

    my $res = $client->login($pop3_username, $self->{password})
	or die "Cannot login via POP3";
    $res = 0 if ($res eq '0E0');
    $res = 0 + $res;

    # printf STDERR "_connect: found %u messages\n", $res;

    $self->{last_id} = $res;
    $self->{client} = $client;
}

sub _disconnect
{
    my ($self) = @_;

    $self->{client}->quit();
    $self->{client} = undef;
}

sub write_begin
{
    my ($self) = @_;

    die "cannot write messages to POP3 server";
}

sub write_message
{
    my ($self, $msg) = @_;

    die "cannot write messages to POP3 server";
}

sub write_end
{
    my ($self) = @_;

    die "cannot write messages to POP3 server";
}

sub read_begin
{
    my ($self) = @_;
    my $r;

    $self->_connect();
    $self->{next_id} = 1;
}

sub read_message
{
    my ($self, $msg) = @_;

    my $id = $self->{next_id};
    return undef
	if ($id > $self->{last_id});
    $self->{next_id}++;

    return Cassandane::Message->new(fh => $self->{client}->getfh($id));
}

sub read_end
{
    my ($self) = @_;

    $self->_disconnect();
    $self->{next_id} = undef;
}

1;
