#!/usr/bin/perl

package Cassandane::IMAPMessageStore;
use strict;
use warnings;
use Mail::IMAPTalk;
use Cassandane::Util::DateTime qw(to_rfc822);

# TODO: isa Cassandane::MessageStore

sub new
{
    my $class = shift;
    my %params = @_;
    my $self = {
	host => 'localhost',
	port => 143,
	folder => 'INBOX',
	username => undef,
	password => undef,
	verbose => 0,
	client => undef,
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

sub begin
{
    my ($self) = @_;
    my $r;

    my $client = Mail::IMAPTalk->new(
			    Server => $self->{host},
			    Port => $self->{port},
			    Username => $self->{username},
			    Password => $self->{password}
			)
	or die "Cannot connect to server \"$self->{host}:$self->{port}\": $@";
    $client->set_tracing(1)
	if $self->{verbose};
    $client->parse_mode(Envelope => 1);

    $r = $client->select($self->{folder});
    if (!$r && $client->get_last_error() =~ m/does not exist/)
    {
	$r = $client->create($self->{folder});
    }
    if (!$r)
    {
	die "Cannot select folder \"$self->{folder}\": $@";
    }

    $self->{client} = $client;
}

sub message
{
    my ($self, $msg) = @_;

    $self->{client}->append($self->{folder},
			    { Literal => $msg->as_string() } );
}

sub end
{
    my ($self) = @_;

    $self->{client}->logout();
    $self->{client} = undef;
}

1;
