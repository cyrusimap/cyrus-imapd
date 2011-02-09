#!/usr/bin/perl

package Cassandane::IMAPMessageStore;
use strict;
use warnings;
use Mail::IMAPTalk;
use Cassandane::Util::DateTime qw(to_rfc822);
# use Data::Dumper;

# TODO: isa Cassandane::MessageStore

our $BATCHSIZE = 10;

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
	# state for streaming read
	next_uid => undef,
	last_uid => undef,
	last_batch_uid => undef,
	batch => undef,
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
	if (defined $self->{client} &&
	    ($self->{client}->state() == Mail::IMAPTalk::Authenticated ||
	     $self->{client}->state() == Mail::IMAPTalk::Selected));

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

    $self->{client} = $client;
}

sub _disconnect
{
    my ($self) = @_;

    $self->{client}->logout();
    $self->{client} = undef;
}

sub write_begin
{
    my ($self) = @_;
    my $r;

    $self->_connect();

    $r = $self->{client}->select($self->{folder});
    if (!$r && $self->{client}->get_last_error() =~ m/does not exist/)
    {
	$r = $self->{client}->create($self->{folder});
    }
    if (!$r)
    {
	die "Cannot select folder \"$self->{folder}\": $@";
    }

}

sub write_message
{
    my ($self, $msg) = @_;

    $self->{client}->append($self->{folder},
			    { Literal => $msg->as_string() } );
}

sub write_end
{
    my ($self) = @_;

    $self->_disconnect();
}

sub read_begin
{
    my ($self) = @_;
    my $r;

    $self->_connect();

    $r = $self->{client}->select($self->{folder});
    if (!$r)
    {
	die "Cannot select folder \"$self->{folder}\": $@";
    }
    $self->{next_uid} = 1;
    $self->{last_uid} = -1 + $self->{client}->get_response_code('uidnext');
    $self->{last_batch_uid} = undef;
    $self->{batch} = undef;
}

sub read_message
{
    my ($self, $msg) = @_;

    for (;;)
    {
	while (defined $self->{batch})
	{
	    my $uid = $self->{next_uid};
	    last if $uid > $self->{last_batch_uid};
	    $self->{next_uid}++;
	    my $rr = $self->{batch}->{$uid};
	    next unless defined $rr;
	    delete $self->{batch}->{$uid};

	    # printf STDERR "XXX found uid=$uid in batch\n";
	    # printf STDERR "rr=%s\n", Dumper($rr);
	    return Cassandane::Message->new(
				raw => $rr->{'body'},
				uid => $rr->{'uid'},
				internaldate => $rr->{'internaldate'},
			    );
	}
	$self->{batch} = undef;

	# printf STDERR "XXX batch empty or no batch available\n";

	for (;;)
	{
	    my $first_uid = $self->{next_uid};
	    return undef
		if $first_uid > $self->{last_uid};  # EOF
	    my $last_uid = $first_uid + $BATCHSIZE - 1;
	    $last_uid = $self->{last_uid}
		if $last_uid > $self->{last_uid};
	    # printf STDERR "XXX fetching batch range $first_uid:$last_uid\n";
	    $self->{batch} = $self->{client}->fetch("$first_uid:$last_uid",
						    '(UID INTERNALDATE BODY.PEEK[])');
	    $self->{last_batch_uid} = $last_uid;
	    last if (scalar $self->{batch} > 0);
	    $self->{next_uid} = $last_uid + 1;
	}
	# printf STDERR "XXX have a batch, next_uid=$self->{next_uid}\n";
    }

    return undef;
}

sub read_end
{
    my ($self) = @_;

    $self->_disconnect();
    $self->{next_uid} = undef;
    $self->{last_uid} = undef;
    $self->{last_batch_uid} = undef;
    $self->{batch} = undef;
}

sub remove
{
    my ($self) = @_;

    $self->_connect();
    my $r = $self->{client}->delete($self->{folder});
    die "IMAP DELETE failed: $@"
	if (!defined $r && !($self->{client}->get_last_error() =~ m/does not exist/));
}

sub get_client
{
    my ($self) = @_;

    $self->_connect();
    return $self->{client};
}

1;
