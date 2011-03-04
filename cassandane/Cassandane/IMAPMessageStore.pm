#!/usr/bin/perl

package Cassandane::IMAPMessageStore;
use strict;
use warnings;
use Mail::IMAPTalk;
use Cassandane::Util::Log;
use Cassandane::Util::DateTime qw(to_rfc822);
# use Data::Dumper;
use overload qw("") => \&as_string;

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
	banner => undef,
	# state for streaming read
	next_uid => undef,
	last_uid => undef,
	last_batch_uid => undef,
	batch => undef,
	fetch_attrs => { 'body.peek[]' => 1 },
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

    $self->{client}->logout()
	if defined $self->{client};
    $self->{client} = undef;

    my $client = Mail::IMAPTalk->new(
			    Server => $self->{host},
			    Port => $self->{port}
			)
	or die "Cannot connect to server \"$self->{host}:$self->{port}\": $@";

    my $banner = $client->get_response_code('remainder');
    $client->login($self->{username}, $self->{password})
	or die "Cannot login to server \"$self->{host}:$self->{port}\": $@";

    $client->set_tracing(1)
	if $self->{verbose};
    $client->parse_mode(Envelope => 1);

    $self->{client} = $client;
    $self->{banner} = $banner;
}

sub disconnect
{
    my ($self) = @_;

    $self->{client}->logout()
	if defined $self->{client};
    $self->{client} = undef;
}

sub _select
{
    my ($self) = @_;

    if ($self->{client}->state() == Mail::IMAPTalk::Selected)
    {
	$self->{client}->unselect()
	    or die "Cannot unselect: $@";
    }
    return $self->{client}->select($self->{folder});
}

sub write_begin
{
    my ($self) = @_;
    my $r;

    $self->_connect();

    $r = $self->_select();
    if (!defined $r)
    {
	die "Cannot select folder \"$self->{folder}\": $@"
	    unless $self->{client}->get_last_error() =~ m/does not exist/;
	$self->{client}->create($self->{folder})
	    or die "Cannot create folder \"$self->{folder}\": $@"
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
}

sub set_fetch_attributes
{
    my ($self, @attrs) = @_;

    $self->{fetch_attrs} = { 'body.peek[]' => 1 };
    foreach my $attr (@attrs)
    {
	$attr = lc($attr);
	next
	    unless ($attr =~ m/^[a-z0-9.\[\]<>]+$/);
	next
	    if ($attr =~ m/^body/);
	$self->{fetch_attrs}->{$attr} = 1;
    }
}

sub read_begin
{
    my ($self) = @_;
    my $r;

    $self->_connect();

    $self->_select()
	or die "Cannot select folder \"$self->{folder}\": $@";

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

	    # xlog "found uid=$uid in batch";
	    # xlog "rr=" . Dumper($rr);
	    my $raw = $rr->{'body'};
	    delete $rr->{'body'};
	    return Cassandane::Message->new(raw => $raw, attrs => $rr);
	}
	$self->{batch} = undef;

	# xlog "batch empty or no batch available";

	for (;;)
	{
	    my $first_uid = $self->{next_uid};
	    return undef
		if $first_uid > $self->{last_uid};  # EOF
	    my $last_uid = $first_uid + $BATCHSIZE - 1;
	    $last_uid = $self->{last_uid}
		if $last_uid > $self->{last_uid};
	    # xlog "fetching batch range $first_uid:$last_uid";
	    my $attrs = join(' ', keys %{$self->{fetch_attrs}});
	    $self->{batch} = $self->{client}->fetch("$first_uid:$last_uid",
						    "($attrs)");
	    $self->{last_batch_uid} = $last_uid;
	    last if (scalar $self->{batch} > 0);
	    $self->{next_uid} = $last_uid + 1;
	}
	# xlog "have a batch, next_uid=$self->{next_uid}";
    }

    return undef;
}

sub read_end
{
    my ($self) = @_;

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

sub get_server_name
{
    my ($self) = @_;

    $self->_connect();

    # Cyrus returns the servername config variable in the first
    # word of the untagged OK reponse sent on connection.  We
    # Capture the non-response code part of that in {banner}.
    # which looks like
    # slott02 Cyrus IMAP git2.5.0+0-git-work-6640 server ready
    my ($servername) = ($self->{banner} =~ m/^(\S+)\s+Cyrus\s+IMAP\s+/);
    return $servername;
}

sub as_string
{
    my ($self) = @_;

    return 'imap://' . $self->{host} . ':' . $self->{port} . '/' .  $self->{folder};
}

sub set_folder
{
    my ($self, $folder) = @_;

    if ($self->{folder} ne $folder)
    {
	$self->{folder} = $folder;
    }
}

1;
