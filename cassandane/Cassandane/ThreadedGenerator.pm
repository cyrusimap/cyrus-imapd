#!/usr/bin/perl

package Cassandane::ThreadedGenerator;
use strict;
use warnings;
use base qw(Cassandane::Generator);
use Cassandane::Address;
use Cassandane::Message;
use Cassandane::Util::Log;
use Cassandane::Util::Words;

my $NTHREADS = 5;
my $NMESSAGES = 20 * $NTHREADS;
my $DELTAT = 300;   # seconds
my $FINISH_CHANCE = 0.08;

sub new
{
    my $class = shift;
    my $self = $class->SUPER::new(@_);

    $self->{nmessages} = $NMESSAGES;
    $self->{deltat} = $DELTAT;

    $self->{threads} = [];
    for (my $i = 1 ; $i <= $NTHREADS ; $i++)
    {
	my $thread =
	{
	    id => $i,
	    subject => ucfirst(random_word()) . " " . random_word(),
	    last_message => undef,
	};
	push(@{$self->{threads}}, $thread);
    }

    $self->{next_date} = DateTime->now->epoch -
		    $self->{deltat} * ($self->{nmessages}+1);

    return $self;
}

sub _choose_thread
{
    my ($self) = @_;

    my $i = int(rand(scalar(@{$self->{threads}})));
    my $thread = $self->{threads}->[$i];

    my $dice = rand;
    if ($dice <= $FINISH_CHANCE)
    {
	# detach from the generator...we won't find it again
	splice(@{$self->{threads}}, $i, 1);
    }

    return $thread;
}

#
# Generate a single email.
# Args: Generator, (param-key => param-value ... )
# Returns: Message ref
#
sub generate
{
    my ($self, %params) = @_;

    return undef
	if (!$self->{nmessages});

    my $thread = $self->_choose_thread();
    return undef
	if (!defined $thread);

    my $last = $thread->{last_message};
    if (defined $last)
    {
	$params{subject} = "Re: " . $thread->{subject};
	$params{references} = $last->get_header("Message-ID");
    }
    else
    {
	$params{subject} = $thread->{subject};
    }
    $params{date} = DateTime->from_epoch( epoch => $self->{next_date} );
    $self->{next_date} += $self->{deltat};

    my $msg = $self->SUPER::generate(%params);
    $msg->add_header('X-Cassandane-Thread', $thread->{id});
    $thread->{last_message} = $msg;
    $self->{nmessages}--;

    return $msg;
}

# TODO: test that both References: and In-Reply-To: are tracked in the server
# TODO: test that Subject: isnt tracked in the server

1;
