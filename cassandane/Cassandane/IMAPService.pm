#!/usr/bin/perl

package Cassandane::IMAPService;
use strict;
use warnings;
use base qw(Cassandane::Service);
use Cassandane::Util::Log;

sub new
{
    my $class = shift;
    my $self = $class->SUPER::new(@_);
    return $self;
}

# Return a hash of parameters suitable for passing
# to MessageStoreFactory::create.
sub store_params
{
    my ($self) = @_;

    return
    {
	type => 'imap',
	host => $self->{host},
	port => $self->{port},
	folder => 'inbox.CassandaneTestFolder',
	username => 'cassandane',
	password => 'testpw',
	verbose => get_verbose,
    };
}

1;
