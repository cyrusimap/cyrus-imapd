#!/usr/bin/perl

use strict;
use warnings;
package Cassandane::Test::CyrusInstance;
use base qw(Test::Unit::TestCase);
use Cassandane::CyrusInstance;

sub new
{
    my $class = shift;
    my $self = $class->SUPER::new(@_);
    return $self;
}

sub test_basic
{
#     my ($self) = @_;
# 
#     my $ci = Cassandane::CyrusInstance->new();
#     $ci->add_service('imapd');
#     $ci->start();
#     $ci->stop();
}

1;
