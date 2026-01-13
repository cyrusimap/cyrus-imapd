package Cassandane::Tiny;
use strict;
use warnings;

use Test::Deep ();
use Test::Deep::Hashbag ();
use Import::Into ();

sub import {
  my $caller = caller;

  no warnings 'once';
  $Cassandane::Tiny::Loader::RELOADED = 1;

  # Everyone gets strict and warnings
  strict->import();
  warnings->import();

  Test::Deep->import::into($caller, ':v1');
  Test::Deep::Hashbag->import::into($caller);

  return;
}

1;
