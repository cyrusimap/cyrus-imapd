package Cassandane::Tiny;
use strict;
use warnings;

sub import {
  no warnings 'once';
  $Cassandane::Tiny::Loader::RELOADED = 1;
  return;
}

1;
