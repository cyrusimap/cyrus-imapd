package Cassandane::Tiny;
use strict;
use warnings;

sub import {
  no warnings 'once';
  $Cassandane::Tiny::Loader::RELOADED = 1;

  # Everyone gets strict and warnings
  strict->import();
  warnings->import();

  return;
}

1;
