package Cassandane::Tiny;
use strict;
use warnings;

sub import {
  $Cassandane::Tiny::Loader::RELOADED = 1;
  return;
}

1;
