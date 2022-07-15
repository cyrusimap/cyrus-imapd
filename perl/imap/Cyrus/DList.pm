#!/usr/bin/perl -c
#  Copyright (c) 2017-2022 Fastmail.  All rights reserved.
#
# Author: Bron Gondwana <brong@fastmail.fm>
#
# Redistribution and use in source and binary forms, with or without
# modification, are permitted provided that the following conditions
# are met:
#
# 1. Redistributions of source code must retain the above copyright
#    notice, this list of conditions and the following disclaimer.
#
# 2. Redistributions in binary form must reproduce the above copyright
#    notice, this list of conditions and the following disclaimer in
#    the documentation and/or other materials provided with the
#    distribution.
#
# 3. The name "Carnegie Mellon University" must not be used to
#    endorse or promote products derived from this software without
#    prior written permission. For permission or any other legal
#    details, please contact
#      Office of Technology Transfer
#      Carnegie Mellon University
#      5000 Forbes Avenue
#      Pittsburgh, PA  15213-3890
#      (412) 268-4387, fax: (412) 268-7395
#      tech-transfer@andrew.cmu.edu
#
# 4. Redistributions of any form whatsoever must retain the following
#    acknowledgment:
#    "This product includes software developed by Computing Services
#     at Carnegie Mellon University (http://www.cmu.edu/computing/)."
#
# CARNEGIE MELLON UNIVERSITY DISCLAIMS ALL WARRANTIES WITH REGARD TO
# THIS SOFTWARE, INCLUDING ALL IMPLIED WARRANTIES OF MERCHANTABILITY
# AND FITNESS, IN NO EVENT SHALL CARNEGIE MELLON UNIVERSITY BE LIABLE
# FOR ANY SPECIAL, INDIRECT OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES
# WHATSOEVER RESULTING FROM LOSS OF USE, DATA OR PROFITS, WHETHER IN
# AN ACTION OF CONTRACT, NEGLIGENCE OR OTHER TORTIOUS ACTION, ARISING
# OUT OF OR IN CONNECTION WITH THE USE OR PERFORMANCE OF THIS SOFTWARE.

use strict;
use warnings;

package Cyrus::DList;

use File::Temp;

sub new_kvlist {
  my $class = shift;
  my $key = shift;

  return bless {
    type => 'kvlist',
    key => $key,
    data => [],
  }, ref($class) || $class;
}

sub new_list {
  my $class = shift;
  my $key = shift;

  return bless {
    type => 'list',
    key => $key,
    data => [],
  }, ref($class) || $class;
}

sub new_perl {
  my $class = shift;
  my $key = shift;
  my $val = shift;
  my $Self = $class->new_list(undef);
  $Self->add_perl($key, $val);
  return $Self->{data}[0];
}

sub add_perl {
  my $Self = shift;
  my $key = shift;
  my $val = shift;

  if (not ref($val)) {
    $Self->add_atom($key, $val);
  }

  elsif (ref($val) eq 'ARRAY') {
    my $child = $Self->add_list($key);
    $child->add_perl(undef, $_) for @$val;
  }

  elsif (ref($val) eq 'HASH') {
    my $child = $Self->add_kvlist($key);
    my $order = delete $val->{__kvlist_order};

    if ($order) {
      die "Unknown order " . ref($order) if ref($order) ne 'ARRAY';
      foreach my $k (grep { exists $val->{$_} } @{$order}) {
        $child->add_perl($k, delete $val->{$k});
      }
    }

    $child->add_perl($_, $val->{$_}) for sort keys %$val;
  }

  elsif (ref($val) eq 'REF') {
    my $item = $$val;
    if (ref($item) eq 'ARRAY') {
      $Self->add_file($key, @$item);
    } else {
      die "Unknown file format " . ref($item);
    }
  }

  else {
    die "UNKNOWN $key " . ref($val);
  }
}

sub add_list {
  my $Self = shift;
  my $key = shift;

  die unless $Self->{type} =~ m/list/;

  my $res = bless {
    type => 'list',
    key => $key,
    data => [],
  };
  push @{$Self->{data}}, $res;

  return $res;
}
  

sub add_kvlist {
  my $Self = shift;
  my $key = shift;

  die unless $Self->{type} =~ m/list/;

  my $res = bless {
    type => 'kvlist',
    key => $key,
    data => [],
  };
  push @{$Self->{data}}, $res;

  return $res;
}

sub add_file {
  my $Self = shift;
  my $key = shift;
  my $partition = shift;
  my $guid = shift;
  my $size = shift;
  my $value = shift;

  die unless $Self->{type} =~ m/list/;

  my $res = bless {
    type => 'file',
    key => $key,
    partition => $partition,
    guid => $guid,
    size => $size,
    data => $value,
  };
  push @{$Self->{data}}, $res;

  return $res;
}

sub add_atom {
  my $Self = shift;
  my $key = shift;
  my $value = shift;

  die unless $Self->{type} =~ m/list/;

  my $res = bless {
    type => 'atom',
    key => $key,
    data => $value,
  };
  push @{$Self->{data}}, $res;

  return $res;
}

sub _getastring {
  my $ref = shift;
  return undef if $$ref eq '';
  if ($$ref =~ m/^{/) {
    $$ref =~ s/^{(\d+)\+?}\r?\n//; # strip literal spec
    my $len = $1;
    return substr($$ref, 0, $len, '');
  }
  if ($$ref =~ m/^"/) {
    $$ref =~ s/^"((?:[^"\\]++|\\.)*+)"//;
    return $1;
  }
  return _getword($ref);
}

sub _getword {
  my $ref = shift;
  $$ref =~ s/^([^\ \)]+)//;
  my $res = $1;
  return undef if $res eq 'NIL';
  return $res;
}

# Great - custom magic
sub _parse_string {
  my $Self = shift;
  my $ref = shift;
  my $parsekey = shift;

  my $key = '';

  if ($parsekey) {
    $key = _getword($ref);
    $$ref =~ s/^\s+//;
    die unless $$ref;
  }

  if ($$ref =~ s/^\(//) {
    my $Child = $Self->add_list($key);
    while ($$ref !~ s/^\)//) {
      $$ref =~ s/^\s+//;
      die unless $$ref;
      $Child->_parse_string($ref, 0);
      $$ref =~ s/^\s+//;
    }
  }

  elsif ($$ref =~ s/^\%//) {
    # kvlist
    if ($$ref =~ s/^\(//) {
      die unless $$ref;
      my $Child = $Self->add_kvlist($key);
      while (not ($$ref =~ s/^\)//)) {
        $Child->_parse_string($ref, 1);
        $$ref =~ s/^\s+//;
      }
    }
    elsif ($$ref =~ s/^\{//) {
      die unless $$ref;
      my $partition = _getword($ref);
      $$ref =~ s/^\s+//;
      my $guid = _getword($ref);
      $$ref =~ s/^\s+//;
      my $size = _getword($ref);
      $$ref =~ s/^}\r?\n//;
      my $content = substr($$ref, 0, $size, '');
      $Self->add_file($key, $partition, $guid, $size, $content);
    }
  }
  else {
    my $content = _getastring($ref);
    $Self->add_atom($key, $content);
  }
}

sub parse_string {
  my $class = shift;
  my $string = shift;
  my $parsekey = shift;
  my $base = $class->new_list();
  $base->_parse_string(\$string, $parsekey);
  return $base->{data}[0];
}

sub _printastring {
  my $str = shift;
  return 'NIL' unless defined $str;
  if (length($str) < 1024) {
    # atom - actually it's more than this, but this will do
    if ($str =~ m/^\\?[A-Za-z0-9][A-Za-z0-9_]*$/ and $str ne 'NIL') {
      return $str;
    }
    # quotable
    if ($str !~ m/[\x80-\xff\r\n\"\%\\]/) {
      return '"' . $str . '"';
    }
  }
  return '{' . length($str) . "+}\r\n" . $str;
}

sub as_string {
  my $Self = shift;

  if ($Self->{type} eq 'kvlist') {
    my @items = map { _printastring($_->{key}) => $_->as_string() } @{$Self->{data}};
    return '%(' . join(' ', @items) . ')';
  }
  elsif ($Self->{type} eq 'list') {
    my @items = map { $_->as_string() } @{$Self->{data}};
    return '(' . join(' ', @items) . ')';
  }
  elsif ($Self->{type} eq 'file') {
    my @items = ($Self->{partition}, $Self->{guid}, $Self->{size});
    return '%{' . join (' ', @items) . "}\r\n" . $Self->{data};
  }
  else {
    return _printastring($Self->{data});
  }
}

sub as_perl {
  my $Self = shift;

  if ($Self->{type} eq 'kvlist') {
    my $kvlist = {};
    my @order;

    foreach my $datum (@{$Self->{data}}) {
      push @order, $datum->{key};
      $kvlist->{$datum->{key}} = $datum->as_perl();
    }

    $kvlist->{__kvlist_order} = [ @order ];
    return $kvlist;
  }
  elsif ($Self->{type} eq 'list') {
    return [ map { $_->as_perl() } @{$Self->{data}} ];
  }
  elsif ($Self->{type} eq 'file') {
    return \[ $Self->{partition}, $Self->{guid}, $Self->{size}, $Self->{data} ];
  }
  else {
    return $Self->{data};
  }
}

sub anyevent_read_type {
  my ($handle, $cb, $parsekey) = @_;

  my %obj;
  %obj = (
    data => '',
    getline => sub {
      if ($_[1] =~ m/(\d+)\+?\}$/) {
        my $length = $1;
        $obj{data} .= $_[1] . $_[2];
        # compatible with both file literals and regular literals
        $_[0]->unshift_read(chunk => $length, $obj{getliteral});
      }
      else {
        my $dlist = Cyrus::DList->parse_string($obj{data} . $_[1], $parsekey);
        $cb->($handle, $dlist);
        %obj = (); # drop refs
      }
      1
    },
    getliteral => sub {
      $obj{data} .= $_[1];
      $_[0]->unshift_read (line => $obj{getline});
      1
    },
  );

  return sub {
    $_[0]->unshift_read (line => $obj{getline});
    1
  };
};

sub anyevent_write_type {
  my ($handle, $dlist, $printkey) = @_;
  my $string = '';
  $string .= _printastring($dlist->{key}) . ' ' if $printkey;
  $string .= $dlist->as_string() . "\n";
  $handle->push_write($string);
}

1;
