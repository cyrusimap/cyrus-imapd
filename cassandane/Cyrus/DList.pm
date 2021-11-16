#!/usr/bin/perl -c

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
    $child->add_perl($_, $val->{$_}) for keys %$val;
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
  if (length($str) < 1024) {
    # atom - actually it's more than this, but this will do
    if ($str =~ m/^\\?[A-Za-z0-9][A-Za-z0-9_]*$/) {
      return $str;
    }
    # quotable
    if ($str !~ m/[\x80-\xff\r\n\"\%\\]/) {
      return '"' . $str . '"';
    }
  }
  return '{' . length($str) . "}\r\n" . $str;
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
    return { map { $_->{key} => $_->as_perl() } @{$Self->{data}} };
  }
  elsif ($Self->{type} eq 'list') {
    return [ map { $_->as_perl() } @{$Self->{data}} ];
  }
  else {
    return $Self->{data};
  }
}

sub parse_io {
  my $class = shift;
  my $io = shift;
  my $parsekey = shift;

  my $line = $io->getline();
  while ($line =~ m/(\d+)\+?\}$/m) {
    my $length = $1;
    my $buf;
    my $res = $io->read($buf, $length);
    die "didn't get data" unless $res eq $length;
    $line .= $buf;
  }

  return $class->parse_string($line, $parsekey);
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
