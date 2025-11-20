package Cyrus::Backup::Tar;

sub new {
  my $class = shift;
  my $dir = shift;
  my $file = shift;
  my $state = shift;

  return bless {
    dir => $dir,
    file => $file,
    state => $state,
    count => 0,
  }, ref($class) || $class;
}

sub _openfile {
  my $Self = shift;

  my $offset = 0;

  my $tarfile = "$Self->{dir}/$Self->{file}";

  my $item = $Self->{state}->get('');
  if ($item) {
    if ($item->{filename} ne $Self->{file}) {
      die "$tarfile: filename mismatched, expected $item->{filename}\n";
    }

    my @stat = stat($tarfile);
    if ($stat[7] > $item->{size}) {
      warn "$tarfile: file size mismatch: $stat[7] > $item->{size}, truncating\n";
      truncate($tarfile, $item->{size});
    }
    if ($item->{size} > $stat[7]) {
      warn "$tarfile: file size too small: $item->{size} > $stat[7], cleaning out backup and starting again";
      $Self->{state}->{dbh}->rollback();
      $Self->{state}->dbwipe();
      $Self->{state}->{dbh}->begin_work();
      unlink($tarfile);
    }
    else {
      # XXX: check mtime and inode too?  Risky if files moved, etc.
      $offset = $item->{offset};
    }
  }
  elsif (-f $tarfile) {
    $Logger->log(["%s: bogus file, removing", $tarfile]);
    unlink($tarfile);
  }

  $Self->{tarfh} = Cyrus::Backup::OpenDataFile($tarfile, 'a') ||
    die "$tarfile: can't stream to tarfile: $!";
  $Self->{tarstream} = Archive::Tar::Stream->new(outfh => $Self->{tarfh}, outpos => $offset);

  return 1;
}

sub addfile {
  my $Self = shift;
  my $fh = shift;
  my $name = shift;
  my $sha1 = shift;
  my $size = shift;
  my $mtime = shift;
  my $inode = shift;

  $Self->snapshot() if ++$Self->{count} > 1000;
  $Self->_openfile() unless $Self->{tarstream};

  # ok, storing the inode in $devminor is skanky hack that's bound to annoy someone, and sha1 in linkname even more so!
  seek($fh, 0, 0);
  my $header = $Self->{tarstream}->AddFile($name, $size, $fh, mtime => $mtime, devminor => $inode, linkname => $sha1);
  $Self->{state}->addheader($header, $header->{_pos});

  return 1;
}

sub delfile {
  my $Self = shift;
  my $name = shift;

  return unless $Self->{state}->get($name);

  $Self->snapshot() if ++$Self->{count} > 1000;
  $Self->_openfile() unless $Self->{tarstream};

  # ok, storing the inode in $devminor is skanky hack that's bound to annoy someone, and sha1 in linkname even more so!
  my $header = $Self->{tarstream}->AddFile($name, 0, undef, mtime => 0, devminor => 0, linkname => "");
  $Self->{state}->addheader($header, $header->{_pos});

  return 1;
}

sub addlink {
  my $Self = shift;
  my $name = shift;
  my $target = shift;
  my $mtime = shift;

  $Self->snapshot() if ++$Self->{count} > 1000;
  $Self->_openfile() unless $Self->{tarstream};

  my $header = $Self->{tarstream}->AddLink($name, $target, typeflag => 2, mtime => $mtime);
  $Self->{state}->addheader($header, $header->{_pos});

  return 1;
}

sub snapshot {
  my $Self = shift;

  if ($Self->{tarstream}) { # changes made
    my $finalpos = $Self->{tarstream}->OutPos();
    $Self->{tarfh}->close();
    delete $Self->{tarfh};
    delete $Self->{tarstream};
    my @stat = stat("$Self->{dir}/$Self->{file}");
    $Self->{state}->snapshot($Self->{file}, $stat[7], $stat[9], $finalpos);
    $Self->{count} = 0;
  }
}

sub finish {
  my $Self = shift;

  if ($Self->{tarstream}) { # changes made
    my $finalpos = $Self->{tarstream}->OutPos();
    $Self->{tarfh}->close();
    delete $Self->{tarfh};
    delete $Self->{tarstream};
    my @stat = stat("$Self->{dir}/$Self->{file}");
    $Self->{state}->finish($Self->{file}, $stat[7], $stat[9], $finalpos);
  }
  else {
    $Self->{state}->cancel();
  }

  return 1;
}

1;
