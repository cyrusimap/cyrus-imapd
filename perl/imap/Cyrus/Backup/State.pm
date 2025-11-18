package Cyrus::Backup::State;

use Cyrus::Backup;
use DBI;

sub TABLES {
  my $Version = Cyrus::Backup::CurrentBackupVersion();
  return (
  status => qq{
CREATE TABLE status (
  filename TEXT NOT NULL,
  size INTEGER NOT NULL,
  mtime INTEGER NOT NULL,
  offset INTEGER NOT NULL,
  version INTEGER NOT NULL DEFAULT $Version,
  PRIMARY KEY (filename)
);
  },
  imap => qq{
CREATE TABLE imap (
  name TEXT NOT NULL,
  folderid INTEGER NOT NULL,
  deleted INTEGER NOT NULL,
  offset INTEGER NOT NULL,
  PRIMARY KEY (name, folderid)
);
  },
  meta => qq{
CREATE TABLE meta (
  type TEXT NOT NULL,
  name TEXT NOT NULL,
  sha1 TEXT,
  size INTEGER NOT NULL,
  mtime INTEGER NOT NULL,
  inode INTEGER NOT NULL,
  stale INTEGER NOT NULL,
  offset INTEGER NOT NULL,
  PRIMARY KEY (type, name)
);
  },
  fmeta => qq{
CREATE TABLE fmeta (
  folderid INTEGER NOT NULL,
  name TEXT NOT NULL,
  sha1 TEXT,
  size INTEGER NOT NULL,
  mtime INTEGER NOT NULL,
  inode INTEGER NOT NULL,
  stale INTEGER NOT NULL,
  offset INTEGER NOT NULL,
  PRIMARY KEY (folderid, name)
);
  },
  folders => qq{
CREATE TABLE folders (
  folderid INTEGER PRIMARY KEY,
  uniqueid TEXT,
  UNIQUE (uniqueid)
);
  },
  files => qq{
CREATE TABLE files (
  fileid INTEGER PRIMARY KEY,
  guid TEXT NOT NULL,
  size INTEGER NOT NULL,
  refcount INTEGER NOT NULL,
  offset INTEGER NOT NULL,
  UNIQUE (guid)
);
  },
  indexed => qq{
CREATE TABLE indexed (
  folderid INTEGER NOT NULL,
  uid INTEGER NOT NULL,
  fileid INTEGER NOT NULL,
  deleted INTEGER NOT NULL,
  PRIMARY KEY (folderid, uid)
);
  },
);
}

sub new {
  my $class = shift;
  my $dir = shift;
  my $file = shift;
  my %args = @_;

  my $dbh = DBI->connect("dbi:SQLite:dbname=$dir/$file")
    || die "Failed to connect to database $dir/$file: $DBI::errstr";
  $dbh->{HandleError} = sub {
    die "DB Exception: " . shift;
  };

  unless ($dbh->selectrow_array('SELECT name from sqlite_master WHERE name = "status"')) {
    _dbinit($dbh);
  }

  my $status = $dbh->selectrow_hashref("SELECT * FROM status");
  $status ||= { version => Cyrus::Backup::CurrentBackupVersion() }; # no row
  $status->{version} ||= 1; # old style DB

  if ($args{Unsafe}) {
    $dbh->do("PRAGMA synchronous = OFF");
    $dbh->do("PRAGMA temp_store = MEMORY");
    $dbh->do("PRAGMA cache_size = 50000");
  }

  $dbh->begin_work();

  my $Self = bless { dir => $dir, file => $file, dbh => $dbh,
                 version => $status->{version} }, ref($class) || $class;

  return $Self;
}

sub dbwipe {
  my $Self = shift;
  my $dbh = $Self->{dbh};
  my %TABLES = TABLES();
  foreach my $table (keys %TABLES) {
    $dbh->do("DROP TABLE $table");
  }
  _dbinit($dbh);
}

sub _dbinit {
  my $dbh = shift;

  die "Failed to start transaction"
    unless $dbh->begin_work();
  my %TABLES = TABLES();
  foreach my $table (keys %TABLES) {
    die "Failed to create table $table"
      unless $dbh->do($TABLES{$table});
  }
  die "Failed to create upref"
    unless $dbh->do(<<EOF);
CREATE TRIGGER upref AFTER INSERT ON indexed
BEGIN
  UPDATE files SET refcount = refcount + 1 WHERE fileid = new.fileid;
END;
EOF

  die "Failed to create downref"
    unless $dbh->do(<<EOF);
CREATE TRIGGER downref AFTER DELETE ON indexed
BEGIN
  UPDATE files SET refcount = refcount - 1 WHERE fileid = old.fileid;
END;
EOF

# this should never fire, but still
  die "Failed to create changeref"
    unless $dbh->do(<<EOF);
CREATE TRIGGER changeref AFTER UPDATE OF fileid ON indexed
BEGIN
  UPDATE files SET refcount = refcount + 1 WHERE fileid = new.fileid;
  UPDATE files SET refcount = refcount - 1 WHERE fileid = old.fileid;
END;
EOF

  die "Failed to commit"
    unless $dbh->commit();

  return 1;
}

sub dbh {
  my $Self = shift;

  return $Self->{dbh};
}

sub addheader {
  my $Self = shift;
  my $header = shift;
  my $offset = shift;

  my $filename = $header->{name};
  my $target = $header->{linkname};
  my $size = $header->{size};
  my $mtime = $header->{mtime};
  my $inode = $header->{devminor};

  my $dbh = $Self->{dbh};

  # most commonly it will be a file :)
  if ($filename =~ m{files/([^/]+)}) {
    my $guid = $1;

    my $data = $Self->get($filename);
    if ($data) {
      # ho hum duplicate will get removed later on compress
      # we'd rather keep the first one thanks :)
    }
    else {
      $dbh->do("INSERT INTO files (guid, size, refcount, offset) VALUES (?, ?, ?, ?)", {}, $guid, $size, 0, $offset);
      $Self->{_fileids}{$guid} = $dbh->func('last_insert_rowid');
    }
  }

  elsif ($filename =~ m{^folders/([^/]+)/cyrus\.(.*)}) {
    my $unq = $1;
    my $name = $2;
    my $folderid = $Self->folderid($unq);

    my $stale = 0;

    my $data = $Self->get($filename);
    if ($data) {
      $stale = $data->{stale} + $data->{size};
    }

    if ($size) {
      $dbh->do("REPLACE INTO fmeta (folderid, name, sha1, size, mtime, inode, stale, offset)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?)", {},
                $folderid, $name, $target, $size, $mtime, $inode, $stale, $offset);
    }
    else {
      $dbh->do("DELETE FROM fmeta WHERE folderid = ? AND name = ?", {}, $folderid, $name);
    }
  }

  elsif ($filename =~ m{^imap/([^/]+)}) {
    my $name = $1;
    my $item = $Self->get($filename);
    if ($item and not $item->{deleted}) {
      $dbh->do("UPDATE imap SET deleted = ? WHERE name = ? AND deleted = 0", {}, $mtime, $name);
    }
    my $folderid = $Self->folderid($target);
    # if no folderid (symlink to nowhere) we just have the deleted record left
    if ($folderid) {
      $dbh->do("REPLACE INTO imap VALUES (?, ?, ?, ?)", {}, $name, $folderid, 0, $offset);
    }
  }

  elsif ($filename =~ m{^(meta|annot)/([^/]+)}) {
    my $type = $1;
    my $name = $2;

    my $stale = 0;

    my $data = $Self->get($filename);
    if ($data) {
      $stale = $data->{stale} + $data->{size};
    }

    if ($size) {
      $dbh->do("REPLACE INTO meta (type, name, sha1, size, mtime, inode, stale, offset)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?)", {},
                $type, $name, $target, $size, $mtime, $inode, $stale, $offset);
    }
    else {
      $dbh->do("DELETE FROM meta WHERE type = ? AND name = ?", {}, $type, $name);
    }
  }
}

sub fileid {
  my $Self = shift;
  my $guid = shift;

  my $dbh = $Self->{dbh};

  unless (exists $Self->{_fileids}{$guid}) {
    my $sth = $dbh->prepare_cached("SELECT fileid FROM files WHERE guid = ?");
    my ($fileid) = $dbh->selectrow_array($sth, {}, $guid);
    $Self->{_fileids}{$guid} = $fileid;
  }

  return $Self->{_fileids}{$guid};
}

sub filedata {
  my $Self = shift;
  my $fileid = shift;

  my $dbh = $Self->{dbh};

  my $sth = $dbh->prepare_cached("SELECT * FROM files WHERE fileid = ?");
  my $data = $dbh->selectrow_hashref($sth, {}, $fileid);

  return $data;
}

sub folderid {
  my $Self = shift;
  my $unq = shift;

  return 0 if $unq eq '';

  my $dbh = $Self->{dbh};

  my ($folderid) = $dbh->selectrow_array("SELECT folderid FROM folders where uniqueid = ?", {}, $unq);

  unless ($folderid) {
    $dbh->do("INSERT INTO folders (uniqueid) VALUES (?)", {}, $unq);
    $folderid = $dbh->func('last_insert_rowid');
  }

  return $folderid;
}

sub get_all {
  my $Self = shift;
  my $filename = shift;

  my $dbh = $Self->{dbh};

  # most commonly it will be a file :)
  if ($filename =~ m{^files/([^/]+)}) {
    my $guid = $1;

    my $sth = $dbh->prepare_cached("SELECT * FROM files WHERE guid = ?");
    my $data = $dbh->selectrow_hashref($sth, {}, $guid);

    return $data;
  }

  elsif ($filename =~ m{^folders/([^/]+)/cyrus\.(.*)}) {
    my $unique = $1;
    my $name = $2;
    my $folderid = $Self->folderid($unique);

    my $sth = $dbh->prepare_cached("SELECT * FROM fmeta WHERE folderid = ? AND name = ?");
    my $data = $dbh->selectrow_hashref($sth, {}, $folderid, $name);

    return $data;
  }

  elsif ($filename =~ m{^imap/([^/]+)}) {
    my $name = $1;

    my $sth = $dbh->prepare_cached("SELECT * FROM imap WHERE name = ? ORDER BY offset DESC");
    $sth->execute($name);

    my @data;
    while (my $item = $sth->fetchrow_hashref()) {
      push @data, $item;
    }

    return @data;
  }

  elsif ($filename =~ m{^(meta|sieve|annot)/([^/]+)}) {
    my $type = $1;
    my $name = $2;

    my $sth = $dbh->prepare_cached("SELECT * FROM meta WHERE type = ? AND name = ?");
    my $data = $dbh->selectrow_hashref($sth, {}, $type, $name);

    return $data;
  }

  elsif ($filename eq '') {
    # backup status

    my $data = $dbh->selectrow_hashref("SELECT * FROM status");

    return $data;
  }

  else {
    die "unknown filename requested: $filename";
  }
}

sub get {
  my $Self = shift;

  return (($Self->get_all(@_))[0]);
}

sub file_exists {
  my $Self = shift;
  my $filename = shift;
  my $size = shift;
  my $mtime = shift;
  my $inode = shift;

  my $dbh = $Self->{dbh};

  my $data = $Self->get($filename);

  # most commonly it will be a file :)
  if ($filename =~ m{^files/([^/]+)}) {
    return $data;
  }

  else {
    return 0 unless $data->{sha1};
    return ($data
        and $data->{size} == $size
        and $data->{mtime} == $mtime
        and $data->{inode} == $inode);
  }
}

sub cancel {
  my $Self = shift;

  my $dbh = $Self->{dbh};

  $dbh->rollback();

  # stop anyone using it any more!
  delete $Self->{dbh};

  # touch the database file anyway
  my $time = time();
  utime($time, $time, "$Self->{dir}/$Self->{file}");

  return 1;
}

sub done {
  my $Self = shift;

  my $dbh = $Self->{dbh};

  $dbh->commit();

  # stop anyone using it any more!
  delete $Self->{dbh};

  return 1;
}

sub finish {
  my $Self = shift;
  my $backupfile = shift;
  my $size = shift;
  my $mtime = shift;
  my $offset = shift;

  my $dbh = $Self->{dbh};

  $dbh->do("DELETE FROM status");
  $dbh->do("INSERT INTO status VALUES (?, ?, ?, ?, ?)", {}, $backupfile, $size, $mtime, $offset, $Self->{version});

  $dbh->commit();

  # stop anyone using it any more!
  delete $Self->{dbh};

  return 1;
}

sub snapshot {
  my $Self = shift;
  my $backupfile = shift;
  my $size = shift;
  my $mtime = shift;
  my $offset = shift;

  my $dbh = $Self->{dbh};

  $dbh->do("DELETE FROM status");
  if ($Self->{version} == 1) {
    $dbh->do("INSERT INTO status VALUES (?, ?, ?, ?)", {}, $backupfile, $size, $mtime, $offset);
  }
  else {
    $dbh->do("INSERT INTO status VALUES (?, ?, ?, ?, ?)", {}, $backupfile, $size, $mtime, $offset, $Self->{version});
  }

  $dbh->commit();

  # back on the wagon
  $dbh->begin_work();

  return 1;
}

sub DESTROY {
  my $Self = shift;
  $Self->cancel() if $Self->{dbh};
}

1;
