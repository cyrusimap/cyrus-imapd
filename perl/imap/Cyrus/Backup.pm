# Module to handle backups.  By moving all the logic here I can more

# easily support running backups from multiple different sources, and
# also changing the protocol.
# XXX - more error checking and consistency of tar vs state file checking
#
# XXX - tune the when-to-rebuild figures
package Cyrus::Backup;

use Cyrus::Backup::State;
use Cyrus::Backup::Tar;
use Archive::Tar::Stream;
use IO::Socket::INET;
use IO::File;
use File::Temp;
use File::Copy;
use File::Path;
use File::Spec;
use Cyrus::IndexFile;
use Digest::SHA;
use Date::Format;

our $BackupVersion = 5;
# UPDATE THIS WHENEVER A NEW CYRUS INDEX MINOR_VERSION IS CREATED
our $MAX_INDEXVERSION = 20;

our $MAX_AGE = (7 * 24 * 60 * 60); # 7 days
our $BACKUP_PATHS;
our $TEMPDIR = -d "/tmpfs" ? "/tmpfs" : "/tmp";

sub CurrentBackupVersion {
  return $BackupVersion;
}

sub GetIO {
  my $Server = shift;
  my $Port = shift || 2901;

  if ($Server =~ s/:(\d+)//) {
    $Port = $1;
  }

  # Connect to data agent
  for (1..3) {
    my $IO = IO::Socket::INET->new(
      PeerAddr => $Server,
      PeerPort => $Port,
    );
    if ($IO) {
      $IO->autoflush(1);
      return $IO;
    }
    sleep 5;
  }
  die "Failed to connect to $Server:$Port 3 times\n";
}

sub GetUsers {
  my $Host = shift;
  my $Port = shift;
  my $ServerName = shift;

  my $IO = GetIO($Host, $Port);

  my @list = iolist($IO, 'USERS', $ServerName);
  return map { $_->[1] } grep { $_->[0] eq 'USER' } @list;
}

# BACKUP PHASE:
# * connects to the user's IMAP server
# * for each file in:
#       meta
#       @folders/cyrus.{index,expunge,header}
#   - check if the mtime, size and inode on the server are identical, skip if they are
#
#   - if any meta file at all has changed, fetch the whole lot.  There's not other sane
#     way, because locking in the cyrusbackupd means they'll be consistent if we sync
#     them like this
#
# Store all files and primary meta information (folder name => folderpath mappings)
# in a tar file.  Store useful lookupable meta information for the above logic in
# a sqlite file (backupstate.sqlite3) for quick lookup.
sub BackupUser {
  my $Host = shift;
  my $Port = shift;
  my $MetaDir = shift;
  my $DataDir = shift;
  my $ServerName = shift;
  my $CyrusName = shift;
  my $DoCompress = shift;

  # create a separate directory so we're not sharing a directory
  # for temp files, during the backup.  It will clean up at function exit
  local $TEMPDIR = File::Temp->newdir(DIR => $TEMPDIR);

  my $IO = GetIO($Host, $Port);

  local $| = 1;
  my $Now = time();
  my $ExpireTime = $Now - $MAX_AGE;

  my $state = Cyrus::Backup::State->new($MetaDir, 'backupstate.sqlite3');
  my $status = $state->get('');
  my $NewName;
  if ($status) {
    $NewName = $status->{filename};
  }
  else {
    $NewName = NewDataFilename($DoCompress, $Now);
    my $rel = File::Spec->abs2rel("$DataDir/$NewName", $MetaDir);
    symlink($rel, "$MetaDir/$NewName") unless $DataDir eq $MetaDir;
  }
  my $tar = Cyrus::Backup::Tar->new($DataDir, $NewName, $state);

  # do meta (seen, subs)
  my @items = iolist($IO, 'META', $ServerName, $CyrusName);
  pop @items; # status line
  foreach my $item (@items) {
    my (undef, $name, $size, $mtime, $inode) = @$item;
    my $filename = "meta/$name";
    next if $state->file_exists($filename, $size, $mtime, $inode);
    # XXX - fetch together?
    my ($fh, $fsize, $fmtime, $finode, $sha1) = iofile($IO, 'META', $ServerName, $CyrusName, $name);
    $tar->addfile($fh, $filename, $sha1, $fsize, $fmtime, $finode);
  }

  # get the folders
  my @fmulti = iolist($IO, "FMULTISTATUS", $ServerName, $CyrusName);
  pop @fmulti; # status line
  my %knownfolders = map { $_->[1] => 1 } grep { $_->[0] eq 'FOLDER' } @fmulti;
  my %fmeta;
  foreach my $item (grep { $_->[0] eq 'STAT' } @fmulti) {
    push @{$fmeta{$item->[1]}}, $item;
  }

  # any not in this list?  deprecate them now!
  my $oldfolders = $state->dbh->selectcol_arrayref('SELECT name FROM imap WHERE deleted = 0 AND folderid <> 0');
  foreach my $folder (@$oldfolders) {
    next if $knownfolders{$folder};
    # this says "it's been deleted", so the cleanup can know that it's time for it to go!
    $tar->addlink("imap/$folder/", "", $Now);
  }

  # ok, let's go!
  foreach my $folderdetail (grep { $_->[0] eq 'FOLDER' } @fmulti) {
    my $dirty = 0;
    my $FolderName = $folderdetail->[1];
    my @fmeta = @{$fmeta{$folderdetail->[1]}};
    my $uniqueid = $folderdetail->[2];
    my $folderid = $state->folderid($uniqueid);

    # what was the old folderpath for this folder name?
    my $folderitem = $state->get("imap/$FolderName/");
    my $oldfolderid;
    $oldfolderid = $folderitem->{folderid}
      if ($folderitem and not $folderitem->{deleted});

    if ($oldfolderid and $oldfolderid eq $folderid) {
      # folder is the same, check the files
      foreach my $item (@fmeta) {
        my (undef, undef, $name, $size, $mtime, $inode) = @$item;
        next if $state->file_exists("folders/$uniqueid/cyrus.$name", $size, $mtime, $inode);
        # changed file on server
        $dirty = 1;
        last;
      }
    }
    else {
      # new or renamed folder!
      $dirty = 1;
    }

    next unless $dirty;

    # OK, the folder is dirty - we need to fetch everything:
    my %content;
    my $res = iofiles($IO, ['FMETA', $ServerName, $CyrusName, $FolderName, 'header', 'index', 'annotations', 'mailbox_annotations'], sub {
      my $name = shift;
      $content{$name} = \@_;
    });

    # use the updated folderid if it's changed
    unless ($uniqueid eq $res->[2]) {
      $uniqueid = $res->[2];
      $folderid = $state->folderid($uniqueid);
    }

    # parse changed index files and download any missing data files
    foreach my $name ('index') {
      next unless $content{$name};
      my ($fh, $size, $mtime, $inode, $sha1) = @{$content{$name}};
      next if $state->file_exists("folders/$uniqueid/cyrus.$name", $size, $mtime, $inode);

      # read the index file
      ParseIndex($FolderName, $uniqueid, $fh, $state, sub {
        my $guidmap = shift;
        # deal with missing GUIDs!

        my @uids = sort { $a <=> $b } keys %$guidmap;
        my $cb = sub {
          my ($uid, $fh, $size, $mtime, $inode, $sha1) = @_;
          my $guid = $guidmap->{$uid};
          if ($guid ne $sha1) {
            die "File $CyrusName " . qfn($FolderName) . " $uid changed underfoot: $guid => $sha1\n";
          }
          $tar->addfile($fh, "files/$guid", $sha1, $size, $mtime, $inode);
        };

        while (my @batch = splice(@uids, 0, 1024)) {
          iofiles($IO, ['FDATA', $ServerName, $CyrusName, $FolderName, @batch], $cb);
        }
      });

      $tar->addfile($fh, "folders/$uniqueid/cyrus.$name", $sha1, $size, $mtime, $inode);
    }

    # then add the other files if they've changed, or remove them if they're gone
    foreach my $name ('header', 'annotations', 'mailbox_annotations') {
      if ($content{$name}) {
        my ($fh, $size, $mtime, $inode, $sha1) = @{$content{$name}};
        next if $state->file_exists("folders/$uniqueid/cyrus.$name", $size, $mtime, $inode);
        $tar->addfile($fh, "folders/$uniqueid/cyrus.$name", $sha1, $size, $mtime, $inode);
      }
      else {
        $tar->delfile("folders/$uniqueid/cyrus.$name");
      }
    }

    # finally create or update the link it it's changed
    unless ($oldfolderid and $oldfolderid eq $folderid) {
      $tar->addlink("imap/$FolderName/", $uniqueid, $Now);
    }
  }

  # finally, store our changes
  my $outpos = $tar->{tarstream} ? $tar->{tarstream}->OutPos() : $status->{offset};
  $tar->finish();

  die "failed to create file $DataDir/$NewName\n" unless -f "$DataDir/$NewName";

  # remove stale data files :)
  if (opendir(DH, $DataDir)) {
    while (my $item = readdir(DH)) {
      next if ($item eq 'backupstate.sqlite3' and $DataDir eq $Metadir);
      next if $item eq $NewName;
      next if $item eq '..';
      next if $item eq '.';
      warn "REMOVING STALE FILE $DataDir/$item\n";
      unlink("$DataDir/$item");
    }
    closedir(DH);
  }

  die "failed to create link $MetaDir/$NewName\n"
    unless -e "$MetaDir/$NewName";

  # remove stale files :)
  if (opendir(DH, $MetaDir)) {
    while (my $item = readdir(DH)) {
      next if $item eq 'backupstate.sqlite3';
      next if $item eq $NewName;
      next if $item eq '.lock';
      next if $item eq '..';
      next if $item eq '.';
      warn "REMOVING STALE FILE $MetaDir/$item\n";
      unlink("$MetaDir/$item");
    }
    closedir(DH);
  }

  return ($state->{version}, $outpos);
}

# COMPRESS PHASE:
# * no IMAP server connection
# * using the backupstate database:
#   - calculate the percentage of the tar file that is valid
#   - if the valid percentage is too low, then compress:
#
# * compress is:
#   - open a new tar file
#   - open a new state database
#   - stream from the current tar file.  For each record, check the backupstate
#     records to see if this is a valid record.  If so, stream to new tar file and
#     insert the relevant records in the new state db.
#   - move the new state database over the old one
#   - clean up the old tar file
#
#  NOTE: backup file name is: backupdata-$unixtime.tar.gz, where $unixtime is when it
#  was last compressed.  This name is stored in the state database, so you don't need to
#  know it other than for cleanup, etc.
sub CompressBackup {
  my $MetaDir = shift;
  my $DataDir = shift;
  my $UserId = shift;
  my $BackupSet = shift;
  my $Percent = shift || 80;
  my $DoCompress = shift;

  local $| = 1;
  my $Now = time();
  my $ExpireTime = $Now - $MAX_AGE;

  my $state = Cyrus::Backup::State->new($MetaDir, 'backupstate.sqlite3');
  my $status = $state->get('');
  unless ($status) {
    $state->done();
    return (0, 0, 0);
  }

  my $total = 0;
  my $stale = 0;

  # Meta files are always
  $stale += ($state->dbh->selectrow_array("SELECT SUM(stale) FROM meta") || 0);
  $total += ($state->dbh->selectrow_array("SELECT SUM(size+stale) FROM meta") || 0);

  # Clean up folders and get a usage summary too
  my %folders;
  my $folderids = $state->dbh->selectcol_arrayref("SELECT DISTINCT folderid FROM fmeta");
  foreach my $folderid (@$folderids) {
    my $ftotal = $state->dbh->selectrow_array("SELECT SUM(size+stale) FROM fmeta WHERE folderid = ?", {}, $folderid);
    $total += $ftotal;

    my ($exists) = $state->dbh->selectrow_array("SELECT name FROM imap WHERE folderid = ? AND (deleted = 0 OR deleted > ?)", {}, $folderid, $ExpireTime);
    if ($exists) {
      $stale += $state->dbh->selectrow_array("SELECT SUM(stale) FROM fmeta WHERE folderid = ?", {}, $folderid);
      $folders{$folderid} = 1;
    }
    else {
      $stale += $ftotal;

      # delete all index records (brings refcount down)
      $state->dbh->do("DELETE FROM indexed WHERE folderid = ?", {}, $folderid);
    }
  }

  # finally, summarise the files!
  $total += $state->dbh->selectrow_array("SELECT SUM(size) FROM files") || 0;
  $stale += $state->dbh->selectrow_array("SELECT SUM(size) FROM files WHERE refcount = 0") || 0;

  # now we know everything :)  Do we need to compress?
  my $percentage = int((100 * ($total - $stale)) / $total);

  if ($percentage >= $Percent) {
    $state->done();
    return (0, $status->{offset}, $percentage);
  }

  if ($total > 100_000_000) {
    alarm($total / 100_000); # 10000 s per gb
  }

  my $OldName = $status->{filename};
  my $NewName = NewDataFilename($DoCompress, $Now);
  if ($NewName eq $OldName) {
    die "run too soon - same name ($NewName)";
  }
  my $infh = OpenDataFile("$DataDir/$OldName", 'r') ||
    die "can't stream for $DataDir/$OldName: $!";
  my $outfh = OpenDataFile("$DataDir/$NewName", 'w') ||
    die "can't stream to $DataDir/$NewName: $!";

  unlink("$MetaDir/backupstate.sqlite3.NEW") if -e "$MetaDir/backupstate.sqlite3.NEW";
  my $outstate = Cyrus::Backup::State->new($MetaDir, "backupstate.sqlite3.NEW", Unsafe => 1);
  my $ts = Archive::Tar::Stream->new(infh => $infh, outfh => $outfh);

  # we are happy to die with an inconsistent state if the source file is incomplete
  $ts->SafeCopy(0);

  # refcounts were bogus, so we need to index
  if ($state->{version} < 5) {
    $state->dbh->do("CREATE INDEX fileidx on indexed (fileid)");
  }

  my %seen_files;
  $ts->StreamCopy(sub {
    my $header = shift;
    my $outpos = shift;
    my $fh = shift;

    my $offset = $header->{_pos};

    my $key = $header->{name};
    return 'SKIP' unless $key;

    my ($cur, @list) = $state->get_all($key);

    # doesn't exist at all!
    return 'SKIP' unless $cur;

    # old annot/ or sieve/ - we don't need any more
    return 'SKIP' if $key =~ m{^annot/};
    return 'SKIP' if $key =~ m{^sieve/};

    # it's a file no longer pointed to
    if ($key =~ m{^files/}) {
      return 'SKIP' unless $cur->{refcount};
      if ($state->{version} < 5) {
        my ($count) = $state->dbh->selectrow_array("SELECT COUNT(*) FROM indexed WHERE fileid = ?", {}, $cur->{fileid});
        return 'SKIP' unless $count;
      }
    }

    # it's in a folder no longer active
    elsif ($key =~ m{^folders/([^/]+)}) {
      my $folderid = $state->folderid($1); # was it valid in the old one?
      return 'SKIP' unless $folders{$folderid};
    }

    my $rc = 0;

    # special case for IMAP folders, we need to check
    # back a week!
    if ($key =~ m{^imap/}) {
      foreach my $item ($cur, @list) {
        next if ($item->{deleted} and $item->{deleted} < $ExpireTime);
        $rc = 1 if $item->{offset} == $offset;
      }
    }

    # we always want the earliest copy possible for files,
    # since they may be referenced in early indexes
    elsif ($key =~ m{^files/}) {
      $rc = 1;
    }

    # otherwise keep if it's the most current only
    else {
      $rc = 1 if $cur->{offset} == $offset;
    }

    # if we're keeping it, we also want to keep the new state
    if ($rc) {
      # for index or expunge files, we'll want to parse the file for
      # status records!
      if ($key =~ m{^folders/([^/]+)/cyrus.index$}) {
        return 'EDIT' unless $fh;
        my $unq = $1;
        my $name = $2;
        ParseIndex('', $unq, $fh, $outstate);
        seek($fh, 0, 0);
      }
      unless ($key =~ m{^imap/} or $header->{linkname}) {
        return 'EDIT' unless $fh;
        $header->{linkname} = GetSHA1($fh);
        seek($fh, 0, 0);
      }
      if ($key =~ m{^imap/}) {
        $header->{linkname} =~ s{^folders/}{};
      }
      if ($key =~ m{^files/}) {
        # then make sure we only get one copy of it
        return 'SKIP' if $seen_files{$key};
        $seen_files{$key} = 1;
      }
      $outstate->addheader($header, $outpos);
      return 'KEEP'; # no fiddling here!
      # need to parse the message to fetch the sha1
    }

    return 'SKIP';
  });

  my $finalpos = $ts->OutPos();
  $infh->close();
  $outfh->close();

  my @stat = stat("$DataDir/$NewName");
  $state->cancel();
  $outstate->finish($NewName, $stat[7], $stat[9], $finalpos);

  if (rename("$MetaDir/backupstate.sqlite3.NEW", "$MetaDir/backupstate.sqlite3")) {
    # remove old data file
    unlink("$DataDir/$OldName");
    unlink("$MetaDir/$OldName");
    my $rel = File::Spec->abs2rel("$DataDir/$NewName", $MetaDir);
    symlink($rel, "$MetaDir/$NewName") unless $DataDir eq $MetaDir;
  }
  else {
    die "FAILED TO RENAME $MetaDir/backupstate.sqlite3.NEW: $!";
  }

  return (CurrentBackupVersion(), $finalpos, $percentage);
}

# All the data in the state database is recreatable from the tar file.  This function does
# so.
sub RebuildState {
  my $MetaDir = shift;
  my $DataDir = shift;
  my $tarfile = shift;
  my $statefile = shift;

  die "statefile exists" if -f "$MetaDir/$statefile";
  die "tarfile doesn't exist" unless -f "$DataDir/$tarfile";

  my $infh = OpenDataFile("$DataDir/$tarfile", 'r');
  my $outstate = Cyrus::Backup::State->new($MetaDir, $statefile);
  my $ts = Archive::Tar::Stream->new(infh => $infh);

  my $digest = Digest::SHA->new();

  my %seen_files;
  $ts->StreamCopy(sub {
    my $header = shift;
    my $outpos = shift;
    my $fh = shift;
    my $key = $header->{name};

    if ($key =~ m{^folders/([^/]+)/cyrus.index$}) {
      my $unq = $1;
      return 'EDIT' unless $fh;
      ParseIndex('', $unq, $fh, $outstate);
    }
    if ($key !~ m{^imap/} and not $header->{linkname}) {
      # no sha1
      return 'EDIT' unless $fh;
      $header->{linkname} = GetSHA1($fh);
    }
    if ($key =~ m{^files/02[0-9a-f]{22}0*$}) {
      # upgrade to sha1
      $header->{name} = "files/$header->{linkname}";
    }
    if ($key =~ m{^files/}) {
      return 'SKIP' if $seen_files{$key};
      $seen_files{$key} = 1;
    }

    $outstate->addheader($header, $header->{_pos});
    return 'SKIP';
  });

  my $finalpos = $ts->InPos();
  $infh->close();

  my @stat = stat("$DataDir/$tarfile");
  $outstate->finish($tarfile, $stat[7], $stat[9], $finalpos);
}

sub NewDataFilename {
  my $DoCompress = shift;
  my $Now = shift || time();
  return $DoCompress ? "backupdata-$Now.tar.gz" : "backupdata-$Now.tar";
}

sub OpenDataFile {
  my $Filename = shift;
  my $Mode = shift || '';
  if ($Mode eq 'a') {
    return $Filename =~ m/\.gz$/ ?
      IO::File->new("| gzip >> $Filename") :
      IO::File->new($Filename, 'a');
  } elsif ($Mode eq 'w') {
    return $Filename =~ m/\.gz$/ ?
      IO::File->new("| gzip > $Filename") :
      IO::File->new($Filename, 'w');
  } else {
    return $Filename =~ m/\.gz$/ ?
      IO::File->new("zcat $Filename |") :
      IO::File->new($Filename, 'r');
  }
}

sub GetSHA1 {
  my $fh = shift;
  seek($fh, 0, 0);
  my $digest = Digest::SHA->new();
  $digest->addfile($fh);
  return $digest->hexdigest();
}

sub qfn {
  my $string = shift;
  if ($string =~ m{(.*?)\@(.*)}) {
    $string = $2 . '!' . $1;
  }
  return "'$string'"; # mostly good :)
}

# Parse an index file, optionally also fetching message files via a callback.
# updates the indexed table in the state database.
sub ParseIndex {
  my $FolderName = shift;
  my $uniqueid = shift;
  my $fh = shift;
  my $state = shift;
  my $missingsub = shift;

  my $dbh = $state->dbh();
  my $folderid = $state->folderid($uniqueid);

  seek($fh, 0, 0);
  my $index = eval { Cyrus::IndexFile->new($fh, strict_crc => 1) };

  my $o_uid = $index->record_offset_for('Uid');
  my $o_last = $index->record_offset_for('LastUpdated');
  my $o_sysflags = $index->record_offset_for('SystemFlags');
  my $o_guid = $index->record_offset_for('MessageGuid');

  unless ($index) {
    die "Failed to read index for $FolderName ($uniqueid, $is_expunge)\n";
  }

  # speed things up again!
  if ($index->{version} < 10 or $index->{version} > $MAX_INDEXVERSION) {
    die "Don't know how to handle indexes with version $index->{version} for $FolderName ($uniqueid, $is_expunge)\n";
  }

  my $sth = $dbh->prepare("SELECT uid,fileid,deleted FROM indexed WHERE folderid = ? ORDER BY uid ASC");
  $sth->execute($folderid);

  my $Now = time();
  my $ExpireTime = $Now - $MAX_AGE;

  # scan through the database and the index file in step

  # track changes to be made.
  my @todel;
  my @toadd;

  my $record = $index->next_record_raw();
  my $dbitem = $sth->fetchrow_arrayref();

  my $uid = $record ? unpack('N', substr($record, $o_uid, 4)) : undef;
  my $guid;
  my $last;

  # cases:
  # 1) they both exist and are the same,
  # 2) $record is less or $uid is blank and $record exists
  # 3) $uid is less or $record is blank and $uid exists
  # 4) EXIT - both finish :)

  while (1) {

    # 1) they both exist and are the same,
    if ($dbitem and $record and $dbitem->[0] == $uid) {
      # move forward (both, since they matched)
      $record = $index->next_record_raw(); 
      $uid = $record ? unpack('N', substr($record, $o_uid, 4)) : undef;
      $dbitem = $sth->fetchrow_arrayref();
    }

    # 2) $record is less or $uid is blank and $record exists
    # RARE - this would be something like an undelete?
    elsif ($record and (not $dbitem or $uid < $dbitem->[0])) {

      # ignore it if it's old, otherwise create and fetch
      my $sysflags = unpack('N', substr($record, $o_sysflags, 4));
      unless ($sysflags & (1<<30)) { # unlinked
        $guid = unpack('H40', substr($record, $o_guid, 20));
        push @toadd, [$uid, $guid, $is_expunge ? $last : 0];
      }

      # move forward
      $record = $index->next_record_raw();
      $uid = $record ? unpack('N', substr($record, 0, 4)) : undef;
    }

    # 3) $uid is less or $record is blank and $uid exists
    elsif ($dbitem and (not $record or $dbitem->[0] < $uid)) {
      # remove the stale record
      unless ($dbitem->[2]) {
        push @todel, $dbitem->[0];
      }

      # move forward
      $dbitem = $sth->fetchrow_arrayref();
    }

    # 4) EXIT - both finish :)
    else {
      last;
    }
  }

  $sth->finish();

  if (@todel) {
    my $sth = $dbh->prepare("DELETE FROM indexed WHERE folderid = ? AND uid = ?");
    foreach my $need_delete (@todel) {
      unless ($sth->execute($folderid, $need_delete)) {
        die "failed to delete from DB: " . $dbh->errstr;
      }
    }
  }

  if (@toadd) {
    my $sth = $dbh->prepare("INSERT INTO indexed (folderid, uid, fileid, deleted) VALUES (?, ?, ?, ?)");
    my %need;
    foreach my $need_create (@toadd) {
      my ($uid, $guid, $last) = @$need_create;
      my $fileid = $state->fileid($guid);
      unless ($fileid) {
        $need{$uid} = $guid;
      }
    }
    $missingsub->(\%need) if (keys %need and $missingsub);
    foreach my $need_create (@toadd) {
      my ($uid, $guid, $last) = @$need_create;
      my $fileid = $state->fileid($guid);
      unless ($fileid) {
        die "no file for $uniqueid $uid ($guid) and no way to get it\n";
      }
      unless ($sth->execute($folderid, $uid, $fileid, $last)) {
        die "failed to add to DB: " . $dbh->errstr;
      }
    }
  }

  return 1;
}

sub iocmd {
  my $IO = shift;
  my @args = @_;
  my $cmd = join(' ', map { uri($_) } @args);

  my $old = alarm(12000);

  warn "IOCMD: $cmd\n" if $ENV{DEBUGIO};

  $IO->print("$cmd\n");
  my $res = $IO->getline();
  chomp($res);
  warn "    => $res\n" if $ENV{DEBUGIO};
  unless ($res =~ m/^OK/) {
    die "IO $cmd failed $res\n";
  }
  alarm($old);
  return $res;
}

sub iolist {
  my $IO = shift;
  my @args = @_;

  iocmd($IO, @args);
  my @res;
  while (my $line = $IO->getline()) {
    chomp($line);
    push @res, [map { deuri($_) } split / /, $line];
    last if $line =~ m/^DONE/;
    warn " * $line\n" if $ENV{DEBUGIO};
  }
  warn "DONE\n" if $ENV{DEBUGIO};

  return @res;
}

sub iofile {
  my $IO = shift;
  my @args = @_;

  my @res;
  iofiles($IO, \@args, sub {
    my $file = shift;
    @res = @_;
  });

  unless ($res[0]) {
    die "failed to fetch file <@args>\n";
  }

  return @res;
}

sub iofiles {
  my $IO = shift;
  my $args = shift;
  my $callback = shift;

  my $res = iocmd($IO, @$args);
  while ($res = $IO->getline()) {
    chomp($res);
    last if $res =~ m/^DONE/;
    next unless $res =~ m/^DATA (\S+) (\d+) (\d+) (\d+)/;
    my $file = $1;
    my $size = $2;
    my $mtime = $3;
    my $inode = $4;

    my ($tempfile, $checksha) = slurpbytes($IO, $size);
    my $line = $IO->getline();
    unless ($line =~ m/^DONE \S+ (\S+)/) {
      die "Failed to finish file: $line\n";
    }

    # check sha1 locally
    my $sha1 = $1;
    warn " * $sha1 $file $size $mtime $inode\n" if $ENV{DEBUGIO};
    unless ($checksha eq $sha1) {
      die "SHA1 mismatch for fetched file $file: $sha1 => $checksha\n";
    }

    $callback->($file, $tempfile, $size, $mtime, $inode, $sha1);
  }
  warn "DONE\n" if $ENV{DEBUGIO};

  return [map { deuri($_) } split / /, $res]; # split the DONE line
}

sub slurpbytes {
  my $fh = shift;
  my $bytes = shift;
  my $TempFile = File::Temp->new(DIR => $TEMPDIR);
  my $digest = Digest::SHA->new();
  my $buf;
  while ($bytes > 0) {
    my $toget = $bytes > 1048576 ? 1048576 : $bytes;
    my $n = read($fh, $buf, $toget);
    unless ($n > 0) {
      die "failed dot read with $toget bytes to get: $!\n";
    }
    syswrite($TempFile, $buf, $n);
    $digest->add($buf);
    $bytes -= $n;
  }
  return ($TempFile, $digest->hexdigest);
}

sub uri {
  my $Val = shift;
  $Val =~ s/([^A-Za-z0-9\-_.,])/sprintf('%%%02X', ord($1))/ge;
  return $Val;
}

sub deuri {
  my $Val = shift;
  $Val =~ s/\%([a-fA-F0-9][a-fA-F0-9])/chr(hex($1))/ge;
  return $Val;
}

sub _DoStream {
  my ($BaseDir, $Prefix, $ts) = @_;
  my @dirs;
  opendir(DH, $BaseDir) || return;
  while (my $item = readdir(DH)) {
    next if $item =~ /^\./; # no invisible files
    if (-d "$BaseDir/$item") {
      push @dirs, $item;
    }
    else {
      my $fh = IO::File->new("<$BaseDir/$item");
      $ts->AddFile("$Prefix/$item", -s $fh, $fh);
    }
  }
  closedir(DH);
  foreach my $dir (@dirs) {
    _DoStream("$BaseDir/$dir", "$Prefix/$dir", $ts);
  }
}

1;
