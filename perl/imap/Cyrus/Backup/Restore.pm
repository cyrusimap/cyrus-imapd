package Cyrus::Backup::Restore;

use Archive::Tar::Stream;
use Cyrus::Backup;
use Cyrus::Backup::State;
use File::Copy;

sub new {
  my $class = shift;
  my $path = shift;

  my $DBName = 'backupstate.sqlite3';

  my $state = Cyrus::Backup::State->new($path, $DBName);

  return bless {
    path => $path,
    state => $state,
  }, ref($class) || $class;
}

sub TarFileName {
  my $Self = shift;

  my $state = $Self->{state};
  my ($filename) = $state->dbh->selectrow_array("SELECT filename FROM status");

  return $filename;
}

sub GetTar {
  my $Self = shift;
  my $path = $Self->{path};

  my $filename = $Self->TarFileName();

  my $infh = Cyrus::Backup::OpenDataFile("$path/$filename", 'r')
    || die "can't read tar file";

  return Archive::Tar::Stream->new(infh => $infh);
}

sub GetFile {
  my $Self = shift;
  my $path = $Self->{path};
  my @sha1s = @_;

  my %wanted = map { ("files/$_" => "$path/files/$_") } @sha1s;
  return @sha1s unless grep { not -f $_ } values %wanted;

  my $ts = $Self->GetTar();

  $ts->StreamCopy(sub {
    my $header = shift;
    my $outpos = shift;
    my $fh = shift;

    return 'SKIP' unless $wanted{$header->{name}};
    return 'SKIP' if -f $wanted{$header->{name}};
    return 'EDIT' unless $fh;
    my $check = ME::CyrusBackup::GetSHA1($fh);
    if ("files/$check" eq $header->{name}) {
      my ($login, $pass, $uid, $gid) = getpwnam('cyrus');
      seek($fh, 0, 0);
      unless (-d "$path/files") {
        mkdir("$path/files");
        chown($uid, $gid, "$path/files");
      }
      File::Copy::copy($fh, $wanted{$header->{name}});
      chown($uid, $gid, $wanted{$header->{name}});
    }
    return 'SKIP';
  });

  return grep { -f $_ } values %wanted;
}

sub DESTROY {
  my $Self = shift;
  $Self->{state}->cancel();
}

1;
