use SIEVE::managesieve;
use Getopt::Long;

$ret = GetOptions("a|authname:s",
                  "u|username:s",
		  "r|realm:s",
		  "e|exec:s"
                  );
if (!$ret || $#ARGV != 0) { 
    show_help();
    exit;
}

$acapserver = $ARGV[0];

$username = $opt_u;
$authname = $opt_a;
$realm    = $opt_r;
$exec     = $opt_e;

if (defined $exec) {
  $tmpfile = "/tmp/sieveshell.tmp";
  open (TMP,">$tmpfile") || die "Unable to open tmp file";
  print TMP $exec;
  close(TMP);
  open (TMP,"<$tmpfile") || die "Unable to open tmp file";
  unlink($tmpfile);
  $filehandle = *TMP;
} else {
  $filehandle = *STDIN;
  $interactive = 1;
}



sub list_cb {

  my($name, $isactive) = @_ ;
  
  print "$name ";
  if ($isactive == 1) {
    print " <- active script\n";
  } else {
    print "\n";
  }

}

sub prompt {

  my($type, $prompt) = @_ ;

  if (($type eq "username") && (defined $username)) {
    $username;
    return;
  } elsif (($type eq "authname") && (defined $authname)) {
    $authname;
    return;
  } elsif (($type eq "realm") && (defined $realm)) {
    $realm;
    return;
  }

  print "$prompt: ";

  $b = <STDIN>;
  chop($b);
  
  $b;
}

sub show_help {
  print "Usage:\n";
  print "  sieveshell [-u username][-a authname][-r realm] <server>\n";
  print "\n";
  print "help             - this screen\n";
  print "list             - list scripts on server\n";
  print "put <filename>   - upload script to server (implicitly set active if no active script)\n";
  print "get <name> [<filename>] - get script. if no filename display to stdout\n";
  print "delete <name>    - delete script.\n";
  print "activate <name>  - set a script as the active script\n";
  print "quit             - Quit\n";
}

# main code

my $obj = sieve_get_handle($acapserver,"prompt","prompt","prompt","prompt");

if (!defined $obj) {
  die "Unable to connect to server";
}

if ($interactive == 1) {
  print "> ";
}

while(<$filehandle>) {

  @words = split ' ',$_;

  if (($words[0] eq "put") || ($words[0] eq "p")) {

    $ret = sieve_put_file($obj, $words[1]);
    
    if ($ret != 0) { print "Upload failed\n"; }

  } elsif (($words[0] eq "list") || ($words[0] eq "l") || ($words[0] eq "ls")) {
    
    $ret = sieve_list($obj, "list_cb");

    if ($ret != 0) { print "List command failed\n"; }

  } elsif (($words[0] eq "activate") || ($words[0] eq "a")) {

    $ret = sieve_activate($obj, $words[1]);
    if ($ret != 0) { print "Activate failed\n"; }

  } elsif (($words[0] eq "delete") || ($words[0] eq "d")) {    

    $ret = sieve_delete($obj, $words[1]);
    if ($ret != 0) { print "Delete failed\n"; }

  } elsif (($words[0] eq "get") || ($words[0] eq "g")) {

    $ret = sieve_get($obj, $words[1], $str);
    if ($ret != 0) { 
      print "get failed\n"; 
    } else {
      if ($words[2]) {
	open (OUTPUT,">$words[2]") || die "Unable to open $words[2]";
	print OUTPUT $str;
	close(OUTPUT);
      } else {
	print $str;
      }
    }

  } elsif (($words[0] eq "quit") || ($words[0] eq "q")) {
    exit 0;

  } elsif (($words[0] eq "help") || ($words[0] eq "?")) {
    show_help();
  } else {
    print "Invalid command: $words[0]\n";
  } 

  if ($interactive == 1) {
    print "> ";
  }
}
