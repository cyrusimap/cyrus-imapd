#use SIEVE::Cyrus;
use Getopt::Long;

$ret = GetOptions("v|views:s",
		  "l|list",
		  "p|port:i",
		  "i|installs:s",
		  "a|activates:s",
		  "d|deletes:s",
		  "m|mechanism:s",
		  "g|gets:s",
                  "u|authname:s",
		  "t|username:s",
		  "w|password:s"
                  );
if (!$ret || $#ARGV != 0) { 
    show_help();
    exit;
}

$acapserver = $ARGV[0];

$username = $opt_t;
$authname = $opt_u;
$pass = $opt_w;
$views = $opt_v;
$list = $opt_l;
$port = $opt_p;
$installs = $opt_i;
$activates = $opt_a;
$deletes = $opt_d;
$mech = $opt_m;
$gets = $opt_g;


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
  print "NOTE: This program is deprecated. Please use sieveshell\n";
  print "\n";
  print "Usage:\n";
  print "  installsieve [options] <server>\n";
  print "\n";
  print "  -v <name>    view script\n";
  print "  -l           list available scripts\n";
  print "  -p <port>    port to connect to\n";
  print "  -i <file>    filename of script to install\n";
  print "  -a <name>    Set <name> as the active script\n";
  print "  -d <name>    Delete <name> script from server\n";
  print "  -m <mech>    Mechanism to use for authentication\n";
  print "  -g <name>    Get script <name> and save to disk\n";
  print "  -u <user>    Userid/Authname to use\n";
  print "  -t <user>    Userid to use (for proxying)\n";
  print "  -w <passwd>  Specify password (Should only be used for automated scripts)\n";
  print "\n";
}

#main code

my $obj = sieve_get_handle($acapserver,"prompt","prompt","prompt","prompt");

if (!defined $obj) {
  die "Unable to connect to server";
}

if (defined $installs) {
  $ret = sieve_put_file($obj, $installs);
  if ($ret != 0) { print "Upload failed\n"; }
}

if (defined $deletes) {
  $ret = sieve_delete($obj, $deletes);
  if ($ret != 0) { print "Delete failed\n"; }
}

if (defined $activates) {
  $ret = sieve_activate($obj, $activates);
  if ($ret != 0) { print "Activate failed\n"; }
}

if (defined $gets) {
  $ret = sieve_get($obj, $gets, $str);
  if ($ret != 0) { 
    print "get failed\n"; 
  } else {
    open (OUTPUT,">$gets") || die "Unable to open $gets";
    print OUTPUT $str;
    close(OUTPUT);    
  }
}

if ($list == 1) {
  $ret = sieve_list($obj, "list_cb");  
  if ($ret != 0) { print "List command failed\n"; }
}
