use Getopt::Long;
use Cyrus::IMAP;
use Cyrus::IMAP::Admin;

GetOptions("s|server=s" => \$server,
           "w|where=s" => \$where,
           "u|user=s" => \$user);

if (@ARGV) {
    $re = shift(@ARGV);
}

my $cyrus = Cyrus::IMAP->new($server);
$cyrus->authenticate(-user => $user, -maxssf => 0);

#list mailboxes in inbox.*
my @info = ();
$cyrus->addcallback({-trigger => 'LIST',
		     -callback => sub {
		        my %d = @_;
			next unless $d{-text} =~ s/^\(([^\)]*)\) //;
			my $attrs = $1;
			my $sep = '';
			# NIL or (attrs) "sep" "str"
			if ($d{-text} =~ /^N/) {
			  return if $d{-text} !~ s/^NIL//;
			}
			elsif ($d{-text} =~ s/\"\\?(.)\"//) {
			  $sep = $1;
			}
			return unless $d{-text} =~ s/^ //;
			my $mbox;
			if ($d{-text} =~ /\"(([^\\\"]*\\)*[^\\\"]*)\"/) {
			  ($mbox = $1) =~ s/\\(.)/$1/g;
			} else {
			  $d{-text} =~ /^([]!\#-[^-~]+)/;
			  $mbox = $1;
			}
			push @{$d{-rock}}, $mbox;
		      },
		      -rock => \@info});

my ($rc, $msg) = $cyrus->send('', '', "LIST * $where*");
$cyrus->addcallback({-trigger => 'LIST'});
if ($rc eq 'OK') {
} else {
  die "IMAP Error: $msg ";
}

my %mb_size;
my %mb_msgs;

foreach $a (@info) {
  ($b, $c) = sizeofmailbox($a);

  @z = split(/\./, $a);
  
  undef $str;
  foreach $y (@z) {
    if (defined $str) {
      $str=$str.".";
    }
    $str=$str.$y;
    $mb_size{$str} += $b;
    $mb_msgs{$str} += $c;
  }


}

foreach $a (sort keys %mb_size) {
  if (defined $mb_size{$a}) {
    showsize($mb_size{$a}, $mb_msgs{$a}, $a);
  }
}


sub sizeofmailbox {
  my ($mb) = @_;

  #select something
  my @info = ();
  $flags = Cyrus::IMAP::CALLBACK_NUMBERED;
  $cyrus->addcallback({-trigger => 'FLAGS', -flags => $flags,
		       -callback => sub {
			 
		       },
		       -rock => \@info});
  my ($rc, $msg) = $cyrus->send('', '', "SELECT $mb");
  if ($rc eq 'OK') {
  } else {
    print "Failure!\n";
  }

  #list size of all msgs
  my $totalsize = 0;
  $flags = 1;
  
  my %info = ();
  $info{'totalsize'} = 0;
  $info{'messages'} = 0;
  
  $cyrus->addcallback({-trigger => 'FETCH', -flags => $flags,
		       -callback => sub {
			 my %d = @_;
			 my $msgno = 1;
			 $msgno = $d{-msgno};
			 
			 my $size = 0;
			 if ( $d{-text} =~ /\(RFC822.SIZE (\d+)\)/)
			   {			 
			     $size = $1;
			   }
			 ${$d{-rock}}{'totalsize'} += $size;
		         ${$d{-rock}}{'messages'}++;
		    }, 
  -rock => \%info});

  my ($rc, $msg) = $cyrus->send('', '', 'FETCH 1:* RFC822.SIZE');
  $cyrus->addcallback({-trigger => 'FETCH'});

  ($info{'totalsize'}, $info{'messages'});
} 

sub showsize {

  my ($size,$msgs, $name) = @_;

  if ($size < 1024) {
    printf "%9.2f bytes\t", $size;
  } elsif ($size < 1024*1024) {
    $size = $size/1024;
    printf "%9.2f KB\t", $size;
  } elsif ($size < 1024*1024*1024) {
    $size = $size/ (1024 *1024);
    printf "%9.2f MB\t", $size;
  } else {
    print "too fucking big\t";
  }

  printf "%5d msgs\t", $msgs;

  print "\t$name\n";
}
