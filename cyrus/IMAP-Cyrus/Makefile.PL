use ExtUtils::MakeMaker;

# ugly hork to work around a MakeMaker "feature"
BEGIN {if (! -f 'libcyrperl.a') {system 'touch', 'libcyrperl.a'; $created = 1}}
END {if ($created) { unlink 'libcyrperl.a' }}

# pre-work, grabs some vars we need
use IO::File;
$libs = '';
$cyrus_lib = ($ENV{CYRUS_SRC} || '..') . '/lib';
{
  if (! -f $cyrus_lib . '/Makefile') {
    die "A fully configured Cyrus IMAPD source tree was not found.
Please specify its location in the CYRUS_SRC environment variable.";
  }
  my $fh = IO::File->new("$cyrus_lib/Makefile", O_RDONLY)
    or die "Can't find Cyrus IMAPD library Makefile";
  my $line;
  my $pic;
  if ($rules =~ /^CCCDLFLAGS\s*=\s*(.*)\r?$/m) {
    $pic = $1;
  }
  while (defined ($line = $fh->getline)) {
    if ($line =~ /^srcdir\s*=/) {
      $line =~ s/(=\s*)(.*)\r?$/$1$cyrus_lib\/$2/;
    }
    elsif ($line =~ /^LIBS\s*=\s*(.*)\r?$/) {
      my $l = $1;
      $l =~ s/(^|\s)-lf?l(\s|$)/ /;
      $libs .= ($libs ? ' ' : '') . $l;
    }
    elsif ($line =~ /^LDFLAGS\s*=\s*(.*)\r?$/) {
      $libs = $1 . ($libs ? ' ' : '') . $libs;
    }
  }
}

# See lib/ExtUtils/MakeMaker.pm for details of how to influence
# the contents of the Makefile that is written.
WriteMakefile(
    'NAME'	=> 'IMAP::Cyrus',
    'ABSTRACT'  => 'Cyrus administrative interface',
    'VERSION_FROM' => 'Cyrus.pm', # finds $VERSION
    'macro'	=> {'IMCLIENT_LIBS' => ''},	# hack
    'clean'	=> {'FILES' => 'libcyrperl.a cyradm'},
    'LIBS'	=> ["-L. -lcyrperl -lsasl $libs"],   # e.g., '-lm' 
    'DEFINE'	=> '',     # e.g., '-DHAVE_SOMETHING' 
    'INC'	=> '',     # e.g., '-I/usr/include/other' 
    'EXE_FILES' => [cyradm],
);

package MY;

# return standard top targets, with LIBS from Cyrus prepended
sub top_targets {
  # get the standard targets
  my $rules = shift->SUPER::top_targets(@_);
  # add our rules to the Makefile fragment
  $rules .= <<"EOF";
  
config :: libcyrperl.a

libcyrperl.a: $::cyrus_lib/libcyrus.a xsutil.o
	cp $::cyrus_lib/libcyrus.a libcyrperl.a
	\$(AR) \$(AR_STATIC_ARGS) libcyrperl.a xsutil.o
	\$(RANLIB) libcyrperl.a

EOF
  $rules;
}

sub dynamic_lib {
  # get the standard targets
  my $rules = shift->SUPER::dynamic_lib(@_);
  # add our rules to the Makefile fragment
  $rules =~ s/(:\s+\$\(OBJECT\))(\s)/$1$2libcyrperl.a$2/mg;
  $rules;
}
