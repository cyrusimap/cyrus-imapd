use ExtUtils::MakeMaker;

# See lib/ExtUtils/MakeMaker.pm for details of how to influence
# the contents of the Makefile that is written.
WriteMakefile( 
    'NAME'	=> 'Cyrus::IMAP',
    'ABSTRACT'  => 'Cyrus administrative interface',
    'VERSION_FROM' => 'IMAP.pm', # finds $VERSION
    'macro'	=> {'IMCLIENT_LIBS' => ''},	# hack
    'clean'	=> {'FILES' => 'libcyrperl.a cyradm'},
    'LIBS'	=> ['-lsasl -L../../../lib/ -lcyrus -lssl -lcrypto'],   # e.g., '-lm'
    'DEFINE'	=> '',     # e.g., '-DHAVE_SOMETHING' 
    'INC'	=> '-I../../lib',     # e.g., '-I/usr/include/other' 
    'EXE_FILES' => [cyradm],
);
