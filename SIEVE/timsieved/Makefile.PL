use ExtUtils::MakeMaker;
# See lib/ExtUtils/MakeMaker.pm for details of how to influence
# the contents of the Makefile that is written.
WriteMakefile(
    'NAME'	=> 'SIEVE::Cyrus',
    'VERSION_FROM' => 'Cyrus.pm', # finds $VERSION
    'LIBS'	=> ['-L../installsieve/ -linstallsieve -lsasl -L../../lib/ -lcyrus -lssl -lcrypto'],   # e.g., '-lm' 
    'DEFINE'	=> '',     # e.g., '-DHAVE_SOMETHING' 
    'INC'	=> '-I../installsieve/',     # e.g., '-I/usr/include/other' 
);
