
use strict;
use warnings;

BEGIN {
	eval "use Net::POP3";
	if ( $@ ) {
		print "1..0 # no Net::POP3\n";
		exit
	}
}

use Net::SSLGlue::POP3;

my $capath = '/etc/ssl/certs/'; # unix?
-d $capath or do {
	print "1..0 # cannot find system CA-path\n";
	exit
};

# first try to connect w/o smtp
# plain
diag( "connect inet to pop.gmx.net:110" );
IO::Socket::INET->new( 'pop.gmx.net:110' ) or do {
	print "1..0 # pop.gmx.net:110 not reachable\n";
	exit
};

# ssl to the right host
diag( "connect ssl to pop.gmx.net:995" );
IO::Socket::SSL->new( 
	PeerAddr => 'pop.gmx.net:995',
	SSL_ca_path => $capath,
	SSL_verify_mode => 1,
	SSL_verifycn_scheme => 'smtp' 
) or do {
	print "1..0 # pop.gmx.net:995 not reachable with SSL\n";
	exit
};

# ssl to the wrong host 
# the certificate pop.gmx.de returns is for pop.gmx.net
diag( "connect ssl to pop.gmx.de:995" );
IO::Socket::SSL->new( 
	PeerAddr => 'pop.gmx.de:995',
	SSL_ca_path => $capath,
	SSL_verify_mode => 1,
	SSL_verifycn_scheme => 'smtp' 
) and do {
	print "1..0 # pop.gmx.de:995 reachable with SSL\n";
	exit
};

print "1..6\n";

# first direct SSL
my $smtp = Net::POP3->new( 'pop.gmx.net', 
	SSL => 1, 
	SSL_ca_path => $capath,
);
print $smtp ? "ok\n" : "not ok # smtp connect pop.gmx.net\n";

# then starttls
$smtp = Net::POP3->new( 'pop.gmx.net' );
my $ok = $smtp->starttls( SSL_ca_path => $capath );
print $ok ? "ok\n" : "not ok # smtp starttls pop.gmx.net\n";
# check that we can talk on connection
print $smtp->quit ? "ok\n": "not ok # quit failed\n";

# against wrong host should fail
$smtp = Net::POP3->new( 'pop.gmx.de' ); # should succeed
$ok = $smtp->starttls( SSL_ca_path => $capath ); 
print $ok ? "not ok # smtp starttls pop.gmx.de did not fail\n": "ok\n";

# but not if we specify the right SSL_verifycn_name
$smtp = Net::POP3->new( 'pop.gmx.de' ); # should succeed
$ok = $smtp->starttls( SSL_ca_path => $capath, SSL_verifycn_name => 'pop.gmx.net' ); 
print $ok ? "ok\n" : "not ok # smtp starttls pop.gmx.de/net\n";

# or disable verification
$smtp = Net::POP3->new( 'pop.gmx.de' ); # should succeed
$ok = $smtp->starttls( SSL_verify_mode => 0 );
print $ok ? "ok\n" : "not ok # smtp starttls pop.gmx.de\n";

sub diag { 
	#print STDERR "@_\n" 
}
