
use strict;
use warnings;

BEGIN {
	eval "use Net::SMTP";
	if ( $@ ) {
		print "1..0 # no Net::SMTP\n";
		exit
	}
}

use Net::SSLGlue::SMTP;

my $capath = '/etc/ssl/certs/'; # unix?
-d $capath or do {
	print "1..0 # cannot find system CA-path\n";
	exit
};

# first try to connect w/o smtp
# plain
diag( "connect inet to mail.gmx.net:25" );
IO::Socket::INET->new( 'mail.gmx.net:25' ) or do {
	print "1..0 # mail.gmx.net:25 not reachable\n";
	exit
};

# ssl to the right host
diag( "connect ssl to mail.gmx.net:465" );
IO::Socket::SSL->new( 
	PeerAddr => 'mail.gmx.net:465',
	SSL_ca_path => $capath,
	SSL_verify_mode => 1,
	SSL_verifycn_scheme => 'smtp' 
) or do {
	print "1..0 # mail.gmx.net:465 not reachable with SSL\n";
	exit
};

# ssl to the wrong host 
# the certificate mail.gmx.de returns is for mail.gmx.net
diag( "connect ssl to mail.gmx.de:465" );
IO::Socket::SSL->new( 
	PeerAddr => 'mail.gmx.de:465',
	SSL_ca_path => $capath,
	SSL_verify_mode => 1,
	SSL_verifycn_scheme => 'smtp' 
) and do {
	print "1..0 # mail.gmx.de:465 reachable with SSL\n";
	exit
};

print "1..6\n";

# first direct SSL
my $smtp = Net::SMTP->new( 'mail.gmx.net', 
	SSL => 1, 
	SSL_ca_path => $capath,
);
print $smtp ? "ok\n" : "not ok # smtp connect mail.gmx.net\n";

# then starttls
$smtp = Net::SMTP->new( 'mail.gmx.net' );
my $ok = $smtp->starttls( SSL_ca_path => $capath );
print $ok ? "ok\n" : "not ok # smtp starttls mail.gmx.net\n";
# check that we can talk on connection
print $smtp->quit ? "ok\n": "not ok # quit failed\n";

# against wrong host should fail
$smtp = Net::SMTP->new( 'mail.gmx.de' ); # should succeed
$ok = $smtp->starttls( SSL_ca_path => $capath ); 
print $ok ? "not ok # smtp starttls mail.gmx.de did not fail\n": "ok\n";

# but not if we specify the right SSL_verifycn_name
$smtp = Net::SMTP->new( 'mail.gmx.de' ); # should succeed
$ok = $smtp->starttls( SSL_ca_path => $capath, SSL_verifycn_name => 'mail.gmx.net' ); 
print $ok ? "ok\n" : "not ok # smtp starttls mail.gmx.de/net\n";

# or disable verification
$smtp = Net::SMTP->new( 'mail.gmx.de' ); # should succeed
$ok = $smtp->starttls( SSL_verify_mode => 0 );
print $ok ? "ok\n" : "not ok # smtp starttls mail.gmx.de\n";

sub diag { 
	#print STDERR "@_\n" 
}
