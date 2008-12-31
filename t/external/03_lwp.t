
use strict;
use warnings;

BEGIN {
	eval "use LWP";
	if ( $@ ) {
		print "1..0 # no LWP\n";
		exit
	}
}

use Net::SSLGlue::LWP;
use LWP::Simple;

my $capath = '/etc/ssl/certs/'; # unix?
-d $capath or do {
	print "1..0 # cannot find system CA-path\n";
	exit
};
Net::SSLGlue::LWP->import( SSL_ca_path => $capath );

#
# first check everything directly with IO::Socket::SSL
#

# signin.ebay.de has a certificate, which is for signin.ebay.com
# but where signin.ebay.de is a subjectAltName
IO::Socket::SSL->new(
	PeerAddr => 'signin.ebay.de:443',
	SSL_ca_path => $capath,
	SSL_verify_mode => 1,
	SSL_verifycn_scheme => 'http'
) or do {
	print "1..0 # ssl connect signin.ebay.de failed\n";
	exit
};

# www.fedora.org has a certificate which has nothing in common 
# with the hostname
my $sock = IO::Socket::INET->new( 'www.fedora.org:443' ) or do {
	print "1..0 # connect to www.fedora.org failed\n";
	exit
};
IO::Socket::SSL->start_SSL( $sock,
	SSL_ca_path => $capath,
	SSL_verify_mode => 1,
	SSL_verifycn_scheme => 'http'
) and do {
	print "1..0 # certificate for www.fedora.org unexpectly correct\n";
	exit
};

#
# and than check, that LWP uses the same checks
#

print "1..3\n";

# signin.ebay.de -> should succeed
my $content = get( 'https://signin.ebay.de' );
print $content ? "ok\n": "not ok # lwp connect signin.ebay.de: $@\n";

# www.fedora.org -> should fail
$content = get( 'https://www.fedora.org' );
print $content ? "not ok # lwp ssl connect www.fedora.org should fail\n": "ok\n";

# www.fedora.org -> should succeed if verify mode is 0
{
	local %Net::SSLGlue::LWP::SSLopts = %Net::SSLGlue::LWP::SSLopts;
	$Net::SSLGlue::LWP::SSLopts{SSL_verify_mode} = 0;
	$content = get( 'https://www.fedora.org' );
	print $content ? "ok\n": "not ok # lwp ssl www.fedora.org w/o ssl verify\n";
}

