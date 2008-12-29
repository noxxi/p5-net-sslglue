use strict;
use LWP::Simple;
use Net::SSLGlue::LWP SSL_ca_path => '/etc/ssl/certs';

print get( 'https://www.comdirect.de' ) || die $@;
