use strict;
use warnings;

print "1..3\n";
for (
	[ 'Net::SMTP','SMTP' ],
	[ 'LWP',      'LWP'  ],
	[ 'Net::LDAP','LDAP' ],
) {
	my ($pkg,$glue) = @$_;
	eval "use $pkg";
	if ( ! $@ ) {
		eval "use Net::SSLGlue::$glue";
		print $@ ? "not ok # load $glue glue failed\n": "ok # load $glue glue\n"
	} else {
		print "ok # skip $glue glue\n"
	}
}
