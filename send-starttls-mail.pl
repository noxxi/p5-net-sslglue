use strict;
use warnings;

use Net::SSLGlue::SMTP;
my $smtp = Net::SMTP->new( 'mail.gmx.net', Debug => 1 ) or die $@;
$smtp->starttls( SSL_ca_path => "/etc/ssl/certs" ) or die $@;
$smtp->auth( '990896','affentanz13' );
$smtp->mail( 'coyote.frank@gmx.net' );
$smtp->to( 'steffen@noxxi.de' );
$smtp->data;
$smtp->datasend( <<EOD );
From: me
To: you
Subject: test test

lalaal
EOD
$smtp->dataend;
$smtp->quit;

