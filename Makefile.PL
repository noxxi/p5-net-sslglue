use ExtUtils::MakeMaker;
require 5.008;
WriteMakefile(
	NAME => 'Net::SSLGlue',
	VERSION_FROM => 'lib/Net/SSLGlue.pm',
	PREREQ_PM => {
		'IO::Socket::SSL' => 1.14,
	},
);
