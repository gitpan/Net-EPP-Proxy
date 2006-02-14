#!/usr/bin/perl
# $Id: Makefile.PL,v 1.2 2006/02/14 16:47:06 gavin Exp $

use ExtUtils::MakeMaker;

WriteMakefile(
    'NAME'			=> 'Net::EPP::Proxy',
    'VERSION_FROM'		=> 'lib/Net/EPP/Proxy.pm',
    'PREREQ_PM'			=> {
	'Net::Server'		=> 0,
	'Net::EPP::Client'	=> '0.05',
	'Net::EPP::Frame'	=> 0,
	'Time::HiRes'		=> 0,
	'Digest::MD5'		=> 0,
    },
);
