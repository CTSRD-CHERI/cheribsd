#!/bin/sh
#-
# SPDX-License-Identifier: BSD-2-Clause-FreeBSD
#
# Copyright 2018 Allan Jude <allanjude@freebsd.org>
#
# Redistribution and use in source and binary forms, with or without
# modification, are permitted providing that the following conditions 
# are met:
# 1. Redistributions of source code must retain the above copyright
#    notice, this list of conditions and the following disclaimer.
# 2. Redistributions in binary form must reproduce the above copyright
#    notice, this list of conditions and the following disclaimer in the
#    documentation and/or other materials provided with the distribution.
#
# THIS SOFTWARE IS PROVIDED BY THE AUTHOR ``AS IS'' AND ANY EXPRESS OR
# IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED
# WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
# ARE DISCLAIMED.  IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR ANY
# DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
# DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS
# OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
# HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT,
# STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING
# IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE
# POSSIBILITY OF SUCH DAMAGE.
#
# $FreeBSD$

############################################################ CONFIGURATION

: ${DESTDIR:=}
: ${FILEPAT:="\.pem$|\.crt$|\.cer$|\.crl$"}
: ${VERBOSE:=0}

############################################################ GLOBALS

SCRIPTNAME="${0##*/}"
ERRORS=0
NOOP=0
UNPRIV=0

############################################################ FUNCTIONS

do_hash()
{
	local hash

	if hash=$( openssl x509 -noout -subject_hash -in "$1" ); then
		echo "$hash"
		return 0
	else
		echo "Error: $1" >&2
		ERRORS=$(( $ERRORS + 1 ))
		return 1
	fi
}

get_decimal()
{
	local checkdir hash decimal

	checkdir=$1
	hash=$2
	decimal=0

	while [ -e "$checkdir/$hash.$decimal" ]; do
		decimal=$((decimal + 1))
	done

	echo ${decimal}
	return 0
}

create_trusted_link()
{
	local blisthash certhash hash
	local suffix

	hash=$( do_hash "$1" ) || return
	certhash=$( openssl x509 -sha1 -in "$1" -noout -fingerprint )
	for blistfile in $(find $BLACKLISTDESTDIR -name "$hash.*"); do
		blisthash=$( openssl x509 -sha1 -in "$blistfile" -noout -fingerprint )
		if [ "$certhash" = "$blisthash" ]; then
			echo "Skipping blacklisted certificate $1 ($blistfile)"
			return 1
		fi
	done
	suffix=$(get_decimal "$CERTDESTDIR" "$hash")
	[ $VERBOSE -gt 0 ] && echo "Adding $hash.$suffix to trust store"
	[ $NOOP -eq 0 ] && \
		install ${INSTALLFLAGS} -lrs $(realpath "$1") "$CERTDESTDIR/$hash.$suffix"
}

create_blacklisted()
{
	local hash srcfile filename
	local suffix

	# If it exists as a file, we'll try that; otherwise, we'll scan
	if [ -e "$1" ]; then
		hash=$( do_hash "$1" ) || return
		srcfile=$(realpath "$1")
		suffix=$(get_decimal "$BLACKLISTDESTDIR" "$hash")
		filename="$hash.$suffix"
	elif [ -e "${CERTDESTDIR}/$1" ];  then
		srcfile=$(realpath "${CERTDESTDIR}/$1")
		hash=$(echo "$1" | sed -Ee 's/\.([0-9])+$//')
		suffix=$(get_decimal "$BLACKLISTDESTDIR" "$hash")
		filename="$hash.$suffix"
	else
		return
	fi
	[ $VERBOSE -gt 0 ] && echo "Adding $filename to blacklist"
	[ $NOOP -eq 0 ] && install ${INSTALLFLAGS} -lrs "$srcfile" "$BLACKLISTDESTDIR/$filename"
}

do_scan()
{
	local CFUNC CSEARCH CPATH CFILE
	local oldIFS="$IFS"
	CFUNC="$1"
	CSEARCH="$2"

	IFS=:
	set -- $CSEARCH
	IFS="$oldIFS"
	for CPATH in "$@"; do
		[ -d "$CPATH" ] || continue
		echo "Scanning $CPATH for certificates..."
		for CFILE in $(ls -1 "${CPATH}" | grep -Ee "${FILEPAT}"); do
			[ -e "$CPATH/$CFILE" -a $UNPRIV -eq 0 ] || continue
			[ $VERBOSE -gt 0 ] && echo "Reading $CFILE"
			"$CFUNC" "$CPATH/$CFILE"
		done
	done
}

do_list()
{
	local CFILE subject

	if [ -e "$1" ]; then
		cd "$1"
		for CFILE in *.[0-9]; do
			if [ ! -s "$CFILE" ]; then
				echo "Unable to read $CFILE" >&2
				ERRORS=$(( $ERRORS + 1 ))
				continue
			fi
			subject=
			if [ $VERBOSE -eq 0 ]; then
				subject=$( openssl x509 -noout -subject -nameopt multiline -in "$CFILE" |
				    sed -n '/commonName/s/.*= //p' )
			fi
			[ "$subject" ] ||
			    subject=$( openssl x509 -noout -subject -in "$CFILE" )
			printf "%s\t%s\n" "$CFILE" "$subject"
		done
		cd -
	fi
}

cmd_rehash()
{

	if [ $NOOP -eq 0 ]; then
		if [ -e "$CERTDESTDIR" ]; then
			find "$CERTDESTDIR" -type link -delete
		else
			mkdir -p "$CERTDESTDIR"
		fi
		if [ -e "$BLACKLISTDESTDIR" ]; then
			find "$BLACKLISTDESTDIR" -type link -delete
		else
			mkdir -p "$BLACKLISTDESTDIR"
		fi
	fi

	do_scan create_blacklisted "$BLACKLISTPATH"
	do_scan create_trusted_link "$TRUSTPATH"
}

cmd_list()
{
	echo "Listing Trusted Certificates:"
	do_list "$CERTDESTDIR"
}

cmd_blacklist()
{
	local BPATH

	shift # verb
	[ $NOOP -eq 0 ] && mkdir -p "$BLACKLISTDESTDIR"
	for BFILE in "$@"; do
		echo "Adding $BFILE to blacklist"
		create_blacklisted "$BFILE"
	done
}

cmd_unblacklist()
{
	local BFILE blisthash certhash hash

	shift # verb
	for BFILE in "$@"; do
		if [ -s "$BFILE" ]; then
			hash=$( do_hash "$BFILE" )
			certhash=$( openssl x509 -sha1 -in "$BFILE" -noout -fingerprint )
			for BLISTEDFILE in $(find $BLACKLISTDESTDIR -name "$hash.*"); do
				blisthash=$( openssl x509 -sha1 -in "$BLISTEDFILE" -noout -fingerprint )
				if [ "$certhash" = "$blisthash" ]; then
					echo "Removing $(basename "$BLISTEDFILE") from blacklist"
					[ $NOOP -eq 0 ] && rm -f $BLISTEDFILE
				fi
			done
		elif [ -e "$BLACKLISTDESTDIR/$BFILE" ]; then
			echo "Removing $BFILE from blacklist"
			[ $NOOP -eq 0 ] && rm -f "$BLACKLISTDESTDIR/$BFILE"
		else
			echo "Cannot find $BFILE" >&2
			ERRORS=$(( $ERRORS + 1 ))
		fi
	done
}

cmd_blacklisted()
{
	echo "Listing Blacklisted Certificates:"
	do_list "$BLACKLISTDESTDIR"
}

usage()
{
	exec >&2
	echo "Manage the TLS trusted certificates on the system"
	echo "	$SCRIPTNAME [-v] list"
	echo "		List trusted certificates"
	echo "	$SCRIPTNAME [-v] blacklisted"
	echo "		List blacklisted certificates"
	echo "	$SCRIPTNAME [-nUv] [-D <destdir>] [-M <metalog>] rehash"
	echo "		Generate hash links for all certificates"
	echo "	$SCRIPTNAME [-nv] blacklist <file>"
	echo "		Add <file> to the list of blacklisted certificates"
	echo "	$SCRIPTNAME [-nv] unblacklist <file>"
	echo "		Remove <file> from the list of blacklisted certificates"
	exit 64
}

############################################################ MAIN

while getopts D:M:nUv flag; do
	case "$flag" in
	D) DESTDIR=${OPTARG} ;;
	M) METALOG=${OPTARG} ;;
	n) NOOP=1 ;;
	U) UNPRIV=1 ;;
	v) VERBOSE=$(( $VERBOSE + 1 )) ;;
	esac
done
shift $(( $OPTIND - 1 ))

: ${METALOG:=${DESTDIR}/METALOG}
INSTALLFLAGS=
[ $UNPRIV -eq 1 ] && INSTALLFLAGS=-U -M ${METALOG} -D ${DESTDIR}
: ${TRUSTPATH:=${DESTDIR}/usr/share/certs/trusted:${DESTDIR}/usr/local/share/certs:${DESTDIR}/usr/local/etc/ssl/certs}
: ${BLACKLISTPATH:=${DESTDIR}/usr/share/certs/blacklisted:${DESTDIR}/usr/local/etc/ssl/blacklisted}
: ${CERTDESTDIR:=${DESTDIR}/etc/ssl/certs}
: ${BLACKLISTDESTDIR:=${DESTDIR}/etc/ssl/blacklisted}

[ $# -gt 0 ] || usage
case "$1" in
list)		cmd_list ;;
rehash)		cmd_rehash ;;
blacklist)	cmd_blacklist "$@" ;;
unblacklist)	cmd_unblacklist "$@" ;;
blacklisted)	cmd_blacklisted ;;
*)		usage # NOTREACHED
esac

retval=$?
[ $ERRORS -gt 0 ] && echo "Encountered $ERRORS errors" >&2
exit $retval

################################################################################
# END
################################################################################
