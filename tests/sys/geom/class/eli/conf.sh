#!/bin/sh

class="eli"
base=$(atf_get ident)
MAX_SECSIZE=8192

attach_md()
{
	local _md
	local rv=$1
	shift

	[ -c /dev/mdctl ] || atf_skip "no /dev/mdctl to create md devices"
	_md=$(mdconfig -a "$@") || atf_fail "failed to allocate md(4)"
	echo $_md >> $TEST_MDS_FILE || exit
	eval "${rv}='${_md}'"
}

# Execute `func` for each combination of cipher, sectorsize, and hmac algo
# `func` usage should be:
# func <cipher> <aalgo> <secsize>
for_each_geli_config() {
	func=$1
	backing_filename=$2
	local ciphers aalgos secsizes
	ciphers=aes-xts:128 aes-xts:256 \
	    aes-cbc:128 aes-cbc:192 aes-cbc:256 \
	    camellia-cbc:128 camellia-cbc:192 camellia-cbc:256
	aalgos=hmac/sha1 hmac/ripemd160 hmac/sha256 hmac/sha384 hmac/sha512
	secsizes=512 1024 2048 4096 $MAX_SECSIZE
	# Note: The combinatorics explosion here results in tests taking an
	# extremely long time for RISC-V purecap. For example, integrity_test
	# runs for 2 hours and times out and init_test takes about 40 minutes.
	# Unless the include_slow_tests option is set, we run only
	# one configuration instead of the full matrix to reduce CI test time
	# by almost 4 hours.
	if [ "$(atf_config_get include_slow_tests false)" != "true" ]; then
		# FIXME: which configuration is best for test coverage?
		ciphers=aes-cbc:256
		aalgos=hmac/ripemd160
		secsizes=2048
	fi

	# Double the sector size to allow for the HMACs' storage space.
	osecsize=$(( $MAX_SECSIZE * 2 ))
	# geli needs 512B for the label.
	bytes=`expr $osecsize \* $sectors + 512`b

	if [ -n "$backing_filename" ]; then
		# Use a file-backed md(4) device, so we can deliberatly corrupt
		# it without detaching the geli device first.
		truncate -s $bytes backing_file
		attach_md md -t vnode -f backing_file
	else
		attach_md md -t malloc -s $bytes
	fi


	for cipher in $ciphers; do
		ealgo=${cipher%%:*}
		keylen=${cipher##*:}
		for aalgo in $aalgos; do
			for secsize in $secsizes; do
				${func} $cipher $aalgo $secsize
				geli detach ${md} 2>/dev/null
			done
		done
	done
}

# Execute `func` for each combination of cipher, and sectorsize, with no hmac
# `func` usage should be:
# func <cipher> <secsize>
for_each_geli_config_nointegrity() {
	func=$1
	local ciphers secsizes
	ciphers=aes-xts:128 aes-xts:256 \
	    aes-cbc:128 aes-cbc:192 aes-cbc:256 \
	    camellia-cbc:128 camellia-cbc:192 camellia-cbc:256
	secsizes=512 1024 2048 4096 $MAX_SECSIZE
	# Note: The combinatorics explosion here results in tests taking an
	# extremely long time for RISC-V purecap. For example, integrity_test
	# runs for 2 hours and times out and init_test takes about 40 minutes.
	# Unless the include_slow_tests option is set, we run only
	# one configuration instead of the full matrix to reduce CI test time
	# by almost 4 hours.
	if [ "$(atf_config_get include_slow_tests false)" != "true" ]; then
		# FIXME: which configuration is best for test coverage?
		ciphers=aes-cbc:256
		secsizes=2048
	fi

	# geli needs 512B for the label.
	bytes=`expr $MAX_SECSIZE \* $sectors + 512`b
	attach_md md -t malloc -s $bytes
	for cipher in $ciphers; do
		ealgo=${cipher%%:*}
		keylen=${cipher##*:}
		for secsize in $secsizes; do
			${func} $cipher $secsize
			geli detach ${md} 2>/dev/null
		done
	done
}

geli_test_cleanup()
{
	if [ -f "$TEST_MDS_FILE" ]; then
		while read md; do
			[ -c /dev/${md}.eli ] && \
				geli detach $md.eli 2>/dev/null
			mdconfig -d -u $md 2>/dev/null
		done < $TEST_MDS_FILE
	fi
	true
}

geli_test_setup()
{
	geom_atf_test_setup
}

ATF_TEST=true
. `dirname $0`/../geom_subr.sh
