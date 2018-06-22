#!/bin/sh
# $FreeBSD$

. $(dirname $0)/conf.sh

base=`basename $0`
sectors=2
keyfile=`mktemp $base.XXXXXX` || exit 1
sector=`mktemp $base.XXXXXX` || exit 1

echo "1..600"

do_test() {
	cipher=$1
	aalgo=$2
	secsize=$3
	ealgo=${cipher%%:*}
	keylen=${cipher##*:}

	geli init -B none -a $aalgo -e $ealgo -l $keylen -P -K $keyfile -s $secsize ${md} 2>/dev/null

	# Corrupt 8 bytes of data.
	dd if=/dev/${md} of=${sector} bs=512 count=1 >/dev/null 2>&1
	dd if=/dev/random of=${sector} bs=1 count=8 seek=64 conv=notrunc >/dev/null 2>&1
	dd if=${sector} of=/dev/${md} bs=512 count=1 >/dev/null 2>&1
	geli attach -p -k $keyfile ${md}

	dd if=/dev/${md}.eli of=/dev/null bs=${secsize} count=1 >/dev/null 2>&1
	if [ $? -ne 0 ]; then
		echo "ok $i - aalgo=${aalgo} ealgo=${ealgo} keylen=${keylen} sec=${secsize}"
	else
		echo "not ok $i - aalgo=${aalgo} ealgo=${ealgo} keylen=${keylen} sec=${secsize}"
	fi
	i=$((i+1))
}

i=1
dd if=/dev/random of=${keyfile} bs=512 count=16 >/dev/null 2>&1

for_each_geli_config do_test

rm -f $keyfile $sector
