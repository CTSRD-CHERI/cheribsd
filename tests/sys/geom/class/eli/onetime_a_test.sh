#!/bin/sh
# $FreeBSD$

. $(dirname $0)/conf.sh

base=`basename $0`
sectors=8
rnd=`mktemp $base.XXXXXX` || exit 1

echo "1..600"

do_test() {
	cipher=$1
	aalgo=$2
	secsize=$3
	ealgo=${cipher%%:*}
	keylen=${cipher##*:}

	geli onetime -a $aalgo -e $ealgo -l $keylen -s $secsize ${md} 2>/dev/null

	secs=`diskinfo /dev/${md}.eli | awk '{print $4}'`

	dd if=${rnd} of=/dev/${md}.eli bs=${secsize} count=${secs} 2>/dev/null

	md_rnd=`dd if=${rnd} bs=${secsize} count=${secs} 2>/dev/null | md5`
	md_ddev=`dd if=/dev/${md}.eli bs=${secsize} count=${secs} 2>/dev/null | md5`

	if [ ${md_rnd} = ${md_ddev} ]; then
		echo "ok $i - aalgo=${aalgo} ealgo=${ealgo} keylen=${keylen} sec=${secsize}"
	else
		echo "not ok $i - aalgo=${aalgo} ealgo=${ealgo} keylen=${keylen} sec=${secsize}"
	fi
	i=$((i+1))
}

i=1
dd if=/dev/random of=${rnd} bs=1024 count=1024 >/dev/null 2>&1

for_each_geli_config do_test

rm -f $rnd
