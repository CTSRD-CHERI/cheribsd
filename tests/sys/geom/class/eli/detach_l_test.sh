#!/bin/sh
# $FreeBSD$

. $(dirname $0)/conf.sh

base=`basename $0`
sectors=100
keyfile=`mktemp $base.XXXXXX` || exit 1
md=$(attach_md -t malloc -s `expr $sectors + 1`)

echo "1..4"

dd if=/dev/random of=${keyfile} bs=512 count=16 >/dev/null 2>&1

geli init -B none -P -K $keyfile ${md}
geli attach -p -k $keyfile ${md}
if [ -c /dev/${md}.eli ]; then
	echo "ok 1"
else
	echo "not ok 1"
fi
# Be sure it doesn't detach before 'detach -l'.
dd if=/dev/${md}.eli of=/dev/null 2>/dev/null
sleep 1
if [ -c /dev/${md}.eli ]; then
	echo "ok 2"
else
	echo "not ok 2"
fi
geli detach -l ${md}
if [ -c /dev/${md}.eli ]; then
	echo "ok 3"
else
	echo "not ok 3"
fi
dd if=/dev/${md}.eli of=/dev/null 2>/dev/null
sleep 1
if [ ! -c /dev/${md}.eli ]; then
	echo "ok 4"
else
	echo "not ok 4"
fi

rm -f $keyfile
