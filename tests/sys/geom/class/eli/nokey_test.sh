#!/bin/sh
# $FreeBSD$

. $(dirname $0)/conf.sh

base=`basename $0`
sectors=100
keyfile=`mktemp $base.XXXXXX` || exit 1
md=$(attach_md -t malloc -s `expr $sectors + 1`)

echo "1..8"

geli init -B none -P ${md} 2>/dev/null
if [ $? -ne 0 ]; then
	echo "ok 1"
else
	echo "not ok 1"
fi

dd if=/dev/random of=${keyfile} bs=512 count=16 >/dev/null 2>&1

geli init -B none -P -K ${keyfile} ${md} 2>/dev/null
if [ $? -eq 0 ]; then
	echo "ok 2"
else
	echo "not ok 2"
fi
geli attach -p ${md} 2>/dev/null
if [ $? -ne 0 ]; then
	echo "ok 3"
else
	echo "not ok 3"
fi
geli attach -p -k ${keyfile} ${md} 2>/dev/null
if [ $? -eq 0 ]; then
	echo "ok 4"
else
	echo "not ok 4"
fi
geli setkey -n 0 -P ${md} 2>/dev/null
if [ $? -ne 0 ]; then
	echo "ok 5"
else
	echo "not ok 5"
fi
geli detach ${md} 2>/dev/null
if [ $? -eq 0 ]; then
	echo "ok 6"
else
	echo "not ok 6"
fi
geli setkey -n 0 -p -P -K ${keyfile} ${md} 2>/dev/null
if [ $? -ne 0 ]; then
	echo "ok 7"
else
	echo "not ok 7"
fi
geli setkey -n 0 -p -k ${keyfile} -P ${md} 2>/dev/null
if [ $? -ne 0 ]; then
	echo "ok 8"
else
	echo "not ok 8"
fi

rm -f $keyfile
