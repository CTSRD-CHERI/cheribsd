#!/bin/sh
# $FreeBSD$

. $(dirname $0)/conf.sh

base=`basename $0`
sectors=100
keyfile1=`mktemp $base.XXXXXX` || exit 1
keyfile2=`mktemp $base.XXXXXX` || exit 1
md=$(attach_md -t malloc -s `expr $sectors + 1`)

echo "1..9"

dd if=/dev/random of=${keyfile1} bs=512 count=16 >/dev/null 2>&1
dd if=/dev/random of=${keyfile2} bs=512 count=16 >/dev/null 2>&1

geli init -B none -P -K $keyfile1 ${md}
geli attach -p -k $keyfile1 ${md}
geli setkey -n 1 -P -K $keyfile2 ${md}

# Kill attached provider.
geli kill ${md}
if [ $? -eq 0 ]; then
	echo "ok 1"
else
	echo "not ok 1"
fi
sleep 1
# Provider should be automatically detached.
if [ ! -c /dev/${md}.eli ]; then
	echo "ok 2"
else
	echo "not ok 2"
fi

# We cannot use keyfile1 anymore.
geli attach -p -k $keyfile1 ${md} 2>/dev/null
if [ $? -ne 0 ]; then
	echo "ok 3"
else
	echo "not ok 3"
fi

# We cannot use keyfile2 anymore.
geli attach -p -k $keyfile2 ${md} 2>/dev/null
if [ $? -ne 0 ]; then
	echo "ok 4"
else
	echo "not ok 4"
fi

geli init -B none -P -K $keyfile1 ${md}
geli setkey -n 1 -p -k $keyfile1 -P -K $keyfile2 ${md}

# Should be possible to attach with keyfile1.
geli attach -p -k $keyfile1 ${md}
if [ $? -eq 0 ]; then
	echo "ok 5"
else
	echo "not ok 5"
fi
geli detach ${md}

# Should be possible to attach with keyfile2.
geli attach -p -k $keyfile2 ${md}
if [ $? -eq 0 ]; then
	echo "ok 6"
else
	echo "not ok 6"
fi
geli detach ${md}

# Kill detached provider.
geli kill ${md}
if [ $? -eq 0 ]; then
	echo "ok 7"
else
	echo "not ok 7"
fi

# We cannot use keyfile1 anymore.
geli attach -p -k $keyfile1 ${md} 2>/dev/null
if [ $? -ne 0 ]; then
	echo "ok 8"
else
	echo "not ok 8"
fi

# We cannot use keyfile2 anymore.
geli attach -p -k $keyfile2 ${md} 2>/dev/null
if [ $? -ne 0 ]; then
	echo "ok 9"
else
	echo "not ok 9"
fi

rm -f $keyfile1 $keyfile2
