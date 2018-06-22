#!/bin/sh
# $FreeBSD$

. $(dirname $0)/conf.sh

base=`basename $0`
sectors=100
keyfile=`mktemp $base.XXXXXX` || exit 1
backupfile=`mktemp $base.XXXXXX` || exit 1

echo "1..13"

dd if=/dev/random of=${keyfile} bs=512 count=16 >/dev/null 2>&1

md=$(attach_md -t malloc -s `expr $sectors`)

# -B none
rm -f /var/backups/${md}.eli
geli init -B none -P -K $keyfile ${md} 2>/dev/null
if [ ! -f /var/backups/${md}.eli ]; then
	echo "ok 1 - -B none"
else
	echo "not ok 1 - -B none"
fi

# no -B
rm -f /var/backups/${md}.eli
geli init -P -K $keyfile ${md} >/dev/null 2>&1
if [ -f /var/backups/${md}.eli ]; then
	echo "ok 2 - no -B"
else
	echo "not ok 2 - no -B"
fi
geli clear ${md}
geli attach -p -k $keyfile ${md} 2>/dev/null
if [ $? -ne 0 ]; then
	echo "ok 3 - no -B"
else
	echo "not ok 3 - no -B"
fi
if [ ! -c /dev/${md}.eli ]; then
	echo "ok 4 - no -B"
else
	echo "not ok 4 - no -B"
fi
geli restore /var/backups/${md}.eli ${md}
if [ $? -eq 0 ]; then
	echo "ok 5 - no -B"
else
	echo "not ok 5 - no -B"
fi
geli attach -p -k $keyfile ${md} 2>/dev/null
if [ $? -eq 0 ]; then
	echo "ok 6 - no -B"
else
	echo "not ok 6 - no -B"
fi
if [ -c /dev/${md}.eli ]; then
	echo "ok 7 - no -B"
else
	echo "not ok 7 - no -B"
fi
geli detach ${md}
rm -f /var/backups/${md}.eli

# -B file
rm -f $backupfile
geli init -B $backupfile -P -K $keyfile ${md} >/dev/null 2>&1
if [ -f $backupfile ]; then
	echo "ok 8 - -B file"
else
	echo "not ok 8 - -B file"
fi
geli clear ${md}
geli attach -p -k $keyfile ${md} 2>/dev/null
if [ $? -ne 0 ]; then
	echo "ok 9 - -B file"
else
	echo "not ok 9 - -B file"
fi
if [ ! -c /dev/${md}.eli ]; then
	echo "ok 10 - -B file"
else
	echo "not ok 10 - -B file"
fi
geli restore $backupfile ${md}
if [ $? -eq 0 ]; then
	echo "ok 11 - -B file"
else
	echo "not ok 11 - -B file"
fi
geli attach -p -k $keyfile ${md} 2>/dev/null
if [ $? -eq 0 ]; then
	echo "ok 12 - -B file"
else
	echo "not ok 12 - -B file"
fi
if [ -c /dev/${md}.eli ]; then
	echo "ok 13 - -B file"
else
	echo "not ok 13 - -B file"
fi

rm -f $backupfile $keyfile
