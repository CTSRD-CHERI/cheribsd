#!/bin/sh
# Scan for ifreq ioctl uses that aren't case statements
#

# Sanity check: must run from the sys directory
if ! [ -d sys -a -e ../UPDATING ]; then
	echo "this doesn't seem to be a src/sys directory"
	exit 1
fi

SPACE_TAB=" 	"
IOCTLS=$(git grep -h "define.*struct ifreq)" | \
    sed -e "s/#define[${SPACE_TAB}]*//" -e "s/[${SPACE_TAB}].*//" | \
    grep -v ^IBCS2_ | \
    sort -u)

for ioctl in $IOCTLS; do
	git grep "[^A-Z_]$ioctl[^A-Z_]" | grep -v "#define" | grep -v CASE_IOC_IFREQ
done
