#!/bin/sh
# Replace bare case-statements for ifreq ioctls with CASE_IOC_IFREQ():
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
	echo $ioctl
	if ! git grep -q "case ${ioctl}:"; then
		continue
	fi
	case_files=$(git grep -l "case ${ioctl}:")
	echo $case_files
	sed -i.bak -e "s/case ${ioctl}:/CASE_IOC_IFREQ(${ioctl}):/" $case_files
done
