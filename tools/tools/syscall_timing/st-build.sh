#!/bin/sh -e

if [ -z "${WORKSPACE}" ]; then
	echo '${WORKSPACE} environment variable empty or not set.'
	exit 1
fi

CHERI_ROOT="${WORKSPACE}/cheri"
CHERI_OUTPUT="${WORKSPACE}/syscall-timing"
CHERI_SDK="${WORKSPACE}/sdk"
CHERI_SYSROOT="${WORKSPACE}/sdk/sysroot256/"
#CHERI_FREEBSD="${CHERI_OUTPUT}/freebsd-mips"
ST_SRC="${WORKSPACE}/tools/tools/syscall_timing"
ST_INSTALL="${WORKSPACE}/syscall_timing"

#CHERI_ROOT="${HOME}/cheri"
#CHERI_OUTPUT="${CHERI_ROOT}/output"
#CHERI_SDK="${CHERI_OUTPUT}/sdk"
#CHERI_SYSROOT="${CHERI_OUTPUT}/sdk/sysroot256"
#CHERI_FREEBSD="${CHERI_OUTPUT}/freebsd-mips"
#ST_SRC="${HOME}/cheri/cheribsd/tools/tools/syscall_timing"
#ST_INSTALL="${HOME}/syscall_timing"

CFLAGS_COMMON="-pipe -O2 -cheri=256 -cheri-cap-table-abi=pcrel -msoft-float -ggdb -static -integrated-as"
CFLAGS_LIBSTATCOUNTERS="-Wl,--whole-archive -lstatcounters -Wl,--no-whole-archive"

# Don't add -fstack-protector-strong; it breaks CHERI binaries.
SSP_CFLAGS="" export SSP_CFLAGS

CC="${CHERI_SDK}/bin/clang" export CC
CFLAGS="${CFLAGS_COMMON} ${CFLAGS_LIBSTATCOUNTERS} --sysroot=${CHERI_SYSROOT} -B${CHERI_SDK}/bin -target cheri-unknown-freebsd -mabi=purecap" export CFLAGS
DESTDIR="${ST_INSTALL}/cheri/" export DESTDIR
mkdir -p "${ST_INSTALL}/cheri"
cd "${ST_SRC}"
make clean all install

CC="${CHERI_SDK}/bin/clang" export CC
CFLAGS="${CFLAGS_COMMON} ${CFLAGS_LIBSTATCOUNTERS} --sysroot=${CHERI_SYSROOT} -B${CHERI_SDK}/bin -target cheri-unknown-freebsd -mabi=n64" export CFLAGS
DESTDIR="${ST_INSTALL}/hybrid/" export DESTDIR
mkdir -p "${ST_INSTALL}/hybrid"
cd "${ST_SRC}"
make clean all install

#CC="${CHERI_SDK}/bin/clang" export CC
#CFLAGS="${CFLAGS_COMMON} --sysroot=${CHERI_FREEBSD} -B${CHERI_SDK}/bin -target mips64-unknown-freebsd -mabi=n64" export CFLAGS
#mkdir -p "${ST_INSTALL}/mips"
#cd "${ST_SRC}"
#make clean all
#cp "${ST_SRC}/syscall_timing" "${ST_INSTALL}/mips/"

