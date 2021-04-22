# $FreeBSD$

CFLAGS.reloc.c+=-fno-jump-tables

# XXX-MAYBE-OBE: Added in 46fa9656e6167f41a3de4dc9faed3722f4124440
RTLD_ENTRY=	rtld_start

.if ${MACHINE_CPU:Mcheri}
CFLAGS+=	-DRTLD_HAS_CAPRELOCS
.endif

.if ${MACHINE_ABI:Mpurecap}
CLEANFILES+=	cheri_plt_code.dump cheri_plt_code.text cheri_plt_code.inc

cheri_plt_code.dump: cheri_plt_code.o
	${OBJDUMP:Uobjdump} -triple=mips64-unknown-freebsd -d -x -s cheri_plt_code.o > ${.TARGET}

cheri_plt_code.text: cheri_plt_code.o
	${OBJCOPY} -O binary --only-section=.text cheri_plt_code.o ${.TARGET}

# Generate the code for the PLT stubs as a single C array using objcopy+xxd/file2c
cheri_plt_code.inc: cheri_plt_code.text
# ${XXD:U/usr/local/bin/xxd} -i -c4 < cheri_plt_code.text > ${.TARGET}
	file2c -x -s -n4 < cheri_plt_code.text > ${.TARGET}

cheri_plt.o: cheri_plt_code.inc

generate_all_files: cheri_plt_code.inc .PHONY

# Build the CHERI PLT stuff as C++
SRCS+=	cheri_plt.cpp
CXXFLAGS+=	-std=c++11 -fno-rtti -fno-exceptions
# We need to be able to find cheri_plt_code.inc
CXXFLAGS+=	-I.
CFLAGS+=	-I${SRCTOP}/contrib/uthash/src
.endif
