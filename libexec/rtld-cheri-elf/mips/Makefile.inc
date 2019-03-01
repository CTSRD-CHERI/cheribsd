
CLEANFILES+=	plt_code.o plt_code.dump plt_code.text plt_code.inc

plt_code.o:
	${CC} ${CFLAGS} -c ${.CURDIR}/mips/plt_code.S -o ${.TARGET}

plt_code.dump: plt_code.o
	${OBJDUMP:Uobjdump} -triple=cheri-unknown-freebsd -d -x -s plt_code.o > ${.TARGET}

plt_code.text: plt_code.o
	${OBJCOPY} -O binary --only-section=.text plt_code.o ${.TARGET}

# Generate the code for the PLT stubs as a single C array using objcopy+xxd/file2c
plt_code.inc: plt_code.text
# ${XXD:U/usr/local/bin/xxd} -i -c4 < ${.CURDIR}/plt_code.text > ${.CURDIR}/plt_code.inc
	file2c -x -s -n4 < plt_code.text > ${.TARGET}

cheri_plt.o: plt_code.inc

generate_all_files: plt_code.inc


# Build the CHERI PLT stuff as C++
SRCS+=	cheri_plt.cpp
CXXFLAGS+= -std=c++11 -fno-rtti -fno-exceptions
# We need to be able to find plt_code.inc
CXXFLAGS+=	-I.
CFLAGS+=	-I${SRCTOP}/contrib/uthash/src
