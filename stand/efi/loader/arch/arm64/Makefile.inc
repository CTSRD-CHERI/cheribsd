HAVE_FDT=yes

SRCS+=	exec.c \
	exec_elf64.c \
	exec_elf64c.c \
	start.S

.PATH:	${BOOTSRC}/arm64/libarm64
CFLAGS+=-I${BOOTSRC}/arm64/libarm64
SRCS+=	cache.c

CFLAGS+=	-mgeneral-regs-only
