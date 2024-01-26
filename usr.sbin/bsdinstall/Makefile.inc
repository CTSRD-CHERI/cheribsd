PACKAGE=bsdinstall

CFLAGS+= -I${SRCTOP}/contrib/bsddialog/lib -I${.OBJDIR}/../include

.include "../Makefile.inc"
