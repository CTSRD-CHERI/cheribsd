#
# CHERI-specific interfaces
#

.PATH:	${LIBC_SRCTOP}/cheri

SRCS+=strfcap.c
MAN+=strfcap.3

SYM_MAPS+=${LIBC_SRCTOP}/cheri/Symbol.map
