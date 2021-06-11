#
# CHERI-specific interfaces
#

.PATH:	${LIBC_SRCTOP}/cheri

SRCS+=strfcap.c

SYM_MAPS+=${LIBC_SRCTOP}/cheri/Symbol.map
