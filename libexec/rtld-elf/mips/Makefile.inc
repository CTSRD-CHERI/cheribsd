# $FreeBSD$

CFLAGS.reloc.c+=-fno-jump-tables

# XXX-MAYBE-OBE: Added in 46fa9656e6167f41a3de4dc9faed3722f4124440
RTLD_ENTRY=	rtld_start
