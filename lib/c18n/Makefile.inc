CHERI_LIB_C18N=yes

SHLIBDIR=       /usr/lib${COMPAT_libcompat:U}/c18n
LIBDIR=         /usr/lib${COMPAT_libcompat:U}/c18n

CFLAGS+=-DCHERI_LIB_C18N

.include "../Makefile.inc"
