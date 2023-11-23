
.include <src.opts.mk>

.PATH: ${LIBC_SRCTOP}/db/hash

SRCS+=	hash.c hash_bigkey.c hash_buf.c hash_func.c hash_log2.c \
	hash_page.c ndbm.c

.if ${MACHINE_ABI:Mpurecap}
CFLAGS.hash.c+=		-Wno-cheri-bitwise-operations
CFLAGS.hash_buf.c+=	-Wno-cheri-bitwise-operations
.endif
