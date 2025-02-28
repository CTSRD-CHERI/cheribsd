KMOD=	zlib_c18n

COMPARTMENTS=	module allocator zlib

SRCS.module=	zlib_mod.c

SRCS.allocator+=	zcalloc.c

SRCS.zlib+=	adler32.c
SRCS.zlib+=	crc32.c
SRCS.zlib+=	compress.c
SRCS.zlib+=	deflate.c
SRCS.zlib+=	inffast.c
SRCS.zlib+=	inflate.c
SRCS.zlib+=	inftrees.c
SRCS.zlib+=	trees.c
SRCS.zlib+=	uncompr.c
SRCS.zlib+=	zutil.c

.include "../zlib/Makefile"
