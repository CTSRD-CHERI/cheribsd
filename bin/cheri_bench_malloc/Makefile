# $FreeBSD$

.include <src.opts.mk>

NEED_CHERI=pure
LIBADD+=pthread
LIBADD+=cheri_caprevoke

PROG=  cheri_bench_malloc
SRCS=  main.c \
       capdirty.c \
       malloc_comb.c

.include <bsd.prog.mk>
