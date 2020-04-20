# $FreeBSD$
       
.PATH: ${LIBC_SRCTOP}/stdlib/snmalloc
       
SNMALLOCSRCS:=	malloc.cc
       
SYM_MAPS+=	${LIBC_SRCTOP}/stdlib/snmalloc/Symbol.map
       
CXXFLAGS+=	-I${SRCTOP}/contrib/snmalloc/src
CXXFLAGS+=	-I${SRCTOP}/contrib/snmalloc/src/override
CXXFLAGS+=	-std=c++17 -mcx16 -fno-exceptions -fno-rtti -DSNMALLOC_USE_THREAD_CLEANUP
CXXFLAGS+=	-ftls-model=initial-exec
SHARED_CXXFLAGS+=-fomit-frame-pointer
STATIC_CXXFLAGS+=-fomit-frame-pointer
PO_CXXFLAGS+=	-fno-omit-frame-pointer
CXXFLAGS+=	-DNDEBUG   
CXXFLAGS+=	-DSNMALLOC_EXPOSE_PAGEMAP
CXXFLAGS+=	-DSNMALLOC_EXPORT="__attribute__((weak))"
.ifndef NO_INCORRECT_FREE_CHECK
CXXFLAGS+=	-DCHECK_CLIENT
.endif
#CXXFLAGS+=	-O0 -fno-inline

.for src in ${SNMALLOCSRCS}
MISRCS+=snmalloc_${src}
CLEANFILES+=snmalloc_${src}
snmalloc_${src}: ${SRCTOP}/contrib/snmalloc/src/override/${src} .NOMETA
	ln -sf ${.ALLSRC} ${.TARGET}
.endfor
