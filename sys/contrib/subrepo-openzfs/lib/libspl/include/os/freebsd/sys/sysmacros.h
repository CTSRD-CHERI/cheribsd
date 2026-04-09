#if !defined(__CHERI__) && !defined(__CHERI_HYBRID__)
#ifndef copyinptr
#define        copyinptr       copyin
#endif
#ifndef copyoutptr
#define        copyoutptr      copyout
#endif

#ifndef __capability
#define        __capability
#endif
#ifndef __cheri_fromcap
#define        __cheri_fromcap
#endif
#ifndef PTR2CAP
#define        PTR2CAP(x)      (x)
#endif
#endif
