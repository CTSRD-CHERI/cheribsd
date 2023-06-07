#ifndef __DRM_ASM_BARRIER_H__
#define __DRM_ASM_BARRIER_H__

#include <linux/compiler.h>

#define smp_mb()	mb()
#define smp_rmb()	rmb()
#define smp_wmb()	wmb()

#define smp_store_release(p, v)					\
do {									\
	smp_mb();							\
	WRITE_ONCE(*p, v);						\
} while (0)


#define smp_load_acquire(p)						\
({									\
	typeof(*p) ___p1 = READ_ONCE(*p);				\
	smp_mb();										\
	___p1;								\
})


#endif /* __DRM_ASM_BARRIER_H__ */
