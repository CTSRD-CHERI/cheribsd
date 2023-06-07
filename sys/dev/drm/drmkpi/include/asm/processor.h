#ifndef __DRM_ASM_PROCESSOR_H__
#define __DRM_ASM_PROCESSOR_H__

#include <machine/cpu.h>
#include <asm/barrier.h>

#define smp_mb()	mb()
#define smp_rmb()	rmb()
#define smp_wmb()	wmb()

static __always_inline void cpu_relax(void)
{
   cpu_spinwait();
}

#endif /* __DRM_ASM_PROCESSOR_H__ */
