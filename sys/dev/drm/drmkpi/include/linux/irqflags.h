#ifndef __DRMCOMPAT_LINUX_IRQFLAGS_H__
#define	__DRMCOMPAT_LINUX_IRQFLAGS_H__

#define	local_irq_restore(flags)	do { } while (0)
#define	local_irq_save(flags)		do { (flags) = 0; } while (0)
#define	irqs_disabled()							\
    (curthread->td_critnest != 0 || curthread->td_intr_nesting_level != 0)

#endif /* __DRMCOMPAT_LINUX_IRQFLAGS_H__ */
