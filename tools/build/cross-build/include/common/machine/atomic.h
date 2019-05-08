#pragma once

#ifndef __BUILDING_LOCALEDEF
#error "Should only be used when building localedef"
#endif

static inline long
atomic_fetchadd_long(volatile long *p, long v)
{

	return __atomic_fetch_add(p, v, __ATOMIC_SEQ_CST);
}

static inline void
atomic_add_long(volatile long *p, long v)
{
	atomic_fetchadd_long(p, v);
}
