#pragma once

#include_next <sys/param.h>

#ifndef BLKDEV_IOSIZE
#define BLKDEV_IOSIZE  PAGE_SIZE	/* default block device I/O size */
#endif
#ifndef DFLTPHYS
#define DFLTPHYS	(64 * 1024)	/* default max raw I/O transfer size */
#endif
#ifndef MAXPHYS
#define MAXPHYS		(128 * 1024)	/* max raw I/O transfer size */
#endif
#ifndef MAXDUMPPGS
#define MAXDUMPPGS	(DFLTPHYS/PAGE_SIZE)
#endif

#ifndef MCLSHIFT
#define MCLSHIFT	11		/* convert bytes to mbuf clusters */
#endif

#ifndef MCLBYTES
#define MCLBYTES	(1 << MCLSHIFT)	/* size of an mbuf cluster */
#endif

#ifndef __PAST_END
#define __PAST_END(array, offset) (((__typeof__(*(array)) *)(array))[offset])
#endif
