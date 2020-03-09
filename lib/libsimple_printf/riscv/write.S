#include "SYS.h"
#include <sys/cdefs.h>
/*
 * We want to avoid any dependency on libc here so just do the syscall directly.
 * We also don't care about errors here to avoid any dependency on errno
 */

#define WRITE_NAME __CONCAT(SIMPLE_PRINTF_PREFIX, _write)
ENTRY(WRITE_NAME)
	.hidden _C_LABEL(WRITE_NAME)
	_SYSCALL(write);
	RETURN;
END(WRITE_NAME)
