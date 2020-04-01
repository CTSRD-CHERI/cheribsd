#include "SYS.h"
#include <sys/cdefs.h>
/*
 * We want to avoid any dependency on libc here so just do the syscall directly.
 * We also don't care about errors here to avoid any dependency on errno
 */
ENTRY(SIMPLE_PRINTF_WRITE_FUNC)
	.hidden _C_LABEL(SIMPLE_PRINTF_WRITE_FUNC)
	_SYSCALL(write);
	RETURN;
END(SIMPLE_PRINTF_WRITE_FUNC)
