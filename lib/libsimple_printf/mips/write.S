#include "SYS.h"
/*
 * We want to avoid any dependency on libc here so just do the syscall directly.
 * We also don't care about errors here to avoid any dependency on errno
 */
LEAF(SIMPLE_PRINTF_WRITE_FUNC)
	.hidden _C_LABEL(SIMPLE_PRINTF_WRITE_FUNC)
	PIC_PROLOGUE(SIMPLE_PRINTF_WRITE_FUNC);
	SYSTRAP(write);
	PIC_RETURN()
END(SIMPLE_PRINTF_WRITE_FUNC)
