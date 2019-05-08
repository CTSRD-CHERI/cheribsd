#include <machine/asm.h>
#include <machine/cherireg.h>

.set noreorder
.set noat
.text
	clc $c26, $0, -(2* CHERICAP_SIZE)($c12)
	clc $c12, $0, -CHERICAP_SIZE($c12)
	cjr $c12
	nop
