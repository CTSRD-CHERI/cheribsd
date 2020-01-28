#include <machine/asm.h>
#include <machine/cherireg.h>

.set noreorder
.set noat
.text
	# move $pcc into a CapGPR since we don't have pc-relative loads
	# Note: we can't use $c12 for loading here, since it may be a sentry
	# and therefore does not allow loading or modification.
	cgetpcc $c26
	clc $c12, $0, -CHERICAP_SIZE($c26)
	cjr $c12
	clc $c26, $0, -(2 * CHERICAP_SIZE)($c26)	# load $cgp in delay slot
