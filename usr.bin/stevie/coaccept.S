.set noreorder
.set noat

.text
.global coaccept

coaccept:
	ccall	$c3, $c4, 1
	cgetpcc $c11
	jr	$ra
	nop
