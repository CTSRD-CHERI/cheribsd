.set noreorder
.set noat

.text
.global cocall

cocall:
	ccall	$c3, $c4, 1
	cgetpcc $c5
	jr	$ra
	nop
