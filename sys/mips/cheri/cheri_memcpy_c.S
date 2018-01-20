#include <machine/asm.h>

#include <machine/cheriasm.h>
#include <machine/cherireg.h>

//#include "assym.s"

.set noat
.set noreorder

#ifdef __KERN_FUNC_PREFIX
#define	FUNC_PREFIX(f)	kern_ ## f
#else
#define	FUNC_PREFIX(f)	f
#endif

/*
 * Implement CHERI memcpy() and bcopy() variants in assembly; C works fine in
 * the kernel most of the time, but copyincap() and copyoutcap() require that
 * no callee-save registers be trampled over due to fault-based error
 * handling.
 *
 * This version handles both aligned and unaligned access.
 * This version also handles overlapping copies.
 * All entry points except the "nocap" ones preserve tags if the pointers
 * are equally aligned mod CHERICAP_SIZE.
 *
 * bcopy versions accepts:
 * c3 - source pointer
 * c4 - destination pointer
 * a0 - length
 *
 * memcpy has inverted source/destination pointers and returns dest.
 */
LEAF(FUNC_PREFIX(memcpy_c))
XLEAF(FUNC_PREFIX(memmove_c))
	cmove	$c1, $c3
	cmove	$c3, $c4
	cmove	$c4, $c1
	b FUNC_PREFIX(bcopy_c)		/* skip stripping LOAD_CAP */
	nop
XLEAF(FUNC_PREFIX(memcpynocap_c))
XLEAF(FUNC_PREFIX(memmovenocap_c))
	cmove	$c1, $c3
	cmove	$c3, $c4
	cmove	$c4, $c1
XLEAF(FUNC_PREFIX(bcopynocap_c))
	li	t0, ~CHERI_PERM_LOAD_CAP
	candperm	$c3, $c3, t0	/* strip LOAD_CAP from dst */
XLEAF(FUNC_PREFIX(bcopy_c))
	beqz	a0, return	/* return immediately if zero-length */
	cltu	t0, $c3, $c4	/* forward or backward copy? */
	bnez	t0, backward

forward:
	cgetbase	t0, $c3
	cgetoffset	t8, $c3
	daddu		t0, t0, t8	// t0: src virtual address
	cgetbase	t1, $c4
	cgetoffset	t8, $c4
	daddu		t1, t1, t8	// t1: dst virtual address

f_byte_copy:
	/*
	 * Two pointers of unknown alignment.  If they have the same
	 * alignment mod double-word size we copy up to the next dword
	 * boundry.  If not, then we copy the whole lot one byte at a
	 * time.
	 */
	andi		t2, t0, (SZREG-1)
	andi		t3, t1, (SZREG-1)
	bne		t2, t3, f_cannot_be_word_aligned
	move		a1, a0		// a1: how much to copy
f_can_be_word_aligned:
	andi		a1, t0, (SZREG-1)
	li		t9, SZREG
	beqz		a1, f_dword_copy	// already aligned (common)
	dsub		a1, t9, a1
f_cannot_be_word_aligned:
	li		a2, 1		// a2: how much we will have copied
f_byte_loop:
	clb		t9, a2, -1($c3)
	csb		t9, a2, -1($c4)
	bne		a1, a2, f_byte_loop
	daddi		a2, 1

	daddu		t0, t0, a1	// update virtual addresses
	daddu		t1, t1, a1
	cincoffset	$c3, $c3, a1	// update capability offsets
	cincoffset	$c4, $c4, a1
	dsub		a0, a0, a1	// update amount to copy
	beqz		a0, return	// exit if done

f_dword_copy:
	/*
	 * Two word aligned pointers.  If they have the same
	 * alignment mod capability size, we copy up to capability
	 * alignment.  Otherwise we copy up to any tail.
	 *
	 * XXX: if dest disallows capability stores we should copy all...
	 */
	andi		t2, t0, (CHERICAP_SIZE - 1)
	andi		t3, t1, (CHERICAP_SIZE - 1)
	and		a1, a0, -SZREG	// a1: amount we could copy
	bne		t2, t3, f_cannot_be_cap_aligned
	nop
f_can_be_cap_aligned:
	andi		a1, t0, (CHERICAP_SIZE - 1)	// just to capability
	li		t9, CHERICAP_SIZE
	beqz		a1, f_cap_copy	// already aligned (common)
	dsub		a1, t9, a1
f_cannot_be_cap_aligned:
	li		a2, SZREG	// a2: how much we will have copied
f_dword_loop:
	cld		t9, a2, -SZREG($c3)
	csd		t9, a2, -SZREG($c4)
	bne		a1, a2, f_dword_loop
	daddi		a2, SZREG

	daddu		t0, t0, a1	// update virtual addresses
	daddu		t1, t1, t1
	cincoffset	$c3, $c3, a1	// update capability offsets
	cincoffset	$c4, $c4, a1
	dsub		a0, a0, a1	// update amount to copy
	beqz		a0, return	// exit if done

f_cap_copy:
	/*
	 * Two capability aligned pointers.  Copy up to any odd trailer.
	 */
	slti		t9, a0, CHERICAP_SIZE
	and		a1, a0, -CHERICAP_SIZE	// mask off trailer
	bnez		t9, f_copy_tail
	nop
	li		a2, CHERICAP_SIZE // a2: how much we will have copied
f_cap_loop:
	/* XXX: ISA says offset if <<4, but -1 is rejected by llvm... */
	clc		$c2, a2, -CHERICAP_SIZE($c3)
	csc		$c2, a2, -CHERICAP_SIZE($c4)
	bne		a1, a2, f_cap_loop
	daddi		a2, CHERICAP_SIZE

	cincoffset	$c3, $c3, a1	// update capability offsets
	cincoffset	$c4, $c4, a1
	dsub		a0, a0, a1	// update amount to copy
	beqz		a0, return	// exit if done

f_copy_tail:
	li		a2, 1		// a2: how much we will have copied
f_tail_loop:
	clb		t9, a2, -1($c3)
	csb		t9, a2, -1($c4)
	bne		a0, a2, f_tail_loop
	daddi		a2, 1

	b return
	nop

backward:
	cincoffset	$c3, $c3, a0	// Move to the end
	cincoffset	$c4, $c4, a0
	cgetbase	t0, $c3
	cgetoffset	t8, $c3
	daddu		t0, t0, t8	// t0: src virtual address (end)
	cgetbase	t1, $c4
	cgetoffset	t8, $c4
	daddu		t1, t1, t8	// t1: dst virtual address (end)

b_byte_copy:
	/*
	 * Two pointers at the end of regions of unknown alignment.
	 * If they share the same alignment mod double-word size, copy
	 * backwards one byte at a time to the next double-word boundary.
	 */
	andi		t2, t0, (SZREG-1)
	andi		t3, t1, (SZREG-1)
	bne		t2, t3, b_cannot_be_dword_aligned
	move		a1, a0		// a1: how much to copy
b_can_be_dword_aligned:
	andi		a1, t0, (SZREG-1)	// a1: just to align
	beqz		a1, b_dword_copy	// tail is dword aligned
b_cannot_be_dword_aligned:
	dsub		a1, zero, a1	// End (negative) offset
	li		a2, -1		// a2: offset we will have copy
	li		a3, -1		// a3: increment
b_byte_loop:
	clb		t9, a2, 0($c3)
	csb		t9, a2, 0($c3)
	bne		a1, a2, b_byte_loop
	daddu		a2, a2, a3

	dadd		t0, t0, a1	// update virtual addresses
	dadd		t1, t1, a1
	cincoffset	$c3, $c3, a1	// update capability offsets
	cincoffset	$c4, $c4, a1
	dadd		a0, a0, a1	// update amount to copy
	beqz		a0, return	// exit if done

b_dword_copy:
	/*
	 * Two pointers at the end of the un-copied regions with double
	 * word alignment.  If they have the same alignment mod
	 * capability size, we copy down to capability alignment.
	 * Otherwise we copy up to any header.
	 *
	 * XXX: if dest disallows capability stores we should copy all...
	 */
	andi		t2, t0, (CHERICAP_SIZE - 1)
	andi		t3, t1, (CHERICAP_SIZE - 1)
	and		a1, a0, -SZREG	// a1: amount we could copy
	bne		t2, t3, b_cannot_be_cap_aligned
	nop
b_can_be_cap_aligned:
	andi		a1, t0, (CHERICAP_SIZE - 1)	// just to capability
	beqz		a1, b_cap_copy	// already aligned (common)
b_cannot_be_cap_aligned:
	dsub		a1, zero, a1	// End (negative) offset
	li		a2, -SZREG	// a2: offset we will copy
	li		a3, -SZREG	// a3: increment
b_dword_loop:
	cld		t9, a2, 0($c3)
	csd		t9, a2, 0($c3)
	bne		a1, a2, b_dword_loop
	daddu		a2, a2, a3

	cincoffset	$c3, $c3, a1	// update capability offsets
	cincoffset	$c4, $c4, a1
	dadd		a0, a0, a1	// update amount to copy
	beqz		a0, return	// exit if done

b_cap_copy:
	/*
	 * Two capability aligned pointers to the end of the buffers.
	 * Copy down the any unaligned header.
	 */
	li		a2, -CHERICAP_SIZE	// a2: offset we will copy
	and		a1, a0, a2		// a1: amount we could copy
	slt		t9, a0, a2
	bnez		t9, b_copy_head
	li		a3, -CHERICAP_SIZE	// a3: incremnt
	dsub		a1, zero, a1	// a1: end offset (negative)
b_cap_loop:
	clc		$c2, a2, 0($c3)
	csc		$c2, a2, 0($c4)
	bne		a1, a2, b_cap_loop
	daddu		a2, a2, a3

	cincoffset	$c3, $c3, a1	// update capability offsets
	cincoffset	$c4, $c4, a1
	dadd		a0, a0, a1	// update amount to copy

b_copy_head:
	beqz		a0, return
	dsub		a1, zero, a0	// a1: offset to copy to
	li		a2, -1		// a2: offset we will copy
	li		a3, -1		// a3: increment
b_head_loop:
	clb		t9, a2, 0($c3)
	csb		t9, a2, 0($c4)
	bne		a1, a2, b_head_loop
	daddi		a2, 1

return:
	jr	ra
	cmove	$c3, $c1	/* need to return original c3 for memcpy */
END(FUNC_PREFIX(memcpy_c))
