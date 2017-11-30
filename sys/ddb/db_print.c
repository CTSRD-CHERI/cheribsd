/*-
 * Mach Operating System
 * Copyright (c) 1991,1990 Carnegie Mellon University
 * All Rights Reserved.
 *
 * Permission to use, copy, modify and distribute this software and its
 * documentation is hereby granted, provided that both the copyright
 * notice and this permission notice appear in all copies of the
 * software, derivative works or modified versions, and any portions
 * thereof, and that both notices appear in supporting documentation.
 *
 * CARNEGIE MELLON ALLOWS FREE USE OF THIS SOFTWARE IN ITS
 * CONDITION.  CARNEGIE MELLON DISCLAIMS ANY LIABILITY OF ANY KIND FOR
 * ANY DAMAGES WHATSOEVER RESULTING FROM THE USE OF THIS SOFTWARE.
 *
 * Carnegie Mellon requests users of this software to return to
 *
 *  Software Distribution Coordinator  or  Software.Distribution@CS.CMU.EDU
 *  School of Computer Science
 *  Carnegie Mellon University
 *  Pittsburgh PA 15213-3890
 *
 * any improvements or extensions that they make and grant Carnegie the
 * rights to redistribute these changes.
 *
 */
/*
 *	Author: David B. Golub, Carnegie Mellon University
 *	Date:	7/90
 */

/*
 * Miscellaneous printing.
 */

#include <sys/cdefs.h>
__FBSDID("$FreeBSD$");

#include <sys/param.h>
#include <sys/kdb.h>
#include <sys/proc.h>

#include <machine/pcb.h>
#include <machine/vmparam.h>

#include <ddb/ddb.h>
#include <ddb/db_variables.h>
#include <ddb/db_sym.h>

void
db_show_regs(db_expr_t _1, bool _2, db_expr_t _3, char *_4)
{
	struct db_variable *regp;
	db_expr_t value, offset;
	const char *name;

	for (regp = db_regs; regp < db_eregs; regp++) {
		if (!db_read_variable(regp, &value))
			continue;
		db_printf("%-12s%#*lr", regp->name,
		    (int)(sizeof(unsigned long) * 2 + 2), (unsigned long)value);
#ifdef __mips__
		if (value >= VM_MAXUSER_ADDRESS) {
#if __has_feature(capabilities)
			if ((value % sizeof(void * __capability)) == 0)
				db_printf("\t(capability-aligned)");
			else
#endif
			if ((value % 8) == 0)
				db_printf("\t(dword-aligned)");
			else if ((value % 4) == 0)
				db_printf("\t(word-aligned)");
			else if ((value % 2) == 0)
				db_printf("\t(halfword-aligned)");
			else
				db_printf("\t(unaligned)");
		}
#endif
		db_find_xtrn_sym_and_offset((db_addr_t)value, &name, &offset);
		if (name != NULL && offset <= (unsigned long)db_maxoff &&
		    offset != value) {
			db_printf("\t%s", name);
			if (offset != 0)
				db_printf("+%+#lr", (long)offset);
		}
		db_printf("\n");
	}
	db_print_loc_and_inst(PC_REGS());
}
