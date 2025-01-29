/*
 * CDDL HEADER START
 *
 * The contents of this file are subject to the terms of the
 * Common Development and Distribution License (the "License").
 * You may not use this file except in compliance with the License.
 *
 * You can obtain a copy of the license at usr/src/OPENSOLARIS.LICENSE
 * or http://www.opensolaris.org/os/licensing.
 * See the License for the specific language governing permissions
 * and limitations under the License.
 *
 * When distributing Covered Code, include this CDDL HEADER in each
 * file and include the License file at usr/src/OPENSOLARIS.LICENSE.
 * If applicable, add the following below this CDDL HEADER, with the
 * fields enclosed by brackets "[]" replaced with your own identifying
 * information: Portions Copyright [yyyy] [name of copyright owner]
 *
 * CDDL HEADER END
 *
 */

/* ARGSUSED */
static int
dtrace_modevent(module_t mod __unused, int type, void *data __unused)
{
	int error = 0;

	switch (type) {
	case MOD_LOAD:
		if (!dtrace_enabled) {
			printf(
    "DTrace is experimental on this platform and is disabled by default.\n");
			printf(
    "Set the debug.dtrace_enabled sysctl to 1 to allow dtrace.ko to load.\n");
			printf(
    "Be prepared for bugs and kernel panics if you use DTrace.\n");
			printf(
    "Please report bugs at https://github.com/CTSRD-CHERI/cheribsd");
			return (ENOTSUP);
		}

		break;

	case MOD_UNLOAD:
		break;

	case MOD_SHUTDOWN:
		break;

	default:
		error = EOPNOTSUPP;
		break;

	}
	return (error);
}
