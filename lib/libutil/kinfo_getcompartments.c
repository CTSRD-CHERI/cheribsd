/*-
 * Copyright (c) 2026 Konrad Witaszczyk
 *
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * This software was developed by SRI International, the University of
 * Cambridge Computer Laboratory (Department of Computer Science and
 * Technology), and Capabilities Limited under Defense Advanced Research
 * Projects Agency / Air Force Research Laboratory (DARPA/AFRL) Contract
 * No. FA8750-24-C-B047 ("DEC").
 */

#include <sys/types.h>
#include <sys/sysctl.h>
#include <sys/user.h>

#include <cheri/c18n.h>

#include <stdlib.h>
#include <string.h>

#include "libutil.h"

#define	SYSCTL_KERN_KC18N_COMPARTS	"kern.kc18n_compartments"

struct kinfo_cheri_kc18n_compart *
kinfo_getcompartments(int *cntp)
{
	char *buf, *bp, *ep;
	struct kinfo_cheri_kc18n_compart *kckc, *list, *kp;
	size_t len;
	int cnt, i;

	buf = NULL;
	for (i = 0; i < 3; i++) {
		if (sysctlbyname(SYSCTL_KERN_KC18N_COMPARTS, NULL, &len, NULL,
		    0) < 0) {
			free(buf);
			return (NULL);
		}
		buf = reallocf(buf, len);
		if (buf == NULL)
			return (NULL);
		if (sysctlbyname(SYSCTL_KERN_KC18N_COMPARTS, buf, &len, NULL,
		    0) == 0) {
			goto unpack;
		}
		if (errno != ENOMEM) {
			free(buf);
			return (NULL);
		}
	}
	free(buf);
	return (NULL);

unpack:
	/* Count items */
	cnt = 0;
	bp = buf;
	ep = buf + len;
	while (bp < ep) {
		kckc = (struct kinfo_cheri_kc18n_compart *)(uintptr_t)bp;
		bp += kckc->kckc_structsize;
		cnt++;
	}

	list = calloc(cnt, sizeof(*list));
	if (list == NULL) {
		free(buf);
		return (NULL);
	}

	/* Unpack */
	bp = buf;
	kp = list;
	while (bp < ep) {
		kckc = (struct kinfo_cheri_kc18n_compart *)(uintptr_t)bp;
		memcpy(kp, kckc, kckc->kckc_structsize);
		bp += kckc->kckc_structsize;
		kp->kckc_structsize = sizeof(*kp);
		kp++;
	}
	free(buf);
	*cntp = cnt;
	return (list);
}
