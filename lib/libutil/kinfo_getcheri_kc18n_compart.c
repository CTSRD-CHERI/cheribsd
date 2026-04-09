#include <sys/types.h>
#include <sys/sysctl.h>
#include <sys/user.h>

#include <cheri/c18n.h>

#include <stdlib.h>
#include <string.h>

#include "libutil.h"

static struct kinfo_cheri_kc18n_compart *
kinfo_getcheri_kc18n_compart_impl(int *cntp, const char *compartsysctl)
{
	char *buf, *bp, *ep;
	struct kinfo_cheri_kc18n_compart *kckc, *list, *kp;
	size_t len;
	int cnt, i;

	buf = NULL;
	for (i = 0; i < 3; i++) {
		if (sysctlbyname(compartsysctl, NULL, &len, NULL, 0) < 0) {
			free(buf);
			return (NULL);
		}
		buf = reallocf(buf, len);
		if (buf == NULL)
			return (NULL);
		if (sysctlbyname(compartsysctl, buf, &len, NULL, 0) == 0)
			goto unpack;
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

struct kinfo_cheri_kc18n_compart *
kinfo_getcheri_kc18n_compart(int *cntp)
{
	return (kinfo_getcheri_kc18n_compart_impl(cntp,
	    "kern.kc18n_compartments"));
}
