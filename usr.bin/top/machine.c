/*
 * top - a top users display for Unix
 *
 * SYNOPSIS:  For FreeBSD-2.x and later
 *
 * DESCRIPTION:
 * Originally written for BSD4.4 system by Christos Zoulas.
 * Ported to FreeBSD 2.x by Steven Wallace && Wolfram Schneider
 * Order support hacked in from top-3.5beta6/machine/m_aix41.c
 *   by Monte Mitzelfelt (for latest top see http://www.groupsys.com/topinfo/)
 *
 * This is the machine-dependent module for FreeBSD 2.2
 * Works for:
 *	FreeBSD 2.2.x, 3.x, 4.x, and probably FreeBSD 2.1.x
 *
 * LIBS: -lkvm
 *
 * AUTHOR:  Christos Zoulas <christos@ee.cornell.edu>
 *          Steven Wallace  <swallace@freebsd.org>
 *          Wolfram Schneider <wosch@FreeBSD.org>
 *          Thomas Moestl <tmoestl@gmx.net>
 *
 * $FreeBSD$
 */

#include <sys/param.h>
#include <sys/errno.h>
#include <sys/file.h>
#include <sys/proc.h>
#include <sys/resource.h>
#include <sys/rtprio.h>
#include <sys/signal.h>
#include <sys/sysctl.h>
#include <sys/time.h>
#include <sys/user.h>
#include <sys/vmmeter.h>

#include <err.h>
#include <kvm.h>
#include <math.h>
#include <nlist.h>
#include <paths.h>
#include <pwd.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <strings.h>
#include <unistd.h>
#include <vis.h>

#include "top.h"
#include "machine.h"
#include "screen.h"
#include "utils.h"
#include "layout.h"

#define GETSYSCTL(name, var) getsysctl(name, &(var), sizeof(var))
#define	SMPUNAMELEN	13
#define	UPUNAMELEN	15

extern struct process_select ps;
extern char* printable(char *);
static int smpmode;
enum displaymodes displaymode;
#ifdef TOP_USERNAME_LEN
static int namelength = TOP_USERNAME_LEN;
#else
static int namelength = 8;
#endif
/* TOP_JID_LEN based on max of 999999 */
#define TOP_JID_LEN 7
#define TOP_SWAP_LEN 6
static int jidlength;
static int swaplength;
static int cmdlengthdelta;

/* Prototypes for top internals */
void quit(int);

/* get_process_info passes back a handle.  This is what it looks like: */

struct handle {
	struct kinfo_proc **next_proc;	/* points to next valid proc pointer */
	int remaining;			/* number of pointers remaining */
};

/* declarations for load_avg */
#include "loadavg.h"

/* define what weighted cpu is.  */
#define weighted_cpu(pct, pp) ((pp)->ki_swtime == 0 ? 0.0 : \
			 ((pct) / (1.0 - exp((pp)->ki_swtime * logcpu))))

/* what we consider to be process size: */
#define PROCSIZE(pp) ((pp)->ki_size / 1024)

#define RU(pp)	(&(pp)->ki_rusage)
#define RUTOT(pp) \
	(RU(pp)->ru_inblock + RU(pp)->ru_oublock + RU(pp)->ru_majflt)

#define	PCTCPU(pp) (pcpu[pp - pbase])

/* definitions for indices in the nlist array */

/*
 *  These definitions control the format of the per-process area
 */

static char io_header[] =
    "  PID%*s %-*.*s   VCSW  IVCSW   READ  WRITE  FAULT  TOTAL PERCENT COMMAND";

#define io_Proc_format \
    "%5d%*s %-*.*s %6ld %6ld %6ld %6ld %6ld %6ld %6.2f%% %.*s"

static char smp_header_thr[] =
    "  PID%*s %-*.*s  THR PRI NICE   SIZE    RES%*s STATE   C   TIME %7s COMMAND";
static char smp_header[] =
    "  PID%*s %-*.*s "   "PRI NICE   SIZE    RES%*s STATE   C   TIME %7s COMMAND";

#define smp_Proc_format \
    "%5d%*s %-*.*s %s%3d %4s%7s %6s%*.*s %-6.6s %2d%7s %6.2f%% %.*s"

static char up_header_thr[] =
    "  PID%*s %-*.*s  THR PRI NICE   SIZE    RES%*s STATE    TIME %7s COMMAND";
static char up_header[] =
    "  PID%*s %-*.*s "   "PRI NICE   SIZE    RES%*s STATE    TIME %7s COMMAND";

#define up_Proc_format \
    "%5d%*s %-*.*s %s%3d %4s%7s %6s%*.*s %-6.6s%.0d%7s %6.2f%% %.*s"


/* process state names for the "STATE" column of the display */
/* the extra nulls in the string "run" are for adding a slash and
   the processor number when needed */

char *state_abbrev[] = {
	"", "START", "RUN\0\0\0", "SLEEP", "STOP", "ZOMB", "WAIT", "LOCK"
};


static kvm_t *kd;

/* values that we stash away in _init and use in later routines */

static double logcpu;

/* these are retrieved from the kernel in _init */

static load_avg  ccpu;

/* these are used in the get_ functions */

static int lastpid;

/* these are for calculating cpu state percentages */

static long cp_time[CPUSTATES];
static long cp_old[CPUSTATES];
static long cp_diff[CPUSTATES];

/* these are for detailing the process states */

int process_states[8];
char *procstatenames[] = {
	"", " starting, ", " running, ", " sleeping, ", " stopped, ",
	" zombie, ", " waiting, ", " lock, ",
	NULL
};

/* these are for detailing the cpu states */

int cpu_states[CPUSTATES];
char *cpustatenames[] = {
	"user", "nice", "system", "interrupt", "idle", NULL
};

/* these are for detailing the memory statistics */

int memory_stats[7];
char *memorynames[] = {
	"K Active, ", "K Inact, ", "K Laundry, ", "K Wired, ", "K Buf, ",
	"K Free", NULL
};

int arc_stats[7];
char *arcnames[] = {
	"K Total, ", "K MFU, ", "K MRU, ", "K Anon, ", "K Header, ", "K Other",
	NULL
};

int carc_stats[4];
char *carcnames[] = {
	"K Compressed, ", "K Uncompressed, ", ":1 Ratio, ",
	NULL
};

int swap_stats[7];
char *swapnames[] = {
	"K Total, ", "K Used, ", "K Free, ", "% Inuse, ", "K In, ", "K Out",
	NULL
};


/* these are for keeping track of the proc array */

static int nproc;
static int onproc = -1;
static int pref_len;
static struct kinfo_proc *pbase;
static struct kinfo_proc **pref;
static struct kinfo_proc *previous_procs;
static struct kinfo_proc **previous_pref;
static int previous_proc_count = 0;
static int previous_proc_count_max = 0;
static int previous_thread;

/* data used for recalculating pctcpu */
static double *pcpu;
static struct timespec proc_uptime;
static struct timeval proc_wall_time;
static struct timeval previous_wall_time;
static uint64_t previous_interval = 0;

/* total number of io operations */
static long total_inblock;
static long total_oublock;
static long total_majflt;

/* these are for getting the memory statistics */

static int arc_enabled;
static int carc_enabled;
static int pageshift;		/* log base 2 of the pagesize */

/* define pagetok in terms of pageshift */

#define pagetok(size) ((size) << pageshift)

/* swap usage */
#define ki_swap(kip) \
    ((kip)->ki_swrss > (kip)->ki_rssize ? (kip)->ki_swrss - (kip)->ki_rssize : 0)

/* useful externals */
long percentages(int cnt, int *out, long *new, long *old, long *diffs);

#ifdef ORDER
/*
 * Sorting orders.  The first element is the default.
 */
char *ordernames[] = {
	"cpu", "size", "res", "time", "pri", "threads",
	"total", "read", "write", "fault", "vcsw", "ivcsw",
	"jid", "swap", "pid", NULL
};
#endif

/* Per-cpu time states */
static int maxcpu;
static int maxid;
static int ncpus;
static u_long cpumask;
static long *times;
static long *pcpu_cp_time;
static long *pcpu_cp_old;
static long *pcpu_cp_diff;
static int *pcpu_cpu_states;

static int compare_swap(const void *a, const void *b);
static int compare_jid(const void *a, const void *b);
static int compare_pid(const void *a, const void *b);
static int compare_tid(const void *a, const void *b);
static const char *format_nice(const struct kinfo_proc *pp);
static void getsysctl(const char *name, void *ptr, size_t len);
static int swapmode(int *retavail, int *retfree);
static void update_layout(void);
static int find_uid(uid_t needle, int *haystack);

static int
find_uid(uid_t needle, int *haystack)
{
	size_t i = 0;

	for (; i < TOP_MAX_UIDS; ++i)
		if ((uid_t)haystack[i] == needle)
			return 1;
	return 0;
}

void
toggle_pcpustats(void)
{

	if (ncpus == 1)
		return;
	update_layout();
}

/* Adjust display based on ncpus and the ARC state. */
static void
update_layout(void)
{

	y_mem = 3;
	y_arc = 4;
	y_carc = 5;
	y_swap = 4 + arc_enabled + carc_enabled;
	y_idlecursor = 5 + arc_enabled + carc_enabled;
	y_message = 5 + arc_enabled + carc_enabled;
	y_header = 6 + arc_enabled + carc_enabled;
	y_procs = 7 + arc_enabled + carc_enabled;
	Header_lines = 7 + arc_enabled + carc_enabled;

	if (pcpu_stats) {
		y_mem += ncpus - 1;
		y_arc += ncpus - 1;
		y_carc += ncpus - 1;
		y_swap += ncpus - 1;
		y_idlecursor += ncpus - 1;
		y_message += ncpus - 1;
		y_header += ncpus - 1;
		y_procs += ncpus - 1;
		Header_lines += ncpus - 1;
	}
}

int
machine_init(struct statics *statics, char do_unames)
{
	int i, j, empty, pagesize;
	uint64_t arc_size;
	boolean_t carc_en;
	size_t size;
	struct passwd *pw;

	size = sizeof(smpmode);
	if ((sysctlbyname("machdep.smp_active", &smpmode, &size,
	    NULL, 0) != 0 &&
	    sysctlbyname("kern.smp.active", &smpmode, &size,
	    NULL, 0) != 0) ||
	    size != sizeof(smpmode))
		smpmode = 0;

	size = sizeof(arc_size);
	if (sysctlbyname("kstat.zfs.misc.arcstats.size", &arc_size, &size,
	    NULL, 0) == 0 && arc_size != 0)
		arc_enabled = 1;
	size = sizeof(carc_en);
	if (arc_enabled &&
	    sysctlbyname("vfs.zfs.compressed_arc_enabled", &carc_en, &size,
	    NULL, 0) == 0 && carc_en == 1)
		carc_enabled = 1;

	if (do_unames) {
	    while ((pw = getpwent()) != NULL) {
		if (strlen(pw->pw_name) > namelength)
			namelength = strlen(pw->pw_name);
	    }
	}
	if (smpmode && namelength > SMPUNAMELEN)
		namelength = SMPUNAMELEN;
	else if (namelength > UPUNAMELEN)
		namelength = UPUNAMELEN;

	kd = kvm_open(NULL, _PATH_DEVNULL, NULL, O_RDONLY, "kvm_open");
	if (kd == NULL)
		return (-1);

	GETSYSCTL("kern.ccpu", ccpu);

	/* this is used in calculating WCPU -- calculate it ahead of time */
	logcpu = log(loaddouble(ccpu));

	pbase = NULL;
	pref = NULL;
	pcpu = NULL;
	nproc = 0;
	onproc = -1;

	/* get the page size and calculate pageshift from it */
	pagesize = getpagesize();
	pageshift = 0;
	while (pagesize > 1) {
		pageshift++;
		pagesize >>= 1;
	}

	/* we only need the amount of log(2)1024 for our conversion */
	pageshift -= LOG1024;

	/* fill in the statics information */
	statics->procstate_names = procstatenames;
	statics->cpustate_names = cpustatenames;
	statics->memory_names = memorynames;
	if (arc_enabled)
		statics->arc_names = arcnames;
	else
		statics->arc_names = NULL;
	if (carc_enabled)
		statics->carc_names = carcnames;
	else
		statics->carc_names = NULL;
	statics->swap_names = swapnames;
#ifdef ORDER
	statics->order_names = ordernames;
#endif

	/* Allocate state for per-CPU stats. */
	cpumask = 0;
	ncpus = 0;
	GETSYSCTL("kern.smp.maxcpus", maxcpu);
	size = sizeof(long) * maxcpu * CPUSTATES;
	times = malloc(size);
	if (times == NULL)
		err(1, "malloc %zu bytes", size);
	if (sysctlbyname("kern.cp_times", times, &size, NULL, 0) == -1)
		err(1, "sysctlbyname kern.cp_times");
	pcpu_cp_time = calloc(1, size);
	maxid = (size / CPUSTATES / sizeof(long)) - 1;
	for (i = 0; i <= maxid; i++) {
		empty = 1;
		for (j = 0; empty && j < CPUSTATES; j++) {
			if (times[i * CPUSTATES + j] != 0)
				empty = 0;
		}
		if (!empty) {
			cpumask |= (1ul << i);
			ncpus++;
		}
	}
	size = sizeof(long) * ncpus * CPUSTATES;
	pcpu_cp_old = calloc(1, size);
	pcpu_cp_diff = calloc(1, size);
	pcpu_cpu_states = calloc(1, size);
	statics->ncpus = ncpus;

	update_layout();

	/* all done! */
	return (0);
}

char *
format_header(char *uname_field)
{
	static char Header[128];
	const char *prehead;

	if (ps.jail)
		jidlength = TOP_JID_LEN + 1;	/* +1 for extra left space. */
	else
		jidlength = 0;

	if (ps.swap)
		swaplength = TOP_SWAP_LEN + 1;  /* +1 for extra left space */
	else
		swaplength = 0;

	switch (displaymode) {
	case DISP_CPU:
		/*
		 * The logic of picking the right header format seems reverse
		 * here because we only want to display a THR column when
		 * "thread mode" is off (and threads are not listed as
		 * separate lines).
		 */
		prehead = smpmode ?
		    (ps.thread ? smp_header : smp_header_thr) :
		    (ps.thread ? up_header : up_header_thr);
		snprintf(Header, sizeof(Header), prehead,
		    jidlength, ps.jail ? " JID" : "",
		    namelength, namelength, uname_field,
		    swaplength, ps.swap ? " SWAP" : "",
		    ps.wcpu ? "WCPU" : "CPU");
		break;
	case DISP_IO:
		prehead = io_header;
		snprintf(Header, sizeof(Header), prehead,
		    jidlength, ps.jail ? " JID" : "",
		    namelength, namelength, uname_field);
		break;
	}
	cmdlengthdelta = strlen(Header) - 7;
	return (Header);
}

static int swappgsin = -1;
static int swappgsout = -1;
extern struct timeval timeout;


void
get_system_info(struct system_info *si)
{
	long total;
	struct loadavg sysload;
	int mib[2];
	struct timeval boottime;
	uint64_t arc_stat, arc_stat2;
	int i, j;
	size_t size;

	/* get the CPU stats */
	size = (maxid + 1) * CPUSTATES * sizeof(long);
	if (sysctlbyname("kern.cp_times", pcpu_cp_time, &size, NULL, 0) == -1)
		err(1, "sysctlbyname kern.cp_times");
	GETSYSCTL("kern.cp_time", cp_time);
	GETSYSCTL("vm.loadavg", sysload);
	GETSYSCTL("kern.lastpid", lastpid);

	/* convert load averages to doubles */
	for (i = 0; i < 3; i++)
		si->load_avg[i] = (double)sysload.ldavg[i] / sysload.fscale;

	/* convert cp_time counts to percentages */
	for (i = j = 0; i <= maxid; i++) {
		if ((cpumask & (1ul << i)) == 0)
			continue;
		percentages(CPUSTATES, &pcpu_cpu_states[j * CPUSTATES],
		    &pcpu_cp_time[j * CPUSTATES],
		    &pcpu_cp_old[j * CPUSTATES],
		    &pcpu_cp_diff[j * CPUSTATES]);
		j++;
	}
	percentages(CPUSTATES, cpu_states, cp_time, cp_old, cp_diff);

	/* sum memory & swap statistics */
	{
		static unsigned int swap_delay = 0;
		static int swapavail = 0;
		static int swapfree = 0;
		static long bufspace = 0;
		static uint64_t nspgsin, nspgsout;

		GETSYSCTL("vfs.bufspace", bufspace);
		GETSYSCTL("vm.stats.vm.v_active_count", memory_stats[0]);
		GETSYSCTL("vm.stats.vm.v_inactive_count", memory_stats[1]);
		GETSYSCTL("vm.stats.vm.v_laundry_count", memory_stats[2]);
		GETSYSCTL("vm.stats.vm.v_wire_count", memory_stats[3]);
		GETSYSCTL("vm.stats.vm.v_free_count", memory_stats[5]);
		GETSYSCTL("vm.stats.vm.v_swappgsin", nspgsin);
		GETSYSCTL("vm.stats.vm.v_swappgsout", nspgsout);
		/* convert memory stats to Kbytes */
		memory_stats[0] = pagetok(memory_stats[0]);
		memory_stats[1] = pagetok(memory_stats[1]);
		memory_stats[2] = pagetok(memory_stats[2]);
		memory_stats[3] = pagetok(memory_stats[3]);
		memory_stats[4] = bufspace / 1024;
		memory_stats[5] = pagetok(memory_stats[5]);
		memory_stats[6] = -1;

		/* first interval */
		if (swappgsin < 0) {
			swap_stats[4] = 0;
			swap_stats[5] = 0;
		}

		/* compute differences between old and new swap statistic */
		else {
			swap_stats[4] = pagetok(((nspgsin - swappgsin)));
			swap_stats[5] = pagetok(((nspgsout - swappgsout)));
		}

		swappgsin = nspgsin;
		swappgsout = nspgsout;

		/* call CPU heavy swapmode() only for changes */
		if (swap_stats[4] > 0 || swap_stats[5] > 0 || swap_delay == 0) {
			swap_stats[3] = swapmode(&swapavail, &swapfree);
			swap_stats[0] = swapavail;
			swap_stats[1] = swapavail - swapfree;
			swap_stats[2] = swapfree;
		}
		swap_delay = 1;
		swap_stats[6] = -1;
	}

	if (arc_enabled) {
		GETSYSCTL("kstat.zfs.misc.arcstats.size", arc_stat);
		arc_stats[0] = arc_stat >> 10;
		GETSYSCTL("vfs.zfs.mfu_size", arc_stat);
		arc_stats[1] = arc_stat >> 10;
		GETSYSCTL("vfs.zfs.mru_size", arc_stat);
		arc_stats[2] = arc_stat >> 10;
		GETSYSCTL("vfs.zfs.anon_size", arc_stat);
		arc_stats[3] = arc_stat >> 10;
		GETSYSCTL("kstat.zfs.misc.arcstats.hdr_size", arc_stat);
		GETSYSCTL("kstat.zfs.misc.arcstats.l2_hdr_size", arc_stat2);
		arc_stats[4] = arc_stat + arc_stat2 >> 10;
		GETSYSCTL("kstat.zfs.misc.arcstats.other_size", arc_stat);
		arc_stats[5] = arc_stat >> 10;
		si->arc = arc_stats;
	}
	if (carc_enabled) {
		GETSYSCTL("kstat.zfs.misc.arcstats.compressed_size", arc_stat);
		carc_stats[0] = arc_stat >> 10;
		carc_stats[2] = arc_stat >> 10; /* For ratio */
		GETSYSCTL("kstat.zfs.misc.arcstats.uncompressed_size", arc_stat);
		carc_stats[1] = arc_stat >> 10;
		si->carc = carc_stats;
	}

	/* set arrays and strings */
	if (pcpu_stats) {
		si->cpustates = pcpu_cpu_states;
		si->ncpus = ncpus;
	} else {
		si->cpustates = cpu_states;
		si->ncpus = 1;
	}
	si->memory = memory_stats;
	si->swap = swap_stats;


	if (lastpid > 0) {
		si->last_pid = lastpid;
	} else {
		si->last_pid = -1;
	}

	/*
	 * Print how long system has been up.
	 * (Found by looking getting "boottime" from the kernel)
	 */
	mib[0] = CTL_KERN;
	mib[1] = KERN_BOOTTIME;
	size = sizeof(boottime);
	if (sysctl(mib, nitems(mib), &boottime, &size, NULL, 0) != -1 &&
	    boottime.tv_sec != 0) {
		si->boottime = boottime;
	} else {
		si->boottime.tv_sec = -1;
	}
}

#define NOPROC	((void *)-1)

/*
 * We need to compare data from the old process entry with the new
 * process entry.
 * To facilitate doing this quickly we stash a pointer in the kinfo_proc
 * structure to cache the mapping.  We also use a negative cache pointer
 * of NOPROC to avoid duplicate lookups.
 * XXX: this could be done when the actual processes are fetched, we do
 * it here out of laziness.
 */
const struct kinfo_proc *
get_old_proc(struct kinfo_proc *pp)
{
	struct kinfo_proc **oldpp, *oldp;

	/*
	 * If this is the first fetch of the kinfo_procs then we don't have
	 * any previous entries.
	 */
	if (previous_proc_count == 0)
		return (NULL);
	/* negative cache? */
	if (pp->ki_udata == NOPROC)
		return (NULL);
	/* cached? */
	if (pp->ki_udata != NULL)
		return (pp->ki_udata);
	/*
	 * Not cached,
	 * 1) look up based on pid.
	 * 2) compare process start.
	 * If we fail here, then setup a negative cache entry, otherwise
	 * cache it.
	 */
	oldpp = bsearch(&pp, previous_pref, previous_proc_count,
	    sizeof(*previous_pref), ps.thread ? compare_tid : compare_pid);
	if (oldpp == NULL) {
		pp->ki_udata = NOPROC;
		return (NULL);
	}
	oldp = *oldpp;
	if (bcmp(&oldp->ki_start, &pp->ki_start, sizeof(pp->ki_start)) != 0) {
		pp->ki_udata = NOPROC;
		return (NULL);
	}
	pp->ki_udata = oldp;
	return (oldp);
}

/*
 * Return the total amount of IO done in blocks in/out and faults.
 * store the values individually in the pointers passed in.
 */
long
get_io_stats(struct kinfo_proc *pp, long *inp, long *oup, long *flp,
    long *vcsw, long *ivcsw)
{
	const struct kinfo_proc *oldp;
	static struct kinfo_proc dummy;
	long ret;

	oldp = get_old_proc(pp);
	if (oldp == NULL) {
		bzero(&dummy, sizeof(dummy));
		oldp = &dummy;
	}
	*inp = RU(pp)->ru_inblock - RU(oldp)->ru_inblock;
	*oup = RU(pp)->ru_oublock - RU(oldp)->ru_oublock;
	*flp = RU(pp)->ru_majflt - RU(oldp)->ru_majflt;
	*vcsw = RU(pp)->ru_nvcsw - RU(oldp)->ru_nvcsw;
	*ivcsw = RU(pp)->ru_nivcsw - RU(oldp)->ru_nivcsw;
	ret =
	    (RU(pp)->ru_inblock - RU(oldp)->ru_inblock) +
	    (RU(pp)->ru_oublock - RU(oldp)->ru_oublock) +
	    (RU(pp)->ru_majflt - RU(oldp)->ru_majflt);
	return (ret);
}

/*
 * If there was a previous update, use the delta in ki_runtime over
 * the previous interval to calculate pctcpu.  Otherwise, fall back
 * to using the kernel's ki_pctcpu.
 */
static double
proc_calc_pctcpu(struct kinfo_proc *pp)
{
	const struct kinfo_proc *oldp;

	if (previous_interval != 0) {
		oldp = get_old_proc(pp);
		if (oldp != NULL)
			return ((double)(pp->ki_runtime - oldp->ki_runtime)
			    / previous_interval);

		/*
		 * If this process/thread was created during the previous
		 * interval, charge it's total runtime to the previous
		 * interval.
		 */
		else if (pp->ki_start.tv_sec > previous_wall_time.tv_sec ||
		    (pp->ki_start.tv_sec == previous_wall_time.tv_sec &&
		    pp->ki_start.tv_usec >= previous_wall_time.tv_usec))
			return ((double)pp->ki_runtime / previous_interval);
	}
	return (pctdouble(pp->ki_pctcpu));
}

/*
 * Return true if this process has used any CPU time since the
 * previous update.
 */
static int
proc_used_cpu(struct kinfo_proc *pp)
{
	const struct kinfo_proc *oldp;

	oldp = get_old_proc(pp);
	if (oldp == NULL)
		return (PCTCPU(pp) != 0);
	return (pp->ki_runtime != oldp->ki_runtime ||
	    RU(pp)->ru_nvcsw != RU(oldp)->ru_nvcsw ||
	    RU(pp)->ru_nivcsw != RU(oldp)->ru_nivcsw);
}

/*
 * Return the total number of block in/out and faults by a process.
 */
long
get_io_total(struct kinfo_proc *pp)
{
	long dummy;

	return (get_io_stats(pp, &dummy, &dummy, &dummy, &dummy, &dummy));
}

static struct handle handle;

caddr_t
get_process_info(struct system_info *si, struct process_select *sel,
    int (*compare)(const void *, const void *))
{
	int i;
	int total_procs;
	long p_io;
	long p_inblock, p_oublock, p_majflt, p_vcsw, p_ivcsw;
	long nsec;
	int active_procs;
	struct kinfo_proc **prefp;
	struct kinfo_proc *pp;
	struct timespec previous_proc_uptime;

	/* these are copied out of sel for speed */
	int show_idle;
	int show_jid;
	int show_self;
	int show_system;
	int show_uid;
	int show_command;
	int show_kidle;

	/*
	 * If thread state was toggled, don't cache the previous processes.
	 */
	if (previous_thread != sel->thread)
		nproc = 0;
	previous_thread = sel->thread;

	/*
	 * Save the previous process info.
	 */
	if (previous_proc_count_max < nproc) {
		free(previous_procs);
		previous_procs = malloc(nproc * sizeof(*previous_procs));
		free(previous_pref);
		previous_pref = malloc(nproc * sizeof(*previous_pref));
		if (previous_procs == NULL || previous_pref == NULL) {
			(void) fprintf(stderr, "top: Out of memory.\n");
			quit(23);
		}
		previous_proc_count_max = nproc;
	}
	if (nproc) {
		for (i = 0; i < nproc; i++)
			previous_pref[i] = &previous_procs[i];
		bcopy(pbase, previous_procs, nproc * sizeof(*previous_procs));
		qsort(previous_pref, nproc, sizeof(*previous_pref),
		    ps.thread ? compare_tid : compare_pid);
	}
	previous_proc_count = nproc;
	previous_proc_uptime = proc_uptime;
	previous_wall_time = proc_wall_time;
	previous_interval = 0;

	pbase = kvm_getprocs(kd, sel->thread ? KERN_PROC_ALL : KERN_PROC_PROC,
	    0, &nproc);
	(void)gettimeofday(&proc_wall_time, NULL);
	if (clock_gettime(CLOCK_UPTIME, &proc_uptime) != 0)
		memset(&proc_uptime, 0, sizeof(proc_uptime));
	else if (previous_proc_uptime.tv_sec != 0 &&
	    previous_proc_uptime.tv_nsec != 0) {
		previous_interval = (proc_uptime.tv_sec -
		    previous_proc_uptime.tv_sec) * 1000000;
		nsec = proc_uptime.tv_nsec - previous_proc_uptime.tv_nsec;
		if (nsec < 0) {
			previous_interval -= 1000000;
			nsec += 1000000000;
		}
		previous_interval += nsec / 1000;
	}
	if (nproc > onproc) {
		pref = realloc(pref, sizeof(*pref) * nproc);
		pcpu = realloc(pcpu, sizeof(*pcpu) * nproc);
		onproc = nproc;
	}
	if (pref == NULL || pbase == NULL || pcpu == NULL) {
		(void) fprintf(stderr, "top: Out of memory.\n");
		quit(23);
	}
	/* get a pointer to the states summary array */
	si->procstates = process_states;

	/* set up flags which define what we are going to select */
	show_idle = sel->idle;
	show_jid = sel->jid != -1;
	show_self = sel->self == -1;
	show_system = sel->system;
	show_uid = sel->uid[0] != -1;
	show_command = sel->command != NULL;
	show_kidle = sel->kidle;

	/* count up process states and get pointers to interesting procs */
	total_procs = 0;
	active_procs = 0;
	total_inblock = 0;
	total_oublock = 0;
	total_majflt = 0;
	memset((char *)process_states, 0, sizeof(process_states));
	prefp = pref;
	for (pp = pbase, i = 0; i < nproc; pp++, i++) {

		if (pp->ki_stat == 0)
			/* not in use */
			continue;

		if (!show_self && pp->ki_pid == sel->self)
			/* skip self */
			continue;

		if (!show_system && (pp->ki_flag & P_SYSTEM))
			/* skip system process */
			continue;

		p_io = get_io_stats(pp, &p_inblock, &p_oublock, &p_majflt,
		    &p_vcsw, &p_ivcsw);
		total_inblock += p_inblock;
		total_oublock += p_oublock;
		total_majflt += p_majflt;
		total_procs++;
		process_states[pp->ki_stat]++;

		if (pp->ki_stat == SZOMB)
			/* skip zombies */
			continue;

		if (!show_kidle && pp->ki_tdflags & TDF_IDLETD)
			/* skip kernel idle process */
			continue;

		PCTCPU(pp) = proc_calc_pctcpu(pp);
		if (sel->thread && PCTCPU(pp) > 1.0)
			PCTCPU(pp) = 1.0;
		if (displaymode == DISP_CPU && !show_idle &&
		    (!proc_used_cpu(pp) ||
		     pp->ki_stat == SSTOP || pp->ki_stat == SIDL))
			/* skip idle or non-running processes */
			continue;

		if (displaymode == DISP_IO && !show_idle && p_io == 0)
			/* skip processes that aren't doing I/O */
			continue;

		if (show_jid && pp->ki_jid != sel->jid)
			/* skip proc. that don't belong to the selected JID */
			continue;

		if (show_uid && !find_uid(pp->ki_ruid, sel->uid))
			/* skip proc. that don't belong to the selected UID */
			continue;

		*prefp++ = pp;
		active_procs++;
	}

	/* if requested, sort the "interesting" processes */
	if (compare != NULL)
		qsort(pref, active_procs, sizeof(*pref), compare);

	/* remember active and total counts */
	si->p_total = total_procs;
	si->p_active = pref_len = active_procs;

	/* pass back a handle */
	handle.next_proc = pref;
	handle.remaining = active_procs;
	return ((caddr_t)&handle);
}

static char fmt[512];	/* static area where result is built */

char *
format_next_process(caddr_t handle, char *(*get_userid)(int), int flags)
{
	struct kinfo_proc *pp;
	const struct kinfo_proc *oldp;
	long cputime;
	double pct;
	struct handle *hp;
	char status[16];
	int cpu, state;
	struct rusage ru, *rup;
	long p_tot, s_tot;
	char *proc_fmt, thr_buf[6];
	char jid_buf[TOP_JID_LEN + 1], swap_buf[TOP_SWAP_LEN + 1];
	char *cmdbuf = NULL;
	char **args;
	const int cmdlen = 128;

	/* find and remember the next proc structure */
	hp = (struct handle *)handle;
	pp = *(hp->next_proc++);
	hp->remaining--;

	/* get the process's command name */
	if ((pp->ki_flag & P_INMEM) == 0) {
		/*
		 * Print swapped processes as <pname>
		 */
		size_t len;

		len = strlen(pp->ki_comm);
		if (len > sizeof(pp->ki_comm) - 3)
			len = sizeof(pp->ki_comm) - 3;
		memmove(pp->ki_comm + 1, pp->ki_comm, len);
		pp->ki_comm[0] = '<';
		pp->ki_comm[len + 1] = '>';
		pp->ki_comm[len + 2] = '\0';
	}

	/*
	 * Convert the process's runtime from microseconds to seconds.  This
	 * time includes the interrupt time although that is not wanted here.
	 * ps(1) is similarly sloppy.
	 */
	cputime = (pp->ki_runtime + 500000) / 1000000;

	/* calculate the base for cpu percentages */
	pct = PCTCPU(pp);

	/* generate "STATE" field */
	switch (state = pp->ki_stat) {
	case SRUN:
		if (smpmode && pp->ki_oncpu != NOCPU)
			sprintf(status, "CPU%d", pp->ki_oncpu);
		else
			strcpy(status, "RUN");
		break;
	case SLOCK:
		if (pp->ki_kiflag & KI_LOCKBLOCK) {
			sprintf(status, "*%.6s", pp->ki_lockname);
			break;
		}
		/* fall through */
	case SSLEEP:
		if (pp->ki_wmesg != NULL) {
			sprintf(status, "%.6s", pp->ki_wmesg);
			break;
		}
		/* FALLTHROUGH */
	default:

		if (state >= 0 &&
		    state < sizeof(state_abbrev) / sizeof(*state_abbrev))
			sprintf(status, "%.6s", state_abbrev[state]);
		else
			sprintf(status, "?%5d", state);
		break;
	}

	cmdbuf = (char *)malloc(cmdlen + 1);
	if (cmdbuf == NULL) {
		warn("malloc(%d)", cmdlen + 1);
		return NULL;
	}

	if (!(flags & FMT_SHOWARGS)) {
		if (ps.thread && pp->ki_flag & P_HADTHREADS &&
		    pp->ki_tdname[0]) {
			snprintf(cmdbuf, cmdlen, "%s{%s%s}", pp->ki_comm,
			    pp->ki_tdname, pp->ki_moretdname);
		} else {
			snprintf(cmdbuf, cmdlen, "%s", pp->ki_comm);
		}
	} else {
		if (pp->ki_flag & P_SYSTEM ||
		    pp->ki_args == NULL ||
		    (args = kvm_getargv(kd, pp, cmdlen)) == NULL ||
		    !(*args)) {
			if (ps.thread && pp->ki_flag & P_HADTHREADS &&
		    	    pp->ki_tdname[0]) {
				snprintf(cmdbuf, cmdlen,
				    "[%s{%s%s}]", pp->ki_comm, pp->ki_tdname,
				    pp->ki_moretdname);
			} else {
				snprintf(cmdbuf, cmdlen,
				    "[%s]", pp->ki_comm);
			}
		} else {
			char *src, *dst, *argbuf;
			char *cmd;
			size_t argbuflen;
			size_t len;

			argbuflen = cmdlen * 4;
			argbuf = (char *)malloc(argbuflen + 1);
			if (argbuf == NULL) {
				warn("malloc(%zu)", argbuflen + 1);
				free(cmdbuf);
				return NULL;
			}

			dst = argbuf;

			/* Extract cmd name from argv */
			cmd = strrchr(*args, '/');
			if (cmd == NULL)
				cmd = *args;
			else
				cmd++;

			for (; (src = *args++) != NULL; ) {
				if (*src == '\0')
					continue;
				len = (argbuflen - (dst - argbuf) - 1) / 4;
				strvisx(dst, src,
				    MIN(strlen(src), len),
				    VIS_NL | VIS_CSTYLE);
				while (*dst != '\0')
					dst++;
				if ((argbuflen - (dst - argbuf) - 1) / 4 > 0)
					*dst++ = ' '; /* add delimiting space */
			}
			if (dst != argbuf && dst[-1] == ' ')
				dst--;
			*dst = '\0';

			if (strcmp(cmd, pp->ki_comm) != 0) {
				if (ps.thread && pp->ki_flag & P_HADTHREADS &&
				    pp->ki_tdname[0])
					snprintf(cmdbuf, cmdlen,
					    "%s (%s){%s%s}", argbuf,
					    pp->ki_comm, pp->ki_tdname,
					    pp->ki_moretdname);
				else
					snprintf(cmdbuf, cmdlen,
					    "%s (%s)", argbuf, pp->ki_comm);
			} else {
				if (ps.thread && pp->ki_flag & P_HADTHREADS &&
				    pp->ki_tdname[0])
					snprintf(cmdbuf, cmdlen,
					    "%s{%s%s}", argbuf, pp->ki_tdname,
					    pp->ki_moretdname);
				else
					strlcpy(cmdbuf, argbuf, cmdlen);
			}
			free(argbuf);
		}
	}

	if (ps.jail == 0)
		jid_buf[0] = '\0';
	else
		snprintf(jid_buf, sizeof(jid_buf), "%*d",
		    jidlength - 1, pp->ki_jid);

	if (ps.swap == 0)
		swap_buf[0] = '\0';
	else
		snprintf(swap_buf, sizeof(swap_buf), "%*s",
		    swaplength - 1,
		    format_k2(pagetok(ki_swap(pp)))); /* XXX */

	if (displaymode == DISP_IO) {
		oldp = get_old_proc(pp);
		if (oldp != NULL) {
			ru.ru_inblock = RU(pp)->ru_inblock -
			    RU(oldp)->ru_inblock;
			ru.ru_oublock = RU(pp)->ru_oublock -
			    RU(oldp)->ru_oublock;
			ru.ru_majflt = RU(pp)->ru_majflt - RU(oldp)->ru_majflt;
			ru.ru_nvcsw = RU(pp)->ru_nvcsw - RU(oldp)->ru_nvcsw;
			ru.ru_nivcsw = RU(pp)->ru_nivcsw - RU(oldp)->ru_nivcsw;
			rup = &ru;
		} else {
			rup = RU(pp);
		}
		p_tot = rup->ru_inblock + rup->ru_oublock + rup->ru_majflt;
		s_tot = total_inblock + total_oublock + total_majflt;

		snprintf(fmt, sizeof(fmt), io_Proc_format,
		    pp->ki_pid,
		    jidlength, jid_buf,
		    namelength, namelength, (*get_userid)(pp->ki_ruid),
		    rup->ru_nvcsw,
		    rup->ru_nivcsw,
		    rup->ru_inblock,
		    rup->ru_oublock,
		    rup->ru_majflt,
		    p_tot,
		    s_tot == 0 ? 0.0 : (p_tot * 100.0 / s_tot),
		    screen_width > cmdlengthdelta ?
		    screen_width - cmdlengthdelta : 0,
		    printable(cmdbuf));

		free(cmdbuf);

		return (fmt);
	}

	/* format this entry */
	if (smpmode) {
		if (state == SRUN && pp->ki_oncpu != NOCPU)
			cpu = pp->ki_oncpu;
		else
			cpu = pp->ki_lastcpu;
	} else
		cpu = 0;
	proc_fmt = smpmode ? smp_Proc_format : up_Proc_format;
	if (ps.thread != 0)
		thr_buf[0] = '\0';
	else
		snprintf(thr_buf, sizeof(thr_buf), "%*d ",
		    (int)(sizeof(thr_buf) - 2), pp->ki_numthreads);

	snprintf(fmt, sizeof(fmt), proc_fmt,
	    pp->ki_pid,
	    jidlength, jid_buf,
	    namelength, namelength, (*get_userid)(pp->ki_ruid),
	    thr_buf,
	    pp->ki_pri.pri_level - PZERO,
	    format_nice(pp),
	    format_k2(PROCSIZE(pp)),
	    format_k2(pagetok(pp->ki_rssize)),
	    swaplength, swaplength, swap_buf,
	    status,
	    cpu,
	    format_time(cputime),
	    ps.wcpu ? 100.0 * weighted_cpu(pct, pp) : 100.0 * pct,
	    screen_width > cmdlengthdelta ? screen_width - cmdlengthdelta : 0,
	    printable(cmdbuf));

	free(cmdbuf);

	/* return the result */
	return (fmt);
}

static void
getsysctl(const char *name, void *ptr, size_t len)
{
	size_t nlen = len;

	if (sysctlbyname(name, ptr, &nlen, NULL, 0) == -1) {
		fprintf(stderr, "top: sysctl(%s...) failed: %s\n", name,
		    strerror(errno));
		quit(23);
	}
	if (nlen != len) {
		fprintf(stderr, "top: sysctl(%s...) expected %lu, got %lu\n",
		    name, (unsigned long)len, (unsigned long)nlen);
		quit(23);
	}
}

static const char *
format_nice(const struct kinfo_proc *pp)
{
	const char *fifo, *kproc;
	int rtpri;
	static char nicebuf[4 + 1];

	fifo = PRI_NEED_RR(pp->ki_pri.pri_class) ? "" : "F";
	kproc = (pp->ki_flag & P_KPROC) ? "k" : "";
	switch (PRI_BASE(pp->ki_pri.pri_class)) {
	case PRI_ITHD:
		return ("-");
	case PRI_REALTIME:
		/*
		 * XXX: the kernel doesn't tell us the original rtprio and
		 * doesn't really know what it was, so to recover it we
		 * must be more chummy with the implementation than the
		 * implementation is with itself.  pri_user gives a
		 * constant "base" priority, but is only initialized
		 * properly for user threads.  pri_native gives what the
		 * kernel calls the "base" priority, but it isn't constant
		 * since it is changed by priority propagation.  pri_native
		 * also isn't properly initialized for all threads, but it
		 * is properly initialized for kernel realtime and idletime
		 * threads.  Thus we use pri_user for the base priority of
		 * user threads (it is always correct) and pri_native for
		 * the base priority of kernel realtime and idletime threads
		 * (there is nothing better, and it is usually correct).
		 *
		 * The field width and thus the buffer are too small for
		 * values like "kr31F", but such values shouldn't occur,
		 * and if they do then the tailing "F" is not displayed.
		 */
		rtpri = ((pp->ki_flag & P_KPROC) ? pp->ki_pri.pri_native :
		    pp->ki_pri.pri_user) - PRI_MIN_REALTIME;
		snprintf(nicebuf, sizeof(nicebuf), "%sr%d%s",
		    kproc, rtpri, fifo);
		break;
	case PRI_TIMESHARE:
		if (pp->ki_flag & P_KPROC)
			return ("-");
		snprintf(nicebuf, sizeof(nicebuf), "%d", pp->ki_nice - NZERO);
		break;
	case PRI_IDLE:
		/* XXX: as above. */
		rtpri = ((pp->ki_flag & P_KPROC) ? pp->ki_pri.pri_native :
		    pp->ki_pri.pri_user) - PRI_MIN_IDLE;
		snprintf(nicebuf, sizeof(nicebuf), "%si%d%s",
		    kproc, rtpri, fifo);
		break;
	default:
		return ("?");
	}
	return (nicebuf);
}

/* comparison routines for qsort */

static int
compare_pid(const void *p1, const void *p2)
{
	const struct kinfo_proc * const *pp1 = p1;
	const struct kinfo_proc * const *pp2 = p2;

	if ((*pp2)->ki_pid < 0 || (*pp1)->ki_pid < 0)
		abort();

	return ((*pp1)->ki_pid - (*pp2)->ki_pid);
}

static int
compare_tid(const void *p1, const void *p2)
{
	const struct kinfo_proc * const *pp1 = p1;
	const struct kinfo_proc * const *pp2 = p2;

	if ((*pp2)->ki_tid < 0 || (*pp1)->ki_tid < 0)
		abort();

	return ((*pp1)->ki_tid - (*pp2)->ki_tid);
}

/*
 *  proc_compare - comparison function for "qsort"
 *	Compares the resource consumption of two processes using five
 *	distinct keys.  The keys (in descending order of importance) are:
 *	percent cpu, cpu ticks, state, resident set size, total virtual
 *	memory usage.  The process states are ordered as follows (from least
 *	to most important):  WAIT, zombie, sleep, stop, start, run.  The
 *	array declaration below maps a process state index into a number
 *	that reflects this ordering.
 */

static int sorted_state[] = {
	0,	/* not used		*/
	3,	/* sleep		*/
	1,	/* ABANDONED (WAIT)	*/
	6,	/* run			*/
	5,	/* start		*/
	2,	/* zombie		*/
	4	/* stop			*/
};


#define ORDERKEY_PCTCPU(a, b) do { \
	double diff; \
	if (ps.wcpu) \
		diff = weighted_cpu(PCTCPU((b)), (b)) - \
		    weighted_cpu(PCTCPU((a)), (a)); \
	else \
		diff = PCTCPU((b)) - PCTCPU((a)); \
	if (diff != 0) \
		return (diff > 0 ? 1 : -1); \
} while (0)

#define ORDERKEY_CPTICKS(a, b) do { \
	int64_t diff = (int64_t)(b)->ki_runtime - (int64_t)(a)->ki_runtime; \
	if (diff != 0) \
		return (diff > 0 ? 1 : -1); \
} while (0)

#define ORDERKEY_STATE(a, b) do { \
	int diff = sorted_state[(b)->ki_stat] - sorted_state[(a)->ki_stat]; \
	if (diff != 0) \
		return (diff > 0 ? 1 : -1); \
} while (0)

#define ORDERKEY_PRIO(a, b) do { \
	int diff = (int)(b)->ki_pri.pri_level - (int)(a)->ki_pri.pri_level; \
	if (diff != 0) \
		return (diff > 0 ? 1 : -1); \
} while (0)

#define	ORDERKEY_THREADS(a, b) do { \
	int diff = (int)(b)->ki_numthreads - (int)(a)->ki_numthreads; \
	if (diff != 0) \
		return (diff > 0 ? 1 : -1); \
} while (0)

#define ORDERKEY_RSSIZE(a, b) do { \
	long diff = (long)(b)->ki_rssize - (long)(a)->ki_rssize; \
	if (diff != 0) \
		return (diff > 0 ? 1 : -1); \
} while (0)

#define ORDERKEY_MEM(a, b) do { \
	long diff = (long)PROCSIZE((b)) - (long)PROCSIZE((a)); \
	if (diff != 0) \
		return (diff > 0 ? 1 : -1); \
} while (0)

#define ORDERKEY_JID(a, b) do { \
	int diff = (int)(b)->ki_jid - (int)(a)->ki_jid; \
	if (diff != 0) \
		return (diff > 0 ? 1 : -1); \
} while (0)

#define ORDERKEY_SWAP(a, b) do { \
	int diff = (int)ki_swap(b) - (int)ki_swap(a); \
	if (diff != 0) \
		return (diff > 0 ? 1 : -1); \
} while (0)

/* compare_cpu - the comparison function for sorting by cpu percentage */

int
#ifdef ORDER
compare_cpu(void *arg1, void *arg2)
#else
proc_compare(void *arg1, void *arg2)
#endif
{
	struct kinfo_proc *p1 = *(struct kinfo_proc **)arg1;
	struct kinfo_proc *p2 = *(struct kinfo_proc **)arg2;

	ORDERKEY_PCTCPU(p1, p2);
	ORDERKEY_CPTICKS(p1, p2);
	ORDERKEY_STATE(p1, p2);
	ORDERKEY_PRIO(p1, p2);
	ORDERKEY_RSSIZE(p1, p2);
	ORDERKEY_MEM(p1, p2);

	return (0);
}

#ifdef ORDER
/* "cpu" compare routines */
int compare_size(), compare_res(), compare_time(), compare_prio(),
    compare_threads();

/*
 * "io" compare routines.  Context switches aren't i/o, but are displayed
 * on the "io" display.
 */
int compare_iototal(), compare_ioread(), compare_iowrite(), compare_iofault(),
    compare_vcsw(), compare_ivcsw();

int (*compares[])() = {
	compare_cpu,
	compare_size,
	compare_res,
	compare_time,
	compare_prio,
	compare_threads,
	compare_iototal,
	compare_ioread,
	compare_iowrite,
	compare_iofault,
	compare_vcsw,
	compare_ivcsw,
	compare_jid,
	compare_swap,
	NULL
};

/* compare_size - the comparison function for sorting by total memory usage */

int
compare_size(void *arg1, void *arg2)
{
	struct kinfo_proc *p1 = *(struct kinfo_proc **)arg1;
	struct kinfo_proc *p2 = *(struct kinfo_proc **)arg2;

	ORDERKEY_MEM(p1, p2);
	ORDERKEY_RSSIZE(p1, p2);
	ORDERKEY_PCTCPU(p1, p2);
	ORDERKEY_CPTICKS(p1, p2);
	ORDERKEY_STATE(p1, p2);
	ORDERKEY_PRIO(p1, p2);

	return (0);
}

/* compare_res - the comparison function for sorting by resident set size */

int
compare_res(void *arg1, void *arg2)
{
	struct kinfo_proc *p1 = *(struct kinfo_proc **)arg1;
	struct kinfo_proc *p2 = *(struct kinfo_proc **)arg2;

	ORDERKEY_RSSIZE(p1, p2);
	ORDERKEY_MEM(p1, p2);
	ORDERKEY_PCTCPU(p1, p2);
	ORDERKEY_CPTICKS(p1, p2);
	ORDERKEY_STATE(p1, p2);
	ORDERKEY_PRIO(p1, p2);

	return (0);
}

/* compare_time - the comparison function for sorting by total cpu time */

int
compare_time(void *arg1, void *arg2)
{
	struct kinfo_proc *p1 = *(struct kinfo_proc **)arg1;
	struct kinfo_proc *p2 = *(struct kinfo_proc **)arg2;

	ORDERKEY_CPTICKS(p1, p2);
	ORDERKEY_PCTCPU(p1, p2);
	ORDERKEY_STATE(p1, p2);
	ORDERKEY_PRIO(p1, p2);
	ORDERKEY_RSSIZE(p1, p2);
	ORDERKEY_MEM(p1, p2);

	return (0);
}

/* compare_prio - the comparison function for sorting by priority */

int
compare_prio(void *arg1, void *arg2)
{
	struct kinfo_proc *p1 = *(struct kinfo_proc **)arg1;
	struct kinfo_proc *p2 = *(struct kinfo_proc **)arg2;

	ORDERKEY_PRIO(p1, p2);
	ORDERKEY_CPTICKS(p1, p2);
	ORDERKEY_PCTCPU(p1, p2);
	ORDERKEY_STATE(p1, p2);
	ORDERKEY_RSSIZE(p1, p2);
	ORDERKEY_MEM(p1, p2);

	return (0);
}

/* compare_threads - the comparison function for sorting by threads */
int
compare_threads(void *arg1, void *arg2)
{
	struct kinfo_proc *p1 = *(struct kinfo_proc **)arg1;
	struct kinfo_proc *p2 = *(struct kinfo_proc **)arg2;

	ORDERKEY_THREADS(p1, p2);
	ORDERKEY_PCTCPU(p1, p2);
	ORDERKEY_CPTICKS(p1, p2);
	ORDERKEY_STATE(p1, p2);
	ORDERKEY_PRIO(p1, p2);
	ORDERKEY_RSSIZE(p1, p2);
	ORDERKEY_MEM(p1, p2);

	return (0);
}

/* compare_jid - the comparison function for sorting by jid */
static int
compare_jid(const void *arg1, const void *arg2)
{
	struct kinfo_proc *p1 = *(struct kinfo_proc **)arg1;
	struct kinfo_proc *p2 = *(struct kinfo_proc **)arg2;

	ORDERKEY_JID(p1, p2);
	ORDERKEY_PCTCPU(p1, p2);
	ORDERKEY_CPTICKS(p1, p2);
	ORDERKEY_STATE(p1, p2);
	ORDERKEY_PRIO(p1, p2);
	ORDERKEY_RSSIZE(p1, p2);
	ORDERKEY_MEM(p1, p2);

	return (0);
}

/* compare_swap - the comparison function for sorting by swap */
static int
compare_swap(const void *arg1, const void *arg2)
{
	struct kinfo_proc *p1 = *(struct kinfo_proc **)arg1;
	struct kinfo_proc *p2 = *(struct kinfo_proc **)arg2;

	ORDERKEY_SWAP(p1, p2);
	ORDERKEY_PCTCPU(p1, p2);
	ORDERKEY_CPTICKS(p1, p2);
	ORDERKEY_STATE(p1, p2);
	ORDERKEY_PRIO(p1, p2);
	ORDERKEY_RSSIZE(p1, p2);
	ORDERKEY_MEM(p1, p2);

	return (0);
}
#endif /* ORDER */

/* assorted comparison functions for sorting by i/o */

int
#ifdef ORDER
compare_iototal(void *arg1, void *arg2)
#else
io_compare(void *arg1, void *arg2)
#endif
{
	struct kinfo_proc *p1 = *(struct kinfo_proc **)arg1;
	struct kinfo_proc *p2 = *(struct kinfo_proc **)arg2;

	return (get_io_total(p2) - get_io_total(p1));
}

#ifdef ORDER
int
compare_ioread(void *arg1, void *arg2)
{
	struct kinfo_proc *p1 = *(struct kinfo_proc **)arg1;
	struct kinfo_proc *p2 = *(struct kinfo_proc **)arg2;
	long dummy, inp1, inp2;

	(void) get_io_stats(p1, &inp1, &dummy, &dummy, &dummy, &dummy);
	(void) get_io_stats(p2, &inp2, &dummy, &dummy, &dummy, &dummy);

	return (inp2 - inp1);
}

int
compare_iowrite(void *arg1, void *arg2)
{
	struct kinfo_proc *p1 = *(struct kinfo_proc **)arg1;
	struct kinfo_proc *p2 = *(struct kinfo_proc **)arg2;
	long dummy, oup1, oup2;

	(void) get_io_stats(p1, &dummy, &oup1, &dummy, &dummy, &dummy);
	(void) get_io_stats(p2, &dummy, &oup2, &dummy, &dummy, &dummy);

	return (oup2 - oup1);
}

int
compare_iofault(void *arg1, void *arg2)
{
	struct kinfo_proc *p1 = *(struct kinfo_proc **)arg1;
	struct kinfo_proc *p2 = *(struct kinfo_proc **)arg2;
	long dummy, flp1, flp2;

	(void) get_io_stats(p1, &dummy, &dummy, &flp1, &dummy, &dummy);
	(void) get_io_stats(p2, &dummy, &dummy, &flp2, &dummy, &dummy);

	return (flp2 - flp1);
}

int
compare_vcsw(void *arg1, void *arg2)
{
	struct kinfo_proc *p1 = *(struct kinfo_proc **)arg1;
	struct kinfo_proc *p2 = *(struct kinfo_proc **)arg2;
	long dummy, flp1, flp2;

	(void) get_io_stats(p1, &dummy, &dummy, &dummy, &flp1, &dummy);
	(void) get_io_stats(p2, &dummy, &dummy, &dummy, &flp2, &dummy);

	return (flp2 - flp1);
}

int
compare_ivcsw(void *arg1, void *arg2)
{
	struct kinfo_proc *p1 = *(struct kinfo_proc **)arg1;
	struct kinfo_proc *p2 = *(struct kinfo_proc **)arg2;
	long dummy, flp1, flp2;

	(void) get_io_stats(p1, &dummy, &dummy, &dummy, &dummy, &flp1);
	(void) get_io_stats(p2, &dummy, &dummy, &dummy, &dummy, &flp2);

	return (flp2 - flp1);
}
#endif /* ORDER */

/*
 * proc_owner(pid) - returns the uid that owns process "pid", or -1 if
 *		the process does not exist.
 *		It is EXTREMELY IMPORTANT that this function work correctly.
 *		If top runs setuid root (as in SVR4), then this function
 *		is the only thing that stands in the way of a serious
 *		security problem.  It validates requests for the "kill"
 *		and "renice" commands.
 */

int
proc_owner(int pid)
{
	int cnt;
	struct kinfo_proc **prefp;
	struct kinfo_proc *pp;

	prefp = pref;
	cnt = pref_len;
	while (--cnt >= 0) {
		pp = *prefp++;
		if (pp->ki_pid == (pid_t)pid)
			return ((int)pp->ki_ruid);
	}
	return (-1);
}

static int
swapmode(int *retavail, int *retfree)
{
	int n;
	struct kvm_swap swapary[1];
	static int pagesize = 0;
	static u_long swap_maxpages = 0;

	*retavail = 0;
	*retfree = 0;

#define CONVERT(v)	((quad_t)(v) * pagesize / 1024)

	n = kvm_getswapinfo(kd, swapary, 1, 0);
	if (n < 0 || swapary[0].ksw_total == 0)
		return (0);

	if (pagesize == 0)
		pagesize = getpagesize();
	if (swap_maxpages == 0)
		GETSYSCTL("vm.swap_maxpages", swap_maxpages);

	/* ksw_total contains the total size of swap all devices which may
	   exceed the maximum swap size allocatable in the system */
	if ( swapary[0].ksw_total > swap_maxpages )
		swapary[0].ksw_total = swap_maxpages;

	*retavail = CONVERT(swapary[0].ksw_total);
	*retfree = CONVERT(swapary[0].ksw_total - swapary[0].ksw_used);

	n = (int)(swapary[0].ksw_used * 100.0 / swapary[0].ksw_total);
	return (n);
}
