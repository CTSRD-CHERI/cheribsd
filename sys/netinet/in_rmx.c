/*-
 * Copyright 1994, 1995 Massachusetts Institute of Technology
 *
 * Permission to use, copy, modify, and distribute this software and
 * its documentation for any purpose and without fee is hereby
 * granted, provided that both the above copyright notice and this
 * permission notice appear in all copies, that both the above
 * copyright notice and this permission notice appear in all
 * supporting documentation, and that the name of M.I.T. not be used
 * in advertising or publicity pertaining to distribution of the
 * software without specific, written prior permission.  M.I.T. makes
 * no representations about the suitability of this software for any
 * purpose.  It is provided "as is" without express or implied
 * warranty.
 *
 * THIS SOFTWARE IS PROVIDED BY M.I.T. ``AS IS''.  M.I.T. DISCLAIMS
 * ALL EXPRESS OR IMPLIED WARRANTIES WITH REGARD TO THIS SOFTWARE,
 * INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES OF
 * MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE. IN NO EVENT
 * SHALL M.I.T. BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL,
 * SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT
 * LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF
 * USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND
 * ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY,
 * OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT
 * OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
 * SUCH DAMAGE.
 */

#include <sys/cdefs.h>
__FBSDID("$FreeBSD$");

#include "opt_mpath.h"

#include <sys/param.h>
#include <sys/systm.h>
#include <sys/kernel.h>
#include <sys/sysctl.h>
#include <sys/socket.h>
#include <sys/mbuf.h>

#include <net/if.h>
#include <net/if_var.h>
#include <net/route.h>
#include <net/route/route_var.h>
#include <net/route/nhop.h>
#include <net/route/shared.h>
#include <net/vnet.h>

#include <netinet/in.h>
#include <netinet/in_var.h>
#include <netinet/ip.h>
#include <netinet/ip_icmp.h>
#include <netinet/ip_var.h>

extern int	in_inithead(void **head, int off, u_int fibnum);
#ifdef VIMAGE
extern int	in_detachhead(void **head, int off);
#endif

static int
rib4_preadd(u_int fibnum, const struct sockaddr *addr, const struct sockaddr *mask,
    struct nhop_object *nh)
{
	const struct sockaddr_in *addr4 = (const struct sockaddr_in *)addr;
	uint16_t nh_type;
	int rt_flags;

	/* XXX: RTF_LOCAL && RTF_MULTICAST */

	rt_flags = nhop_get_rtflags(nh);

	if (rt_flags & RTF_HOST) {

		/*
		 * Backward compatibility:
		 * if the destination is broadcast,
		 * mark route as broadcast.
		 * This behavior was useful when route cloning
		 * was in place, so there was an explicit cloned
		 * route for every broadcasted address.
		 * Currently (2020-04) there is no kernel machinery
		 * to do route cloning, though someone might explicitly
		 * add these routes to support some cases with active-active
		 * load balancing. Given that, retain this support.
		 */
		if (in_broadcast(addr4->sin_addr, nh->nh_ifp)) {
			rt_flags |= RTF_BROADCAST;
			nhop_set_rtflags(nh, rt_flags);
			nh->nh_flags |= NHF_BROADCAST;
		}
	}

	/*
	 * Check route MTU:
	 * inherit interface MTU if not set or
	 * check if MTU is too large.
	 */
	if (nh->nh_mtu == 0) {
		nh->nh_mtu = nh->nh_ifp->if_mtu;
	} else if (nh->nh_mtu > nh->nh_ifp->if_mtu)
		nh->nh_mtu = nh->nh_ifp->if_mtu;

	/* Ensure that default route nhop has special flag */
	const struct sockaddr_in *mask4 = (const struct sockaddr_in *)mask;
	if ((rt_flags & RTF_HOST) == 0 && mask4 != NULL &&
	    mask4->sin_addr.s_addr == 0)
		nh->nh_flags |= NHF_DEFAULT;

	/* Set nhop type to basic per-AF nhop */
	if (nhop_get_type(nh) == 0) {
		if (nh->nh_flags & NHF_GATEWAY)
			nh_type = NH_TYPE_IPV4_ETHER_NHOP;
		else
			nh_type = NH_TYPE_IPV4_ETHER_RSLV;

		nhop_set_type(nh, nh_type);
	}

	return (0);
}

static int _in_rt_was_here;
/*
 * Initialize our routing tree.
 */
int
in_inithead(void **head, int off, u_int fibnum)
{
	struct rib_head *rh;

	rh = rt_table_init(32, AF_INET, fibnum);
	if (rh == NULL)
		return (0);

	rh->rnh_preadd = rib4_preadd;
#ifdef	RADIX_MPATH
	rt_mpath_init_rnh(rh);
#endif
	*head = (void *)rh;

	if (_in_rt_was_here == 0 ) {
		_in_rt_was_here = 1;
	}
	return 1;
}

#ifdef VIMAGE
int
in_detachhead(void **head, int off)
{

	rt_table_destroy((struct rib_head *)(*head));
	return (1);
}
#endif

/*
 * This zaps old routes when the interface goes down or interface
 * address is deleted.  In the latter case, it deletes static routes
 * that point to this address.  If we don't do this, we may end up
 * using the old address in the future.  The ones we always want to
 * get rid of are things like ARP entries, since the user might down
 * the interface, walk over to a completely different network, and
 * plug back in.
 */
struct in_ifadown_arg {
	struct ifaddr *ifa;
	int del;
};

static int
in_ifadownkill(const struct rtentry *rt, const struct nhop_object *nh,
    void *xap)
{
	struct in_ifadown_arg *ap = xap;

	if (nh->nh_ifa != ap->ifa)
		return (0);

	if ((nhop_get_rtflags(nh) & RTF_STATIC) != 0 && ap->del == 0)
		return (0);

	return (1);
}

void
in_ifadown(struct ifaddr *ifa, int delete)
{
	struct in_ifadown_arg arg;

	KASSERT(ifa->ifa_addr->sa_family == AF_INET,
	    ("%s: wrong family", __func__));

	arg.ifa = ifa;
	arg.del = delete;

	rt_foreach_fib_walk_del(AF_INET, in_ifadownkill, &arg);
	ifa->ifa_flags &= ~IFA_ROUTE;		/* XXXlocking? */
}

