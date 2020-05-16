# $FreeBSD$
#
# SPDX-License-Identifier: BSD-2-Clause-FreeBSD
#
# Copyright (c) 2020 Mark Johnston <markj@FreeBSD.org>
#
# Redistribution and use in source and binary forms, with or without
# modification, are permitted provided that the following conditions
# are met:
# 1. Redistributions of source code must retain the above copyright
#    notice, this list of conditions and the following disclaimer.
# 2. Redistributions in binary form must reproduce the above copyright
#    notice, this list of conditions and the following disclaimer in the
#    documentation and/or other materials provided with the distribution.
#
# THIS SOFTWARE IS PROVIDED BY THE AUTHOR AND CONTRIBUTORS ``AS IS'' AND
# ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
# IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
# ARE DISCLAIMED.  IN NO EVENT SHALL THE AUTHOR OR CONTRIBUTORS BE LIABLE
# FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
# DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS
# OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
# HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
# LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY
# OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
# SUCH DAMAGE.

. $(atf_get_srcdir)/utils.subr

TABLE_STATS_ZERO_REGEXP='Packets: 0[[:space:]]*Bytes: 0[[:space:]]'
TABLE_STATS_NONZERO_REGEXP='Packets: [1-9][0-9]*[[:space:]]*Bytes: [1-9][0-9]*[[:space:]]'

atf_test_case "v4_counters" "cleanup"
v4_counters_head()
{
	atf_set descr 'Verify per-address counters for v4'
	atf_set require.user root
}

v4_counters_body()
{
	pft_init

	epair_send=$(vnet_mkepair)
	ifconfig ${epair_send}a 192.0.2.1/24 up

	vnet_mkjail alcatraz ${epair_send}b
	jexec alcatraz ifconfig ${epair_send}b 192.0.2.2/24 up
	jexec alcatraz pfctl -e

	pft_set_rules alcatraz \
	    "table <foo> counters { 192.0.2.1 }" \
	    "block all" \
	    "pass in from <foo> to any" \
	    "pass out from any to <foo>"

	atf_check -s exit:0 -o ignore ping -c 3 192.0.2.2

	atf_check -s exit:0 -e ignore \
	    -o match:'In/Block:.*'"$TABLE_STATS_ZERO_REGEXP" \
	    -o match:'In/Pass:.*'"$TABLE_STATS_NONZERO_REGEXP" \
	    -o match:'Out/Block:.*'"$TABLE_STATS_ZERO_REGEXP" \
	    -o match:'Out/Pass:.*'"$TABLE_STATS_NONZERO_REGEXP" \
	    jexec alcatraz pfctl -t foo -T show -vv
}

v4_counters_cleanup()
{
	pft_cleanup
}

atf_test_case "v6_counters" "cleanup"
v6_counters_head()
{
	atf_set descr 'Verify per-address counters for v6'
	atf_set require.user root
}

v6_counters_body()
{
	pft_init

	epair_send=$(vnet_mkepair)
	ifconfig ${epair_send}a inet6 2001:db8:42::1/64 up no_dad -ifdisabled

	vnet_mkjail alcatraz ${epair_send}b
	jexec alcatraz ifconfig ${epair_send}b inet6 2001:db8:42::2/64 up no_dad
	jexec alcatraz pfctl -e

	pft_set_rules alcatraz \
	    "table <foo6> counters { 2001:db8:42::1 }" \
	    "block all" \
	    "pass in from <foo6> to any" \
	    "pass out from any to <foo6>"

	atf_check -s exit:0 -o ignore ping6 -c 3 2001:db8:42::2

	atf_check -s exit:0 -e ignore \
	    -o match:'In/Block:.*'"$TABLE_STATS_ZERO_REGEXP" \
	    -o match:'In/Pass:.*'"$TABLE_STATS_NONZERO_REGEXP" \
	    -o match:'Out/Block:.*'"$TABLE_STATS_ZERO_REGEXP" \
	    -o match:'Out/Pass:.*'"$TABLE_STATS_NONZERO_REGEXP" \
	    jexec alcatraz pfctl -t foo6 -T show -vv
}

v6_counters_cleanup()
{
	pft_cleanup
}

atf_init_test_cases()
{
	atf_add_test_case "v4_counters"
	atf_add_test_case "v6_counters"
}
