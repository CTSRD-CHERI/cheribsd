# $FreeBSD$

. $(atf_get_srcdir)/utils.subr

atf_test_case "v6" "cleanup"
v6_head()
{
	atf_set descr 'IPv6 fragmentation test'
	atf_set require.user root
	atf_set require.progs scapy
}

v6_body()
{
	pft_init

	epair_send=$(pft_mkepair)
	epair_link=$(pft_mkepair)

	pft_mkjail alcatraz ${epair_send}b ${epair_link}a
	pft_mkjail singsing ${epair_link}b

	ifconfig ${epair_send}a inet6 2001:db8:42::1/64 no_dad up

	jexec alcatraz ifconfig ${epair_send}b inet6 2001:db8:42::2/64 no_dad up
	jexec alcatraz ifconfig ${epair_link}a inet6 2001:db8:43::2/64 no_dad up
	jexec alcatraz sysctl net.inet6.ip6.forwarding=1

	jexec singsing ifconfig ${epair_link}b inet6 2001:db8:43::3/64 no_dad up
	jexec singsing route add -6 2001:db8:42::/64 2001:db8:43::2
	route add -6 2001:db8:43::/64 2001:db8:42::2

	jexec alcatraz ifconfig ${epair_send}b inet6 -ifdisabled
	jexec alcatraz ifconfig ${epair_link}a inet6 -ifdisabled
	jexec singsing ifconfig ${epair_link}b inet6 -ifdisabled
	ifconfig ${epair_send}a inet6 -ifdisabled

	jexec alcatraz pfctl -e
	pft_set_rules alcatraz \
		"scrub fragment reassemble" \
		"block in" \
		"pass in inet6 proto icmp6 icmp6-type { neighbrsol, neighbradv }" \
		"pass in inet6 proto icmp6 icmp6-type { echoreq, echorep }"

	# Host test
	atf_check -s exit:0 -o ignore \
		ping6 -c 1 2001:db8:42::2

	atf_check -s exit:0 -o ignore \
		ping6 -c 1 -s 4500 2001:db8:42::2

	atf_check -s exit:0 -o ignore\
		ping6 -c 1 -b 70000 -s 65000 2001:db8:42::2

	# Forwarding test
	atf_check -s exit:0 -o ignore \
		ping6 -c 1 2001:db8:43::3

	atf_check -s exit:0 -o ignore \
		ping6 -c 1 -s 4500 2001:db8:43::3

	atf_check -s exit:0 -o ignore\
		ping6 -c 1 -b 70000 -s 65000 2001:db8:43::3
}

v6_cleanup()
{
	pft_cleanup
}

atf_init_test_cases()
{
	atf_add_test_case "v6"
}
