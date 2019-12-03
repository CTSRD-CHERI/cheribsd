#!/usr/bin/env python
#
# SPDX-License-Identifier: BSD-2-Clause
#
# Copyright (c) 2017 Kristof Provost <kp@FreeBSD.org>
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
#

import argparse
import scapy.all as sp
import sys
from sniffer import Sniffer

PAYLOAD_MAGIC = bytes.fromhex('42c0ffee')

def check_ping_request(args, packet):
	if args.ip6:
		return check_ping6_request(args, packet)
	else:
		return check_ping4_request(args, packet)

def check_ping4_request(args, packet):
	"""
	Verify that the packet matches what we'd have sent
	"""
	dst_ip = args.to[0]

	ip = packet.getlayer(sp.IP)
	if not ip:
		return False
	if ip.dst != dst_ip:
		return False

	icmp = packet.getlayer(sp.ICMP)
	if not icmp:
		return False
	if sp.icmptypes[icmp.type] != 'echo-request':
		return False

	raw = packet.getlayer(sp.Raw)
	if not raw:
		return False
	if raw.load != PAYLOAD_MAGIC:
		return False

	# Wait to check expectations until we've established this is the packet we
	# sent.
	if args.expect_tos:
		if ip.tos != int(args.expect_tos[0]):
			print("Unexpected ToS value %d, expected %d" \
				% (ip.tos, int(args.expect_tos[0])))
			return False

	return True

def check_ping6_request(args, packet):
	"""
	Verify that the packet matches what we'd have sent
	"""
	dst_ip = args.to[0]

	ip = packet.getlayer(sp.IPv6)
	if not ip:
		return False
	if ip.dst != dst_ip:
		return False

	icmp = packet.getlayer(sp.ICMPv6EchoRequest)
	if not icmp:
		return False
	if icmp.data != PAYLOAD_MAGIC:
		return False

	return True

def ping(send_if, dst_ip, args):
	ether = sp.Ether()
	ip = sp.IP(dst=dst_ip)
	icmp = sp.ICMP(type='echo-request')
	raw = sp.raw(PAYLOAD_MAGIC)

	if args.send_tos:
		ip.tos = int(args.send_tos[0])

	req = ether / ip / icmp / raw
	sp.sendp(req, iface=send_if, verbose=False)

def ping6(send_if, dst_ip, args):
	ether = sp.Ether()
	ip6 = sp.IPv6(dst=dst_ip)
	icmp = sp.ICMPv6EchoRequest(data=sp.raw(PAYLOAD_MAGIC))

	req = ether / ip6 / icmp
	sp.sendp(req, iface=send_if, verbose=False)

def main():
	parser = argparse.ArgumentParser("pft_ping.py",
		description="Ping test tool")
	parser.add_argument('--sendif', nargs=1,
		required=True,
		help='The interface through which the packet(s) will be sent')
	parser.add_argument('--recvif', nargs=1,
		help='The interface on which to expect the ICMP echo response')
	parser.add_argument('--ip6', action='store_true',
		help='Use IPv6')
	parser.add_argument('--to', nargs=1,
		required=True,
		help='The destination IP address for the ICMP echo request')

	# Packet settings
	parser.add_argument('--send-tos', nargs=1,
		help='Set the ToS value for the transmitted packet')

	# Expectations
	parser.add_argument('--expect-tos', nargs=1,
		help='The expected ToS value in the received packet')

	args = parser.parse_args()

	# We may not have a default route. Tell scapy where to start looking for routes
	sp.conf.iface6 = args.sendif[0]

	sniffer = None
	if not args.recvif is None:
		sniffer = Sniffer(args, check_ping_request)

	if args.ip6:
		ping6(args.sendif[0], args.to[0], args)
	else:
		ping(args.sendif[0], args.to[0], args)

	if sniffer:
		sniffer.join()

		if sniffer.foundCorrectPacket:
			sys.exit(0)
		else:
			sys.exit(1)

if __name__ == '__main__':
	main()
