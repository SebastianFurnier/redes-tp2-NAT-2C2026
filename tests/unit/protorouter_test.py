import logging
import os
import sys
import time
import unittest
from types import SimpleNamespace

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__),
                                               "../..")))

import pox.core

_original_core = pox.core.core
pox.core.core = SimpleNamespace(
    getLogger=lambda: logging.getLogger("protorouter.test"))
try:
    from ext import protorouter
finally:
    pox.core.core = _original_core

from pox.lib.addresses import EthAddr, IPAddr
from pox.lib.packet.ethernet import ethernet
from pox.lib.packet.icmp import echo, icmp
from pox.lib.packet.ipv4 import ipv4
from pox.lib.packet.tcp import tcp


class ProtoRouterNATTest(unittest.TestCase):
    def setUp(self):
        self.router = protorouter.ProtoRouter.__new__(
            protorouter.ProtoRouter)
        self.router.arp_table = {}
        self.router._nat_by_outgoing = {}
        self.router._nat_by_incoming = {}
        self.router._used_ports = set()
        self.sent_packets = []
        self.router._send_packet_out = (
            lambda packet, out_port, in_port=None:
            self.sent_packets.append((packet, out_port)))
        self.router._install_nat_flows = lambda record: None
        self.router._arp_resolve = lambda *args, **kwargs: None

        now = time.time()
        self._learn("200.0.0.1", "00:00:00:00:00:01", 1, now)
        self._learn("192.168.1.2", "00:00:00:00:00:02", 2, now)
        self._learn("192.168.1.3", "00:00:00:00:00:03", 3, now)

    def _learn(self, ip, mac, port, timestamp):
        self.router.arp_table[IPAddr(ip)] = (
            EthAddr(mac), timestamp, port)

    def _frame(self, src_ip, dst_ip, proto, src_port=None, dst_port=None,
               icmp_type=None, echo_id=None, sequence=None):
        frame = ethernet()
        frame.type = ethernet.IP_TYPE
        ip_packet = ipv4()
        ip_packet.protocol = proto
        ip_packet.srcip = IPAddr(src_ip)
        ip_packet.dstip = IPAddr(dst_ip)

        if proto == protorouter.TCP_PROTO:
            transport = tcp()
            transport.srcport = src_port
            transport.dstport = dst_port
        else:
            transport = icmp()
            transport.type = icmp_type
            transport.code = 0
            transport.payload = echo(id=echo_id, seq=sequence)

        ip_packet.payload = transport
        frame.payload = ip_packet
        return ethernet(raw=frame.pack())

    def test_icmp_echo_translation_and_record_expiration(self):
        records = []
        for host, port in (("192.168.1.2", 2), ("192.168.1.3", 3)):
            packet = self._frame(
                host, "200.0.0.1", protorouter.ICMP_PROTO,
                icmp_type=protorouter.ICMP_ECHO_REQUEST,
                echo_id=3023 + port, sequence=1)
            self.router._handle_outgoing(
                SimpleNamespace(port=port), packet, packet.find("ipv4"))
            records.append(next(
                record for record in self.router._nat_by_outgoing.values()
                if record.private_ip == IPAddr(host)))

        self.assertNotEqual(records[0].public_port, records[1].public_port)

        for record in records:
            reply = self._frame(
                "200.0.0.1", str(protorouter.PUBLIC_IP),
                protorouter.ICMP_PROTO,
                icmp_type=protorouter.ICMP_ECHO_REPLY,
                echo_id=record.public_port, sequence=1)
            self.router._handle_incoming(
                SimpleNamespace(port=protorouter.PUBLIC_PORT),
                reply, reply.find("ipv4"))
            self.assertEqual(reply.find("icmp").payload.id,
                             record.private_port)
            self.assertEqual(reply.find("ipv4").dstip, record.private_ip)

        expired = records[0]
        expired._expires_at = time.time() - 1
        self.router._expire_tables()
        self.assertNotIn(expired.outgoing_key(),
                         self.router._nat_by_outgoing)
        self.assertNotIn(expired.incoming_key(),
                         self.router._nat_by_incoming)
        self.assertNotIn((expired.proto, expired.public_port),
                         self.router._used_ports)

    def test_tcp_clients_get_distinct_mappings_and_replies(self):
        clients = (
            ("192.168.1.2", 2, 54892),
            ("192.168.1.3", 3, 39556),
        )
        records = []
        for host, port, source_port in clients:
            packet = self._frame(
                host, "200.0.0.1", protorouter.TCP_PROTO,
                src_port=source_port, dst_port=9000)
            self.router._handle_outgoing(
                SimpleNamespace(port=port), packet, packet.find("ipv4"))
            record = next(
                record for record in self.router._nat_by_outgoing.values()
                if record.private_ip == IPAddr(host))
            records.append(record)
            self.assertEqual(packet.find("ipv4").srcip,
                             protorouter.PUBLIC_IP)
            self.assertEqual(packet.find("tcp").srcport,
                             record.public_port)

        self.assertEqual([record.public_port for record in records],
                         [54892, 39556])

        for record in records:
            reply = self._frame(
                "200.0.0.1", str(protorouter.PUBLIC_IP),
                protorouter.TCP_PROTO, src_port=9000,
                dst_port=record.public_port)
            self.router._handle_incoming(
                SimpleNamespace(port=protorouter.PUBLIC_PORT),
                reply, reply.find("ipv4"))
            self.assertEqual(reply.find("ipv4").dstip, record.private_ip)
            self.assertEqual(reply.find("tcp").dstport,
                             record.private_port)

    def test_arp_lookup_uses_mac_timestamp_and_port_entry(self):
        ip = IPAddr("200.0.0.1")
        mac = EthAddr("00:00:00:00:00:01")
        self.assertEqual(self.router._arp_lookup(ip), mac)
        self.assertEqual(self.router._arp_port(ip), 1)

        self._learn(ip, str(mac), 1,
                    time.time() - protorouter.ARP_ENTRY_TIMEOUT - 1)
        self.assertIsNone(self.router._arp_lookup(ip))
        self.assertNotIn(ip, self.router.arp_table)


if __name__ == "__main__":
    unittest.main()
