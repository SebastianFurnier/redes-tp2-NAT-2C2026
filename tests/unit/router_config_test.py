import os
import sys
import time
import unittest
from types import SimpleNamespace
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "../..")))

from tests.unit import protorouter_test as base

import pox.openflow.libopenflow_01 as of
from pox.lib.addresses import EthAddr, IPAddr

protorouter = base.protorouter
from ext.router_config import ConfigError, RouterConfig
from ext.arp_table import ArpTable
from ext.nat_table import NatTable

TCP, UDP, ICMP = (protorouter.TCP_PROTO, protorouter.UDP_PROTO, protorouter.ICMP_PROTO)
IDLE, HARD = of.OFPRR_IDLE_TIMEOUT, of.OFPRR_HARD_TIMEOUT

class RouterConfigTest(unittest.TestCase):
    def test_defaults_match_the_provided_topology(self):
        cfg = RouterConfig()
        self.assertEqual(cfg.public_ip, IPAddr("200.0.0.254"))
        self.assertEqual(cfg.public_mac, EthAddr("00:00:00:aa:aa:aa"))
        self.assertEqual(cfg.private_ip, IPAddr("192.168.1.254"))
        self.assertEqual(cfg.private_mac, EthAddr("00:00:00:bb:bb:bb"))
        self.assertEqual((cfg.private_subnet, cfg.private_mask), (IPAddr("192.168.1.0"), 24))
        self.assertEqual(cfg.public_port, 1)
        self.assertEqual((cfg.port_min, cfg.port_max), (10000, 65535))
        self.assertEqual((cfg.flow_idle_timeout, cfg.flow_hard_timeout), (10, 60))

    def test_values_coming_as_strings_from_the_command_line(self):
        cfg = RouterConfig(public_ip="10.0.0.254", public_subnet="10.0.0.0/24",
                           private_ip="172.16.0.254",
                           private_subnet="172.16.0.0/16", public_port="3",
                           port_min="2000", port_max="3000",
                           flow_idle_timeout="5", flow_hard_timeout="30")
        self.assertEqual(cfg.public_ip, IPAddr("10.0.0.254"))
        self.assertEqual(cfg.private_mask, 16)
        self.assertEqual(cfg.public_port, 3)
        self.assertEqual((cfg.port_min, cfg.port_max), (2000, 3000))
        self.assertEqual(cfg.flow_idle_timeout, 5)

    def test_invalid_values_are_rejected_with_a_clear_message(self):
        invalid = [
            ("public_ip", "200.0.0.300", "public_ip"),
            ("public_mac", "00:00:00:aa:aa", "public_mac"),
            ("private_subnet", "192.168.1.0", "private_subnet"),  # sin máscara
            ("public_ip", "201.0.0.254", "no pertenece"),
            ("private_ip", "10.1.1.1", "no pertenece"),
            ("private_subnet", "200.0.0.0/16", "superponen"),  # + private_ip
            ("private_mac", "00:00:00:aa:aa:aa", "iguales"),
            ("port_min", "70000", "port_min"),
            ("port_min", "20000", "mayor"),                # + port_max chico
            ("flow_idle_timeout", "-1", "flow_idle_timeout"),
            ("flow_hard_timeout", "70000", "flow_hard_timeout"),
            ("public_port", True, "falta el valor"),
            ("pending_timeout", "abc", "entero"),
        ]
        for name, value, fragment in invalid:
            kwargs = {name: value}
            if name == "port_min" and value == "20000":
                kwargs["port_max"] = 100
            if name == "private_subnet" and value == "200.0.0.0/16":
                kwargs["private_ip"] = "200.0.1.254"
            with self.assertRaises(ConfigError, msg="%s=%r" % (name, value)) \
                    as ctx:
                RouterConfig(**kwargs)
            self.assertIn(fragment, str(ctx.exception))

    def test_nat_table_uses_the_configured_port_range(self):
        table = NatTable(port_min=2000, port_max=2001)
        a = table.add(TCP, IPAddr("192.168.1.2"), 5000, IPAddr("200.0.0.1"), 80)
        b = table.add(TCP, IPAddr("192.168.1.3"), 5000, IPAddr("200.0.0.1"), 80)
        self.assertEqual(sorted([a.public_port, b.public_port]), [2000, 2001])
        # Rango lleno: no hay más puertos
        self.assertIsNone(table.add(TCP, IPAddr("192.168.1.4"), 5000, IPAddr("200.0.0.1"), 80))
        table.release(a)
        self.assertIsNotNone(table.add(TCP, IPAddr("192.168.1.4"), 5000, IPAddr("200.0.0.1"), 80))

    def test_arp_table_uses_the_configured_timeout(self):
        table = ArpTable(timeout=2)
        table.learn(IPAddr("200.0.0.1"), EthAddr("00:00:00:00:00:01"), 1)
        self.assertIsNotNone(table.lookup(IPAddr("200.0.0.1")))
        table.entries[IPAddr("200.0.0.1")].timestamp = time.time() - 3
        self.assertIsNone(table.lookup(IPAddr("200.0.0.1")))

class _RouterTestCase(unittest.TestCase):
    """Router con reglas reales, ARP precargada y envío de paquetes capturado."""

    CONFIG = None

    def setUp(self):
        self.router = base.make_router()
        if self.CONFIG is not None:
            self.router.config = self.CONFIG
            self.router.arp_table = ArpTable(self.CONFIG.arp_timeout)
            self.router.nat_table = NatTable(self.CONFIG.port_min,
                                             self.CONFIG.port_max)
        self.sent = []
        self.router._send_packet_out = (
            lambda packet, out_port: self.sent.append((packet, out_port)))
        self.cfg = self.router.config

    def learn(self, ip, mac, port):
        self.router.arp_table.learn(IPAddr(ip), EthAddr(mac), port)

    def send(self, src, dst, proto, in_port, **kwargs):
        frame = base._build_frame(src, dst, proto, **kwargs)
        self.router.handle_ip(SimpleNamespace(parsed=frame, port=in_port,
                                              ofp=frame.pack()))

    def flows(self):
        return self.router.connection.flow_mods()

    def expire(self, flow, reason):
        """El switch avisa que `flow` venció."""
        self.router._handle_FlowRemoved(
            SimpleNamespace(ofp=SimpleNamespace(match=flow.match, reason=reason)))


class ConfiguredRouterTest(_RouterTestCase):
    CONFIG = RouterConfig(public_ip="10.0.0.254", public_mac="02:00:00:00:0a:01",
                          public_subnet="10.0.0.0/24", public_port=4,
                          private_ip="172.16.0.254",
                          private_mac="02:00:00:00:0b:01",
                          private_subnet="172.16.0.0/16",
                          flow_idle_timeout=3, flow_hard_timeout=9)

    def setUp(self):
        super(ConfiguredRouterTest, self).setUp()
        self.learn("10.0.0.1", "00:00:00:00:00:01", 4)
        self.learn("172.16.5.7", "00:00:00:00:00:07", 2)

    def test_classification_follows_the_configured_networks(self):
        classify = self.router.classify_packet
        self.assertEqual(classify(IPAddr("172.16.5.7"), IPAddr("10.0.0.1")), protorouter.DIRECTION_OUTGOING)
        self.assertEqual(classify(IPAddr("10.0.0.1"), IPAddr("10.0.0.254")), protorouter.DIRECTION_INCOMING)
        self.assertEqual(classify(IPAddr("192.168.1.2"), IPAddr("200.0.0.1")), protorouter.DIRECTION_OTHER)

    def test_flows_use_configured_addresses_port_and_timeouts(self):
        self.send("172.16.5.7", "10.0.0.1", TCP, 2, src_port=4000, dst_port=80)
        out_flow, in_flow = self.flows()
        self.assertEqual((out_flow.idle_timeout, out_flow.hard_timeout), (3, 9))
        self.assertEqual((in_flow.idle_timeout, in_flow.hard_timeout), (3, 9))
        self.assertEqual(out_flow.actions[0].nw_addr, IPAddr("10.0.0.254"))
        self.assertEqual(out_flow.actions[2].dl_addr, EthAddr("02:00:00:00:0a:01"))
        self.assertEqual(out_flow.actions[-1].port, 4)
        self.assertEqual(in_flow.match.in_port, 4)
        self.assertEqual(in_flow.match.nw_dst, IPAddr("10.0.0.254"))
        self.assertEqual(in_flow.actions[2].dl_addr, EthAddr("02:00:00:00:0b:01"))

    def test_default_config_of_another_router_is_not_modified(self):
        self.assertEqual(protorouter.ProtoRouter.config.public_ip, IPAddr("200.0.0.254"))

class FlowExpiryTest(_RouterTestCase):
    def setUp(self):
        super(FlowExpiryTest, self).setUp()
        self.learn("200.0.0.1", "00:00:00:00:00:01", 1)
        self.learn("192.168.1.2", "00:00:00:00:00:02", 2)
        self.learn("192.168.1.3", "00:00:00:00:00:03", 3)

    def connect(self, host="192.168.1.2", port=2, src_port=4321):
        self.send(host, "200.0.0.1", TCP, port, src_port=src_port, dst_port=80)
        return self.router.nat_table.lookup_outgoing(
            TCP, IPAddr(host), src_port, IPAddr("200.0.0.1"), 80)

    def test_idle_expiry_of_both_rules_releases_the_public_port(self):
        record = self.connect()
        out_flow, in_flow = self.flows()
        self.assertEqual(record.flows_alive, 2)

        self.expire(out_flow, IDLE)
        self.assertIn(record, self.router.nat_table.outgoing.values())
        self.expire(in_flow, IDLE)

        self.assertEqual(self.router.nat_table.outgoing, {})
        self.assertEqual(self.router.nat_table.incoming, {})
        self.assertTrue(self.router.nat_table.is_free(TCP, record.public_port))

    def test_one_live_rule_keeps_the_connection(self):
        """Un stream que solo va en un sentido no pierde su puerto."""
        record = self.connect()
        out_flow, _in_flow = self.flows()
        self.expire(out_flow, IDLE)
        self.assertIn(record, self.router.nat_table.outgoing.values())
        self.assertFalse(record.flows_installed)

    def test_traffic_after_a_single_expired_rule_reinstalls_both(self):
        record = self.connect()
        out_flow, _in_flow = self.flows()
        self.expire(out_flow, IDLE)
        self.connect()                       # el siguiente paquete saliente
        self.assertEqual(len(self.flows()), 4)
        self.assertTrue(record.flows_installed)
        self.assertEqual(record.flows_alive, 2)

    def test_traffic_after_full_idle_expiry_creates_the_record_again(self):
        record = self.connect()
        first_port = record.public_port
        for flow in self.flows():
            self.expire(flow, IDLE)
        self.assertEqual(self.router.nat_table.outgoing, {})

        again = self.connect()
        self.assertEqual(len(self.flows()), 4)
        self.assertTrue(again.flows_installed)
        self.assertEqual(again.public_port, first_port)

    def test_hard_timeout_reinstalls_the_rules_and_keeps_the_record(self):
        record = self.connect()
        for flow in self.flows():
            self.expire(flow, HARD)
        self.assertIn(record, self.router.nat_table.outgoing.values())
        self.assertEqual(len(self.flows()), 4)
        self.assertTrue(record.flows_installed)
        self.assertEqual(record.flows_alive, 2)

    def test_hard_timeout_without_arp_leaves_a_cold_record(self):
        record = self.connect()
        for flow in self.flows():
            # El ARP del servidor venció mientras tanto
            self.router.arp_table.entries.pop(IPAddr("200.0.0.1"), None)
            self.expire(flow, HARD)
        self.assertFalse(record.flows_installed)
        self.assertIsNotNone(record.cold_since)
        self.assertEqual(len(self.flows()), 2)      # no se pudo reinstalar

    def test_cold_records_are_released_after_the_grace_period(self):
        record = self.connect()
        record.flows_installed = False
        record.cold_since = time.time() - 1
        self.router.clean_cold_records()             # todavía en gracia
        self.assertIn(record, self.router.nat_table.outgoing.values())

        record.cold_since = time.time() - self.cfg.flow_idle_timeout - 1
        self.router.clean_cold_records()
        self.assertEqual(self.router.nat_table.outgoing, {})

    def test_connection_without_arp_never_installs_and_is_cleaned(self):
        self.router.arp_table.entries.pop(IPAddr("200.0.0.1"))
        record = self.connect()
        self.assertEqual(self.flows(), [])
        self.assertIsNotNone(record.cold_since)
        record.cold_since -= self.cfg.flow_idle_timeout + 1
        self.router.clean_cold_records()
        self.assertEqual(self.router.nat_table.outgoing, {})

    def test_removal_requested_by_the_controller_is_ignored(self):
        record = self.connect()
        for flow in self.flows():
            self.expire(flow, of.OFPRR_DELETE)
        self.assertIn(record, self.router.nat_table.outgoing.values())
        self.assertTrue(record.flows_installed)

    def test_removal_of_an_unknown_rule_is_ignored(self):
        record = self.connect()
        out_flow, in_flow = self.flows()
        for flow in (out_flow, in_flow):
            self.expire(flow, IDLE)
        # Un aviso duplicado o tardío no rompe nada ni libera de más
        other = self.connect("192.168.1.3", port=3, src_port=7777)
        self.expire(out_flow, IDLE)
        self.assertIn(other, self.router.nat_table.outgoing.values())
        self.assertTrue(other.flows_installed)
        self.assertEqual(other.flows_alive, 2)

    def test_connections_expire_independently(self):
        a = self.connect("192.168.1.2", port=2, src_port=4000)
        b = self.connect("192.168.1.3", port=3, src_port=5000)
        a_out, a_in, _b_out, _b_in = self.flows()
        self.expire(a_out, IDLE)
        self.expire(a_in, IDLE)
        self.assertNotIn(a, self.router.nat_table.outgoing.values())
        self.assertIn(b, self.router.nat_table.outgoing.values())
        self.assertEqual(b.flows_alive, 2)

    def test_ping_rules_expire_and_release_the_record(self):
        self.send("192.168.1.2", "200.0.0.1", ICMP, 2,
                  icmp_type=protorouter.ICMP_ECHO_REQUEST, echo_id=77,
                  sequence=1)
        record = next(iter(self.router.nat_table.outgoing.values()))
        for flow in self.flows():
            self.expire(flow, IDLE)
        self.assertNotIn(record, self.router.nat_table.outgoing.values())
        self.assertEqual(self.router.nat_table.incoming, {})

    def test_udp_expiry_frees_port_for_reuse_by_another_host(self):
        # h2 y h3 usan el mismo puerto origen: h3 recibe otro puerto público
        a = self.connect("192.168.1.2", port=2, src_port=5555)
        self.send("192.168.1.3", "200.0.0.1", UDP, 3, src_port=5555,
                  dst_port=80)
        outgoing = self.router.nat_table.outgoing
        self.assertEqual(len(outgoing), 2)
        for flow in self.flows()[:2]:
            self.expire(flow, IDLE)
        self.assertNotIn(a, outgoing.values())
        self.assertTrue(self.router.nat_table.is_free(TCP, a.public_port))

if __name__ == "__main__":
    unittest.main()