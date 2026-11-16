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


if __name__ == "__main__":
    unittest.main()