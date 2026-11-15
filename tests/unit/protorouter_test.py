import logging
import os
import sys
import time
import unittest
from types import SimpleNamespace

log = logging.getLogger("protorouter.test")
log.setLevel(logging.INFO)
if not log.handlers:
    _stream = sys.stderr
    try:
        _stream.reconfigure(encoding="utf-8", errors="replace")
    except (AttributeError, ValueError):
        pass
    _handler = logging.StreamHandler(_stream)
    _handler.setFormatter(logging.Formatter("    | %(message)s"))
    log.addHandler(_handler)
    log.propagate = False

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__),
                                               "../..")))

import pox.core


class _QuietLogger(logging.Logger):
    """Logger del controlador: descarta sus mensajes (sólo interesa la traza)."""

    def handle(self, record):
        pass


_original_core = pox.core.core
pox.core.core = SimpleNamespace(getLogger=lambda: _QuietLogger("protorouter"))
try:
    from ext import protorouter
finally:
    pox.core.core = _original_core

import pox.openflow.libopenflow_01 as of
from pox.lib.addresses import EthAddr, IPAddr
from pox.lib.packet.ethernet import ethernet
from pox.lib.packet.icmp import echo, icmp
from pox.lib.packet.ipv4 import ipv4
from pox.lib.packet.tcp import tcp
from pox.lib.packet.udp import udp

try:
    from arp_table import ARP_TIMEOUT, ArpTable
except ImportError:
    from ext.arp_table import ARP_TIMEOUT, ArpTable


class FakeConnection(object):
    """Registra todo lo que el router manda al switch."""

    def __init__(self):
        self.messages = []

    def addListeners(self, listener):
        pass

    def send(self, msg):
        self.messages.append(msg)

    def flow_mods(self):
        return [m for m in self.messages if isinstance(m, of.ofp_flow_mod)]

    def packet_outs(self):
        return [m for m in self.messages
                if isinstance(m, of.ofp_packet_out)]


def make_router():
    """Crea un router sin timers ni listeners (todo mockeado)."""
    router = protorouter.ProtoRouter.__new__(protorouter.ProtoRouter)
    router.connection = FakeConnection()
    router.arp_table = ArpTable()
    router._nat_by_outgoing = {}
    router._nat_by_incoming = {}
    router._used_ports = set()
    router.pending = {}
    router.pending_time = {}
    # No queremos que los tests disparen ARP al aire
    router.send_arp_request = lambda *args, **kwargs: None
    return router


# Nombre de cada prueba tal como se muestra en el log de ejecución.
# Una prueba sin entrada acá se muestra con su nombre de método.
TEST_DESCRIPTIONS = {
    # -- Clasificación de paquetes --
    "test_private_to_public_is_outgoing":
        "Clasificación: privado -> público es SALIENTE",
    "test_public_to_public_ip_is_incoming":
        "Clasificación: público -> IP pública es ENTRANTE",
    "test_private_to_private_is_dropped":
        "Clasificación: privado -> privado se DESCARTA (es 'otro')",
    "test_public_to_other_ip_is_dropped":
        "Clasificación: público -> otra IP pública se DESCARTA",
    "test_other_traffic_does_not_install_flows":
        "Clasificación: el tráfico descartado no instala reglas ni crea "
        "registros",
    "test_non_ip_non_arp_frame_is_ignored":
        "Clasificación: una trama que no es IP ni ARP se ignora",
    # -- Traducción saliente --
    # (los docstrings de las pruebas tienen prioridad sobre esta tabla)
    "test_udp_hardcoded_packet_translation":
        "Saliente UDP: 192.168.1.3:5555 -> 200.0.0.1:53 se traduce "
        "(IP y puerto origen)",
    "test_ping_only_changes_ip":
        "Saliente ping: sólo se cambia la IP (el id de echo no cambia)",
    "test_same_connection_reuses_record":
        "Saliente: los 3 paquetes de una conexión reusan el mismo registro y "
        "puerto público",
    "test_arp_pending_does_not_send_untranslated_packet":
        "Saliente: sin MAC destino el paquete queda encolado (no se envía "
        "sin traducir)",
    # -- Traducción entrante --
    "test_tcp_reply_is_translated_back":
        "Entrante TCP: la respuesta restaura IP y puerto destino originales",
    "test_udp_reply_is_translated_back":
        "Entrante UDP: la respuesta restaura IP y puerto destino originales",
    "test_ping_reply_keeps_echo_id_and_restores_ip":
        "Entrante ping: conserva el id de echo y restaura la IP privada",
    "test_unknown_incoming_is_dropped":
        "Entrante: un paquete sin registro NAT se DESCARTA",
    "test_icmp_echo_reply_without_record_is_dropped":
        "Entrante: un echo reply sin registro NAT se DESCARTA",
    # -- Reglas en el switch --
    "test_tcp_installs_two_flow_mods":
        "Reglas TCP: se instalan las dos reglas (ida y vuelta) con sus "
        "acciones",
    "test_udp_installs_two_flow_mods":
        "Reglas UDP: se instalan las dos reglas (ida y vuelta) con sus "
        "acciones",
    "test_ping_installs_two_flow_mods_by_type":
        "Reglas ping: las dos reglas se matchean por tipo de ICMP (sin "
        "acciones de puerto)",
    "test_flows_installed_only_once":
        "Reglas: el segundo paquete de la conexión no reinstala los flujos",
    "test_first_packet_is_sent_translated":
        "Primer paquete: se reenvía ya traducido por el puerto público",
    "test_raw_first_packet_is_forwarded_translated":
        "Primer paquete: la trama cruda del PacketIn sale traducida",
    # -- Tabla NAT y ARP --
    "test_record_is_registered_in_both_directions":
        "Tabla NAT: el registro se indexa en los dos sentidos",
    "test_keys":
        "Tabla NAT: claves de ida y de vuelta del NATRecord",
    "test_arp_lookup_uses_mac_timestamp_and_port_entry":
        "ARP: la tabla devuelve MAC, puerto y expira por timestamp",
}


def _description(instance):
    """Descripción legible de una prueba de la clase indicada."""
    method = getattr(instance, instance._testMethodName, None)
    if method is not None and method.__doc__:
        return method.__doc__.strip().splitlines()[0]
    return TEST_DESCRIPTIONS.get(instance._testMethodName,
                                 instance._testMethodName)


class _LoggedTestCase(unittest.TestCase):
    """Muestra en el log qué prueba se está ejecutando y con qué resultado."""

    def run(self, result=None):
        name = self._testMethodName
        log.info("")
        log.info("=" * 70)
        log.info("PRUEBA: %s", name)
        log.info("  %s", _description(self))
        log.info("-" * 70)
        try:
            super(_LoggedTestCase, self).run(result)
        finally:
            if result is not None:
                failed = (result.failures + result.errors)
                was_failure = any(test is self for test, _ in failed)
                skipped = any(test is self for test, _ in result.skipped)
            else:
                was_failure = skipped = False
            outcome = ("FALLO" if was_failure
                       else "OMITIDA" if skipped else "OK")
            log.info("RESULTADO: %s", outcome)


class ProtoRouterNATTest(_LoggedTestCase):
    def setUp(self):
        self.router = make_router()
        self.router.arp_table = ArpTable()
        self.router._nat_by_outgoing = {}
        self.router._nat_by_incoming = {}
        self.router._used_ports = set()
        self.sent_packets = []
        self.router._send_packet_out = (
            lambda packet, out_port:
            self.sent_packets.append((packet, out_port)))
        # Por defecto no instalamos reglas reales (cada test lo activa)
        self.router.install_nat_flows = lambda record: None

        now = time.time()
        # Estado inicial compartido: servidor (puerto 1), h2 (puerto 2) y
        # h3 (puerto 3) ya conocidos por ARP.
        self._learn("200.0.0.1", "00:00:00:00:00:01", 1, now)
        self._learn("192.168.1.2", "00:00:00:00:00:02", 2, now)
        self._learn("192.168.1.3", "00:00:00:00:00:03", 3, now)
        log.info("ARP precargada: 200.0.0.1->1  192.168.1.2->2  192.168.1.3->3")

    def _learn(self, ip, mac, port, timestamp):
        """Carga una entrada ARP con un timestamp a medida."""
        self.router.arp_table.learn(IPAddr(ip), EthAddr(mac), port)
        self.router.arp_table.entries[IPAddr(ip)].timestamp = timestamp

    def _frame(self, src_ip, dst_ip, proto, **kwargs):
        return _build_frame(src_ip, dst_ip, proto, **kwargs)

    def _event(self, packet, in_port=2):
        return SimpleNamespace(parsed=packet, port=in_port,
                               ofp=packet.pack())

    def _send(self, packet, in_port):
        """Entrega un paquete al controlador y deja traza de lo que hizo."""
        flows_before = len(self.router.connection.flow_mods())
        sent_before = len(self.sent_packets)

        log.info("  PACKET_IN  %s  [in_port=%s]", _describe(packet), in_port)
        event = self._event(packet, in_port)
        self.router.handle_ip(event)

        new_flows = self.router.connection.flow_mods()[flows_before:]
        for flow in new_flows:
            log.info("  REGLA      %s", _describe_flow(flow))

        for frame, out_port in self.sent_packets[sent_before:]:
            log.info("  PACKET_OUT %s  [out_port=%s]",
                     _describe(frame), out_port)

        if len(self.router.connection.flow_mods()) == flows_before \
                and len(self.sent_packets) == sent_before:
            log.info("  DESCARTADO: no se envió nada al switch")
        return event

    def _outgoing(self, src_ip, dst_ip, proto, in_port, **kwargs):
        """Simula un paquete saliente que llegó al controlador."""
        packet = self._frame(src_ip, dst_ip, proto, **kwargs)
        return packet, self._send(packet, in_port)

    def _incoming(self, src_ip, dst_ip, proto, **kwargs):
        packet = self._frame(src_ip, dst_ip, proto, **kwargs)
        return packet, self._send(packet, protorouter.PUBLIC_PORT)


def _describe(frame):
    """Resumen legible de una trama: IPs, puerto o id de echo."""
    ip_pkt = frame.find("ipv4")
    if ip_pkt is None:
        return "(trama sin IPv4)"
    text = "%s -> %s" % (ip_pkt.srcip, ip_pkt.dstip)
    tcp_pkt = frame.find("tcp")
    udp_pkt = frame.find("udp")
    icmp_pkt = frame.find("icmp")
    if tcp_pkt is not None:
        return "%s TCP %s:%s -> %s" % (text, ip_pkt.srcip, tcp_pkt.srcport,
                                        tcp_pkt.dstport)
    if udp_pkt is not None:
        return "%s UDP %s:%s -> %s" % (text, ip_pkt.srcip, udp_pkt.srcport,
                                        udp_pkt.dstport)
    if icmp_pkt is not None:
        echo_pkt = icmp_pkt.payload
        kind = {0: "echo-reply", 8: "echo-request"}.get(icmp_pkt.type,
                                                         str(icmp_pkt.type))
        return "%s ICMP %s id=%s" % (text, kind,
                                      getattr(echo_pkt, "id", "?"))
    return text


def _describe_flow(flow):
    """Resumen legible de una regla OpenFlow instalada."""
    match = flow.match
    parts = ["in_port=%s" % match.in_port]
    if match.nw_src is not None:
        parts.append("src=%s" % match.nw_src)
    if match.nw_dst is not None:
        parts.append("dst=%s" % match.nw_dst)
    if match.nw_proto is not None:
        parts.append("proto=%s" % match.nw_proto)
    if match.tp_src is not None:
        parts.append("tp_src=%s" % match.tp_src)
    if match.tp_dst is not None:
        parts.append("tp_dst=%s" % match.tp_dst)
    actions = []
    for action in flow.actions:
        if isinstance(action, of.ofp_action_output):
            actions.append("OUTPUT:%s" % action.port)
        elif isinstance(action, of.ofp_action_nw_addr):
            field = "NW_SRC" if action.type == of.OFPAT_SET_NW_SRC \
                else "NW_DST"
            actions.append("SET_%s:%s" % (field, action.nw_addr))
        elif isinstance(action, of.ofp_action_tp_port):
            field = "TP_SRC" if action.type == of.OFPAT_SET_TP_SRC \
                else "TP_DST"
            actions.append("SET_%s:%s" % (field, action.tp_port))
        elif isinstance(action, of.ofp_action_dl_addr):
            field = "DL_SRC" if action.type == of.OFPAT_SET_DL_SRC \
                else "DL_DST"
            actions.append("SET_%s:%s" % (field, action.dl_addr))
        else:
            actions.append(type(action).__name__)
    return "[%s] -> %s" % (" ".join(parts), " ".join(actions))


def _build_frame(src_ip, dst_ip, proto, src_port=None, dst_port=None,
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
    elif proto == protorouter.UDP_PROTO:
        transport = udp()
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


class ClassificationTest(ProtoRouterNATTest):
    def test_private_to_public_is_outgoing(self):
        self.assertEqual(
            self.router.classify_packet(IPAddr("192.168.1.2"),
                                        IPAddr("200.0.0.1")),
            protorouter.DIRECTION_OUTGOING)

    def test_public_to_public_ip_is_incoming(self):
        self.assertEqual(
            self.router.classify_packet(IPAddr("200.0.0.1"),
                                        protorouter.PUBLIC_IP),
            protorouter.DIRECTION_INCOMING)

    def test_private_to_private_is_dropped(self):
        self.assertEqual(
            self.router.classify_packet(IPAddr("192.168.1.2"),
                                        IPAddr("192.168.1.3")),
            protorouter.DIRECTION_OTHER)

    def test_public_to_other_ip_is_dropped(self):
        self.assertEqual(
            self.router.classify_packet(IPAddr("200.0.0.1"),
                                        IPAddr("200.0.0.5")),
            protorouter.DIRECTION_OTHER)

    def test_other_traffic_does_not_install_flows(self):
        packet = self._frame("200.0.0.1", "192.168.1.2",
                             protorouter.TCP_PROTO, src_port=1, dst_port=2)
        event = self._event(packet, protorouter.PUBLIC_PORT)
        self.router.handle_ip(event)
        self.assertEqual(self.router.connection.flow_mods(), [])
        self.assertEqual(self.router.connection.packet_outs(), [])
        self.assertEqual(self.router._nat_by_outgoing, {})

    def test_non_ip_non_arp_frame_is_ignored(self):
        frame = ethernet(type=0x88cc, src=EthAddr("00:00:00:00:00:09"),
                         dst=EthAddr("00:00:00:00:00:0a"))
        event = self._event(frame, 2)
        self.router._handle_PacketIn(event)
        self.assertEqual(self.router.connection.messages, [])


class OutgoingTest(ProtoRouterNATTest):
    def test_tcp_hardcoded_packet_translation(self):
        """Saliente TCP: 192.168.1.2:4321 -> 200.0.0.1:80 se traduce."""
        self._outgoing("192.168.1.2", "200.0.0.1",
                       protorouter.TCP_PROTO, in_port=2,
                       src_port=4321, dst_port=80)

        record = self.router._nat_by_outgoing.get(
            (protorouter.TCP_PROTO, IPAddr("192.168.1.2"), 4321,
             IPAddr("200.0.0.1"), 80))
        self.assertIsNotNone(record)
        self.assertGreaterEqual(record.public_port,
                                protorouter.NAT_PORT_MIN)
        self.assertLessEqual(record.public_port,
                             protorouter.NAT_PORT_MAX)

        frame, out_port = self.sent_packets[0]
        self.assertEqual(out_port, protorouter.PUBLIC_PORT)
        self.assertEqual(frame.find("ipv4").srcip, protorouter.PUBLIC_IP)
        self.assertEqual(frame.find("ipv4").dstip, IPAddr("200.0.0.1"))
        self.assertEqual(frame.find("tcp").srcport, record.public_port)
        self.assertEqual(frame.find("tcp").dstport, 80)
        self.assertEqual(frame.src, protorouter.PUBLIC_MAC)
        self.assertEqual(frame.dst, EthAddr("00:00:00:00:00:01"))

    def test_udp_hardcoded_packet_translation(self):
        """Saliente UDP: 192.168.1.3:5555 -> 200.0.0.1:53 se traduce."""
        self._outgoing("192.168.1.3", "200.0.0.1",
                       protorouter.UDP_PROTO, in_port=3,
                       src_port=5555, dst_port=53)

        record = self.router._nat_by_outgoing.get(
            (protorouter.UDP_PROTO, IPAddr("192.168.1.3"), 5555,
             IPAddr("200.0.0.1"), 53))
        self.assertIsNotNone(record)

        frame, out_port = self.sent_packets[0]
        self.assertEqual(out_port, protorouter.PUBLIC_PORT)
        self.assertEqual(frame.find("ipv4").srcip, protorouter.PUBLIC_IP)
        self.assertEqual(frame.find("udp").srcport, record.public_port)
        self.assertEqual(frame.find("udp").dstport, 53)

    def test_ping_only_changes_ip(self):
        """Saliente ping: sólo se cambia la IP (el id de echo no cambia)."""
        self._outgoing("192.168.1.2", "200.0.0.1",
                       protorouter.ICMP_PROTO, in_port=2,
                       icmp_type=protorouter.ICMP_ECHO_REQUEST,
                       echo_id=3023, sequence=1)

        record = self.router._nat_by_outgoing[
            (protorouter.ICMP_PROTO, IPAddr("192.168.1.2"), 3023,
             IPAddr("200.0.0.1"), 3023)]
        self.assertEqual(record.public_port, 3023)

        frame, out_port = self.sent_packets[0]
        self.assertEqual(out_port, protorouter.PUBLIC_PORT)
        self.assertEqual(frame.find("ipv4").srcip, protorouter.PUBLIC_IP)
        self.assertEqual(frame.find("icmp").payload.id, 3023)

    def test_same_connection_reuses_record(self):
        for _ in range(3):
            self._outgoing("192.168.1.2", "200.0.0.1",
                           protorouter.TCP_PROTO, in_port=2,
                           src_port=40000, dst_port=80)
        self.assertEqual(len(self.router._nat_by_outgoing), 1)
        self.assertEqual(len(self.sent_packets), 3)
        ports = {frame.find("tcp").srcport
                 for frame, _ in self.sent_packets}
        self.assertEqual(len(ports), 1)

    def test_arp_pending_does_not_send_untranslated_packet(self):
        """Saliente sin MAC destino: queda encolado, no se envía sin traducir."""
        self._outgoing("192.168.1.2", "200.0.0.7",
                       protorouter.TCP_PROTO, in_port=2,
                       src_port=40000, dst_port=80)
        self.assertEqual(self.sent_packets, [])
        self.assertEqual(self.router.connection.flow_mods(), [])


class IncomingTest(ProtoRouterNATTest):
    def test_tcp_reply_is_translated_back(self):
        self._outgoing("192.168.1.2", "200.0.0.1",
                       protorouter.TCP_PROTO, in_port=2,
                       src_port=4321, dst_port=80)
        record = next(iter(self.router._nat_by_outgoing.values()))
        self.sent_packets.clear()

        packet, _ = self._incoming("200.0.0.1", str(protorouter.PUBLIC_IP),
                                   protorouter.TCP_PROTO,
                                   src_port=80,
                                   dst_port=record.public_port)

        frame, out_port = self.sent_packets[0]
        self.assertEqual(out_port, 2)
        self.assertEqual(frame.find("ipv4").dstip,
                         IPAddr("192.168.1.2"))
        self.assertEqual(frame.find("tcp").dstport, 4321)
        self.assertEqual(frame.dst, EthAddr("00:00:00:00:00:02"))
        self.assertEqual(frame.src, protorouter.PRIVATE_MAC)

    def test_udp_reply_is_translated_back(self):
        self._outgoing("192.168.1.3", "200.0.0.1",
                       protorouter.UDP_PROTO, in_port=3,
                       src_port=5555, dst_port=53)
        record = next(iter(self.router._nat_by_outgoing.values()))
        self.sent_packets.clear()

        self._incoming("200.0.0.1", str(protorouter.PUBLIC_IP),
                       protorouter.UDP_PROTO, src_port=53,
                       dst_port=record.public_port)

        frame, out_port = self.sent_packets[0]
        self.assertEqual(out_port, 3)
        self.assertEqual(frame.find("ipv4").dstip,
                         IPAddr("192.168.1.3"))
        self.assertEqual(frame.find("udp").dstport, 5555)

    def test_ping_reply_keeps_echo_id_and_restores_ip(self):
        self._outgoing("192.168.1.2", "200.0.0.1",
                       protorouter.ICMP_PROTO, in_port=2,
                       icmp_type=protorouter.ICMP_ECHO_REQUEST,
                       echo_id=3023, sequence=1)
        self.sent_packets.clear()

        self._incoming("200.0.0.1", str(protorouter.PUBLIC_IP),
                       protorouter.ICMP_PROTO,
                       icmp_type=protorouter.ICMP_ECHO_REPLY,
                       echo_id=3023, sequence=1)

        frame, out_port = self.sent_packets[0]
        self.assertEqual(out_port, 2)
        self.assertEqual(frame.find("ipv4").dstip,
                         IPAddr("192.168.1.2"))
        self.assertEqual(frame.find("icmp").payload.id, 3023)

    def test_unknown_incoming_is_dropped(self):
        self._incoming("200.0.0.1", str(protorouter.PUBLIC_IP),
                       protorouter.TCP_PROTO, src_port=80, dst_port=5555)
        self.assertEqual(self.sent_packets, [])
        self.assertEqual(self.router.connection.messages, [])

    def test_icmp_echo_reply_without_record_is_dropped(self):
        self._incoming("200.0.0.1", str(protorouter.PUBLIC_IP),
                       protorouter.ICMP_PROTO,
                       icmp_type=protorouter.ICMP_ECHO_REPLY,
                       echo_id=4242, sequence=1)
        self.assertEqual(self.sent_packets, [])


class FlowInstallationTest(ProtoRouterNATTest):
    def setUp(self):
        super(FlowInstallationTest, self).setUp()
        # Flujos reales construidos y enviados por la conexión mock
        del self.router.install_nat_flows
        self.router._send_packet_out = (
            lambda packet, out_port: self.sent_packets.append(
                (packet, out_port)))

    def _install(self, src_ip, dst_ip, proto, in_port=2, **kwargs):
        """Manda un paquete saliente y devuelve (registro, ida, vuelta)."""
        self._outgoing(src_ip, dst_ip, proto, in_port=in_port, **kwargs)
        flows = self.router.connection.flow_mods()
        self.assertEqual(len(flows), 2)
        record = next(iter(self.router._nat_by_outgoing.values()))
        return record, flows[0], flows[1]

    def test_tcp_installs_two_flow_mods(self):
        record, out_flow, in_flow = self._install(
            "192.168.1.2", "200.0.0.1", protorouter.TCP_PROTO,
            src_port=4321, dst_port=80)

        # Ida: privado -> publico
        self.assertEqual(out_flow.match.in_port, 2)
        self.assertEqual(out_flow.match.dl_type, 0x800)
        self.assertEqual(out_flow.match.nw_proto, protorouter.TCP_PROTO)
        self.assertEqual(out_flow.match.nw_src, IPAddr("192.168.1.2"))
        self.assertEqual(out_flow.match.nw_dst, IPAddr("200.0.0.1"))
        self.assertEqual(out_flow.match.tp_src, 4321)
        self.assertEqual(out_flow.match.tp_dst, 80)
        self.assertEqual(out_flow.idle_timeout,
                         protorouter.FLOW_IDLE_TIMEOUT)
        actions = out_flow.actions
        self.assertEqual(actions[0].nw_addr, protorouter.PUBLIC_IP)
        self.assertEqual(actions[1].tp_port, record.public_port)
        self.assertEqual(actions[2].dl_addr, protorouter.PUBLIC_MAC)
        self.assertEqual(actions[3].dl_addr,
                         EthAddr("00:00:00:00:00:01"))
        self.assertEqual(actions[4].port, protorouter.PUBLIC_PORT)

        # Vuelta: publico -> privado
        self.assertEqual(in_flow.match.in_port, protorouter.PUBLIC_PORT)
        self.assertEqual(in_flow.match.nw_src, IPAddr("200.0.0.1"))
        self.assertEqual(in_flow.match.nw_dst, protorouter.PUBLIC_IP)
        self.assertEqual(in_flow.match.tp_src, 80)
        self.assertEqual(in_flow.match.tp_dst, record.public_port)
        actions = in_flow.actions
        self.assertEqual(actions[0].nw_addr, IPAddr("192.168.1.2"))
        self.assertEqual(actions[1].tp_port, 4321)
        self.assertEqual(actions[2].dl_addr, protorouter.PRIVATE_MAC)
        self.assertEqual(actions[3].dl_addr,
                         EthAddr("00:00:00:00:00:02"))
        self.assertEqual(actions[4].port, 2)

    def test_udp_installs_two_flow_mods(self):
        record, out_flow, in_flow = self._install(
            "192.168.1.3", "200.0.0.1", protorouter.UDP_PROTO, in_port=3,
            src_port=5555, dst_port=53)
        self.assertEqual(out_flow.match.nw_proto, protorouter.UDP_PROTO)
        self.assertEqual(out_flow.match.tp_src, 5555)
        self.assertEqual(in_flow.match.tp_dst, record.public_port)
        self.assertEqual(in_flow.match.tp_src, 53)
        self.assertEqual(in_flow.actions[1].tp_port, 5555)
        self.assertEqual(in_flow.actions[4].port, 3)

    def test_ping_installs_two_flow_mods_by_type(self):
        _record, out_flow, in_flow = self._install(
            "192.168.1.2", "200.0.0.1", protorouter.ICMP_PROTO,
            icmp_type=protorouter.ICMP_ECHO_REQUEST,
            echo_id=3023, sequence=1)

        self.assertEqual(out_flow.match.nw_proto, protorouter.ICMP_PROTO)
        self.assertEqual(out_flow.match.tp_src,
                         protorouter.ICMP_ECHO_REQUEST)
        self.assertEqual(out_flow.match.tp_dst, 0)

        self.assertEqual(in_flow.match.nw_proto, protorouter.ICMP_PROTO)
        self.assertEqual(in_flow.match.tp_src,
                         protorouter.ICMP_ECHO_REPLY)
        self.assertEqual(in_flow.match.tp_dst, 0)
        # El ping no toca puertos: solo IP y MAC
        for action in out_flow.actions + in_flow.actions:
            self.assertFalse(isinstance(action, of.ofp_action_tp_port))

    def test_flows_installed_only_once(self):
        self._install("192.168.1.2", "200.0.0.1", protorouter.TCP_PROTO,
                      src_port=4321, dst_port=80)
        # Segundo paquete de la misma conexión: no reinstala
        packet = self._frame("192.168.1.2", "200.0.0.1",
                             protorouter.TCP_PROTO,
                             src_port=4321, dst_port=80)
        self.router.handle_ip(self._event(packet, 2))
        self.assertEqual(len(self.router.connection.flow_mods()), 2)

    def test_first_packet_is_sent_translated(self):
        """Primer paquete: se reenvía ya traducido por el puerto público."""
        self._install("192.168.1.2", "200.0.0.1", protorouter.TCP_PROTO,
                      src_port=4321, dst_port=80)
        self.assertEqual(len(self.sent_packets), 1)
        frame, out_port = self.sent_packets[-1]
        self.assertEqual(out_port, protorouter.PUBLIC_PORT)
        self.assertEqual(frame.find("ipv4").srcip, protorouter.PUBLIC_IP)
        self.assertNotEqual(frame.find("tcp").srcport, 4321)


class FirstPacketRawTest(ProtoRouterNATTest):
    """El paquete original del PacketIn también sale traducido."""

    def setUp(self):
        super(FirstPacketRawTest, self).setUp()
        # Usamos los flujos reales
        del self.router.install_nat_flows

    def test_raw_first_packet_is_forwarded_translated(self):
        # Se usa la trama cruda original del PacketIn (event.ofp)
        event = self._event(_build_frame("192.168.1.2", "200.0.0.1",
                                         protorouter.TCP_PROTO,
                                         src_port=4321, dst_port=80), 2)
        self.router.handle_ip(event)
        self.assertTrue(self.sent_packets, "no se reenvio el paquete")
        forwarded, out_port = self.sent_packets[0]
        self.assertEqual(out_port, protorouter.PUBLIC_PORT)
        self.assertEqual(forwarded.find("ipv4").srcip,
                         protorouter.PUBLIC_IP)
        record = next(iter(self.router._nat_by_outgoing.values()))
        self.assertEqual(forwarded.find("tcp").srcport,
                         record.public_port)


class ArpLookupTest(ProtoRouterNATTest):
    def test_arp_lookup_uses_mac_timestamp_and_port_entry(self):
        ip = IPAddr("200.0.0.1")
        mac = EthAddr("00:00:00:00:00:01")
        self.assertEqual(self.router.arp_table.lookup(ip).mac, mac)
        self.assertEqual(self.router.arp_table.lookup(ip).port, 1)

        self._learn(ip, str(mac), 1, time.time() - ARP_TIMEOUT - 1)
        self.assertIsNone(self.router.arp_table.lookup(ip))
        self.assertNotIn(ip, self.router.arp_table.entries)


class NatRecordTest(unittest.TestCase):
    def test_keys(self):
        record = protorouter.NATRecord(
            protorouter.TCP_PROTO, IPAddr("192.168.1.2"), 4321,
            IPAddr("200.0.0.1"), 80, 10001, 2)
        self.assertEqual(record.outgoing_key(),
                         (protorouter.TCP_PROTO, IPAddr("192.168.1.2"), 4321,
                          IPAddr("200.0.0.1"), 80))
        self.assertEqual(record.incoming_key(),
                         (protorouter.TCP_PROTO, 10001,
                          IPAddr("200.0.0.1"), 80))

    def test_record_is_registered_in_both_directions(self):
        router = make_router()
        record = protorouter.NATRecord(
            protorouter.UDP_PROTO, IPAddr("192.168.1.2"), 4321,
            IPAddr("200.0.0.1"), 80, 10001, 2)
        router._register_record(record)

        self.assertIs(router._nat_by_outgoing[record.outgoing_key()],
                      record)
        self.assertIs(router._nat_by_incoming[record.incoming_key()],
                      record)


def _summary(result):
    """Resumen final de la corrida, con el detalle prueba por prueba."""
    log.info("")
    log.info("=" * 70)
    log.info("RESUMEN DE LA CORRIDA")
    log.info("=" * 70)
    failures = len(result.failures)
    errors = len(result.errors)
    skipped = len(result.skipped)
    passed = result.testsRun - failures - errors - skipped

    for test, _trace in result.skipped:
        log.info("  OMITIDA  %s", test._testMethodName)
    for test, _trace in result.failures:
        log.info("  FALLO    %s", test._testMethodName)
    for test, _trace in result.errors:
        log.info("  ERROR    %s", test._testMethodName)

    log.info("  Total: %d prueba(s) | %d OK | %d fallo(s) | %d error(es)"
             " | %d omitida(s)", result.testsRun, passed, failures, errors,
             skipped)
    log.info("=" * 70)


_original_run = unittest.TextTestRunner.run


def _run_and_summarize(self, test):
    result = _original_run(self, test)
    _summary(result)
    return result


unittest.TextTestRunner.run = _run_and_summarize


if __name__ == "__main__":
    unittest.main()
