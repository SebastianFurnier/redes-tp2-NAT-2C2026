# Import some POX stuff
from pox.core import core                       # Main POX object
import pox.openflow.libopenflow_01 as of        # OpenFlow 1.0 library
from pox.lib.addresses import EthAddr, IPAddr   # Address types
from pox.lib.packet.ethernet import ethernet
from pox.lib.packet.arp import arp
from pox.lib.packet.icmp import echo as icmp_echo
from pox.lib.recoco import Timer
try:
    from arp_table import ArpTable          # cuando corre dentro de POX
except ImportError:                         # cuando se importa como ext.*
    from ext.arp_table import ArpTable
from pox.lib.packet.ethernet import ETHER_BROADCAST, ETHER_ANY
import time

log = core.getLogger()
RED = "\033[31m"
GREEN = "\033[32m"
YELLOW = "\033[33m"
CYAN = "\033[36m"
RESET = "\033[0m"


def log_color(color, msg):
    log.info(f"{color}{msg}{RESET}")


PRIVATE_SUBNET = IPAddr("192.168.1.0")      # Red interna
PRIVATE_MASK = 24                           # Máscara de la red interna
PRIVATE_IP = IPAddr("192.168.1.254")        # IP del router en la red privada
PUBLIC_IP = IPAddr("200.0.0.254")           # IP del router en la red pública
PUBLIC_MAC = EthAddr("00:00:00:aa:aa:aa")   # MAC del router hacia la red pública
PRIVATE_MAC = EthAddr("00:00:00:bb:bb:bb")  # MAC del router hacia la red privada
PUBLIC_SUBNET = IPAddr("200.0.0.0")
PUBLIC_MASK = 24
PUBLIC_PORT = 1                             # Puerto del switch hacia la red pública

PENDING_TIMEOUT = 5

# Timeouts (segundos) de las reglas
FLOW_IDLE_TIMEOUT = 10                      # Timeout de inactividad de flujos
FLOW_HARD_TIMEOUT = 60                      # Timeout duro de flujos

# Rango de puertos públicos a asignar (PAT)
NAT_PORT_MIN = 10000
NAT_PORT_MAX = 65535

# Protocolos de transporte
ICMP_PROTO = 1
TCP_PROTO = 6
UDP_PROTO = 17

ICMP_ECHO_REPLY = 0
ICMP_ECHO_REQUEST = 8

# Clasificación de paquetes IP
DIRECTION_OUTGOING = "outgoing"             # privado -> público
DIRECTION_INCOMING = "incoming"             # público -> IP pública
DIRECTION_OTHER = "other"                   # se descarta

class NATRecord(object):
    """
    Un registro de la tabla NAT: describe una conexión traducida.

    Campos:
      - proto        : 1 (ICMP), 6 (TCP) o 17 (UDP)
      - private_ip   : IPAddr del host interno
      - private_port : puerto origen del host interno (o id ICMP)
      - remote_ip    : IPAddr del host público
      - remote_port  : puerto destino en el host público (o id ICMP)
      - public_port  : puerto público asignado en el router (PAT)
      - in_port      : puerto del switch por donde entra el tráfico privado
    """

    def __init__(self, proto, private_ip, private_port, remote_ip,
                 remote_port, public_port, in_port):
        self.proto = proto
        self.private_ip = private_ip
        self.private_port = private_port
        self.remote_ip = remote_ip
        self.remote_port = remote_port
        self.public_port = public_port
        self.in_port = in_port
        self.flows_installed = False

    def outgoing_key(self):
        """Clave con la que se indexa el tráfico de ida."""
        return (self.proto, self.private_ip, self.private_port,
                self.remote_ip, self.remote_port)

    def incoming_key(self):
        """Clave con la que se indexa el tráfico de vuelta."""
        return (self.proto, self.public_port, self.remote_ip,
                self.remote_port)

    def __str__(self):
        name = {ICMP_PROTO: "ICMP", TCP_PROTO: "TCP",
                UDP_PROTO: "UDP"}.get(self.proto, str(self.proto))
        return (f"{name} {self.private_ip}:{self.private_port} -> "
                f"{PUBLIC_IP}:{self.public_port} <-> "
                f"{self.remote_ip}:{self.remote_port}")


class ProtoRouter(object):
    def __init__(self, connection):
        self.connection = connection
        self.arp_table = ArpTable()
        self.pending = {}
        self.pending_time = {}

        # Tabla NAT indexada en ambos sentidos
        self._nat_by_outgoing = {}   # outgoing_key() -> NATRecord
        self._nat_by_incoming = {}   # incoming_key() -> NATRecord
        self._used_ports = set()     # (proto, puerto público) en uso

        Timer(5, self.arp_table.clean_expired_entries, recurring=True)
        Timer(1, self.clean_expired_pending, recurring=True)
        connection.addListeners(self)

    # Revisa la cabecera de ethernet para ver que tipo es.
    def _handle_PacketIn(self, event):
        if not event.parsed.parsed:
            log.warning("[DROP] PacketIn con trama no reconocida. POX no pudo decodificar el paquete.")
            return

        if event.parsed.type == ethernet.IP_TYPE:
            self.handle_ip(event)
        elif event.parsed.type == ethernet.ARP_TYPE:
            self.handle_arp(event)
        else:
            log_color(YELLOW, f"Paquete ignorado: protocolo no soportado.")

    # Clasifica el paquete IP y lo manda a la traducción correspondiente.
    # Lo que no cruza la frontera privada/pública se descarta.
    def handle_ip(self, event):
        packet = event.parsed
        ip_pkt = packet.payload
        in_port = event.port

        log_color(
            YELLOW, f"RECIBIDO: {ip_pkt.srcip} → {ip_pkt.dstip} | "
            f"MAC: {packet.src} → {packet.dst} | In Port: {in_port}")

        direction = self.classify_packet(ip_pkt.srcip, ip_pkt.dstip)

        if direction == DIRECTION_OUTGOING:
            log_color(GREEN, f"MATCH: {ip_pkt.srcip} → {ip_pkt.dstip} "
                             f"es tráfico saliente")
            self.handle_outgoing(packet)
        elif direction == DIRECTION_INCOMING:
            log_color(GREEN, f"MATCH: {ip_pkt.srcip} → {ip_pkt.dstip} "
                             f"es tráfico entrante (IP pública)")
            self.handle_incoming(packet)
        else:
            log_color(RED, f"NO MATCH: {ip_pkt.srcip} → {ip_pkt.dstip} "
                           f"no cruza la frontera privada/pública. DROP")

    def _is_private(self, ip):
        return ip.inNetwork(PRIVATE_SUBNET, PRIVATE_MASK)

    def classify_packet(self, src_ip, dst_ip):
        """
        Decide qué hacer con un paquete IPv4:

          - DIRECTION_OUTGOING: sale de la red privada hacia afuera.
          - DIRECTION_INCOMING: llega de afuera hacia la IP pública
            (es la respuesta que vuelve a la IP pública).
          - DIRECTION_OTHER   : no cruza la frontera, se descarta.
        """
        src_is_private = self._is_private(src_ip)
        dst_is_private = self._is_private(dst_ip)

        if src_is_private and not dst_is_private:
            return DIRECTION_OUTGOING
        if not src_is_private and not dst_is_private and dst_ip == PUBLIC_IP:
            return DIRECTION_INCOMING
        return DIRECTION_OTHER

    # Todo paquete ARP que llega, aprende su direccion MAC e IP para agregarlo a la tabla.
    def handle_arp(self, event):
        packet = event.parsed
        arp_pkt = packet.payload

        self.arp_table.learn(arp_pkt.protosrc, arp_pkt.hwsrc, event.port)
        self.flush_pending(arp_pkt.protosrc)

        if arp_pkt.opcode != arp.REQUEST:
            return

        if arp_pkt.protodst == PRIVATE_IP:
            router_mac = PRIVATE_MAC
        elif arp_pkt.protodst == PUBLIC_IP:
            router_mac = PUBLIC_MAC
        else:
            return

        arp_reply = arp()
        arp_reply.opcode = arp.REPLY
        arp_reply.hwsrc = router_mac
        arp_reply.protosrc = arp_pkt.protodst   
        arp_reply.hwdst = arp_pkt.hwsrc
        arp_reply.protodst = arp_pkt.protosrc

        ether = ethernet()
        ether.type = ethernet.ARP_TYPE
        ether.src = router_mac
        ether.dst = arp_pkt.hwsrc
        ether.payload = arp_reply

        msg = of.ofp_packet_out()
        msg.data = ether.pack()
        msg.actions.append(of.ofp_action_output(port=event.port))
        self.connection.send(msg)

        log_color(GREEN, f"ARP REPLY: {arp_reply.protosrc} is-at {router_mac} → {arp_reply.protodst} (port {event.port})")
        
    def enqueue_and_resolve(self, ip, packet, in_port):
        if ip in self.pending:
            self.pending[ip].append((packet, in_port, time.time()))
            self.pending_time[ip] = time.time()
            
            log_color(YELLOW, f"ENCOLADO (request ya pendiente): {ip} | {len(self.pending[ip])} en cola")
            return

        self.pending[ip] = [(packet, in_port)]
        log_color(YELLOW, f"ENCOLADO: {ip} sin entrada ARP")
        self.send_arp_request(ip)

    def send_arp_request(self, ip):
        if ip.inNetwork(PUBLIC_SUBNET, PUBLIC_MASK):
            src_ip, src_mac = PUBLIC_IP, PUBLIC_MAC
        elif ip.inNetwork(PRIVATE_SUBNET, PRIVATE_MASK):
            src_ip, src_mac = PRIVATE_IP, PRIVATE_MAC
        else:
            log_color(RED, f"ARP: {ip} no pertenece a ninguna red conectada")
            return

        arp_req = arp()
        arp_req.opcode = arp.REQUEST
        arp_req.hwsrc = src_mac
        arp_req.hwdst = ETHER_ANY
        arp_req.protosrc = src_ip
        arp_req.protodst = ip

        ether = ethernet()
        ether.type = ethernet.ARP_TYPE
        ether.src = src_mac
        ether.dst = ETHER_BROADCAST
        ether.payload = arp_req

        msg = of.ofp_packet_out()
        msg.data = ether.pack()
        msg.actions.append(of.ofp_action_output(port=of.OFPP_FLOOD))
        self.connection.send(msg)

        log_color(CYAN, f"ARP REQUEST: who-has {ip} tell {src_ip}")

    def flush_pending(self, ip):
        packets = self.pending.pop(ip, None)
        self.pending_time.pop(ip, None)

        if not packets:
            return

        log_color(GREEN, f"DESENCOLANDO: {len(packets)} paquete(s) hacia {ip}")
        for item in packets:
            packet = item[0]
            # El paquete se traduce recién ahora (antes no se sabía la MAC
            # destino); si ya venía traducido, encontrarse a sí mismo como
            # origen no hace nada.
            if self._is_private(packet.payload.srcip):
                self.handle_outgoing(packet)
            else:
                self.handle_incoming(packet)

    # ------------------------------------------------------------------
    #  Envío de paquetes
    # ------------------------------------------------------------------

    def _send_packet_out(self, packet, out_port):
        """Manda un paquete al switch por el puerto indicado."""
        msg = of.ofp_packet_out()
        msg.data = packet.pack()
        msg.actions.append(of.ofp_action_output(port=out_port))
        self.connection.send(msg)

    def _forward_packet_out(self, packet, out_port):
        """
        Reenvía por el switch un paquete ya traducido.  Si todavía no se
        conoce la MAC de destino, el paquete se encola hasta tenerla.
        """
        ip_pkt = packet.payload
        dst_entry = self.arp_table.lookup(ip_pkt.dstip)

        if dst_entry is None:
            self.enqueue_and_resolve(ip_pkt.dstip, packet, out_port)
            return

        packet.dst = dst_entry.mac
        self._send_packet_out(packet, dst_entry.port)

        log_color(CYAN, f"ENVIANDO: {ip_pkt.srcip} → {ip_pkt.dstip} | "
                        f"MAC: {packet.src} → {packet.dst} | "
                        f"Out Port: {dst_entry.port}")

    # ------------------------------------------------------------------
    #  Tabla NAT: asignación de puertos públicos
    # ------------------------------------------------------------------

    def _pick_public_port(self, proto, private_port):
        """
        Elige un puerto público libre, evitando colisiones entre conexiones
        activas.  Se reutiliza el puerto original si ya está en el rango
        asignable y está libre; si no, se busca uno libre en el rango.
        Devuelve None si no quedan puertos.
        """
        if (NAT_PORT_MIN <= private_port <= NAT_PORT_MAX
                and (proto, private_port) not in self._used_ports):
            port = private_port
        else:
            # Barrido circular desde el puerto original: reparte los puertos
            # y sigue siendo determinista (se puede testear).
            port = None
            span = NAT_PORT_MAX - NAT_PORT_MIN + 1
            start = NAT_PORT_MIN + (private_port % span)
            for i in range(span):
                p = NAT_PORT_MIN + ((start - NAT_PORT_MIN + i) % span)
                if (proto, p) not in self._used_ports:
                    port = p
                    break
            if port is None:
                log_color(RED, "NAT: ¡sin puertos públicos disponibles!")
                return None
        self._used_ports.add((proto, port))
        return port

    def _register_record(self, record):
        self._nat_by_outgoing[record.outgoing_key()] = record
        self._nat_by_incoming[record.incoming_key()] = record

    # ------------------------------------------------------------------
    #  Traducción: paquetes salientes
    # ------------------------------------------------------------------

    def _get_transport(self, packet, ip_pkt):
        """Devuelve (protocolo, capa de transporte) o (proto, None)."""
        if ip_pkt.protocol == TCP_PROTO:
            return TCP_PROTO, packet.find('tcp')
        if ip_pkt.protocol == UDP_PROTO:
            return UDP_PROTO, packet.find('udp')
        if ip_pkt.protocol == ICMP_PROTO:
            return ICMP_PROTO, packet.find('icmp')
        return ip_pkt.protocol, None

    def handle_outgoing(self, packet):
        """Procesa un paquete de la red privada hacia afuera."""
        ip_pkt = packet.payload
        proto, tp = self._get_transport(packet, ip_pkt)

        if proto == ICMP_PROTO:
            self._handle_outgoing_icmp(packet, ip_pkt, tp)
            return

        if tp is None:
            log_color(RED, f"Tráfico IP sin puertos ({ip_pkt.protocol}): "
                           f"descartado")
            return

        record = self._nat_by_outgoing.get(
            (proto, ip_pkt.srcip, tp.srcport, ip_pkt.dstip, tp.dstport))
        if record is None:
            public_port = self._pick_public_port(proto, tp.srcport)
            if public_port is None:
                return
            record = NATRecord(proto, ip_pkt.srcip, tp.srcport,
                               ip_pkt.dstip, tp.dstport, public_port,
                               PUBLIC_PORT)
            self._register_record(record)
            log_color(GREEN, f"NAT nueva conexión: {record}")
        else:
            log_color(CYAN, f"NAT conexión existente: {record}")

        self.forward_outbound(packet, record)

    def _handle_outgoing_icmp(self, packet, ip_pkt, tp):
        """Ping saliente: solo se cambia la IP, el id de echo se mantiene."""
        if tp is None or tp.type != ICMP_ECHO_REQUEST:
            log_color(RED, "ICMP saliente no-echo-request: descartado")
            return

        echo_pkt = tp.payload
        if not isinstance(echo_pkt, icmp_echo):
            log_color(RED, "ICMP echo malformado: descartado")
            return

        record = self._nat_by_outgoing.get(
            (ICMP_PROTO, ip_pkt.srcip, echo_pkt.id, ip_pkt.dstip,
             echo_pkt.id))
        if record is None:
            record = NATRecord(ICMP_PROTO, ip_pkt.srcip, echo_pkt.id,
                               ip_pkt.dstip, echo_pkt.id, echo_pkt.id,
                               PUBLIC_PORT)
            self._register_record(record)
            log_color(GREEN, f"NAT nueva conexión (ping): {record}")

        self.forward_outbound(packet, record)

    def forward_outbound(self, packet, record):
        """
        Traduce el paquete saliente: IP origen → IP pública (y puerto origen
        → puerto público en TCP/UDP) y lo manda al servidor.
        """
        ip_pkt = packet.payload
        proto, tp = self._get_transport(packet, ip_pkt)

        if proto != ICMP_PROTO and tp is not None:
            tp.srcport = record.public_port
        ip_pkt.srcip = PUBLIC_IP
        packet.src = PUBLIC_MAC

        self._forward_packet_out(packet, PUBLIC_PORT)

        if not record.flows_installed:
            self.install_nat_flows(record)

    # ------------------------------------------------------------------
    #  Traducción: paquetes entrantes
    # ------------------------------------------------------------------

    def handle_incoming(self, packet):
        """Procesa una respuesta que vuelve a la IP pública."""
        ip_pkt = packet.payload
        proto, tp = self._get_transport(packet, ip_pkt)

        if proto == ICMP_PROTO:
            if tp is None or tp.type != ICMP_ECHO_REPLY:
                log_color(RED, "ICMP entrante no-echo-reply: descartado")
                return
            echo_pkt = tp.payload
            if not isinstance(echo_pkt, icmp_echo):
                log_color(RED, "ICMP echo malformado: descartado")
                return
            record = self._nat_by_incoming.get(
                (ICMP_PROTO, echo_pkt.id, ip_pkt.srcip, echo_pkt.id))
            if record is None:
                log_color(RED, f"Descartado: sin entrada NAT para ping "
                               f"id={echo_pkt.id} desde {ip_pkt.srcip}")
                return
            self.forward_inbound(packet, record)
            return

        if tp is None:
            log_color(RED, "Descartado: IP entrante sin puerto "
                           "(no se puede demuxear)")
            return

        record = self._nat_by_incoming.get(
            (proto, tp.dstport, ip_pkt.srcip, tp.srcport))
        if record is None:
            log_color(RED, f"Descartado: sin entrada NAT para "
                           f"{ip_pkt.srcip}:{tp.srcport} → "
                           f"{PUBLIC_IP}:{tp.dstport}")
            return

        log_color(CYAN, f"NAT conexión existente (entrada): {record}")
        self.forward_inbound(packet, record)

    def forward_inbound(self, packet, record):
        """
        Traduce el paquete entrante: IP destino → IP privada (y puerto
        destino → puerto privado en TCP/UDP) y lo entrega al host.
        """
        ip_pkt = packet.payload
        proto, tp = self._get_transport(packet, ip_pkt)

        if proto != ICMP_PROTO and tp is not None:
            tp.dstport = record.private_port
        ip_pkt.dstip = record.private_ip
        packet.src = PRIVATE_MAC

        self._forward_packet_out(packet, self._private_port_of(record))

        if not record.flows_installed:
            self.install_nat_flows(record)

    # ------------------------------------------------------------------
    #  Reglas en el switch
    # ------------------------------------------------------------------

    def install_nat_flows(self, record):
        """
        Instala las dos reglas de la conexión, una de ida y una de vuelta,
        con las acciones de traducción, para que el switch traduzca solo sin
        consultar al controlador.  Sirve para TCP, UDP y ping.

        Solo se instalan si ya conocemos la MAC del servidor y la del host
        privado; si falta alguna, se pide por ARP y se reintenta al llegar
        la respuesta.
        """
        remote_entry = self.arp_table.lookup(record.remote_ip)
        private_entry = self.arp_table.lookup(record.private_ip)

        if remote_entry is None or private_entry is None:
            if remote_entry is None:
                self.send_arp_request(record.remote_ip)
            if private_entry is None:
                self.send_arp_request(record.private_ip)
            return

        proto = record.proto
        is_icmp = proto == ICMP_PROTO

        # -------- Regla de ida: privado → público --------
        fm_out = of.ofp_flow_mod()
        fm_out.idle_timeout = FLOW_IDLE_TIMEOUT
        fm_out.hard_timeout = FLOW_HARD_TIMEOUT
        fm_out.flags |= of.OFPFF_SEND_FLOW_REM

        fm_out.match.in_port = self._private_port_of(record)
        fm_out.match.dl_type = ethernet.IP_TYPE
        fm_out.match.nw_src = record.private_ip
        fm_out.match.nw_dst = record.remote_ip
        fm_out.match.nw_proto = proto
        if is_icmp:
            # En OF 1.0, para ICMP tp_src=type y tp_dst=code
            fm_out.match.tp_src = ICMP_ECHO_REQUEST
            fm_out.match.tp_dst = 0
        else:
            fm_out.match.tp_src = record.private_port
            fm_out.match.tp_dst = record.remote_port

        fm_out.actions.append(of.ofp_action_nw_addr.set_src(PUBLIC_IP))
        if not is_icmp and record.public_port != record.private_port:
            fm_out.actions.append(
                of.ofp_action_tp_port.set_src(record.public_port))
        fm_out.actions.append(of.ofp_action_dl_addr.set_src(PUBLIC_MAC))
        fm_out.actions.append(
            of.ofp_action_dl_addr.set_dst(remote_entry.mac))
        fm_out.actions.append(of.ofp_action_output(port=PUBLIC_PORT))
        self.connection.send(fm_out)

        # -------- Regla de vuelta: público → privado --------
        fm_in = of.ofp_flow_mod()
        fm_in.idle_timeout = FLOW_IDLE_TIMEOUT
        fm_in.hard_timeout = FLOW_HARD_TIMEOUT
        fm_in.flags |= of.OFPFF_SEND_FLOW_REM

        fm_in.match.in_port = PUBLIC_PORT
        fm_in.match.dl_type = ethernet.IP_TYPE
        fm_in.match.nw_src = record.remote_ip
        fm_in.match.nw_dst = PUBLIC_IP
        fm_in.match.nw_proto = proto
        if is_icmp:
            fm_in.match.tp_src = ICMP_ECHO_REPLY
            fm_in.match.tp_dst = 0
        else:
            fm_in.match.tp_src = record.remote_port
            fm_in.match.tp_dst = record.public_port

        fm_in.actions.append(of.ofp_action_nw_addr.set_dst(record.private_ip))
        if not is_icmp and record.public_port != record.private_port:
            fm_in.actions.append(
                of.ofp_action_tp_port.set_dst(record.private_port))
        fm_in.actions.append(of.ofp_action_dl_addr.set_src(PRIVATE_MAC))
        fm_in.actions.append(
            of.ofp_action_dl_addr.set_dst(private_entry.mac))
        fm_in.actions.append(
            of.ofp_action_output(port=private_entry.port))
        self.connection.send(fm_in)

        record.flows_installed = True
        log_color(GREEN, f"Flujos instalados para {record}")

    def _private_port_of(self, record):
        """
        Puerto del switch hacia el host privado de la conexión.  Se aprende
        de la tabla ARP (así h2, h3, ... pueden estar en cualquier puerto) y,
        si todavía no se conoce, se usa el puerto por donde llegó el tráfico.
        """
        entry = self.arp_table.lookup(record.private_ip)
        if entry is None:
            return record.in_port
        return entry.port

    def clean_expired_pending(self):
        now = time.time()
        expired = [ip for ip, t in self.pending_time.items() if now - t > PENDING_TIMEOUT]

        for ip in expired:
            packets = self.pending.pop(ip, [])
            del self.pending_time[ip]
            log_color(RED, f"PENDIENTE VENCIDO: {ip} sin respuesta ARP | {len(packets)} paquete(s) descartado(s)")

def launch():

    def start_switch(event):
        log_color(YELLOW, f"Iniciando ProtoRouter para Switch {event.connection.dpid}")
        ProtoRouter(event.connection)

    core.openflow.addListenerByName("ConnectionUp", start_switch)
