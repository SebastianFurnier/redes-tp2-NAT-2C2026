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
    from nat_table import NatTable
    from router_config import RouterConfig, ConfigError
except ImportError:                         # cuando se importa como ext.*
    from ext.arp_table import ArpTable
    from ext.nat_table import NatTable
    from ext.router_config import RouterConfig, ConfigError
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

# Los valores de red y los tiempos viven en RouterConfig (router_config.py) y
# se arman en launch() con los parámetros de arranque.  Estos nombres son solo los valores por defecto, que usan los tests.
DEFAULT_CONFIG = RouterConfig()
PRIVATE_SUBNET = DEFAULT_CONFIG.private_subnet
PRIVATE_MASK = DEFAULT_CONFIG.private_mask
PRIVATE_IP = DEFAULT_CONFIG.private_ip
PUBLIC_IP = DEFAULT_CONFIG.public_ip
PUBLIC_MAC = DEFAULT_CONFIG.public_mac
PRIVATE_MAC = DEFAULT_CONFIG.private_mac
PUBLIC_SUBNET = DEFAULT_CONFIG.public_subnet
PUBLIC_MASK = DEFAULT_CONFIG.public_mask
PUBLIC_PORT = DEFAULT_CONFIG.public_port
PENDING_TIMEOUT = DEFAULT_CONFIG.pending_timeout
FLOW_IDLE_TIMEOUT = DEFAULT_CONFIG.flow_idle_timeout
FLOW_HARD_TIMEOUT = DEFAULT_CONFIG.flow_hard_timeout

FLOW_IDLE_TIMEOUT = 10                      # Timeout de inactividad de flujos
FLOW_HARD_TIMEOUT = 60                      # Timeout duro de flujos

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

class ProtoRouter(object):
    config = DEFAULT_CONFIG
    def __init__(self, connection, config=None):
        if config is not None:
            self.config = config
        self.connection = connection
        self.arp_table = ArpTable(self.config.arp_timeout)
        self.nat_table = NatTable(self.config.port_min, self.config.port_max)
        self.pending = {}
        self.pending_time = {}

        Timer(5, self.arp_table.clean_expired_entries, recurring=True)
        Timer(1, self.clean_expired_pending, recurring=True)
        Timer(2, self.clean_cold_records, recurring= True)
        connection.addListeners(self)

    def describe(self,record):
        name = {ICMP_PROTO: "ICMP", TCP_PROTO: "TCP",UDP_PROTO: "UDP"}.get(record.proto, str(record.proto))
        return (f"{name} {record.private_ip}:{record.private_port} -> "f"{self.config.public_ip}:{record.public_port} <-> "
            f"{record.remote_ip}:{record.remote_port}")

    # Revisa la cabecera de ethernet para ver que tipo es.
    def _handle_PacketIn(self, event):
        try:
            parsed = event.parsed
            ok = parsed.parsed
        except Exception as e:
            log.warning(f"[DROP] POX no pudo decodificar el paquete: {e}")
            return
        if not ok:
            log.warning("[DROP] PacketIn con trama no reconocida.")
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
        return ip.inNetwork(self.config.private_subnet, self.config.private_mask)

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
        if not src_is_private and not dst_is_private and dst_ip == self.config.public_ip:
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

        if arp_pkt.protodst == self.config.private_ip:
            router_mac = self.config.private_mac
        elif arp_pkt.protodst == self.config.public_ip:
            router_mac = self.config.public_mac
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
        
    def resolve(self, ip, callback):
        entry = self.arp_table.lookup(ip)
        if entry is not None:
            callback(entry)
            return

        if ip in self.pending:
            self.pending[ip].append(callback)
            log_color(YELLOW, f"ENCOLADO (request ya pendiente): {ip} | {len(self.pending[ip])} en cola")
            return

        self.pending[ip] = [callback]
        self.pending_time[ip] = time.time()
        log_color(YELLOW, f"ENCOLADO: {ip} sin entrada ARP")
        self.send_arp_request(ip)

    def send_arp_request(self, ip):
        if ip.inNetwork(self.config.public_subnet, self.config.public_mask):
            src_ip, src_mac = self.config.public_ip, self.config.public_mac
        elif ip.inNetwork(self.config.private_subnet, self.config.private_mask):
            src_ip, src_mac = self.config.private_ip, self.config.private_mac
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
        callbacks = self.pending.pop(ip, None)
        self.pending_time.pop(ip, None)

        if not callbacks:
            return

        entry = self.arp_table.lookup(ip)
        log_color(GREEN, f"DESENCOLANDO: {len(callbacks)} paquete(s) hacia {ip}")
        for callback in callbacks:
            callback(entry)

    # ------------------------------------------------------------------
    #  Envío de paquetes
    # ------------------------------------------------------------------

    def _send_packet_out(self, packet, out_port):
        """Manda un paquete al switch por el puerto indicado."""
        msg = of.ofp_packet_out()
        msg.data = packet.pack()
        msg.actions.append(of.ofp_action_output(port=out_port))
        self.connection.send(msg)

    def _forward_packet_out(self, packet):
        """
        Reenvía por el switch un paquete ya traducido.  Si todavía no se
        conoce la MAC de destino, el paquete se encola hasta tenerla.
        """
        ip_pkt = packet.payload
        dst_entry = self.arp_table.lookup(ip_pkt.dstip)

        if dst_entry is None:
            self.resolve(ip_pkt.dstip,
                         lambda _: self._forward_packet_out(packet))
            return

        packet.dst = dst_entry.mac
        self._send_packet_out(packet, dst_entry.port)

        log_color(CYAN, f"ENVIANDO: {ip_pkt.srcip} → {ip_pkt.dstip} | "
                        f"MAC: {packet.src} → {packet.dst} | "
                        f"Out Port: {dst_entry.port}")

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

        record = self.nat_table.lookup_outgoing(
            proto, ip_pkt.srcip, tp.srcport, ip_pkt.dstip, tp.dstport)
        if record is None:
            record = self.nat_table.add(
                proto, ip_pkt.srcip, tp.srcport, ip_pkt.dstip, tp.dstport)
            if record is None:
                log_color(RED, "NAT: ¡sin puertos públicos disponibles!")
                return
            log_color(GREEN, f"NAT nueva conexión: {self.describe(record)}")
        else:
            log_color(CYAN, f"NAT conexión existente: {self.describe(record)}")

        self.forward_outgoing(packet, record)

    def _handle_outgoing_icmp(self, packet, ip_pkt, tp):
        """Ping saliente: solo se cambia la IP, el id de echo se mantiene."""
        if tp is None or tp.type != ICMP_ECHO_REQUEST:
            log_color(RED, "ICMP saliente no-echo-request: descartado")
            return

        echo_pkt = tp.payload
        if not isinstance(echo_pkt, icmp_echo):
            log_color(RED, "ICMP echo malformado: descartado")
            return

        record = self.nat_table.lookup_outgoing(
            ICMP_PROTO, ip_pkt.srcip, echo_pkt.id, ip_pkt.dstip,
            echo_pkt.id)
        if record is None:
            record = self.nat_table.add(ICMP_PROTO, ip_pkt.srcip, echo_pkt.id,
                                        ip_pkt.dstip, echo_pkt.id)
            log_color(GREEN, f"NAT nueva conexión (ping): {self.describe(record)}")

        self.forward_outgoing(packet, record)

    def forward_outgoing(self, packet, record):
        """
        Traduce el paquete saliente: IP origen → IP pública (y puerto origen
        → puerto público en TCP/UDP) y lo manda al servidor.
        """
        ip_pkt = packet.payload
        proto, tp = self._get_transport(packet, ip_pkt)

        if proto != ICMP_PROTO and tp is not None:
            tp.srcport = record.public_port
        ip_pkt.srcip = self.config.public_ip
        packet.src = self.config.public_mac

        self._forward_packet_out(packet)

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
            record = self.nat_table.lookup_incoming(
                ICMP_PROTO, echo_pkt.id, ip_pkt.srcip, echo_pkt.id)
            if record is None:
                log_color(RED, f"Descartado: sin entrada NAT para ping "
                               f"id={echo_pkt.id} desde {ip_pkt.srcip}")
                return
            self.forward_incoming(packet, record)
            return

        if tp is None:
            log_color(RED, "Descartado: IP entrante sin puerto "
                           "(no se puede demuxear)")
            return

        record = self.nat_table.lookup_incoming(
            proto, tp.dstport, ip_pkt.srcip, tp.srcport)
        if record is None:
            log_color(RED, f"Descartado: sin entrada NAT para "
                           f"{ip_pkt.srcip}:{tp.srcport} → "
                           f"{self.config.public_ip}:{tp.dstport}")
            return

        log_color(CYAN, f"NAT conexión existente (entrada): {self.describe(record)}")
        self.forward_incoming(packet, record)

    def forward_incoming(self, packet, record):
        """
        Traduce el paquete entrante: IP destino → IP privada (y puerto
        destino → puerto privado en TCP/UDP) y lo entrega al host.
        """
        ip_pkt = packet.payload
        proto, tp = self._get_transport(packet, ip_pkt)

        if proto != ICMP_PROTO and tp is not None:
            tp.dstport = record.private_port
        ip_pkt.dstip = record.private_ip
        packet.src = self.config.private_mac

        self._forward_packet_out(packet)

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
        if record.flows_installed:
            return
        if record.outgoing_key() not in self.nat_table.outgoing:
            return 
        
        remote_entry = self.arp_table.lookup(record.remote_ip)
        private_entry = self.arp_table.lookup(record.private_ip)

        if remote_entry is None or private_entry is None:
            if record.cold_since is None:
                record.cold_since = time.time()
            missing = record.remote_ip if remote_entry is None else record.private_ip
            self.resolve(missing, lambda _: self.install_nat_flows(record))
            return

        proto = record.proto
        is_icmp = proto == ICMP_PROTO

        # -------- Regla de ida: privado → público --------
        fm_out = of.ofp_flow_mod()
        fm_out.idle_timeout = self.config.flow_idle_timeout
        fm_out.hard_timeout = self.config.flow_hard_timeout
        fm_out.flags |= of.OFPFF_SEND_FLOW_REM

        fm_out.match.in_port = private_entry.port
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

        fm_out.actions.append(of.ofp_action_nw_addr.set_src(self.config.public_ip))
        if not is_icmp and record.public_port != record.private_port:
            fm_out.actions.append(
                of.ofp_action_tp_port.set_src(record.public_port))
        fm_out.actions.append(of.ofp_action_dl_addr.set_src(self.config.public_mac))
        fm_out.actions.append(
            of.ofp_action_dl_addr.set_dst(remote_entry.mac))
        fm_out.actions.append(of.ofp_action_output(port=self.config.public_port))
        self.connection.send(fm_out)

        # -------- Regla de vuelta: público → privado --------
        fm_in = of.ofp_flow_mod()
        fm_in.idle_timeout = self.config.flow_idle_timeout
        fm_in.hard_timeout = self.config.flow_hard_timeout
        fm_in.flags |= of.OFPFF_SEND_FLOW_REM

        fm_in.match.in_port = self.config.public_port
        fm_in.match.dl_type = ethernet.IP_TYPE
        fm_in.match.nw_src = record.remote_ip
        fm_in.match.nw_dst = self.config.public_ip
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
        fm_in.actions.append(of.ofp_action_dl_addr.set_src(self.config.private_mac))
        fm_in.actions.append(
            of.ofp_action_dl_addr.set_dst(private_entry.mac))
        fm_in.actions.append(
            of.ofp_action_output(port=private_entry.port))
        self.connection.send(fm_in)

        record.flows_installed = True
        record.flows_alive = 2
        record.cold_since = None
        log_color(GREEN, f"Flujos instalados para {self.describe(record)}")

    # ------------------------------------------------------------------
    #  Vencimiento de reglas
    # ------------------------------------------------------------------
    def _handle_FlowRemoved(self,event):
        """El switch avisa que una de las dos reglas de una conexión venció
        (las instalamos con OFPFF_SEND_FLOW_REM)."""

        ofp = event.ofp
        if ofp.reason not in (of.OFPRR_IDLE_TIMEOUT, of.OFPRR_HARD_TIMEOUT):
            return
        
        records = self._records_for_match(ofp.match)

        if not records:
            log_color(YELLOW, "FlowRemoved de una regla sin registro NAT (ya liberado): se ignora")
            return
        for record in records:
            self.flow_expired(record, ofp.reason)

    def _records_for_match(self,match):
        """
        Busca el/los registros NAT a los que pertenece una regla vencida.
        """
        proto = match.nw_proto
        if match.dl_type != ethernet.IP_TYPE or proto not in (ICMP_PROTO, TCP_PROTO, UDP_PROTO):
            return []

        is_return_rule = match.in_port == self.config.public_port
        if proto == ICMP_PROTO:
            if is_return_rule:
                return [r for r in self.nat_table.outgoing.values()
                        if r.proto == ICMP_PROTO
                        and r.remote_ip == match.nw_src]
            return [r for r in self.nat_table.outgoing.values()
                    if r.proto == ICMP_PROTO
                    and r.private_ip == match.nw_src
                    and r.remote_ip == match.nw_dst]

        if is_return_rule:
            record = self.nat_table.lookup_incoming(
                proto, match.tp_dst, match.nw_src, match.tp_src)
        else:
            record = self.nat_table.lookup_outgoing(
                proto, match.nw_src, match.tp_src, match.nw_dst, match.tp_dst)
        return [record] if record is not None else []
    
    def flow_expired(self,record,reason):
        """
        Venció una de las reglas de la conexión.  El registro solo se toca
        cuando el switch ya no tiene ninguna de las dos: mientras una siga
        viva, la conexión recibe tráfico en ese sentido
          - Sin reglas por INACTIVIDAD: la conexión terminó → se libera el
            puerto público. 
          - Sin reglas por HARD TIMEOUT: la conexión puede seguir viva, así
            que se conserva el registro y se reinstalan las reglas ya mismo,
            para no pasar a resolver todo en el controlador.
        """
        record.flows_alive = max(0, record.flows_alive - 1)
        record.flows_installed = False

        if record.flows_alive > 0:
            log_color(YELLOW, f"Venció una regla de {self.describe(record)}; "
                              f"la otra sigue activa")
            return

        if reason == of.OFPRR_IDLE_TIMEOUT:
            self.nat_table.release(record)
            log_color(RED, f"Vencimiento por inactividad: puerto público "
                           f"{record.public_port} liberado "
                           f"({self.describe(record)})")
            return

        log_color(YELLOW, f"Hard timeout: reinstalando reglas de "
                          f"{self.describe(record)}")
        self.install_nat_flows(record)

    def clean_cold_records(self):
        """
        Libera los registros que no lograron instalar sus reglas y llevan más de un idle_timeout
        sin conseguirlo.
        """
        grace = max(self.config.flow_idle_timeout, 1)
        now = time.time()
        cold = [r for r in list(self.nat_table.outgoing.values())
                if r.cold_since is not None and now - r.cold_since > grace]
        for record in cold:
            self.nat_table.release(record)
            log_color(RED, f"Registro sin reglas liberado: "
                           f"{self.describe(record)}")
    
    def clean_expired_pending(self):
        now = time.time()
        expired = [ip for ip, t in self.pending_time.items() if now - t > self.config.pending_timeout]

        for ip in expired:
            callbacks = self.pending.pop(ip, [])
            del self.pending_time[ip]
            log_color(RED, f"PENDIENTE VENCIDO: {ip} sin respuesta ARP | {len(callbacks)} paquete(s) descartado(s)")

def launch(public_ip="200.0.0.254",
           public_mac="00:00:00:aa:aa:aa",
           public_subnet="200.0.0.0/24",
           public_port=1,
           private_ip="192.168.1.254",
           private_mac="00:00:00:bb:bb:bb",
           private_subnet="192.168.1.0/24",
           port_min=10000,
           port_max=65535,
           flow_idle_timeout=10,
           flow_hard_timeout=60,
           pending_timeout=5,
           arp_timeout=10):
    config = RouterConfig(
        public_ip=public_ip, public_mac=public_mac,
        public_subnet=public_subnet, public_port=public_port,
        private_ip=private_ip, private_mac=private_mac,
        private_subnet=private_subnet,
        port_min=port_min, port_max=port_max,
        flow_idle_timeout=flow_idle_timeout,
        flow_hard_timeout=flow_hard_timeout,
        pending_timeout=pending_timeout, arp_timeout=arp_timeout)

    for line in config.summary():
        log_color(CYAN, f"CONFIG {line}")
        

    def start_switch(event):
        log_color(YELLOW, f"Iniciando ProtoRouter para Switch {event.connection.dpid}")
        ProtoRouter(event.connection, config)

    core.openflow.addListenerByName("ConnectionUp", start_switch)