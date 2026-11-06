"""
NAT saliente con traducción por puertos (PAT).

El controlador es un router L3 sobre un switch OpenFlow con dos interfaces:

  - Interfaz pública : 200.0.0.254 / 00:00:00:aa:aa:aa ( puerto 1 )
  - Interfaz privada : 192.168.1.254 / 00:00:00:bb:bb:bb ( puerto 2 )

Funcionalidades implementadas:

  1. Procesamiento de paquetes IPv4 (heredado del protorouter original).
  2. ARP dinámico completo:
       * Responde ARP requests dirigidas a cualquiera de sus dos IPs.
       * Genera ARP requests para resolver MACs de hosts privados y del
         servidor público (y de cualquier host de la red pública).
       * Mantiene una tabla ARP dinámica con expiración.
  3. NAT saliente con PAT:
       * Traduce IP y puerto origen de conexiones iniciadas desde la red
         privada hacia la red pública (TCP y UDP).
       * Mantiene tablas de traducción (registro por conexión) indexadas
         en ambos sentidos.
       * Asigna puertos públicos libres evitando colisiones y reutiliza
         recursos cuando el registro expira.
       * Soporta ICMP echo (ping) mediante NAT simple por identificador.
  4. Instalación de flujos OpenFlow:
       * Para cada conexión se instalan reglas en ambos sentidos (saliente
         y entrante) con las acciones de traducción (SET_NW_SRC/DST,
         SET_TP_SRC/DST, SET_DL_SRC/DST) para que el switch procese los
         paquetes sin volver a consultar al controlador.
       * Se usan timeouts (idle + hard) para liberar recursos.

El controlador solo interviene ante: paquetes de conexiones nuevas, paquetes
ARP, expiración de registros y resolución de MACs.
"""

# Import some POX stuff
from pox.core import core                       # Main POX object
import pox.openflow.libopenflow_01 as of        # OpenFlow 1.0 library
from pox.lib.packet.ethernet import ethernet
from pox.lib.packet.arp import arp as arp_pkt
from pox.lib.packet.icmp import echo as icmp_echo
from pox.lib.addresses import EthAddr, IPAddr   # Address types
from pox.lib.recoco import Timer                # Timers (tablas ARP/NAT)

import time
import random

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
PUBLIC_PORT = 1                             # Puerto del switch hacia la red pública
PRIVATE_SIDE = 0                            # Marcador: lado de la red privada
# El puerto del switch hacia cada host privado se aprende dinámicamente
# (no está hardcodeado: h2, h3, ... pueden estar en cualquier puerto).

# Timeouts (segundos)
FLOW_IDLE_TIMEOUT = 10                      # Timeout de inactividad de flujos
FLOW_HARD_TIMEOUT = 60                      # Timeout duro de flujos
ARP_ENTRY_TIMEOUT = 300                     # Expiración de entradas ARP (5 min)
NAT_RECORD_TIMEOUT = 65                     # Expiración de registros NAT

# Rango de puertos públicos a asignar
NAT_PORT_MIN = 10000
NAT_PORT_MAX = 65535

ICMP_PROTO = 1
TCP_PROTO = 6
UDP_PROTO = 17

ICMP_ECHO_REPLY = 0
ICMP_ECHO_REQUEST = 8


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
    """

    __slots__ = ('proto', 'private_ip', 'private_port', 'remote_ip',
                 'remote_port', 'public_port', 'flows_installed',
                 'in_port', '_expires_at')

    def __init__(self, proto, private_ip, private_port, remote_ip,
                 remote_port, public_port, in_port):
        self.proto = proto
        self.private_ip = private_ip
        self.private_port = private_port
        self.remote_ip = remote_ip
        self.remote_port = remote_port
        self.public_port = public_port
        self.flows_installed = False
        self.in_port = in_port
        self.touch()

    def touch(self):
        self._expires_at = time.time() + NAT_RECORD_TIMEOUT

    @property
    def expired(self):
        return time.time() > self._expires_at

    def outgoing_key(self):
        return (self.proto, self.private_ip, self.private_port,
                self.remote_ip, self.remote_port)

    def incoming_key(self):
        return (self.proto, self.public_port, self.remote_ip,
                self.remote_port)

    def __str__(self):
        p = {ICMP_PROTO: "ICMP", TCP_PROTO: "TCP", UDP_PROTO: "UDP"}.get(
            self.proto, str(self.proto))
        return (f"{p} {self.private_ip}:{self.private_port} -> "
                f"{PUBLIC_IP}:{self.public_port} <-> "
                f"{self.remote_ip}:{self.remote_port}")


class ProtoRouter(object):
    def __init__(self, connection):
        self.connection = connection
        connection.addListeners(self)

        # Tabla ARP dinámica: IPAddr -> (EthAddr, timestamp, switch_port)
        self.arp_table = {}
        # Resoluciones ARP pendientes: IPAddr -> lista de
        # (packet, out_port, record) a enviar cuando llegue la respuesta
        self._arp_pending = {}

        # Tabla NAT indexada en ambos sentidos
        self._nat_by_outgoing = {}   # outgoing_key() -> NATRecord
        self._nat_by_incoming = {}   # incoming_key() -> NATRecord
        self._used_ports = set()     # (proto, puerto público) en uso

        # Limpieza periódica de tablas ARP y NAT
        self._expire_timer = Timer(10, self._expire_tables, recurring=True)

        # Regla para que todo el tráfico ARP llegue al controlador
        self._install_arp_flow()

    # ------------------------------------------------------------------
    #  Utilidades
    # ------------------------------------------------------------------

    def _is_private(self, ip):
        return ip.inNetwork(PRIVATE_SUBNET, PRIVATE_MASK)

    def _send_packet_out(self, packet, out_port, in_port=None):
        msg = of.ofp_packet_out()
        msg.data = packet.pack()
        msg.actions.append(of.ofp_action_output(port=out_port))
        if in_port is not None:
            msg.in_port = in_port
        self.connection.send(msg)

    # ------------------------------------------------------------------
    #  ARP
    # ------------------------------------------------------------------

    def _install_arp_flow(self):
        """Instala (baja prioridad) una regla ARP -> controlador."""
        fm = of.ofp_flow_mod()
        fm.priority = of.OFP_DEFAULT_PRIORITY - 0x1000
        fm.match.dl_type = ethernet.ARP_TYPE
        fm.actions.append(of.ofp_action_output(port=of.OFPP_CONTROLLER))
        self.connection.send(fm)

    def _arp_lookup(self, ip):
        entry = self.arp_table.get(ip)
        if entry is None:
            return None
        mac, ts, _port = entry
        if time.time() - ts > ARP_ENTRY_TIMEOUT:
            del self.arp_table[ip]
            return None
        return mac

    def _arp_port(self, ip):
        """Puerto del switch por donde se accede a 'ip' (o None)."""
        entry = self.arp_table.get(ip)
        if entry is None:
            return None
        return entry[2]

    def _arp_learn(self, ip, mac, port=None):
        old = self.arp_table.get(ip)
        if old is not None and old[0] != mac:
            log_color(YELLOW, f"ARP re-learned {ip}: {old[0]} -> {mac}")
        # El puerto se actualiza si nos llegó por un puerto conocido
        known_port = old[2] if old is not None else None
        self.arp_table[ip] = (mac, time.time(),
                              port if port is not None else known_port)

    def _arp_send_request(self, target_ip, out_port, src_ip):
        """Genera un ARP request desde la interfaz correspondiente."""
        src_mac = PUBLIC_MAC if out_port == PUBLIC_PORT else PRIVATE_MAC
        log_color(YELLOW, f"ARP REQUEST: ¿quién tiene {target_ip}? "
                          f"(pregunto desde {src_ip})")
        e = ethernet(type=ethernet.ARP_TYPE, src=src_mac,
                     dst=EthAddr.BROADCAST)
        a = arp_pkt()
        a.opcode = arp_pkt.REQUEST
        a.hwtype = arp_pkt.HW_TYPE_ETHERNET
        a.prototype = arp_pkt.PROTO_TYPE_IP
        a.hwsrc = src_mac
        a.protosrc = src_ip
        a.hwdst = EthAddr.BROADCAST
        a.protodst = target_ip
        e.payload = a
        self._send_packet_out(e, of.OFPP_FLOOD)

    def _arp_resolve(self, ip, port, item=None):
        """
        Se asegura de conocer la MAC de 'ip'.  Si no la conoce, envía un ARP
        request y encola 'item' = (packet, out_port, record) para enviarlo
        (e instalar sus flujos) cuando llegue la respuesta.

        Devuelve la MAC si se conoce, o None si quedó pendiente.
        """
        mac = self._arp_lookup(ip)
        if mac is not None:
            return mac
        if ip not in self._arp_pending:
            self._arp_pending[ip] = []
            src_ip = PUBLIC_IP if port == PUBLIC_PORT else PRIVATE_IP
            self._arp_send_request(ip, port, src_ip)
        if item is not None:
            self._arp_pending[ip].append(item)
        return None

    def _private_port_of(self, ip):
        """Puerto del switch hacia un host privado (para output del flujo)."""
        port = self._arp_port(ip)
        if port is None or port == PUBLIC_PORT:
            # Sin dato: usar OFPP_FLOOD por la interfaz privada es la única
            # opción segura; pero en la práctica siempre conocemos el puerto
            # porque aprendimos la MAC por ARP antes de traducir.
            return of.OFPP_FLOOD
        return port

    def _arp_flush_pending(self, ip):
        """Al llegar una respuesta ARP, envía lo que esperaba esa MAC."""
        queue = self._arp_pending.pop(ip, [])
        mac = self._arp_lookup(ip)
        for packet, out_port, rec in queue:
            if mac is None:
                continue
            packet.dst = mac
            self._send_packet_out(packet, out_port)
            if rec is not None and not rec.flows_installed:
                self._install_nat_flows(rec)

    def _handle_arp(self, event):
        packet = event.parsed
        a = packet.find('arp')
        if not a:
            return
        in_port = event.port

        # Aprendemos de cualquier ARP (request o reply), con el puerto por
        # donde llegó (así sabemos por dónde salir hacia ese host)
        if a.protosrc != 0:
            self._arp_learn(a.protosrc, a.hwsrc, in_port)

        if a.opcode == arp_pkt.REPLY:
            log_color(GREEN, f"ARP REPLY: {a.protosrc} está en {a.hwsrc}")
            self._arp_flush_pending(a.protosrc)
            return

        if a.opcode != arp_pkt.REQUEST:
            return

        # ¿Es un request dirigido a una de nuestras IPs?
        if a.protodst == PUBLIC_IP or a.protodst == PRIVATE_IP:
            our_mac = PUBLIC_MAC if a.protodst == PUBLIC_IP else PRIVATE_MAC
            log_color(GREEN, f"ARP REQUEST para {a.protodst} -> "
                             f"respondemos {our_mac}")
            r = arp_pkt()
            r.opcode = arp_pkt.REPLY
            r.hwtype = a.hwtype
            r.prototype = a.prototype
            r.hwlen = a.hwlen
            r.protolen = a.protolen
            r.hwsrc = our_mac
            r.protosrc = a.protodst
            r.hwdst = a.hwsrc
            r.protodst = a.protosrc
            e = ethernet(type=ethernet.ARP_TYPE, src=our_mac, dst=a.hwsrc)
            e.payload = r
            # IMPORTANTE: no setear in_port.  OVS descarta los packet_out
            # cuyo in_port coincide con el puerto de salida (protección
            # anti-loop), y el reply debe salir exactamente por ese puerto.
            self._send_packet_out(e, in_port)
            return

        # Request por otra IP: flood (puede ser para otro host del segmento)
        log_color(YELLOW, f"ARP REQUEST para {a.protodst} -> flood")
        msg = of.ofp_packet_out()
        msg.data = event.ofp
        msg.in_port = in_port
        msg.actions.append(of.ofp_action_output(port=of.OFPP_FLOOD))
        self.connection.send(msg)

    # ------------------------------------------------------------------
    #  Expiración de tablas
    # ------------------------------------------------------------------

    def _expire_tables(self):
        now = time.time()
        # ARP
        for ip in list(self.arp_table.keys()):
            mac, ts, _port = self.arp_table[ip]
            if now - ts > ARP_ENTRY_TIMEOUT:
                del self.arp_table[ip]

        # NAT
        dead = [r for r in self._nat_by_outgoing.values() if r.expired]
        for rec in dead:
            self._nat_by_outgoing.pop(rec.outgoing_key(), None)
            self._nat_by_incoming.pop(rec.incoming_key(), None)
            self._used_ports.discard((rec.proto, rec.public_port))
            log_color(YELLOW, f"NAT: expiró {rec}")

    # ------------------------------------------------------------------
    #  Asignación de puertos públicos (PAT)
    # ------------------------------------------------------------------

    def _pick_public_port(self, proto, private_port):
        """
        Elige un puerto público libre.  Reutiliza el puerto original si es
        del rango asignable y está libre; si no, asigna uno del rango
        efímero evitando colisiones con conexiones activas.
        """
        if (NAT_PORT_MIN <= private_port <= NAT_PORT_MAX
                and (proto, private_port) not in self._used_ports):
            port = private_port
        else:
            port = None
            span = NAT_PORT_MAX - NAT_PORT_MIN + 1
            start = random.randint(NAT_PORT_MIN, NAT_PORT_MAX)
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

    # ------------------------------------------------------------------
    #  Manejo de paquetes
    # ------------------------------------------------------------------

    def _handle_PacketIn(self, event):
        if not event.parsed.parsed:
            log.warning("[DROP] PacketIn con trama no reconocida.")
            return

        if event.parsed.type == ethernet.ARP_TYPE:
            self._handle_arp(event)
            return

        if event.parsed.type == ethernet.IP_TYPE:
            self.handle_ip(event)
            return

        log_color(YELLOW, "Paquete ignorado: protocolo distinto de IPv4/ARP.")

    def handle_ip(self, event):
        packet = event.parsed
        ip_pkt = packet.next
        in_port = event.port

        if ip_pkt is None or not ip_pkt.parsed:
            return

        log_color(
            YELLOW, f"RECIBIDO: {ip_pkt.srcip} → {ip_pkt.dstip} | "
            f"MAC: {packet.src} → {packet.dst} | In Port: {in_port}")

        src_is_private = self._is_private(ip_pkt.srcip)
        dst_is_private = self._is_private(ip_pkt.dstip)

        if src_is_private and not dst_is_private:
            self._handle_outgoing(event, packet, ip_pkt)
        elif (not src_is_private) and ip_pkt.dstip == PUBLIC_IP:
            self._handle_incoming(event, packet, ip_pkt)
        else:
            log_color(RED, f"NO MATCH: {ip_pkt.srcip} -> {ip_pkt.dstip} "
                           f"no cruza la frontera privada/pública")

    # -- tráfico privado -> público ------------------------------------

    def _get_transport(self, packet, ip_pkt):
        """Devuelve (protocolo, capa de transporte) o (proto, None)."""
        if ip_pkt.protocol == TCP_PROTO:
            tp = packet.find('tcp')
        elif ip_pkt.protocol == UDP_PROTO:
            tp = packet.find('udp')
        elif ip_pkt.protocol == ICMP_PROTO:
            tp = packet.find('icmp')
        else:
            tp = None
        return ip_pkt.protocol, tp

    def _handle_outgoing(self, event, packet, ip_pkt):
        in_port = event.port
        proto, tp = self._get_transport(packet, ip_pkt)

        if proto == ICMP_PROTO:
            if tp is None or (tp.type != ICMP_ECHO_REQUEST
                              and tp.type != ICMP_ECHO_REPLY):
                log_color(RED, "ICMP no-echo: descartado")
                return
            echo_pkt = tp.payload
            if not isinstance(echo_pkt, icmp_echo):
                log_color(RED, "ICMP echo malformado: descartado")
                return
            # NAT de ICMP: clave por identificador de echo
            key_out = (proto, ip_pkt.srcip, echo_pkt.id,
                       ip_pkt.dstip, echo_pkt.seq)
            rec = self._nat_by_outgoing.get(key_out)
            if rec is None:
                port = self._pick_public_port(proto, echo_pkt.id)
                if port is None:
                    return
                rec = NATRecord(proto, ip_pkt.srcip, echo_pkt.id,
                                ip_pkt.dstip, echo_pkt.seq, port, in_port)
                self._register_record(rec)
            else:
                rec.touch()
            if tp.type == ICMP_ECHO_REQUEST:
                # Reescribir el identificador de echo al "puerto" público
                echo_pkt.id = rec.public_port
                self._forward_outgoing(packet, ip_pkt, rec, rec.public_port)
            else:
                # Reply de otro host privado: sin registro, drop
                log_color(RED, "ICMP reply saliente sin registro: drop")
            return

        if tp is None:
            # IP sin capa de transporte conocida: NAT simple por IP
            self._install_simple_flow(packet, ip_pkt, in_port)
            return

        key_out = (proto, ip_pkt.srcip, tp.srcport,
                   ip_pkt.dstip, tp.dstport)
        rec = self._nat_by_outgoing.get(key_out)
        if rec is None:
            # Nueva conexión: registro + puerto público + flujos
            public_port = self._pick_public_port(proto, tp.srcport)
            if public_port is None:
                return
            rec = NATRecord(proto, ip_pkt.srcip, tp.srcport,
                            ip_pkt.dstip, tp.dstport, public_port, in_port)
            self._register_record(rec)
            log_color(GREEN, f"NAT nueva conexión: {rec}")
        else:
            rec.touch()
            log_color(CYAN, f"NAT conexión existente: {rec}")

        self._forward_outgoing(packet, ip_pkt, rec, rec.public_port)

    def _register_record(self, rec):
        self._nat_by_outgoing[rec.outgoing_key()] = rec
        self._nat_by_incoming[rec.incoming_key()] = rec

    def _forward_outgoing(self, packet, ip_pkt, rec, new_src_port):
        """
        Traduce el paquete saliente (IP, puerto y MAC de origen) y lo reenvía
        por la interfaz pública.  Si no conocemos la MAC del destino, envía
        un ARP y encola el paquete.
        """
        if rec.proto != ICMP_PROTO:
            tp = packet.find('tcp') or packet.find('udp')
            tp.srcport = new_src_port
        ip_pkt.srcip = PUBLIC_IP
        packet.src = PUBLIC_MAC

        dst_mac = self._arp_lookup(ip_pkt.dstip)
        if dst_mac is None:
            dst_mac = self._arp_resolve(ip_pkt.dstip, PUBLIC_PORT,
                                        item=(packet, PUBLIC_PORT, rec))
            if dst_mac is None:
                return
        packet.dst = dst_mac

        # Los checksums se recalculan solos al reempaquetar (pack())
        log_color(CYAN, f"ENVIANDO: {ip_pkt.srcip}:{rec.public_port} → "
                        f"{ip_pkt.dstip}:{rec.remote_port} | "
                        f"MAC: {packet.src} → {packet.dst} | "
                        f"Out Port: {PUBLIC_PORT}")
        self._send_packet_out(packet, PUBLIC_PORT)

        if not rec.flows_installed:
            self._install_nat_flows(rec)

    # -- tráfico público -> privado ------------------------------------

    def _handle_incoming(self, event, packet, ip_pkt):
        proto, tp = self._get_transport(packet, ip_pkt)

        if proto == ICMP_PROTO:
            if tp is None or tp.type != ICMP_ECHO_REPLY:
                log_color(RED, "ICMP entrante no-echo-reply: descartado")
                return
            echo_pkt = tp.payload
            if not isinstance(echo_pkt, icmp_echo):
                log_color(RED, "ICMP echo malformado: descartado")
                return
            key_in = (proto, echo_pkt.id, ip_pkt.srcip, echo_pkt.seq)
            rec = self._nat_by_incoming.get(key_in)
            if rec is None:
                log_color(RED, f"Descartado: sin registro NAT para ICMP "
                               f"id={echo_pkt.id} desde {ip_pkt.srcip}")
                return
            rec.touch()
            # Restaurar el identificador de echo original del host privado
            echo_pkt.id = rec.private_port
            self._forward_incoming(packet, ip_pkt, rec, rec.private_port)
            return

        if tp is None:
            log_color(RED, "Descartado: IP entrante sin puerto "
                           "(no se puede demuxear)")
            return

        key_in = (proto, tp.dstport, ip_pkt.srcip, tp.srcport)
        rec = self._nat_by_incoming.get(key_in)
        if rec is None:
            log_color(RED, f"Descartado: sin registro NAT para "
                           f"{ip_pkt.srcip}:{tp.srcport} -> "
                           f"{PUBLIC_IP}:{tp.dstport}")
            return

        rec.touch()
        log_color(CYAN, f"NAT conexión existente (entrada): {rec}")
        self._forward_incoming(packet, ip_pkt, rec, rec.private_port)

    def _forward_incoming(self, packet, ip_pkt, rec, new_dst_port):
        """
        Traduce el paquete entrante (IP, puerto y MAC de destino) hacia el
        host privado original y lo reenvía por la interfaz privada.
        """
        if rec.proto != ICMP_PROTO:
            tp = packet.find('tcp') or packet.find('udp')
            tp.dstport = new_dst_port
        ip_pkt.dstip = rec.private_ip

        dst_mac = self._arp_lookup(rec.private_ip)
        private_port = self._arp_port(rec.private_ip)
        if dst_mac is None or private_port is None:
            dst_mac = self._arp_resolve(rec.private_ip, PRIVATE_SIDE,
                                        item=(packet, PRIVATE_SIDE, rec))
            if dst_mac is None:
                return
        packet.dst = dst_mac
        packet.src = PUBLIC_MAC

        log_color(CYAN, f"ENVIANDO: {ip_pkt.srcip}:{rec.remote_port} → "
                        f"{ip_pkt.dstip}:{rec.private_port} | "
                        f"MAC: {packet.src} → {packet.dst} | "
                        f"Out Port: {private_port}")
        self._send_packet_out(packet, private_port)

        if not rec.flows_installed:
            self._install_nat_flows(rec)

    # ------------------------------------------------------------------
    #  Instalación de flujos
    # ------------------------------------------------------------------

    def _install_nat_flows(self, rec):
        """
        Instala las reglas OpenFlow de una conexión en ambos sentidos, para
        que el switch procese los paquetes siguientes sin pasar por el
        controlador.  Solo se instalan si conocemos ambas MACs (si no, el
        tráfico sigue procesándose en el controlador hasta resolverlas).
        """
        remote_mac = self._arp_lookup(rec.remote_ip)
        private_mac = self._arp_lookup(rec.private_ip)
        if remote_mac is None or private_mac is None:
            if remote_mac is None:
                self._arp_resolve(rec.remote_ip, PUBLIC_PORT)
            if private_mac is None:
                self._arp_resolve(rec.private_ip, PRIVATE_SIDE)
            return

        proto = rec.proto

        # -------- Flujo saliente (privado -> público) --------
        fm = of.ofp_flow_mod()
        fm.idle_timeout = FLOW_IDLE_TIMEOUT
        fm.hard_timeout = FLOW_HARD_TIMEOUT
        fm.flags |= of.OFPFF_SEND_FLOW_REM

        # Filtro (Saliente): la conexión exacta
        fm.match.in_port = rec.in_port
        fm.match.dl_type = 0x800  # IPv4
        fm.match.nw_src = rec.private_ip
        fm.match.nw_dst = rec.remote_ip
        fm.match.nw_proto = proto
        if proto == ICMP_PROTO:
            # En OF 1.0, para ICMP tp_src=type y tp_dst=code
            fm.match.tp_src = ICMP_ECHO_REQUEST
            fm.match.tp_dst = 0
        else:
            fm.match.tp_src = rec.private_port
            fm.match.tp_dst = rec.remote_port

        # Acciones (Saliente)
        fm.actions.append(of.ofp_action_nw_addr.set_src(PUBLIC_IP))
        if proto != ICMP_PROTO and rec.public_port != rec.private_port:
            fm.actions.append(
                of.ofp_action_tp_port.set_src(rec.public_port))
        fm.actions.append(of.ofp_action_dl_addr.set_src(PUBLIC_MAC))
        fm.actions.append(of.ofp_action_dl_addr.set_dst(remote_mac))
        fm.actions.append(of.ofp_action_output(port=PUBLIC_PORT))
        self.connection.send(fm)

        # -------- Flujo entrante (público -> privado) --------
        fm_back = of.ofp_flow_mod()
        fm_back.idle_timeout = FLOW_IDLE_TIMEOUT
        fm_back.hard_timeout = FLOW_HARD_TIMEOUT
        fm_back.flags |= of.OFPFF_SEND_FLOW_REM

        # Filtro (Entrante)
        fm_back.match.in_port = PUBLIC_PORT
        fm_back.match.dl_type = 0x800
        fm_back.match.nw_src = rec.remote_ip
        fm_back.match.nw_dst = PUBLIC_IP
        fm_back.match.nw_proto = proto
        if proto == ICMP_PROTO:
            fm_back.match.tp_src = ICMP_ECHO_REPLY
            fm_back.match.tp_dst = 0
        else:
            fm_back.match.tp_src = rec.remote_port
            fm_back.match.tp_dst = rec.public_port

        # Acciones (Entrante)
        fm_back.actions.append(
            of.ofp_action_nw_addr.set_dst(rec.private_ip))
        if proto != ICMP_PROTO and rec.public_port != rec.private_port:
            fm_back.actions.append(
                of.ofp_action_tp_port.set_dst(rec.private_port))
        fm_back.actions.append(of.ofp_action_dl_addr.set_src(PRIVATE_MAC))
        fm_back.actions.append(of.ofp_action_dl_addr.set_dst(private_mac))
        fm_back.actions.append(
            of.ofp_action_output(port=self._private_port_of(rec.private_ip)))
        self.connection.send(fm_back)

        rec.flows_installed = True
        log_color(GREEN, f"Flujos instalados para {rec}")

    def _install_simple_flow(self, packet, ip_pkt, in_port):
        """
        Tráfico IP sin capa de transporte conocida desde la red privada.
        Se instala un flujo que solo traduce la IP origen (NAT simple).
        """
        log_color(YELLOW, f"Tráfico IP sin puertos ({ip_pkt.protocol}): "
                          f"NAT simple (solo IP)")
        fm = of.ofp_flow_mod()
        fm.idle_timeout = FLOW_IDLE_TIMEOUT
        fm.hard_timeout = FLOW_HARD_TIMEOUT
        fm.match.in_port = in_port
        fm.match.dl_type = 0x800
        fm.match.nw_src = ip_pkt.srcip
        fm.match.nw_dst = ip_pkt.dstip
        fm.actions.append(of.ofp_action_nw_addr.set_src(PUBLIC_IP))
        fm.actions.append(of.ofp_action_dl_addr.set_src(PUBLIC_MAC))
        remote_mac = self._arp_lookup(ip_pkt.dstip)
        if remote_mac is not None:
            fm.actions.append(of.ofp_action_dl_addr.set_dst(remote_mac))
        fm.actions.append(of.ofp_action_output(port=PUBLIC_PORT))
        self.connection.send(fm)

        # Reenviar el paquete actual
        packet.src = PUBLIC_MAC
        ip_pkt.srcip = PUBLIC_IP
        dst_mac = self._arp_lookup(ip_pkt.dstip)
        if dst_mac is None:
            dst_mac = self._arp_resolve(ip_pkt.dstip, PUBLIC_PORT,
                                        item=(packet, PUBLIC_PORT, None))
            if dst_mac is None:
                return
        packet.dst = dst_mac
        self._send_packet_out(packet, PUBLIC_PORT)


def launch():

    def start_switch(event):
        log_color(YELLOW, f"Iniciando ProtoRouter/NAT para Switch "
                          f"{event.connection.dpid}")
        ProtoRouter(event.connection)

    core.openflow.addListenerByName("ConnectionUp", start_switch)
