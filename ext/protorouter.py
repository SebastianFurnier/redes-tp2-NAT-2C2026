# Import some POX stuff
from pox.core import core                       # Main POX object
import pox.openflow.libopenflow_01 as of        # OpenFlow 1.0 library
from pox.lib.addresses import EthAddr, IPAddr   # Address types
from pox.lib.packet.ethernet import ethernet
from pox.lib.packet.arp import arp
from arp_table import ArpTable
from pox.lib.recoco import Timer
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

PENDING_TIMEOUT = 5

class ProtoRouter(object):
    def __init__(self, connection):
        self.connection = connection
        self.arp_table = ArpTable()
        self.pending = {}
        self.pending_time = {}

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

    # Revisa si el paquete IP tiene direccion de origen dentro de la red privada. Sino, lo descarta.
    # Si esta en la red privada se fija si tiene la entrada ARP con la MAC del host destino.
    # Si no tiene ninguna entrada lo encola para resolverlo despues.
    # Si tiene la direccion MAC del host destino, lo envia con forward_outbound.
    def handle_ip(self, event):
        packet = event.parsed
        ip_pkt = packet.payload
        in_port = event.port

        log_color(
            YELLOW, f"RECIBIDO: {ip_pkt.srcip} → {ip_pkt.dstip} | "
            f"MAC: {packet.src} → {packet.dst} | In Port: {in_port}")

        if ip_pkt.srcip.inNetwork(PRIVATE_SUBNET, PRIVATE_MASK):

            log_color(GREEN, f"MATCH: {ip_pkt.srcip} pertenece a la red privada {PRIVATE_SUBNET}/{PRIVATE_MASK}")

            self.resolve(ip_pkt.dstip, lambda entry: self.forward_outbound(packet, in_port, entry))
        else:
            log_color(RED, f"NO MATCH: {ip_pkt.srcip} no pertenece a {PRIVATE_SUBNET}/{PRIVATE_MASK}")

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
        callbacks = self.pending.pop(ip, None)
        self.pending_time.pop(ip, None)

        if not callbacks:
            return

        entry = self.arp_table.lookup(ip)
        log_color(GREEN, f"DESENCOLANDO: {len(callbacks)} paquete(s) hacia {ip}")
        for callback in callbacks:
            callback(entry)

    def forward_outbound(self, packet, in_port, entry):
        ip_pkt = packet.payload

        # Flujo saliente
        # Todo sintaxis de POX.
        # Crea un nuevo flujo (las reglas que va a instalar en el switch).
        # Le pone un timeout para que venza despues de 10s.  
        fm = of.ofp_flow_mod()
        fm.idle_timeout = 10
        fm.match.dl_type = 0x800 # Esto significa que es IPv4
        fm.match.nw_src = ip_pkt.srcip
        fm.match.in_port = in_port
        fm.actions.append(of.ofp_action_dl_addr.set_src(PUBLIC_MAC))
        fm.actions.append(of.ofp_action_dl_addr.set_dst(entry.mac))
        fm.actions.append(of.ofp_action_output(port=entry.port))
        self.connection.send(fm)

        # Flujo entrante (respuesta)
        fm_back = of.ofp_flow_mod()
        fm_back.idle_timeout = 10
        fm_back.match.dl_type = 0x800
        fm_back.match.nw_src = ip_pkt.dstip
        fm_back.match.nw_dst = ip_pkt.srcip
        fm_back.match.in_port = entry.port
        fm_back.actions.append(of.ofp_action_dl_addr.set_src(PRIVATE_MAC))
        fm_back.actions.append(of.ofp_action_dl_addr.set_dst(packet.src))
        fm_back.actions.append(of.ofp_action_output(port=in_port))
        self.connection.send(fm_back)

        # Paquete actual
        packet.src = PUBLIC_MAC
        packet.dst = entry.mac
        msg = of.ofp_packet_out()
        msg.data = packet.pack()
        msg.actions.append(of.ofp_action_output(port=entry.port))
        self.connection.send(msg)

        log_color(CYAN, f"ENVIANDO: {ip_pkt.srcip} → {ip_pkt.dstip} | "
                        f"MAC: {PUBLIC_MAC} → {entry.mac} | Out Port: {entry.port}")

    # Reenvía un paquete que llega desde la red pública hacia un host de la red privada.
    # entry: entrada ARP del host privado destino (MAC y puerto del switch).
    # Por ahora solo reescribe las MAC y envía el paquete actual. Falta la parte de NAT.
    def forward_inbound(self, packet, in_port, entry):
        ip_pkt = packet.payload

        # TODO (NAT): traducir IP y puerto destino (IP pública:puerto público → IP privada:puerto privado)
        # según la tabla NAT, si el paquete no llegó ya traducido.

        # TODO (NAT): instalar el flujo entrante en el switch para que los próximos paquetes
        # de esta conexión no lleguen al controlador.

        # Paquete actual
        packet.src = PRIVATE_MAC
        packet.dst = entry.mac
        msg = of.ofp_packet_out()
        msg.data = packet.pack()
        msg.actions.append(of.ofp_action_output(port=entry.port))
        self.connection.send(msg)

        log_color(CYAN, f"ENVIANDO (entrante): {ip_pkt.srcip} → {ip_pkt.dstip} | "
                        f"MAC: {PRIVATE_MAC} → {entry.mac} | Out Port: {entry.port}")

    def clean_expired_pending(self):
        now = time.time()
        expired = [ip for ip, t in self.pending_time.items() if now - t > PENDING_TIMEOUT]

        for ip in expired:
            callbacks = self.pending.pop(ip, [])
            del self.pending_time[ip]
            log_color(RED, f"PENDIENTE VENCIDO: {ip} sin respuesta ARP | {len(callbacks)} paquete(s) descartado(s)")

def launch():

    def start_switch(event):
        log_color(YELLOW, f"Iniciando ProtoRouter para Switch {event.connection.dpid}")
        ProtoRouter(event.connection)

    core.openflow.addListenerByName("ConnectionUp", start_switch)
