#!/usr/bin/python3

from mininet.topo import Topo
from mininet.net import Mininet
from mininet.node import RemoteController
from mininet.cli import CLI
from mininet.link import TCLink
from mininet.log import setLogLevel
import ipaddress

import ipaddress

# =====================================================================
#  CONFIGURACIÓN DE LA TOPOLOGÍA
# =====================================================================
# Cambiar una IP, una MAC o agregar/quitar un host es editar esta tabla.
# Al arrancar se imprime el comando de POX con los mismos valores: si se
# cambia algo de ROUTER hay que levantar el controlador con ESE comando.

# Interfaces del router (el switch s1 con el controlador POX)
ROUTER = {
    'public_ip':      '200.0.0.254',
    'public_mac':     '00:00:00:aa:aa:aa',
    'public_subnet':  '200.0.0.0/24',
    'private_ip':     '192.168.1.254',
    'private_mac':    '00:00:00:bb:bb:bb',
    'private_subnet': '192.168.1.0/24',
}

# Host de la red pública (servidor): (nombre, IP, MAC).
# Se conecta al puerto 1 del switch (PUBLIC_PORT).
PUBLIC_PORT = 1
PUBLIC_HOST = ('h1', '200.0.0.1', '00:00:00:00:00:01')

# Hosts de la red privada: (nombre, IP, MAC), en los puertos 2, 3, 4...
# Para sumar un host, agregar una fila.
PRIVATE_HOSTS = [
    ('h2', '192.168.1.2', '00:00:00:00:00:02'),
    ('h3', '192.168.1.3', '00:00:00:00:00:03'),
    ('h4', '192.168.1.4', '00:00:00:00:00:04'),
]

#                                      Tráfico Saliente
#
#                                      <---------------
#
#                           Red Pública                Red Privada
#
#
#                              port 1                     port 2
#        ┌───────┐     IP:  200.0.0.254        /\  IP: 192.168.1.254          ┌───────┐
#        │       │     MAC: 00.00.00.aa.aa.aa /  \ MAC:00.00.00.bb.bb.bb      │       │
#        │  h1   ├───────────────────────────/ s1 \───────────────────────────│  h2   │
#        └───────┘                           \    /                           └───────┘
#       /       /                             \  /                           /       /
#      ─────────                               \/                           ─────────
#  IP:  200.0.0.1/24                                                    IP:  192.168.1.2/24
#  DG:  200.0.0.254                                                     DG:  192.168.1.254
#  MAC: 00:00:00:00:00:01                                               MAC: 00:00:00:00:00:02
#

def check_config():
    """Detecta incoherencias de la tabla antes de levantar la red."""
    public_net = ipaddress.ip_network(ROUTER['public_subnet'])
    private_net = ipaddress.ip_network(ROUTER['private_subnet'])
    if ipaddress.ip_address(ROUTER['public_ip']) not in public_net:
        raise ValueError('public_ip no está en public_subnet')
    if ipaddress.ip_address(ROUTER['private_ip']) not in private_net:
        raise ValueError('private_ip no está en private_subnet')
    if public_net.overlaps(private_net):
        raise ValueError('las subredes pública y privada se superponen')

    hosts = [PUBLIC_HOST] + PRIVATE_HOSTS
    for label, values in (('nombres', [h[0] for h in hosts]),
                          ('IPs', [h[1] for h in hosts] + [ROUTER['public_ip'], ROUTER['private_ip']]),
                          ('MACs', [h[2].lower() for h in hosts] + [ROUTER['public_mac'].lower(), ROUTER['private_mac'].lower()])):
        if len(values) != len(set(values)):
            raise ValueError('hay %s repetidos en la tabla' % label)

    if ipaddress.ip_address(PUBLIC_HOST[1]) not in public_net:
        raise ValueError('%s no está en la red pública' % PUBLIC_HOST[0])
    for name, ip, _mac in PRIVATE_HOSTS:
        if ipaddress.ip_address(ip) not in private_net:
            raise ValueError('%s no está en la red privada' % name)

def controller_command():
    """Comando de POX con los mismos valores que esta topología."""
    args = ' '.join('--%s=%s' % (k, v) for k, v in ROUTER.items())
    return ('python3 pox.py log.level --DEBUG openflow.of_01 --port=6653 '
            'protorouter %s --public_port=%d' % (args, PUBLIC_PORT))

class NATTopo(Topo):

    def build(self):
        s1 = self.addSwitch('s1')
        public_prefix = ipaddress.ip_network(ROUTER['public_subnet']).prefixlen
        private_prefix = ipaddress.ip_network(
            ROUTER['private_subnet']).prefixlen

        name, ip, mac = PUBLIC_HOST
        host = self.addHost(
            name, ip='%s/%d' % (ip, public_prefix), mac=mac,
            defaultRoute='via %s' % ROUTER['public_ip'])
        self.addLink(host, s1, port2=PUBLIC_PORT)

        for number, (name, ip, mac) in enumerate(PRIVATE_HOSTS,
                                                 start=PUBLIC_PORT + 1):
            host = self.addHost(
                name, ip='%s/%d' % (ip, private_prefix), mac=mac,
                defaultRoute='via %s' % ROUTER['private_ip'])
            self.addLink(host, s1, port2=number)

def run():

    check_config()
    print('Controlador POX para esta topología:\n  %s\n' % controller_command())
    
    topo = NATTopo()
    net = Mininet(topo=topo, controller=RemoteController, link=TCLink)
    net.start()

    # Deshabilita IPv6 en hosts
    for host in net.hosts:
        host.cmd("sysctl -w net.ipv6.conf.all.disable_ipv6=1")
        host.cmd("sysctl -w net.ipv6.conf.default.disable_ipv6=1")
        host.cmd("sysctl -w net.ipv6.conf.lo.disable_ipv6=1")

    # Deshabilita IPv6 en switch
    s1 = net.get('s1')
    s1.cmd("sysctl -w net.ipv6.conf.all.disable_ipv6=1")
    s1.cmd("sysctl -w net.ipv6.conf.default.disable_ipv6=1")
    s1.cmd("sysctl -w net.ipv6.conf.lo.disable_ipv6=1")

    CLI(net)
    net.stop()


if __name__ == '__main__':
    setLogLevel('info')
    run()
