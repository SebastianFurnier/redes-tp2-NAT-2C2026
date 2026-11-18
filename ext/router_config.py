from pox.lib.addresses import EthAddr, IPAddr, parse_cidr

class ConfigError(ValueError):
    """Un parámetro de arranque es inválido."""


def _ip(name,value):
    try:
        return IPAddr(str(value))
    except Exception:
        raise ConfigError("--%s: '%s' no es una IP válida" % (name, value))
        
def _mac(name,value):
    try:
        return EthAddr(str(value))
    except Exception:
        raise ConfigError("--%s: '%s' no es una MAC válida ""(formato 00:00:00:aa:aa:aa)" % (name, value))
    
def _subnet(name,value):
    try:
        if "/" not in str(value):
            raise ValueError("Falta la máscara")
        return parse_cidr(str(value), allow_host=True)
    except Exception:
        raise ConfigError("--%s: '%s' no es una subred válida ""(formato 192.168.1.0/24)" % (name, value))

def _int(name,value,minimum,maximum):
    if isinstance(value,bool):
        raise ConfigError("--%s: falta el valor" % name)
    try:
        number = int(value)
    except (TypeError,ValueError):
        raise ConfigError("--%s: '%s' no es un número entero" % (name, value))
    if not minimum <= number <= maximum:
        raise ConfigError("--%s: %d fuera de rango [%d, %d]"% (name, number, minimum, maximum))
    return number

class RouterConfig(object):
    def __init__(self,
                 public_ip="200.0.0.254",
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
        
        self.public_ip = _ip("public_ip", public_ip)
        self.public_mac = _mac("public_mac", public_mac)
        self.public_subnet, self.public_mask = _subnet("public_subnet", public_subnet)
        self.public_port = _int("public_port", public_port, 1, 0xFEFF)

        self.private_ip = _ip("private_ip", private_ip)
        self.private_mac = _mac("private_mac", private_mac)
        self.private_subnet, self.private_mask = _subnet("private_subnet", private_subnet)

        self.port_min = _int("port_min", port_min, 1, 65535)
        self.port_max = _int("port_max", port_max, 1, 65535)
        
        self.flow_idle_timeout = _int("flow_idle_timeout", flow_idle_timeout, 0, 0xFFFF)
        self.flow_hard_timeout = _int("flow_hard_timeout", flow_hard_timeout, 0, 0xFFFF)
        self.pending_timeout = _int("pending_timeout", pending_timeout, 1, 3600)
        self.arp_timeout = _int("arp_timeout", arp_timeout, 1, 86400)

        self._validate()

    def _validate(self):
        if not self.public_ip.inNetwork(self.public_subnet, self.public_mask):
            raise ConfigError("--public_ip %s no pertenece a la subred ""pública %s/%d" % (self.public_ip,self.public_subnet,self.public_mask))
        if not self.private_ip.inNetwork(self.private_subnet,self.private_mask):
            raise ConfigError("--private_ip %s no pertenece a la subred "
                              "privada %s/%d" % (self.private_ip,self.private_subnet,self.private_mask))
        if (self.public_subnet.inNetwork(self.private_subnet,self.private_mask) or self.private_subnet.inNetwork(self.public_subnet, self.public_mask)):
            raise ConfigError("las subredes pública (%s/%d) y privada ""(%s/%d) se superponen" % (self.public_subnet, self.public_mask, self.private_subnet, self.private_mask))
        if self.public_mac == self.private_mac:
            raise ConfigError("--public_mac y --private_mac son iguales")
        if self.port_min > self.port_max:
            raise ConfigError("--port_min (%d) es mayor que --port_max (%d)" % (self.port_min, self.port_max))

    def summary(self):
        """Resumen en una línea por interfaz, para el log de arranque."""
        return [
            "Pública : %s (%s) subred %s/%d, puerto del switch %d"
            % (self.public_ip, self.public_mac, self.public_subnet,self.public_mask, self.public_port),
            "Privada : %s (%s) subred %s/%d"
            % (self.private_ip, self.private_mac, self.private_subnet,self.private_mask),
            "NAT     : puertos públicos %d-%d" % (self.port_min,self.port_max),
            "Reglas  : idle_timeout=%ds hard_timeout=%ds"
            % (self.flow_idle_timeout, self.flow_hard_timeout),
            "Esperas : ARP pendiente %ds, entrada ARP %ds"
            % (self.pending_timeout, self.arp_timeout),
        ]