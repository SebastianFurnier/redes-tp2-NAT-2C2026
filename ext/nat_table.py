ICMP = 1
PORT_MIN = 10000
PORT_MAX = 65535


class NatEntry(object):
    def __init__(self, proto, private_ip, private_port, remote_ip, remote_port, public_port):
        self.proto = proto
        self.private_ip = private_ip
        self.private_port = private_port
        self.remote_ip = remote_ip
        self.remote_port = remote_port
        self.public_port = public_port
        self.flows_installed = False
        self.flows_alive = 0
        self.cold_since = None
        

    def outgoing_key(self):
        return (self.proto, self.private_ip, self.private_port, self.remote_ip, self.remote_port)

    def incoming_key(self):
        return (self.proto, self.public_port, self.remote_ip, self.remote_port)


class NatTable(object):

    # Los valores por defecto son las constantes de siempre (10000 y 65535).
    def __init__(self, port_min=PORT_MIN, port_max=PORT_MAX):
        self.port_min = port_min
        self.port_max = port_max
        self.outgoing = {}
        self.incoming = {}
        self.used_ports = set()

    def add(self, proto, private_ip, private_port, remote_ip, remote_port):
        key = (proto, private_ip, private_port, remote_ip, remote_port)
        if key in self.outgoing:
            return self.outgoing[key]

        if proto == ICMP or self.is_free(proto, private_port):
            public_port = private_port
        else:
            public_port = self.free_port(proto)
        if public_port is None:
            return None

        entry = NatEntry(proto, private_ip, private_port, remote_ip, remote_port, public_port)
        self.outgoing[key] = entry
        self.incoming[entry.incoming_key()] = entry
        self.used_ports.add((proto, public_port))
        return entry

    def lookup_outgoing(self, proto, private_ip, private_port, remote_ip, remote_port):
        return self.outgoing.get((proto, private_ip, private_port, remote_ip, remote_port))

    def lookup_incoming(self, proto, public_port, remote_ip, remote_port):
        return self.incoming.get((proto, public_port, remote_ip, remote_port))

    def release(self, entry):
        self.outgoing.pop(entry.outgoing_key(), None)
        self.incoming.pop(entry.incoming_key(), None)
        self.used_ports.discard((entry.proto, entry.public_port))

    def is_free(self, proto, port):
        return (self.port_min <= port <= self.port_max and (proto, port) not in self.used_ports)
    
    def free_port(self, proto):
        for port in range(self.port_min, self.port_max + 1):
            if self.is_free(proto, port):
                return port
        return None
