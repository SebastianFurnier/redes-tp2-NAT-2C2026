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

    def outbound_key(self):
        return (self.proto, self.private_ip, self.private_port, self.remote_ip, self.remote_port)

    def inbound_key(self):
        return (self.proto, self.public_port, self.remote_ip, self.remote_port)


class NatTable(object):
    def __init__(self):
        self.outbound = {}
        self.inbound = {}
        self.used_ports = set()

    def add(self, proto, private_ip, private_port, remote_ip, remote_port):
        key = (proto, private_ip, private_port, remote_ip, remote_port)
        if key in self.outbound:
            return self.outbound[key]

        public_port = private_port if proto == ICMP else self.free_port(proto)
        if public_port is None:
            return None

        entry = NatEntry(proto, private_ip, private_port, remote_ip, remote_port, public_port)
        self.outbound[key] = entry
        self.inbound[entry.inbound_key()] = entry
        self.used_ports.add((proto, public_port))
        return entry

    def lookup_outbound(self, proto, private_ip, private_port, remote_ip, remote_port):
        return self.outbound.get((proto, private_ip, private_port, remote_ip, remote_port))

    def lookup_inbound(self, proto, public_port, remote_ip, remote_port):
        return self.inbound.get((proto, public_port, remote_ip, remote_port))

    def release(self, entry):
        self.outbound.pop(entry.outbound_key(), None)
        self.inbound.pop(entry.inbound_key(), None)
        self.used_ports.discard((entry.proto, entry.public_port))

    def free_port(self, proto):
        for port in range(PORT_MIN, PORT_MAX + 1):
            if (proto, port) not in self.used_ports:
                return port
        return None
