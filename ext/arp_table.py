import time

ARP_TIMEOUT = 10


class ArpEntry(object):
    def __init__(self, mac, port):
        self.mac = mac                
        self.port = port               
        self.timestamp = time.time()    

    def is_expired(self):
        return time.time() - self.timestamp > ARP_TIMEOUT


class ArpTable(object):
    def __init__(self):
        self.entries = {}              

    def learn(self, ip, mac, port):
        self.entries[ip] = ArpEntry(mac, port)

    def lookup(self, ip):
        entry = self.entries.get(ip)
        if entry is None:
            return None
        if entry.is_expired():
            del self.entries[ip]
            return None
        return entry

    def clean_expired_entries(self):
        expired = [ip for ip, entry in self.entries.items() if entry.is_expired()]
        for ip in expired:
            del self.entries[ip]
