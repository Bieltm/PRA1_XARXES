#Implementeu la taula MAC (RFC-31337 §8.1)
class Switch:
    def __init__(self, policy="flood"):
        # Taula MAC: diccionari on { MAC (bytes) : CID (int) }
        self.taula_mac = {}
        self.policy = policy
        self.BROADCAST_MAC = b'\xff\xff\xff\xff\xff\xff'

    def aprendre_mac(self, mac_origen: bytes, cid: int):
        # Afegeix o sobreescriu la relació MAC -> CID
        self.taula_mac[mac_origen] = cid

    def netejar_macs_per_cid(self, cid: int):
        # Creem una llista amb les MACs a esborrar per no modificar el dict mentre iterem
        macs_a_esborrar = []
        for mac, mapped_cid in self.taula_mac.items():
            if (mapped_cid == cid):
                macs_a_esborrar.append(map)
        for mac in macs_a_esborrar:
            del self.taula_mac[mac]

    def determinar_desti(self, mac_desti: bytes) -> str | int:
        # 1. Broadcast
        if mac_desti == self.BROADCAST_MAC:
            return "BROADCAST"
        # 2. Unicast Conegut
        if mac_desti in self.taula_mac:
            return self.taula_mac[mac_desti] 
        # 3. Unicast Desconegut
        if self.policy == "flood":
            return "FLOOD"
        else:
            return "DISCARD"