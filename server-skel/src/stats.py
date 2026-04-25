#Estadístiques, gestió i mostra.
import threading

class ServerStats:
    def __init__(self):
        # Utilitzem un Lock per evitar condicions de cursa amb els fils
        self.lock = threading.Lock()
        
        # Comptadors de tràfic general
        self.rx_packets = 0
        self.tx_packets = 0
        
        # Comptadors específics de l'RFC-31337
        self.unicast_forwarded = 0
        self.broadcast_forwarded = 0
        self.unknown_unicast = 0
        
    def inc_rx(self):
        with self.lock:
            self.rx_packets += 1
            
    def inc_tx(self):
        with self.lock:
            self.tx_packets += 1
            
    def inc_unicast(self):
        with self.lock:
            self.unicast_forwarded += 1
            
    def inc_broadcast(self):
        with self.lock:
            self.broadcast_forwarded += 1
            
    def inc_unknown_unicast(self):
        with self.lock:
            self.unknown_unicast += 1
            
    def mostrar(self, sessions_actives: int, macs_apreses: int):
        with self.lock:
            print("\n" + "="*35)
            print("     ESTADÍSTIQUES PIXES VPN")
            print("="*35)
            # Dades d'estat actual (es poden passar des del Switch i el Gestor de Sessions)
            print(f" Sessions actives   : {sessions_actives}")
            print(f" MACs a la taula    : {macs_apreses}")
            print("-" * 35)
            # Comptadors acumulats
            print(f" Paquets rebuts     : {self.rx_packets}")
            print(f" Paquets enviats    : {self.tx_packets}")
            print(f" Fwd Unicast        : {self.unicast_forwarded}")
            print(f" Fwd Broadcast      : {self.broadcast_forwarded}")
            print(f" Unknown Unicast    : {self.unknown_unicast}")
            print("="*35 + "\n")