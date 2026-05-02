# Estadístiques, gestió i mostra.
import threading
from datetime import datetime

class ServerStats:
    def __init__(self):
        self.lock = threading.Lock()
        # Comptadors de tràfic general
        self.rx_packets = 0
        self.tx_packets = 0
        # Comptadors específics de l'RFC-31337
        self.unicast_forwarded = 0
        self.broadcast_forwarded = 0
        self.unknown_unicast = 0
        self.discarded_packets = 0
        
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

    def inc_discard(self):
        with self.lock:
            self.discarded_packets += 1
            
    def mostrar(self, sessions_dict, macs_apreses: int):
        with self.lock:
            # Ara calculem les sessions actives mirant quants clients hi ha al diccionari
            sessions_actives = len(sessions_dict)
            
            # Agafem l'hora actual per saber quan s'imprimeix
            now = datetime.now()
            temps_str = now.strftime("%H:%M:%S")

            print("\n" + "="*76)
            print(f"[{temps_str}]          ESTADÍSTIQUES PIXES VPN")
            print("="*76)
            
            # Dades d'estat actual
            print(f" Sessions actives   : {sessions_actives}")
            print(f" MACs a la taula    : {macs_apreses}")
            print("-" * 76)
            
            # Comptadors acumulats
            print(f" Paquets rebuts     : {self.rx_packets}")
            print(f" Paquets enviats    : {self.tx_packets}")
            print(f" Fwd Unicast        : {self.unicast_forwarded}")
            print(f" Fwd Broadcast      : {self.broadcast_forwarded}")
            print(f" Unknown Unicast    : {self.unknown_unicast}")
            print(f" Discarded          : {self.discarded_packets}")
            print("-" * 76)
            
            # Taula de clients
            print(f" {'CID':<5} | {'Estat':<15} | {'Pkts In':<8} | {'Bytes In':<10} | {'Pkts Out':<9} | {'Bytes Out':<10}")
            print("-" * 76)

            # Recorrem els clients per imprimir la seva informació
            if not sessions_dict:
                print(" (Cap client connectat en aquest moment)")
            else:
                for cid, sessio in sessions_dict.items():
                    # Ens assegurem de treure el valor de l'estat per a què quedi bonic
                    estat = sessio.state.value if hasattr(sessio.state, 'value') else str(sessio.state)
                    print(f" {cid:<5} | {estat:<15} | {sessio.pkts_in:<8} | {sessio.bytes_in:<10} | {sessio.pkts_out:<9} | {sessio.bytes_out:<10}")

            print("="*76 + "\n")