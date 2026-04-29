import socket
import time
from datetime import datetime

import protocol
import session
import stats
import switch
import credentials

#Funcio encarregada de llençar un missatge "decorat"
def log_missatge(nivell, func_info, missatge):
    now = datetime.now()
    temps_str = now.strftime("%Y-%m-%d %H:%M:%S.%f")[:-3]
    print(f"{temps_str} | {nivell:<8} | __main__:{func_info} - {missatge}")

class VpnServer:
    def __init__(self, config):
        self.config = config

        # Inicialitzem el Socket
        self.sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        self.sock.bind(('0.0.0.0', config.port))
        self.sock.settimeout(1.0) 

        # Inicialitzem els estats i el switch
        self.stats = stats.ServerStats()
        self.switch = switch.Switch(policy=config.unknown_mac.value)
        self.gestor_sessions = session.Server(self.sock)

        # Inicialitzem els temps
        self.last_stats_time = time.time()
        self.last_watchdog_time = time.time()

    def run(self):
        log_missatge("INFO", "main:319", f"Starting VPN switch on port {self.config.port}")
        log_missatge("INFO", "run:165", f"UDP socket bound on 0.0.0.0:{self.config.port}")
        
        while True:
            current_time = time.time()

            # Watchdog
            if current_time - self.last_watchdog_time >= 1.0:
                cids_actius = list(self.gestor_sessions.session.keys())
                for cid in cids_actius:
                    ha_expirat = self.gestor_sessions.watchdog(self.config.timeout, cid)
                    if ha_expirat:
                        self.switch.eliminar_macs_client(cid)
                        del self.gestor_sessions.session[cid]
                        
                self.last_watchdog_time = current_time

            # Mostrar Estadistiques
            if current_time - self.last_stats_time >= self.config.stats_interval:
                num_macs = len(self.switch.taula_mac)
                self.stats.mostrar(self.gestor_sessions.session, num_macs)
                self.last_stats_time = current_time
            try:
                dades, addr = self.sock.recvfrom(65535)
            except socket.timeout:
                continue
            except Exception as e:
                print(f"Error de xarxa: {e}")
                continue

            self.stats.inc_rx()

            header = protocol.VpnHeader.unpack(dades)
            if not header:
                continue  

            opcode = header.opcode
            cid = header.client_id
            payload = header.payload
            
            # Recuperem la sessio i sumem dades entrants
            sessio_actual = self.gestor_sessions.get_session_by_cid(cid)
            if sessio_actual:
                self._assegurar_comptadors(sessio_actual)
                sessio_actual.pkts_in += 1
                sessio_actual.bytes_in += len(dades)

            if opcode == protocol.Opcode.REGISTER:
                if sessio_actual and sessio_actual.addr != addr:
                    log_missatge("INFO", "handle_register:69", f"Client {cid} roamed from {sessio_actual.addr} to {addr}")
                
                self.gestor_sessions.on_register(cid, addr, payload)
                log_missatge("INFO", "handle_register", f"Client {cid} registered")
                # Comprovem la sessio un cop registrada per actualitzar estadistiques si es nova
                sessio_actual = self.gestor_sessions.get_session_by_cid(cid)
                if sessio_actual:
                    self._assegurar_comptadors(sessio_actual)
                    if sessio_actual.pkts_in == 0:
                        sessio_actual.pkts_in = 1
                        sessio_actual.bytes_in = len(dades)

            elif opcode == protocol.Opcode.AUTH:
                if sessio_actual and sessio_actual.state == session.SessionState.REGISTERING:                    
                    if credentials.validar_contrasenya(payload):
                        sessio_actual.psswd = payload
                        resultat = self.gestor_sessions.verificate(cid, payload)
                    else:
                        self.send_reject(addr, cid)
                    log_missatge("INFO", "handle_register", f"Client {cid} authenticated")

            elif opcode == protocol.Opcode.KEEPALIVE:
                self.gestor_sessions.refresh_ls(dades)

            elif opcode == protocol.Opcode.TRAFFIC:
                if sessio_actual and sessio_actual.state == session.SessionState.AUTHENTICATED:
                    self.gestor_sessions.refresh_ls(dades)
                    trama = dades[11:]

                    if protocol.is_valid_frame(trama):
                        mac_desti, mac_origen = protocol.Get_MadAddr(trama)

                        # Aprenentatge MAC
                        self.switch.aprendre_mac(mac_origen, cid)

                        # Decisio de reenviament
                        accio = self.switch.determinar_desti(mac_desti)

                        if accio == "BROADCAST" or accio == "FLOOD":
                            if accio == "BROADCAST":
                                self.stats.inc_broadcast()
                            else:
                                self.stats.inc_unknown_unicast()
                            self.send_to_all(dades, excepte_cid=cid)
                            
                        else:
                            dest_session = self.gestor_sessions.get_session_by_cid(accio)
                            if dest_session and dest_session.state == session.SessionState.AUTHENTICATED:
                                self.stats.inc_unicast()
                                self.stats.inc_tx()
                                self.sock.sendto(dades, dest_session.addr)
                
                                # Sumem els paquets enviats
                                dest_session.pkts_out += 1
                                dest_session.bytes_out += len(dades)

    def send_to_all(self, dades, excepte_cid):
        for cid, sessio in self.gestor_sessions.session.items():
            if cid != excepte_cid and sessio.state == session.SessionState.AUTHENTICATED:
                self.stats.inc_tx()
                self.sock.sendto(dades, sessio.addr)

    def send_reject(self, addr, cid):
        opcode = bytes([0x06])
        cid_bytes = cid.to_bytes(2, byteorder='big')
        payload = bytes(8)
        packet = opcode + cid_bytes + payload
        self.sock.sendto(packet, addr)