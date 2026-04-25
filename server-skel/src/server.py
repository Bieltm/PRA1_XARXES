import socket
import time

import protocol
import session
import stats
import switch
import credentials

class VpnServer:
    def __init__(self, config):
        self.config = config

        #Inicialitzem el Socket
        self.sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        self.sock.bind(('0.0.0.0', config.port))
        self.sock.settimeout(1.0) 

        #Inicialitzem els estats
        self.stats = stats.ServerStats()
        
        #Inicialitzem el switch
        self.switch = switch.Switch(policy=config.unknown_mac.value)
        #inicialitzem el gestor de sessions de session
        self.gestor_sessions = session.Server(self.sock)

        #Inicialitzem a temps actual el last_time i el watchdog.
        self.last_stats_time = time.time()
        self.last_watchdog_time = time.time()

    def run(self):
        print(f"Escoltant a 0.0.0.0:{self.config.port}...")
        
        while True:
            current_time = time.time()

            if current_time - self.last_watchdog_time >= 1.0:
                cids_actius = list(self.gestor_sessions.session.keys())
                for cid in cids_actius:
                    self.gestor_sessions.watchdog(self.config.timeout, cid)
                self.last_watchdog_time = current_time

            if current_time - self.last_stats_time >= self.config.stats_interval:
                num_sessions = len(self.gestor_sessions.session)
                num_macs = len(self.switch.taula_mac)
                self.stats.mostrar(num_sessions, num_macs)
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
            
            if opcode == protocol.Opcode.REGISTER:
                print(f"Client {cid} registered")
                self.gestor_sessions.on_register(cid, addr, payload)

            elif opcode == protocol.Opcode.AUTH:
                sessio_actual = self.gestor_sessions.get_session_by_cid(cid)
                
                if sessio_actual and sessio_actual.state == session.SessionState.REGISTERING:
                    # Validem el format amb credentials
                    if credentials.validar_contrasenya(payload):
                        sessio_actual.psswd = payload
                        resultat = self.gestor_sessions.verificate(cid, payload)
                        if resultat == 0x05:
                            print(f"Client {cid} authenticated.")
                    else:
                        print(f"Credencials invàlides pel CID {cid}")
                        self.send_reject(addr, cid)

            elif opcode == protocol.Opcode.KEEPALIVE:
                self.gestor_sessions.refresh_ls(dades)

            elif opcode == protocol.Opcode.TRAFFIC:
                sessio_actual = self.gestor_sessions.get_session_by_cid(cid)
                
                if sessio_actual and sessio_actual.state == session.SessionState.AUTHENTICATED:
                    self.gestor_sessions.refresh_ls(dades)
                    trama = dades[11:]

                    if protocol.is_valid_frame(trama):
                        mac_desti, mac_origen = protocol.Get_MadAddr(trama)

                        # Aprenentatge MAC
                        self.switch.aprendre_mac(mac_origen, cid)

                        # Decisió de reenviament
                        accio = self.switch.determinar_desti(mac_desti)

                        if accio == "BROADCAST" or accio == "FLOOD":
                            if accio == "BROADCAST":
                                self.stats.inc_broadcast()
                            else:
                                self.stats.inc_unknown_unicast()
                            self.send_to_all(dades, excepte_cid=cid)
                            
                        elif accio == "DISCARD":
                            self.stats.inc_unknown_unicast()
                            
                        else:
                            dest_session = self.gestor_sessions.get_session_by_cid(accio)
                            if dest_session and dest_session.state == session.SessionState.AUTHENTICATED:
                                self.stats.inc_unicast()
                                self.stats.inc_tx()
                                self.sock.sendto(dades, dest_session.addr)
    
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