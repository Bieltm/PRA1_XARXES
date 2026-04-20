#Gestió de sessions (RFC-31337 §7.1)
from enum import Enum
import time
class SessionState(Enum):
    NONE = "none"
    REGISTERING = "registering"
    AUTHENTICATED = "authenticated"
class Session:
    def __init__(self, cid: int, addr: tuple, psswd):
        self.cid = cid
        self.addr = addr
        self.state = SessionState.NONE
        self.last_seen = time.time()
        self.psswd = psswd
    def get_psswd(self):
            return self.psswd

class Server:
    def __init__(self, server_socket):
        self.session = {}
        self.mac_table = {}
        self.server_socket = server_socket
    def add_session(self, sessio: Session):
        self.session[sessio.cid] = sessio
        return sessio
    def get_session_by_cid(self, cid: int):
        return self.session.get(cid)
    def delete_MAC_entrys(self, cid):
        to_remove = []
        for mac, cid_associat in self.mac_table.items():
            if (cid_associat == cid):
                to_remove.append(mac)
        for mac in to_remove:
                del self.mac_table[mac]
    def send_ack(self, session, cid, server_socket):
        opcode = bytes([0x05])
        cid_bytes = cid.to_bytes(2, byteorder='big')
        payload = bytes(8)
        packet = opcode + cid_bytes + payload
        server_socket.sendto(packet, session.addr)
    #Rebre el REGISTER, comprovar si ja existia sessió per aquell CID (i si cal netejar les MAC), establir last_seen i respondre ACK.
    def on_register(self, cid_rebut, addr_rebut, psswd_rebut):
        if cid_rebut in self.session:
            session = self.get_session_by_cid(cid_rebut)
            if session.addr != addr_rebut:
                session.addr = addr_rebut
                self.delete_MAC_entrys(cid_rebut)
        else:
            session = self.add_session(Session(cid_rebut, addr_rebut, psswd_rebut))
        session.state = SessionState.REGISTERING
        session.last_seen = time.time()
        self.send_ack(session, session.cid, self.server_socket)
    #Un cop el client rep l'ACK del registre, ha de preparar immediatament el paquet d'autenticació:
    def verificate(self, cid_rebut, payload : bytes[8]):
        session = self.get_session_by_cid(cid_rebut)
        #Existència: Verifica que el CID especificat tingui una sessió oberta a la taula.
        if not session:
            return 0x06
        #Estat Correcte: Comprova que la sessió estigui exactament en estat REGISTERING. 
        #Si un client ja autenticat envia un AUTH, el servidor ha de respondre amb un REJECT.
        if session.state != SessionState.REGISTERING:
            return 0x06
        #Comparació de credencials: Compara els 8 bytes del payload amb la contrasenya configurada localment al servidor per a aquell CID.
        psswd = session.get_psswd()
        if (psswd != payload):
            return 0x06
        session.state = SessionState.AUTHENTICATED
        session.last_seen = time.time()
        self.send_ack(session, session.cid, self.server_socket)
        return 0x05
    #Manteniment d'activitat: El client ha d'enviar un missatge KEEPALIVE (Opcode 0x04) si no ha enviat tràfic de dades en els darrers 10 segons.
    #El servidor actualitza el camp last_seen (última vegada vist) cada vegada que rep un missatge de TRAFFIC o KEEPALIVE d'un client autenticat.
    def refresh_ls(self, data_rebut):
        if len(data_rebut) < 11:
            return
        opcode = data_rebut[0]
        cid = int.from_bytes(data_rebut[1:3], byteorder='big')
        session = self.get_session_by_cid(cid)
        if session and session.state == SessionState.AUTHENTICATED:
            if opcode == 0x03 or opcode == 0x04:
                session.last_seen = time.time()
    def watchdog(self, temps_configurat, cid):
        session = self.get_session_by_cid(cid)
        if session is not None:
            if (time.time() - session.last_seen) > temps_configurat:
                self.delete_MAC_entrys(cid)
                del self.session[cid]    
                
            