#Gestió de sessions (RFC-31337 §7.1)
from enum import Enum
import time
class SessionState(Enum):
    NONE = "none"
    REGISTERING = "registering"
    AUTHENTICATED = "authenticated"
class Session:
    def __init__(self, cid: int, addr: tuple):
        self.cid = cid
        self.addr = addr
        self.state = SessionState.NONE
        self.last_seen = None
        self.cids_registrats = set()
        #TODO: def delete_MAC_entrys
        #TODO: def get_psswd
class Server:
    def __init__(self):
        self.session = {}
        self.mac_table = {}
    def add_session(self, sessio: Session):
        self.session[sessio.cid] = sessio
        return sessio
    def get_session_by_cid(self, cid: int):
        return self.session.get(cid)
    #TODO: def send_ack():
    
    #Rebre el REGISTER, comprovar si ja existia sessió per aquell CID (i si cal netejar les MAC), establir last_seen i respondre ACK.
    def on_register(self, cid_rebut, addr_rebut):
        if cid_rebut in self.session:
            session = self.get_session_by_cid(cid_rebut)
            if session.addr != addr_rebut:
                session.addr = addr_rebut
                session.delete_MAC_entrys
        else:
            session = self.add_session(Session(cid_rebut, addr_rebut))
        session.state = SessionState.REGISTERING
        session.last_seen = time.time()
        self.send_ack(session.addr, session.cid)
    #Un cop el client rep l'ACK del registre, ha de preparar immediatament el paquet d'autenticació:
    def verificate(self, cid_rebut, payload : bytes[8]):
        session = self.get_session_by_cid(cid_rebut)
        #Existència: Verifica que el CID especificat tingui una sessió oberta a la taula.
        if not session:
            return 0x06
        #Estat Correcte: Comprova que la sessió estigui exactament en estat REGISTERING. 
        #Si un client ja autenticat envia un AUTH, el servidor ha de respondre amb un REJECT.
        if session.state != Session.REGISTERING:
            return 0x06
        #Comparació de credencials: Compara els 8 bytes del payload amb la contrasenya configurada localment al servidor per a aquell CID.
        psswd = session.get_psswd()
        if (psswd != payload):
            return 0x06
        session.state = SessionState.AUTHENTICATED
        session.last_seen = time.time()
        session.send_ack(self.session.addr, self.session.cid)
        return 0x05
    #Manteniment d'activitat: El client ha d'enviar un missatge KEEPALIVE (Opcode 0x04) si no ha enviat tràfic de dades en els darrers 10 segons.
    def activity_mantain(self, session: Session):
        if session.last_seen is not None:
            temps_recorregut = time.time() - session.last_seen
            if (temps_recorregut > 10):
                return 0x04
            return None
    #El servidor actualitza el camp last_seen (última vegada vist) cada vegada que rep un missatge de TRAFFIC o KEEPALIVE d'un client autenticat.
    def refresh_ls(self, data_rebut):
        opcode = data_rebut[0]
        cid_bytes = data_rebut[1:3]
        cid = int.from_bytes(cid_bytes, byteorder='big')
        sessio = self.get_session_by_cid(cid)
        if (opcode == 0x05 or opcode == 0x04):
            if sessio:
                sessio.last_seen = time.time()
    #Expiracio de sessio:El servidor executa un procés periòdic de vigilància ("watchdog"). Si la diferència entre l'hora actual i el last_seen supera el temps configurat, la sessió s'elimina.
    def watchdog(self, temps_configurat, cid):
        session = self.get_session_by_cid(cid)
        if ((time.time() - session.last_seen)>temps_configurat):
            #Neteja: Quan una sessió expira, el servidor ha d'eliminar simultàniament totes les entrades de la taula de dades MAC associades a aquell CID.
            session.delete_MAC_entrys(cid)
            del self.session[session.cid]