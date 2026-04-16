#Gestió de sessions (RFC-31337 §7.1)
from enum import Enum
import time

class SessionState(Enum):
    NONE = "none"
    REGISTERING = "registering"
    AUTHENTICATED = "authenticated"
class Session:
    cids_registrats = set()
    def __init__(self, cid: int, addr: tuple):
        self.cid = cid
        self.addr = addr
        self.state = SessionState.NONE
        self.last_seen = None
    
    #Rebre el REGISTER, comprovar si ja existia sessió per aquell CID (i si cal netejar les MAC), establir last_seen i respondre ACK.
    def on_register(self, cid_rebut, addr_rebut):
        if cid_rebut in Session.cids_registrats:
            session = self.get_session_by_cid(cid_rebut)
            if session.addr != addr_rebut:
                session.addr = addr_rebut
                self.mac_table.remove_entries_for_cid(cid_rebut)
        else:
            session = Session(cid_rebut, addr_rebut)
            Session.cids_registrats.add(cid_rebut)
        session.state = SessionState.REGISTERING
        session.last_seen = time.time()
        self.send_ack(session.addr, session.cid)



    #def on_authenticate(...): en aquest estat el servidor ja permet el reenviament de missatges de trafic
    #Manteniment d'activitat: El client ha d'enviar un missatge KEEPALIVE (Opcode 0x04) si no ha enviat tràfic de dades en els darrers 10 segons.
    #El servidor actualitza el camp last_seen (última vegada vist) cada vegada que rep un missatge de TRAFFIC o KEEPALIVE d'un client autenticat.
    #Expiracio de sessio:El servidor executa un procés periòdic de vigilància ("watchdog"). Si la diferència entre l'hora actual i el last_seen supera el temps configurat, la sessió s'elimina.
    #Neteja: Quan una sessió expira, el servidor ha d'eliminar simultàniament totes les entrades de la taula de dades MAC associades a aquell CID.

