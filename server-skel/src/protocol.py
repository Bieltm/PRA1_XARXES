#Definiu l’enum Opcode (valors a RFC-31337 §5) i la classe VpnHeader (format a RFC-31337 §4.1).
import struct
from enum import IntEnum
from enum import Enum


class Opcode(IntEnum):
    REGISTER  = 0x01
    AUTH      = 0x02
    TRAFFIC   = 0x03
    KEEPALIVE = 0x04
    ACK       = 0x05
    REJECT    = 0x06
class VpnHeader:
    def __init__(self, opcode: Opcode, client_id: int, payload: bytes = b'\x00' * 8):
        self.opcode = opcode
        self.client_id = client_id
        self.payload = payload
    def pack(self):
        return struct.pack("!BH8s", self.opcode, self.client_id, self.payload)
    @classmethod
    def unpack(cls, dades_rebudes):
        if len(dades_rebudes) < 11:
            return None
        
        capçalera = dades_rebudes[:11]
        raw_opcode, client_id, payload = struct.unpack("!BH8s", capçalera)
        try:
            opcode = Opcode(raw_opcode)
            return cls(opcode, client_id, payload)
        except ValueError:
            return None
        
def Encode_NumSeq(numero):
    return struct.pack("!Q", numero)
def Decode_NumSeq(payload):
    return struct.unpack("!Q", payload)[0]
#Extraccio de les adreçes MAC
def Get_MadAddr(trama_ethernet):
    if len(trama_ethernet) < 14:
        return None, None
    dest_mac = trama_ethernet[0:6] 
    src_mac = trama_ethernet[6:12] 
    return dest_mac, src_mac
#Format de MAC per a humans (convertir a hexadecimal)
def Convert_Hex(mac):
    res = "" 
    for i in range(0, len(mac)):
        v_hex = f"{mac[i]:02x}"
        if i > 0:
            res += ":"
        res += v_hex
    return res.upper()
#Gestió de la contrasenya
def Convert_Password(VpnHeader):
    if (VpnHeader.opcode!=0x02):
        return ""
    return VpnHeader.payload.decode('ascii').strip('\x00')
#Definició de la politica de MACs desconegudes
class UnknownMacPolicy(Enum):
    FLOOD = "flood"      # Inundar tots els clients
    DISCARD = "discard"  # Descartar la trama
#Verificació de la mida de la trama ETHERNET
def is_valid_frame(trama_ethernet):
    # Comprova si la longitud és de 14 o més
    return len(trama_ethernet) >= 14