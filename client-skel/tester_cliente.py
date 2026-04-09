import socket
import struct

# Configuración coincidente con los argumentos de tu cliente
IP = "127.0.0.1"
PORT = 5000
PASSWORD_EXPECTED = b"Xarxes01"

def check_packet(data):
    if len(data) < 11:
        return "❌ Error: Paquete demasiado corto (mínimo 11 bytes)"
    
    # Desempaquetar cabecera PIXES: opcode(1B), client_id(2B, big-endian), payload(8B) [cite: 45, 57]
    opcode, client_id, payload = struct.unpack("!BH8s", data[:11])
    
    if opcode == 0: # Supongamos 0 = REGISTER según RFC
        return f"✅ REGISTER recibido. Client ID: {client_id}"
    elif opcode == 1: # Supongamos 1 = AUTH
        if payload == PASSWORD_EXPECTED:
            return f"✅ AUTH recibido con password correcto."
        else:
            return f"❌ AUTH con password incorrecto: {payload}"
    elif opcode == 2: # Supongamos 2 = KEEPALIVE [cite: 119]
        return f"✅ KEEPALIVE recibido del cliente {client_id}."
    
    return f"❓ Paquete recibido. Opcode: {opcode}, ID: {client_id}"

def run_tester():
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.bind((IP, PORT))
    print(f"🚀 Tester activo en {IP}:{PORT}. Ejecuta tu vpnclient ahora...")

    while True:
        data, addr = sock.recvfrom(2048)
        result = check_packet(data)
        print(f"[{addr}] {result}")

if __name__ == "__main__":
    run_tester()