#Simplificació podeu acceptar qualsevol contrasenya de 8 bytes.
def validar_contrasenya(password: bytes) -> bool:
    # Simplificació: Acceptem qualsevol contrasenya de 8 bytes
    return len(password) == 8