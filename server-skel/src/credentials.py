#Simplificació podeu acceptar qualsevol contrasenya de 8 bytes.
# credentials.py

def validar_contrasenya(password: bytes) -> bool:
    # 1. Ha de tenir exactament 8 bytes
    if len(password) != 8:
        return False
    # 2. Ha de ser caràcters ASCII alfanumèrics (A-Z, a-z, 0-9)
    try:
        text = password.decode('ascii')
    except UnicodeDecodeError:
        return False
    if text.isalnum() == False:
        return False
    return True