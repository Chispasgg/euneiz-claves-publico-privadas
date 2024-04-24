from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.fernet import Fernet
from utils import utils
import base64
import json
import os


def cifrar_mensaje(mensaje, persona_destino):
    # Cargar la clave pública desde el archivo
    with open(f'{utils.ruta_claves_publicas}/{persona_destino}_public_key.pem', 'rb') as f:
        public_key_pem = f.read()
        public_key = serialization.load_pem_public_key(public_key_pem, backend=default_backend())
    
    # Mensaje a cifrar
    # mensaje = mensaje.encode('utf-8')
    mensaje = mensaje.encode('latin-1')
    
    # Cifrado del mensaje utilizando la clave pública
    ciphertext = public_key.encrypt(
        mensaje,
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )
    os.makedirs(utils.ruta_mensajes_cifrados, exist_ok=True)
    
    # Guardar el mensaje cifrado en un archivo de texto
    with open(f'{utils.ruta_mensajes_cifrados}/{persona_destino}_mensaje_cifrado.txt', 'wb') as f:
        f.write(ciphertext)
    ciphertext = str(ciphertext)
    return ciphertext


def __generar_passwd(): 
    # Generamos una clave
    return Fernet.generate_key()
    

def __encrypt(message, clave):
    
    # Creamos la instancia de Fernet
    # Parametros: key: clave generada
    f = Fernet(clave)
    
    # Encriptamos el mensaje
    # utilizando el método "encrypt"
    token = f.encrypt(message.encode('utf-8'))
    
    # Mostramos el token del mensaje en base64
    token = base64.b64encode(token).decode()
    
    # Mostramos el token del mensaje
    # print(token)
    # print(clave)
    
    return token
    

def cifrar_mensaje_con_autoria(mensaje, persona_origen, persona_destino, psswd_lenght=15):
    # Cargar tu clave privada y publica desde un archivo PEM
    with open(f'{utils.ruta_claves_privadas}/{persona_origen}_private_key.pem', 'rb') as f:
        clave_privada_pem = f.read()
        clave_privada = serialization.load_pem_private_key(clave_privada_pem, None, backend=default_backend())
    
    # Cargar la clave pública desde el archivo la otra persona
    with open(f'{utils.ruta_claves_publicas}/{persona_destino}_public_key.pem', 'rb') as f:
        clave_publica_pem = f.read()
        clave_publica_otra_persona = serialization.load_pem_public_key(clave_publica_pem, backend=default_backend())
    
    # generamos una clave aleatoria
    clave = __generar_passwd()
    print(f'passwd: {clave.decode("utf-8")}')
    # ciframos el mensaje
    msg_p0_b64 = __encrypt(mensaje, clave)
    
    # ciframos la passwd con la firma del destinatario (así el destinatario sabra que el mensaje es solo para el)
    clave_cifrada_para_otra_persona = clave_publica_otra_persona.encrypt(
        clave,
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )
    
    clave_cifrada_para_otra_persona_b64 = base64.b64encode(clave_cifrada_para_otra_persona).decode()
    
    # firmamos la passwd y el mensaje cifrado con nuestra firma (así el destinatario sabra que el mensaje es nuestro)
    clave_cifrada_por_la_otra_persona_mas_msg_p0_b64 = f'{clave_cifrada_para_otra_persona_b64}{msg_p0_b64}'
    
    firma_del_emisor = clave_privada.sign(
        clave_cifrada_por_la_otra_persona_mas_msg_p0_b64.encode('utf-8'),
        padding.PSS(
            mgf=padding.MGF1(hashes.SHA256()),
            salt_length=padding.PSS.MAX_LENGTH
        ),
        hashes.SHA256()
    )
    
    firma_del_emisor_b64 = base64.b64encode(firma_del_emisor).decode()
    
    # generamos el primer json con la info NUESTRO MENSAJE
    msg_passwd_f0_f1 = {
        'clave_cifrada': clave_cifrada_para_otra_persona_b64,
        'msg_cifrado': msg_p0_b64,
        'emisor_sign':firma_del_emisor_b64}
    
    # Guardar el mensaje cifrado en un archivo de JSON
    with open(f'{utils.ruta_mensajes_cifrados}/{persona_destino}_v2_mensaje_cifrado.txt', 'w') as f:
        f.write(json.dumps(msg_passwd_f0_f1))
    
    return msg_passwd_f0_f1
    
