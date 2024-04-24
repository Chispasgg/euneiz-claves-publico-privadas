from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.hashes import SHA256
from cryptography.fernet import Fernet
from utils import utils
import base64
import json


def __desencrypt(clave, token_b64):
    # Podemos descifrar el mensaje utilizando 
    # el método "decrypt".
    f2 = Fernet(clave)
    token = base64.b64decode(token_b64)
    try:
        des = f2.decrypt(token)
    except:
        print("No se puede descifrar el mensaje")
        exit()
    # print(des)
    return des


def descifrar_mensaje(persona_receptora):

    # Cargar la clave privada desde el archivo
    with open(f'{utils.ruta_claves_privadas}/{persona_receptora}_private_key.pem', 'rb') as f:
        private_key_pem = f.read()
        private_key = serialization.load_pem_private_key(private_key_pem, password=None, backend=default_backend())
    
    # Leer el mensaje cifrado desde el archivo
    with open(f'{utils.ruta_mensajes_cifrados}/{persona_receptora}_mensaje_cifrado.txt', 'rb') as f:
        ciphertext = f.read()
    
    # Descifrado del mensaje cifrado utilizando la clave privada
    plaintext = private_key.decrypt(
        ciphertext,
        padding.OAEP(
            mgf=padding.MGF1(algorithm=SHA256()),
            algorithm=SHA256(),
            label=None
        )
    )
    
    return plaintext


def descifrar_mensaje_con_autoria(persona_origen, persona_destino):
    # Cargar el archivo con el JSON del mensaje
    with open(f'{utils.ruta_mensajes_cifrados}/{persona_destino}_v2_mensaje_cifrado.txt', 'r') as f:
        mensaje_cifrado_json = json.load(f)
    
    if not mensaje_cifrado_json:
        print("No hay nada en el mensaje")
        exit()
    
    # cargamos los datos del mensaje
    clave_cifrada_para_otra_persona_b64 = mensaje_cifrado_json['clave_cifrada']
    msg_p0_b64 = mensaje_cifrado_json['msg_cifrado']
    
    # Cargar la clave privada nuestra
    with open(f'{utils.ruta_claves_privadas}/{persona_destino}_private_key.pem', 'rb') as f:
        descifrar_clave_privada_pem = f.read()
        descifrar_clave_privada = serialization.load_pem_private_key(descifrar_clave_privada_pem, None, backend=default_backend())
    
    # cargamos la clave publica de la persona que nos ha enviado el mensaje
    with open(f'{utils.ruta_claves_publicas}/{persona_origen}_public_key.pem', 'rb') as f:
        clave_publica_pem = f.read()
        clave_publica_otra_persona = serialization.load_pem_public_key(clave_publica_pem, backend=default_backend())
    
    # descifrar la contraseña
    descifrar_clave_cifrada_para_otra_persona = base64.b64decode(clave_cifrada_para_otra_persona_b64)
    try:
        plaintext = descifrar_clave_privada.decrypt(
            descifrar_clave_cifrada_para_otra_persona,
            padding.OAEP(
                mgf=padding.MGF1(algorithm=SHA256()),
                algorithm=SHA256(),
                label=None
            )
        )
    except:
        print("El mensaje no se puede descifrar la clave privada")
        exit()
    passwd_descifrada = plaintext.decode("utf-8") 
    print(f'passwd: {passwd_descifrada}')
    
    # decodificamos el mensaje
    mensaje_descifrado = __desencrypt(passwd_descifrada, msg_p0_b64)
    
    # verificamos la autoria
    descifrar_emisor_b64 = f'{mensaje_cifrado_json["clave_cifrada"]}{mensaje_cifrado_json["msg_cifrado"]}'
    descifrar_firma_del_emisor = base64.b64decode(mensaje_cifrado_json["emisor_sign"])
    
    mensaje_persona_ok = "La autoria NO esta verificada"
    try:
        clave_publica_otra_persona.verify(
            descifrar_firma_del_emisor,
            descifrar_emisor_b64.encode('utf-8'),
            padding.PSS(
                mgf=padding.MGF1(hashes.SHA256()),
                salt_length=padding.PSS.MAX_LENGTH
            ),
            hashes.SHA256()
        )
        mensaje_persona_ok = "La autoria esta verificada"
    except:
        pass
    
    print(mensaje_persona_ok)
    print("-----------------------------------")
    return mensaje_descifrado
