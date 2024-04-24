from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives import hashes
from cryptography.x509.oid import NameOID
from cryptography import x509
from utils import utils
import datetime
import os


def generar_claves(nombre_claves, password=None):
    
    # Generación de la clave privada RSA
    private_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=2048,
        backend=default_backend()
    )
    
    # Definir los atributos del sujeto (es decir, los atributos del titular del certificado)
    subject = x509.Name([
        x509.NameAttribute(NameOID.COUNTRY_NAME, u"US"),
        x509.NameAttribute(NameOID.STATE_OR_PROVINCE_NAME, u"California"),
        x509.NameAttribute(NameOID.LOCALITY_NAME, u"Mountain View"),
        x509.NameAttribute(NameOID.ORGANIZATION_NAME, u"My Company"),
        x509.NameAttribute(NameOID.COMMON_NAME, u"example.com"),
    ])
    
    # Crear un objeto de solicitud de certificado (CSR)
    csr = x509.CertificateSigningRequestBuilder().subject_name(
        subject
    ).sign(private_key, hashes.SHA256(), default_backend())
    
    # Construir el certificado utilizando CertificateBuilder
    builder = x509.CertificateBuilder()
    builder = builder.subject_name(subject)
    builder = builder.issuer_name(subject)  # En este ejemplo, el emisor es el mismo que el sujeto
    builder = builder.not_valid_before(datetime.datetime.utcnow())
    builder = builder.not_valid_after(datetime.datetime.utcnow() + datetime.timedelta(days=365))  # Duración de 1 año
    builder = builder.serial_number(x509.random_serial_number())
    builder = builder.public_key(csr.public_key())
    
    # Añadir extensiones al certificado
    builder = builder.add_extension(
        x509.SubjectAlternativeName([x509.DNSName(u"example.com")]),
        critical=False,
    )
    
    # Firmar el certificado con la clave privada
    certificate = builder.sign(private_key, hashes.SHA256(), default_backend())
    
    # Convertir el certificado a formato PEM
    cert_pem = certificate.public_bytes(encoding=serialization.Encoding.PEM)
    
    # Extracción de la clave pública correspondiente
    public_key = private_key.public_key()
    
    # Serialización de las claves en formato PEM
    
    print("Generando archivo PEM", end=" ")
    if password:
        print('con contraseña')
        # Añadir contraseña a la clave privada usando algoritmo de cifrado
        encryption_algorithm = serialization.BestAvailableEncryption(password.encode())
        private_key_pem = private_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=encryption_algorithm
        )
        public_key_pem = public_key.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo
        )
    else:
        print('sin contraseña')
        private_key_pem = private_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.NoEncryption()
        )
        public_key_pem = public_key.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo
        )
    
    # generar las carpetas de los artefactos criptograficos
    os.makedirs(utils.ruta_claves_privadas, exist_ok=True)
    os.makedirs(utils.ruta_claves_publicas, exist_ok=True)
    os.makedirs(utils.ruta_certificados, exist_ok=True)
    
    # Guardar las claves en archivos
    with open(f'{utils.ruta_claves_privadas}/{nombre_claves}_private_key.pem', 'wb') as f:
        f.write(private_key_pem)
        
    with open(f'{utils.ruta_claves_publicas}/{nombre_claves}_public_key.pem', 'wb') as f:
        f.write(public_key_pem)
    
    with open(f'{utils.ruta_certificados}/{nombre_claves}_certificate.pem', 'wb') as f:
        f.write(cert_pem)
