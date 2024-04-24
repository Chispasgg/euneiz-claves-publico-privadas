#!/bin/bash

# Define el directorio donde se encuentran los certificados que contienen las claves públicas
CERT_DIR="../certificados"

# Verifica si el directorio existe
if [ ! -d "$CERT_DIR" ]; then
    echo "El directorio especificado no existe."
    exit 1
fi

# Lista todos los archivos PEM en el directorio
echo "Listando todos los certificados y sus fechas de expiración:"
for cert in "$CERT_DIR"/*.pem; do
    if [ -f "$cert" ]; then
        # Extrae la fecha de expiración del certificado
        expiration=$(openssl x509 -enddate -noout -in "$cert" | cut -d= -f2)
        echo "Certificado: $(basename "$cert")"
        echo "Fecha de expiración: $expiration"
        echo ""
    fi
done
