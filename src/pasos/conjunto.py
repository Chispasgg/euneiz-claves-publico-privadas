from pasos.crear_claves import GenerarClaves
from pasos.cifrado import CifradoMensaje
import json
from pasos.descifrar import DescifradoMensaje


def __paso1():
    generar = input("Quieres generar claves publico-privadas? [s/n] ")
    if generar == 's':
        tu_nombre = input("Cual es tu nombre? ")
        GenerarClaves.generar_claves(tu_nombre)
    else:
        __paso2()   


def __paso2():
    cifrar = input("Quieres cifrar un mensaje para una persona concreta?  [s/n] ")
    # cifrar = 's'
    if cifrar == 's':
        persona_origen = input("Quien eres tu? ")
        mensaje = input("Cual es el mensaje? ")
        persona_destino = input("A quien le quieres enviar este mensaje? ")
        # persona_origen = 'patxi1'
        # mensaje = 'hola patxi2'
        # persona_destino = 'patxi2'
        mensaje_codificado = CifradoMensaje.cifrar_mensaje_con_autoria(mensaje, persona_origen, persona_destino)
        print(" El mensaje cifrado para esa persona es:")
        print(json.dumps(mensaje_codificado, indent=1))
    else:
        __paso3()


def __paso3():
    descifrar = input("Quieres descifrar un mensaje?  [s/n] ")
    if descifrar == 's':
        persona_origen = input("Quien envia el mensaje? ")
        persona_destino = input("A quien va dirigido el mensaje? ")
        mensaje_decodificado = DescifradoMensaje.descifrar_mensaje_con_autoria(persona_origen, persona_destino)
        print(" El mensaje decodificado es:")
        print("==============================")
        print(mensaje_decodificado.decode())
        print("==============================")


def conjunto():
    __paso1()
