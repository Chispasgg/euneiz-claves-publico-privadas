from pasos.cifrado import CifradoMensaje
from pasos.descifrar import DescifradoMensaje
from pasos.crear_claves import GenerarClaves


def __paso1():
    generar = input("Quieres generar claves publico-privadas? [s/n] ")
    if generar == 's':
        tu_nombre = input("Cual es tu nombre? ")
        con_passwd = input("Quieres generar una contraseña? [s/n] ")
        if con_passwd == 's':
            password = input("Cual es la contraseña? ")
            GenerarClaves.generar_claves(tu_nombre, password)
        else:
            GenerarClaves.generar_claves(tu_nombre)
    else:
        __paso2()


def __paso2():
    cifrar = input("Quieres cifrar un mensaje?  [s/n] ")
    if cifrar == 's':
        
        mensaje = input("Cual es el mensaje? ")
        persona_destino = input("A quien le quieres enviar este mensaje? ")
        mensaje_codificado = CifradoMensaje.cifrar_mensaje(mensaje, persona_destino)
        print(" El mensaje cifrado para esa persona es:")
        print(mensaje_codificado)
    else:
        __paso3()


def __paso3():
    descifrar = input("Quieres descifrar un mensaje?  [s/n] ")
    if descifrar == 's':
        
        persona_receptora = input("Quien eres tu? ")
        mensaje_decodificado = DescifradoMensaje.descifrar_mensaje(persona_receptora)
        print(" El mensaje decodificado es:")
        print("==============================")
        print(mensaje_decodificado.decode())
        print("==============================")


def basico():
    __paso1()
