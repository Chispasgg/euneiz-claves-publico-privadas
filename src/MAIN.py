'''
Created on 9 feb 2024

@author: chispas
'''

from pasos.basico import basico
from pasos.conjunto import conjunto

if __name__ == '__main__':
    print("INICIO")
    proceso_basico = input("Quieres un proceso basico? [s/n] ")
    if proceso_basico.lower() == 's':
        basico()
    else:
        conjunto()
    
    print("FIN")
